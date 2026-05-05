#!/usr/bin/env python3
# =============================================================================
# test_raw_probe_safety.py  -  Unit tests for raw probe validation and fallback guard
# =============================================================================
# Usage:
#   python -m unittest tools.test_raw_probe_safety
#   python tools/test_raw_probe_safety.py
#
# Key options:
#   No CLI flags; run as a Python unittest module or script
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 04.04.2026
# =============================================================================
from __future__ import annotations

import asyncio
import errno
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.tools import scanner_engine, scanner_probes
from training.tools.scanner_types import PortResult, PROFILES


class RawProbeSafetyTests(unittest.TestCase):
    def test_syn_probe_ignores_mirrored_syn_packet(self) -> None:
        mirrored = scanner_probes.IP(src="127.0.0.1", dst="10.10.10.5") / scanner_probes.TCP(sport=44444, dport=80, flags="S")

        with mock.patch.object(scanner_probes.random, "randint", side_effect=[44444, 123456]):
            with mock.patch.object(scanner_probes, "sr1", return_value=mirrored):
                result = scanner_probes.syn_probe("10.10.10.5", 80, PROFILES["x15"])

        self.assertEqual(result.protocol_flag, "TIMEOUT")
        self.assertEqual(result.state, "filtered")

    def test_syn_probe_accepts_matching_syn_ack(self) -> None:
        syn_ack = scanner_probes.IP(src="10.10.10.5", dst="127.0.0.1", ttl=64) / scanner_probes.TCP(sport=80, dport=44444, flags="SA", ack=999, window=64240)

        with mock.patch.object(scanner_probes.random, "randint", side_effect=[44444, 123456]):
            with mock.patch.object(scanner_probes, "sr1", return_value=syn_ack):
                with mock.patch.object(scanner_probes, "send", return_value=None):
                    result = scanner_probes.syn_probe("10.10.10.5", 80, PROFILES["x15"])

        self.assertEqual(result.protocol_flag, "SYN_ACK")
        self.assertEqual(result.state, "open")
        self.assertEqual(result.tcp_window, 64240)

    def test_raw_guard_switches_to_connect_when_sample_fails(self) -> None:
        engine = scanner_engine.SpikeScanEngine(profile="x15", seed=7)
        ports = list(range(1, 17))

        def fake_batch_syn_probe(host: str, batch_ports: list[int], profile, decoys=None, spoof_ttl=None) -> list[PortResult]:
            return [
                PortResult(host, port, "open", "tcp", "SYN_ACK", 1000.0, 0, port)
                for port in batch_ports
            ]

        def fake_connect_probe(host: str, port: int, timeout: float = 1.0, source_port=None) -> PortResult:
            return PortResult(host, port, "closed", "tcp", "RST", 1000.0, 0, port)

        with mock.patch.object(scanner_engine, "RAW_AVAILABLE", True):
            with mock.patch.object(scanner_engine, "batch_syn_probe", side_effect=fake_batch_syn_probe):
                with mock.patch.object(scanner_engine, "connect_probe", side_effect=fake_connect_probe):
                    with mock.patch.object(scanner_engine.SpikeScanEngine, "_lif_step", return_value=("PROBE_SYN", 1.0, True)):
                        results = engine.scan("10.10.10.5", ports, checkpoint_interval=0)

        self.assertEqual(len(results), len(ports))
        self.assertTrue(all(result.protocol_flag == "RST" for result in results))

    def test_connect_scan_stops_on_persistent_local_socket_exhaustion(self) -> None:
        engine = scanner_engine.SpikeScanEngine(profile="x15", seed=7, speed_level=300)
        ports = list(range(1, 33))

        def fake_batch(host: str, batch_ports: list[int], timeout: float = 1.0, max_concurrency=None, banner_timeout=None) -> list[PortResult]:
            return [
                PortResult(
                    host,
                    port,
                    "filtered",
                    "tcp",
                    "TIMEOUT",
                    100.0,
                    0,
                    port,
                    scan_note=scanner_probes.LOCAL_SOCKET_EXHAUSTED_NOTE,
                )
                for port in batch_ports
            ]

        with mock.patch.object(scanner_engine, "RAW_AVAILABLE", False):
            with mock.patch.object(scanner_engine, "async_batch_connect_probe", side_effect=fake_batch):
                with mock.patch.object(scanner_engine.SpikeScanEngine, "_lif_step", return_value=("PROBE_SYN", 1.0, True)):
                    with self.assertRaisesRegex(RuntimeError, "local TCP connect resources exhausted"):
                        engine.scan("10.10.10.5", ports, checkpoint_interval=0, quiet=True)

    def test_parse_ports_rejects_out_of_range_values(self) -> None:
        with self.assertRaises(ValueError):
            scanner_probes.parse_ports("0")
        with self.assertRaises(ValueError):
            scanner_probes.parse_ports("70000")
        with self.assertRaises(ValueError):
            scanner_probes.parse_ports("65534-70000")

    def test_connect_probe_rejects_out_of_range_port_before_socket_layer(self) -> None:
        with self.assertRaises(ValueError):
            scanner_probes.connect_probe("127.0.0.1", 70000, timeout=0.01)

    def test_parse_ports_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            scanner_probes.parse_ports("@/definitely/missing/ports.txt")

    def test_parse_targets_rejects_large_cidr_before_expansion(self) -> None:
        with self.assertRaises(ValueError):
            scanner_probes.parse_targets("10.0.0.0/8")

    def test_async_batch_connect_probe_limits_concurrency(self) -> None:
        active = 0
        max_active = 0

        async def fake_probe(host: str, port: int, timeout: float, ts_us: int, banner_timeout=None) -> PortResult:
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            await asyncio.sleep(0)
            active -= 1
            return PortResult(host, port, "closed", "tcp", "RST", 100.0, 0, ts_us)

        with mock.patch.object(scanner_probes, "_async_connect_probe", side_effect=fake_probe):
            results = scanner_probes.async_batch_connect_probe(
                "127.0.0.1",
                list(range(1, 21)),
                timeout=0.01,
                max_concurrency=3,
            )

        self.assertEqual(len(results), 20)
        self.assertLessEqual(max_active, 3)

    def test_async_connect_probe_marks_local_socket_exhaustion(self) -> None:
        async def fake_open_connection(host: str, port: int):
            raise OSError(errno.EADDRNOTAVAIL, "Cannot assign requested address")

        with mock.patch("asyncio.open_connection", side_effect=fake_open_connection):
            result = asyncio.run(scanner_probes._async_connect_probe("127.0.0.1", 22, 0.01, 1))

        self.assertEqual(result.protocol_flag, "TIMEOUT")
        self.assertIn(scanner_probes.LOCAL_SOCKET_EXHAUSTED_NOTE, result.scan_note)
        self.assertIn("socket-error=OSError", result.technology)


if __name__ == "__main__":
    unittest.main()
