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


if __name__ == "__main__":
    unittest.main()
