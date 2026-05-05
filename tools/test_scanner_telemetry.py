"""
Scanner Telemetry Unit Tests - tools/test_scanner_telemetry.py
==============================================================
Unit tests for scanner telemetry helpers: Shannon entropy calculation,
active-learning CSV export format, and PortResult dataclass behaviour.

Key commands:
  python -m unittest tools.test_scanner_telemetry
  python tools/test_scanner_telemetry.py

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.4
Created : 01.04.2026
"""
from __future__ import annotations

import csv
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.tools.scanner_enrichment import export_active_learning_rows
from training.tools.scanner import display_results, export_html
from training.tools.scanner_types import (
    MAX_MANUAL_SPEED_LEVEL,
    PROFILES,
    PortResult,
    clamp_speed_level,
    derive_runtime_profile,
)
from training.tools.scanner_utils import _shannon_entropy


class ScannerTelemetryTests(unittest.TestCase):
    def test_entropy_distinguishes_uniform_and_diverse_payloads(self) -> None:
        self.assertEqual(_shannon_entropy(b""), 0.0)
        self.assertLess(_shannon_entropy(b"aaaaaa"), _shannon_entropy(b"abcdef"))

    def test_active_learning_export_includes_only_generic_low_confidence_disagreements(self) -> None:
        rows = [
            PortResult(
                host="10.0.0.1",
                port=443,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_500.0,
                payload_size=32,
                timestamp_us=1,
                service="HTTP",
                service_prediction="Apache httpd",
                service_confidence=0.42,
                response_entropy=4.2,
                tcp_window=64240,
            ),
            PortResult(
                host="10.0.0.2",
                port=22,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=900.0,
                payload_size=24,
                timestamp_us=2,
                service="OpenSSH",
                service_prediction="OpenSSH",
                service_confidence=0.91,
            ),
            PortResult(
                host="10.0.0.3",
                port=8443,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_200.0,
                payload_size=24,
                timestamp_us=3,
                service="Elasticsearch",
                service_prediction="HTTP",
                service_confidence=0.41,
            ),
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "active_learning.csv"
            count = export_active_learning_rows(rows, output, threshold=0.65)
            with output.open(newline="", encoding="utf-8") as handle:
                exported = list(csv.DictReader(handle))

        self.assertEqual(count, 1)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["asset_ip"], "10.0.0.1")
        self.assertEqual(exported[0]["service"], "HTTP")
        self.assertEqual(exported[0]["service_prediction"], "Apache httpd")
        self.assertEqual(exported[0]["tcp_window"], "64240")

    def test_export_html_skips_service_detection_for_non_open_rows_without_banners(self) -> None:
        rows = [
            PortResult(
                host="10.0.0.4",
                port=49152,
                state="filtered",
                protocol="tcp",
                protocol_flag="TIMEOUT",
                rtt_us=1_000_000.0,
                payload_size=0,
                timestamp_us=4,
            )
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "report.html"
            with patch("training.tools.scanner.detect_service", side_effect=AssertionError("detect_service should not run")):
                export_html(rows, output, announce=False)

            self.assertTrue(output.exists())

    def test_manual_speed_level_extends_to_300_without_changing_100_curve(self) -> None:
        level_100 = derive_runtime_profile(PROFILES["x15"], 100)
        level_300 = derive_runtime_profile(PROFILES["x15"], 300)

        self.assertEqual(MAX_MANUAL_SPEED_LEVEL, 300)
        self.assertEqual(clamp_speed_level(999), 300)
        self.assertAlmostEqual(level_100.wait_ms, 0.25)
        self.assertAlmostEqual(level_100.probe_timeout, 0.20)
        self.assertEqual(level_100.max_parallel, 64)
        self.assertLess(level_300.wait_ms, level_100.wait_ms)
        self.assertLess(level_300.probe_timeout, level_100.probe_timeout)
        self.assertEqual(level_300.max_parallel, 192)

    def test_display_results_prints_copyable_text_lines(self) -> None:
        rows = [
            PortResult(
                host="10.0.0.1",
                port=22,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1234.0,
                payload_size=24,
                timestamp_us=1,
                service_version="OpenSSH 9.6",
                banner="SSH-2.0-OpenSSH_9.6\n",
            )
        ]

        stream = io.StringIO()
        with patch("sys.stdout", stream):
            display_results(rows)

        output = stream.getvalue()
        self.assertIn("OPEN host=10.0.0.1 port=22 proto=tcp", output)
        self.assertIn("service='OpenSSH 9.6'", output)
        self.assertIn("banner='SSH-2.0-OpenSSH_9.6'", output)
        self.assertIn("Total: 1 open / 1 probed", output)
        self.assertNotIn("Open Ports", output)

    def test_display_results_minimal_output_shows_only_open_port_fields(self) -> None:
        rows = [
            PortResult(
                host="10.0.0.1",
                port=443,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=800.0,
                payload_size=24,
                timestamp_us=1,
                service="https",
            )
        ]

        stream = io.StringIO()
        with patch("sys.stdout", stream):
            display_results(rows, minimal=True)

        output = stream.getvalue().strip()
        self.assertEqual(output, "OPEN host=10.0.0.1 port=443 proto=tcp service='https'")


if __name__ == "__main__":
    unittest.main()
