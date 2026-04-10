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
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.tools.scanner_enrichment import export_active_learning_rows
from training.tools.scanner_types import PortResult
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


if __name__ == "__main__":
    unittest.main()

