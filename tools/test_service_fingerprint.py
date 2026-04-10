"""
Service Fingerprint Unit Tests - tools/test_service_fingerprint.py
=================================================================
Unit tests for tools/service_fingerprint.py. Verifies that verified Nmap
training rows are promoted during training preparation and that the artifact
records the promotion metadata for later retraining analysis.

Key commands:
  python -m unittest tools.test_service_fingerprint
  python tools/test_service_fingerprint.py

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 04.04.2026
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.service_fingerprint import _promote_verified_rows, train_service_model


class ServiceFingerprintTests(unittest.TestCase):
    def test_verified_rows_are_weighted_for_training(self) -> None:
        rows = [
            {"service": "OpenSSH", "banner": "SSH-2.0-OpenSSH_10.0p2", "target_port": "22", "_verified_source": "1"},
            {"service": "HTTP", "banner": "HTTP/1.1 200 OK", "target_port": "80", "_verified_source": "0"},
        ]

        promoted, counts = _promote_verified_rows(rows, verified_weight=3)

        self.assertEqual(counts["unique_rows"], 2)
        self.assertEqual(counts["verified_rows"], 1)
        self.assertEqual(counts["scanner_rows"], 1)
        self.assertEqual(counts["training_rows"], 4)
        self.assertEqual(sum(1 for row in promoted if row["service"] == "OpenSSH"), 3)

    def test_training_artifact_records_promotion_metadata(self) -> None:
        rows = [
            {"service": "OpenSSH", "banner": "SSH-2.0-OpenSSH_10.0p2", "target_port": "22"},
            {"service": "HTTP", "banner": "HTTP/1.1 200 OK", "target_port": "80"},
        ]
        counts = {
            "unique_rows": 2,
            "verified_rows": 1,
            "scanner_rows": 1,
            "verified_weight": 3,
            "training_rows": 4,
        }

        artifact = train_service_model(rows, training_counts=counts, service_catalog="artifacts/service_catalog.json")

        self.assertEqual(artifact["version"], 3)
        self.assertEqual(artifact["artifact_family"], "service-fingerprint")
        self.assertEqual(artifact["training_counts"]["verified_weight"], 3)
        self.assertEqual(artifact["service_catalog"], "artifacts/service_catalog.json")


if __name__ == "__main__":
    unittest.main()

