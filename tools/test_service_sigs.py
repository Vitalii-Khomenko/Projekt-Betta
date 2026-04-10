"""Regression tests for service signature detection."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.service_sigs import detect_service


class ServiceSignatureTests(unittest.TestCase):
    def test_hex_activemq_banner_prefers_real_service_over_catalog_number_match(self) -> None:
        detected = detect_service(61616, banner="hex:4163746976654d510001")
        self.assertEqual(detected["name"], "ActiveMQ")
        self.assertEqual(detected["display"], "ActiveMQ")

    def test_https_hex_banner_still_detects_https(self) -> None:
        detected = detect_service(18443, banner="hex:160303")
        self.assertEqual(detected["name"], "HTTPS")


if __name__ == "__main__":
    unittest.main()
