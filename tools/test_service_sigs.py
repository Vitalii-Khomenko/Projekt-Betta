"""Regression tests for service signature detection."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_port_catalog_fallback_returns_service_name_when_banner_is_empty(self) -> None:
        with patch("tools.service_sigs.lookup_service_by_port", return_value={"service_name": "kerberos-sec"}):
            detected = detect_service(88)

        self.assertEqual(detected["name"], "kerberos-sec")
        self.assertEqual(detected["display"], "kerberos-sec")
        self.assertEqual(detected["cpe"], "")

    def test_ncacn_http_banner_detects_rpc_over_http(self) -> None:
        detected = detect_service(49676, banner="ncacn_http/1.0")

        self.assertEqual(detected["name"], "Microsoft Windows RPC over HTTP")
        self.assertEqual(detected["display"], "Microsoft Windows RPC over HTTP 1.0")
        self.assertEqual(detected["version"], "1.0")


if __name__ == "__main__":
    unittest.main()
