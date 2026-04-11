#!/usr/bin/env python3
# =============================================================================
# test_scanner_enrichment.py  -  Regression tests for scan enrichment helpers
# =============================================================================
# Usage:
#   python -m unittest tools.test_scanner_enrichment
#   python tools/test_scanner_enrichment.py
#
# Key options:
#   None
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.4
# =============================================================================
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from training.tools import scanner_enrichment
from training.tools.scanner_types import PortResult


class _FakeNetBIOSError(Exception):
    pass


class _FailingSMBConnection:
    def __init__(self, *args, **kwargs) -> None:
        raise _FakeNetBIOSError("Cannot request session (Called Name:*SMBSERVER)")


class ScannerEnrichmentTests(unittest.TestCase):
    def test_enrich_port_results_ignores_netbios_session_failures(self) -> None:
        result = PortResult(
            host="10.129.26.104",
            port=139,
            state="open",
            protocol="tcp",
            protocol_flag="SYN_ACK",
            rtt_us=5_000.0,
            payload_size=0,
            timestamp_us=1,
            service="SMB",
            service_version="SMB",
        )

        with (
            patch.object(scanner_enrichment, "IMPACKET_AVAILABLE", True),
            patch.object(scanner_enrichment, "SMBConnection", _FailingSMBConnection),
            patch.object(scanner_enrichment, "NetBIOSError", _FakeNetBIOSError),
        ):
            scanner_enrichment.enrich_port_results([result])

        self.assertEqual(result.service, "SMB")
        self.assertEqual(result.scan_note, "")


if __name__ == "__main__":
    unittest.main()