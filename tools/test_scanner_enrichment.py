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
# Version : 2.3.5
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


class _FakeLDAPEntry:
    entry_attributes_as_dict = {
        "defaultNamingContext": ["DC=garfield,DC=htb"],
        "rootDomainNamingContext": ["DC=garfield,DC=htb"],
        "dnsHostName": ["DC01.garfield.htb"],
        "supportedLDAPVersion": ["3", "2"],
        "isGlobalCatalogReady": ["TRUE"],
    }


class _FakeLDAPServer:
    last_connect_timeout = None

    def __init__(self, host: str, port: int, connect_timeout: int, use_ssl: bool = False, tls=None, get_info=None) -> None:
        _FakeLDAPServer.last_connect_timeout = connect_timeout


class _FakeLDAPConnection:
    def __init__(self, server, authentication=None, receive_timeout: int | None = None) -> None:
        self.entries = [_FakeLDAPEntry()]

    def open(self) -> None:
        return None

    def bind(self) -> bool:
        return True

    def search(self, search_base: str, search_filter: str, search_scope=None, attributes=None) -> bool:
        return True

    def unbind(self) -> None:
        return None


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

    def test_protocol_probe_detects_rpc_over_http_response(self) -> None:
        result = PortResult(
            host="10.129.26.104",
            port=593,
            state="open",
            protocol="tcp",
            protocol_flag="SYN_ACK",
            rtt_us=2_000.0,
            payload_size=0,
            timestamp_us=1,
        )

        with patch.object(scanner_enrichment, "_socket_roundtrip", return_value="ncacn_http/1.0"):
            details = scanner_enrichment._protocol_probe(result)

        self.assertEqual(details["service"], "ncacn_http")
        self.assertEqual(details["service_version"], "Microsoft Windows RPC over HTTP 1.0")
        self.assertIn("rpc-http-probe=ok", details["technology"])

    def test_probe_ldap_directory_extracts_active_directory_context(self) -> None:
        result = PortResult(
            host="10.129.26.104",
            port=389,
            state="open",
            protocol="tcp",
            protocol_flag="SYN_ACK",
            rtt_us=2_000.0,
            payload_size=0,
            timestamp_us=1,
        )

        with (
            patch.object(scanner_enrichment, "LDAP_AVAILABLE", True),
            patch.object(scanner_enrichment, "LDAPServer", _FakeLDAPServer),
            patch.object(scanner_enrichment, "LDAPConnection", _FakeLDAPConnection),
            patch.object(scanner_enrichment, "LDAP_ANONYMOUS", object()),
            patch.object(scanner_enrichment, "LDAP_BASE", object()),
        ):
            details = scanner_enrichment._probe_ldap_directory(result, timeout=3.5)

        self.assertEqual(_FakeLDAPServer.last_connect_timeout, 3)
        self.assertEqual(details["service"], "ldap")
        self.assertEqual(details["service_version"], "Microsoft Windows Active Directory LDAP")
        self.assertIn("host=DC01.garfield.htb", details["technology"])

    def test_host_context_enrichment_labels_active_directory_related_ports(self) -> None:
        results = [
            PortResult(
                host="10.129.26.104",
                port=88,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_000.0,
                payload_size=0,
                timestamp_us=1,
                os_hint="Windows",
                service="kerberos-sec",
            ),
            PortResult(
                host="10.129.26.104",
                port=389,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_000.0,
                payload_size=0,
                timestamp_us=2,
                os_hint="Windows",
                service="ldap",
            ),
            PortResult(
                host="10.129.26.104",
                port=445,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_000.0,
                payload_size=0,
                timestamp_us=3,
                os_hint="Windows",
                service="SMB",
            ),
            PortResult(
                host="10.129.26.104",
                port=9389,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_000.0,
                payload_size=0,
                timestamp_us=4,
                os_hint="Windows",
                service="adws",
            ),
            PortResult(
                host="10.129.26.104",
                port=49677,
                state="open",
                protocol="tcp",
                protocol_flag="SYN_ACK",
                rtt_us=1_000.0,
                payload_size=0,
                timestamp_us=5,
                os_hint="Windows",
            ),
        ]

        scanner_enrichment._apply_host_context_enrichment(results)

        self.assertEqual(results[0].service_version, "Microsoft Windows Kerberos")
        self.assertEqual(results[1].service_version, "Microsoft Windows Active Directory LDAP")
        self.assertEqual(results[3].service_version, "Active Directory Web Services")
        self.assertEqual(results[1].cpe, "cpe:/o:microsoft:windows")
        self.assertIn("host-context=ActiveDirectory", results[3].technology)
        self.assertEqual(results[4].service, "Microsoft Windows RPC")
        self.assertIn("host-context=WinEphemeralRPC", results[4].technology)


if __name__ == "__main__":
    unittest.main()