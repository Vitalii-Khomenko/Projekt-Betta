# =============================================================================
# test_verify_scan.py  -  Regression tests for Nmap verification and HTML fallback behavior
# =============================================================================
# Usage:
#   python -m unittest tools.test_verify_scan
#   python tools/test_verify_scan.py
#
# Key options:
#   No CLI options; run through unittest.
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 04.04.2026
# =============================================================================
"""Regression tests for verification artifact naming and report rendering."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.verify_scan import parse_nmap_xml, run_nmap
from training.tools.scanner import export_html
from training.tools.scanner_types import PortResult


class VerifyScanTests(unittest.TestCase):
    def test_run_nmap_preserves_dotted_session_prefix_for_xml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "verify"
            session_prefix = "20260404_132857_127.0.0.1"

            with patch("tools.verify_scan.shutil.which", return_value="/usr/bin/nmap"), patch("tools.verify_scan.subprocess.run") as run_mock:
                xml_path = run_nmap("nmap", "127.0.0.1", [22, 80], output_dir, session_prefix, timeout_seconds=123)

            self.assertEqual(
                xml_path,
                output_dir / "20260404_132857_127.0.0.1_nmap_verify.xml",
            )
            command = run_mock.call_args.args[0]
            self.assertIn(str(output_dir / "20260404_132857_127.0.0.1_nmap_verify"), command)
            self.assertEqual(run_mock.call_args.kwargs["timeout"], 123)

    def test_parse_nmap_xml_extracts_verified_os_hint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            xml_path = Path(tmp_dir) / "verify.xml"
            xml_path.write_text(
                "<?xml version='1.0' encoding='UTF-8'?>\n"
                "<nmaprun><host><ports>"
                "<port protocol='tcp' portid='22'>"
                "<state state='open'/>"
                "<service name='ssh' product='OpenSSH' version='10.0p2' ostype='Linux'>"
                "<cpe>cpe:/a:openbsd:openssh:10.0p2</cpe>"
                "<cpe>cpe:/o:linux:linux_kernel</cpe>"
                "</service></port>"
                "</ports></host></nmaprun>",
                encoding="utf-8",
            )

            parsed = parse_nmap_xml(xml_path)

            self.assertEqual(parsed[22]["ostype"], "Linux")
            self.assertEqual(parsed[22]["cpe"], "cpe:/a:openbsd:openssh:10.0p2")

    def test_export_html_uses_verified_os_hint_when_scan_hint_missing(self) -> None:
        result = PortResult(
            host="127.0.0.1",
            port=22,
            state="open",
            protocol="tcp",
            protocol_flag="SYN_ACK",
            rtt_us=900.0,
            payload_size=20,
            timestamp_us=1,
            banner="SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u1",
            service="OpenSSH",
            service_version="OpenSSH 10.0p2",
        )
        verification_summary = {
            "matched_ports": [22],
            "betta_morpho_only_ports": [],
            "nmap_only_ports": [],
            "verified_os_hints": ["Linux"],
            "rows": [
                {
                    "port": 22,
                    "status": "match",
                    "nmap_service": "ssh | OpenSSH | 10.0p2 Debian 7+deb13u1",
                    "normalized_nmap_service": "OpenSSH 10.0p2 Debian 7+deb13u1",
                    "nmap_ostype": "Linux",
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            html_path = Path(tmp_dir) / "report.html"
            export_html([result], html_path, verification_summary=verification_summary)
            html = html_path.read_text(encoding="utf-8")

        self.assertIn("<td>Linux</td>", html)

    def test_export_html_does_not_backfill_host_os_hint_for_closed_rows(self) -> None:
        result = PortResult(
            host="127.0.0.1",
            port=1,
            state="closed",
            protocol="tcp",
            protocol_flag="RST",
            rtt_us=900.0,
            payload_size=0,
            timestamp_us=1,
        )
        verification_summary = {
            "matched_ports": [22],
            "betta_morpho_only_ports": [],
            "nmap_only_ports": [],
            "verified_os_hints": ["Linux"],
            "rows": [],
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            html_path = Path(tmp_dir) / "report.html"
            export_html([result], html_path, verification_summary=verification_summary)
            html = html_path.read_text(encoding="utf-8")

        self.assertIn("<td>1</td>", html)
        self.assertNotIn("<td>Linux</td>", html)


if __name__ == "__main__":
    unittest.main()
