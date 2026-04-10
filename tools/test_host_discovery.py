"""Tests for passive hostname discovery extraction and ranking."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "training" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tools.host_discovery import _build_sample, build_prototype_artifact, discover_from_scan_rows


class HostDiscoveryTests(unittest.TestCase):
    def test_discovery_extracts_location_and_san_candidates(self) -> None:
        artifact = build_prototype_artifact(
            [
                _build_sample("login.lab.local", ["http_location", "technology"], 2, 1, label="high_value"),
                _build_sample("wiki.lab.local", ["banner", "technology"], 1, 1, label="supporting"),
                _build_sample("apache", ["technology"], 1, 1, label="noise"),
            ],
            steps=12,
            beta=0.82,
            threshold=1.0,
        )
        discovered = discover_from_scan_rows(
            [
                {
                    "asset_ip": "10.10.10.5",
                    "target_port": "443",
                    "banner": "",
                    "service": "HTTPS",
                    "service_version": "HTTPS",
                    "scan_note": "",
                    "technology": "HTTPS 302 | location=https://login.lab.local/ | san=portal.lab.local,auth.lab.local",
                }
            ],
            artifact=artifact,
        )
        names = {row["candidate_name"]: row["predicted_label"] for row in discovered}
        self.assertIn("login.lab.local", names)
        self.assertIn("portal.lab.local", names)
        self.assertIn("auth.lab.local", names)
        self.assertEqual(names["login.lab.local"], "high_value")

    def test_discovery_keeps_single_label_infra_hosts_but_drops_generic_noise(self) -> None:
        discovered = discover_from_scan_rows(
            [
                {
                    "asset_ip": "10.10.10.9",
                    "target_port": "445",
                    "banner": "",
                    "service": "SMB",
                    "service_version": "SMB",
                    "scan_note": "",
                    "technology": "smb-probe=ok | server=FS01 | domain=LAB | issuer=Microsoft",
                }
            ]
        )
        names = {row["candidate_name"] for row in discovered}
        self.assertIn("fs01", names)
        self.assertNotIn("microsoft", names)


if __name__ == "__main__":
    unittest.main()
