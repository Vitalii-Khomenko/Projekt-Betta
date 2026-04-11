"""
Service Catalog Unit Tests - tools/test_service_catalog.py
==========================================================
Unit tests for tools/nmap_service_catalog.py. Verifies that the internal
service-catalog artifact can be built from local Nmap-style inputs and then
used for runtime product lookup without reading the raw database files again.

Key commands:
  python -m unittest tools.test_service_catalog
  python tools/test_service_catalog.py

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.4
Created : 04.04.2026
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.nmap_service_catalog import CATALOG_TYPE, SERVICE_CATALOG_ENV, build_catalog, load_catalog, lookup_product, lookup_service_by_port


class ServiceCatalogTests(unittest.TestCase):
    def test_build_catalog_writes_internal_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            probes_path = tmp_path / "nmap-service-probes"
            services_path = tmp_path / "nmap-services"
            artifact_path = tmp_path / "service_catalog.json"

            probes_path.write_text(
                "match ssh m|^SSH-2.0-OpenSSH_([0-9.p]+)| p/OpenSSH/ v/$1/ cpe:/a:openbsd:openssh/\n"
                "match http m|^HTTP/1\\.1 200 OK| p/Apache httpd/ v/2.4.58/ cpe:/a:apache:http_server:2.4.58/\n",
                encoding="utf-8",
            )
            services_path.write_text(
                "ssh 22/tcp 0.1 # SSH\n"
                "http 80/tcp 0.1 # World Wide Web HTTP\n",
                encoding="utf-8",
            )

            payload = build_catalog(output_path=artifact_path, probes_path=probes_path, services_path=services_path)

            self.assertEqual(payload["catalog_type"], CATALOG_TYPE)
            self.assertTrue(artifact_path.exists())

            persisted = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertIn("openssh", persisted["entries"])
            self.assertIn("ssh", persisted["entries"])

    def test_lookup_uses_generated_artifact_without_raw_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            probes_path = tmp_path / "nmap-service-probes"
            services_path = tmp_path / "nmap-services"
            artifact_path = tmp_path / "service_catalog.json"

            probes_path.write_text(
                "match ssh m|^SSH-2.0-OpenSSH_([0-9.p]+)| p/OpenSSH/ v/$1/ cpe:/a:openbsd:openssh/\n",
                encoding="utf-8",
            )
            services_path.write_text("ssh 22/tcp 0.1 # SSH\n", encoding="utf-8")
            build_catalog(output_path=artifact_path, probes_path=probes_path, services_path=services_path)

            probes_path.unlink()
            services_path.unlink()

            catalog = load_catalog(artifact_path)
            lookup = lookup_product("OpenSSH 9.7", catalog_path=artifact_path)

            self.assertIn("openssh", catalog)
            self.assertEqual(lookup.get("product"), "OpenSSH")
            self.assertEqual(lookup.get("cpe"), "cpe:/a:openbsd:openssh")

    def test_lookup_service_by_port_prefers_service_name_over_probe_product(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            probes_path = tmp_path / "nmap-service-probes"
            services_path = tmp_path / "nmap-services"
            artifact_path = tmp_path / "service_catalog.json"

            probes_path.write_text(
                "match ldap m|^\\0| p/OpenLDAP over SSL/ v/2.4.X/ cpe:/a:openldap:openldap/\n",
                encoding="utf-8",
            )
            services_path.write_text("ldap 389/tcp 0.1 # LDAP\nadws 9389/tcp 0.1 # Active Directory Web Services\n", encoding="utf-8")
            build_catalog(output_path=artifact_path, probes_path=probes_path, services_path=services_path)

            port_lookup = lookup_service_by_port(389, catalog_path=artifact_path)

            self.assertEqual(port_lookup.get("service_name"), "ldap")
            self.assertEqual(port_lookup.get("product"), "OpenLDAP over SSL")

    def test_lookup_uses_env_configured_artifact_when_path_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            probes_path = tmp_path / "nmap-service-probes"
            services_path = tmp_path / "nmap-services"
            artifact_path = tmp_path / "service_catalog.json"

            probes_path.write_text(
                "match ssh m|^SSH-2.0-OpenSSH_([0-9.p]+)| p/OpenSSH/ v/$1/ cpe:/a:openbsd:openssh/\n",
                encoding="utf-8",
            )
            services_path.write_text("ssh 22/tcp 0.1 # SSH\n", encoding="utf-8")
            build_catalog(output_path=artifact_path, probes_path=probes_path, services_path=services_path)

            with patch.dict(os.environ, {SERVICE_CATALOG_ENV: str(artifact_path)}, clear=False):
                load_catalog.cache_clear()
                lookup = lookup_product("OpenSSH 9.7")

            load_catalog.cache_clear()
            self.assertEqual(lookup.get("product"), "OpenSSH")


if __name__ == "__main__":
    unittest.main()
