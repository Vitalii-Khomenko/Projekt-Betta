"""
Nmap Service Catalog Builder - tools/nmap_service_catalog.py
============================================================
Builds and loads Betta-Morpho's internal service catalog artifact from the
local Nmap probe databases. Runtime service detection uses the generated
catalog JSON instead of reading /usr/share/nmap files on every scan.

Key commands:
  python tools/nmap_service_catalog.py build
  python tools/nmap_service_catalog.py build --output artifacts/service_catalog.json
  python tools/nmap_service_catalog.py build --probes /usr/share/nmap/nmap-service-probes --services /usr/share/nmap/nmap-services

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import cast
from urllib.parse import unquote

from tools.artifact_schema import FAMILY_SERVICE_CATALOG, attach_artifact_metadata, normalize_artifact_payload, validate_artifact_payload

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG_PATH = ROOT_DIR / "artifacts" / "service_catalog.json"
DEFAULT_PROBES_PATH = Path("/usr/share/nmap/nmap-service-probes")
DEFAULT_SERVICES_PATH = Path("/usr/share/nmap/nmap-services")
CATALOG_TYPE = "betta-morpho-service-catalog"
CATALOG_VERSION = 1
SERVICE_CATALOG_ENV = "BETTA_SERVICE_CATALOG"
_GENERIC_ALIAS_TOKENS = {
    "ssh", "http", "https", "ftp", "smtp", "imap", "pop3", "redis", "mysql", "server",
    "service", "daemon", "proxy", "database", "remote", "admin", "agent", "client", "manager",
    "linux", "windows", "unix", "ssl", "tls",
}

_MATCH_SERVICE_RE = re.compile(r"^(?:match|softmatch)\s+([^\s]+)\s+")
_PRODUCT_RE = re.compile(r"\bp/([^/]+)/")
_VERSION_RE = re.compile(r"\bv/([^/]+)/")
_CPE_RE = re.compile(r"\bcpe:/([^\s]+)")
_PLACEHOLDER_RE = re.compile(r"\$\d+")


def _clean(text: str) -> str:
    return " ".join(text.strip().split())


def _clean_catalog_text(text: str) -> str:
    cleaned = _clean(unquote(text))
    cleaned = _PLACEHOLDER_RE.sub("", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip(" /|:-")


def _alias_key(text: str) -> str:
    lowered = text.lower().strip()
    lowered = re.sub(r"[^a-z0-9]+", " ", lowered)
    return " ".join(lowered.split())


def _contains_placeholder(text: str) -> bool:
    return bool(_PLACEHOLDER_RE.search(text))


def _normalize_version_example(text: str) -> str:
    cleaned = _clean_catalog_text(text)
    if not cleaned or _contains_placeholder(text):
        return ""
    if len(cleaned) == 1 and cleaned.isalpha():
        return ""
    return cleaned


def _normalize_cpe(text: str) -> str:
    cleaned = unquote(text.strip())
    cleaned = _PLACEHOLDER_RE.sub("", cleaned)
    cleaned = cleaned.rstrip("/")
    if re.search(r"/[aho]$", cleaned):
        cleaned = cleaned[:-2]
    cleaned = cleaned.rstrip(":/")
    return cleaned


def _cpe_sort_key(value: str) -> tuple[int, int, int, int, str]:
    parts = value.split(":")
    version = parts[4] if len(parts) > 4 else ""
    placeholder_penalty = 1 if _contains_placeholder(value) else 0
    weak_version_penalty = 1 if version and len(version) == 1 and version.isalpha() else 0
    percent_penalty = 1 if "%" in value else 0
    return (placeholder_penalty, weak_version_penalty, percent_penalty, len(value), value)


def _sorted_cpes(cpes: set[str], product: str) -> list[str]:
    product_key = _alias_key(product)
    product_tokens = [token for token in product_key.split() if token and token not in _GENERIC_ALIAS_TOKENS]

    def _rank(value: str) -> tuple[int, int, int, int, int, str]:
        lowered = value.lower()
        matching_tokens = sum(1 for token in product_tokens if token in lowered)
        token_penalty = 0 if matching_tokens else 1
        kind_penalty = 0 if lowered.startswith("cpe:/a:") else 1
        base = _cpe_sort_key(value)
        return (token_penalty, kind_penalty, -matching_tokens, base[0], base[1], value)

    return sorted({str(value) for value in cpes if str(value)}, key=_rank)


def resolve_catalog_path(catalog_path: str | Path | None = None) -> Path:
    if catalog_path is not None:
        return Path(catalog_path)
    configured = os.environ.get(SERVICE_CATALOG_ENV, "").strip()
    if configured:
        return Path(configured)
    return DEFAULT_CATALOG_PATH


def _empty_entry(product: str = "") -> dict[str, object]:
    return {
        "product": product,
        "service_names": set(),
        "version_examples": set(),
        "cpes": set(),
        "ports": set(),
    }


def _entry_values(entry: dict[str, object], key: str) -> set[str]:
    return cast(set[str], entry[key])


def _ensure_entry(entries: dict[str, dict[str, object]], alias: str, product: str = "") -> dict[str, object]:
    key = _alias_key(alias)
    if not key:
        return _empty_entry(product)
    entry = entries.setdefault(key, _empty_entry(product))
    if product and not entry.get("product"):
        entry["product"] = product
    return entry


def _add_aliases(entries: dict[str, dict[str, object]], alias: str, product: str = "") -> None:
    key = _alias_key(alias)
    if not key:
        return
    _ensure_entry(entries, key, product)
    for token in key.split():
        if len(token) < 3 or token in _GENERIC_ALIAS_TOKENS:
            continue
        _ensure_entry(entries, token, product)


def _parse_probe_catalog(probes_path: Path) -> dict[str, dict[str, object]]:
    entries: dict[str, dict[str, object]] = {}
    if not probes_path.exists():
        return entries

    for raw_line in probes_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line.startswith(("match ", "softmatch ")):
            continue

        service_match = _MATCH_SERVICE_RE.search(line)
        service_name = _clean(service_match.group(1)) if service_match else ""
        product_match = _PRODUCT_RE.search(line)
        if not product_match:
            continue
        product = _clean_catalog_text(product_match.group(1))
        if not product:
            continue

        version_match = _VERSION_RE.search(line)
        cpes = [f"cpe:/{match.group(1)}" for match in _CPE_RE.finditer(line)]
        _add_aliases(entries, product, product)
        if service_name:
            _add_aliases(entries, service_name, product)

        entry = _ensure_entry(entries, product, product)
        if service_name:
            _entry_values(entry, "service_names").add(_clean_catalog_text(service_name))
        if version_match:
            version_example = _normalize_version_example(version_match.group(1))
            if version_example:
                _entry_values(entry, "version_examples").add(version_example)
        for cpe in cpes:
            normalized_cpe = _normalize_cpe(cpe)
            if normalized_cpe:
                _entry_values(entry, "cpes").add(normalized_cpe)

        if service_name:
            alias_entry = _ensure_entry(entries, service_name, product)
            _entry_values(alias_entry, "service_names").add(_clean_catalog_text(service_name))
            _entry_values(alias_entry, "version_examples").update(_entry_values(entry, "version_examples"))
            _entry_values(alias_entry, "cpes").update(_entry_values(entry, "cpes"))
    return entries


def _parse_services_catalog(services_path: Path, entries: dict[str, dict[str, object]]) -> None:
    if not services_path.exists():
        return

    for raw_line in services_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or "/" not in parts[1]:
            continue
        service_name = _clean_catalog_text(parts[0])
        port_proto = parts[1].strip()
        product = service_name
        _add_aliases(entries, service_name, product)
        entry = _ensure_entry(entries, service_name, product)
        _entry_values(entry, "service_names").add(service_name)
        _entry_values(entry, "ports").add(port_proto)


def _normalize_entries(entries: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    normalized: dict[str, dict[str, object]] = {}
    for key, entry in entries.items():
        product = _clean_catalog_text(str(entry.get("product", "")))
        service_names = _entry_values(entry, "service_names")
        version_examples = _entry_values(entry, "version_examples")
        cpes = _entry_values(entry, "cpes")
        ports = _entry_values(entry, "ports")
        sorted_cpes = _sorted_cpes(cpes, product)
        normalized[key] = {
            "product": product,
            "service_names": sorted(str(value) for value in service_names if str(value)),
            "version_examples": sorted(str(value) for value in version_examples if str(value)),
            "cpes": sorted_cpes,
            "ports": sorted(str(value) for value in ports if str(value)),
        }
        normalized_cpe_list = cast(list[str], normalized[key]["cpes"])
        normalized[key]["cpe"] = normalized_cpe_list[0] if normalized_cpe_list else ""
    return normalized


def build_catalog(
    output_path: str | Path = DEFAULT_CATALOG_PATH,
    probes_path: str | Path = DEFAULT_PROBES_PATH,
    services_path: str | Path = DEFAULT_SERVICES_PATH,
) -> dict[str, object]:
    probes = Path(probes_path)
    services = Path(services_path)
    entries = _parse_probe_catalog(probes)
    _parse_services_catalog(services, entries)
    payload = {
        "catalog_type": CATALOG_TYPE,
        "catalog_version": CATALOG_VERSION,
        "generated_from": {
            "probes_path": str(probes),
            "services_path": str(services),
        },
        "entries": _normalize_entries(entries),
    }
    payload = attach_artifact_metadata(
        payload,
        FAMILY_SERVICE_CATALOG,
        model_type=CATALOG_TYPE,
        producer="tools.nmap_service_catalog",
    )
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    load_catalog.cache_clear()
    return payload


@lru_cache(maxsize=8)
def load_catalog(
    catalog_path: str | Path | None = DEFAULT_CATALOG_PATH,
    services_path: str | Path = DEFAULT_SERVICES_PATH,
) -> dict[str, dict[str, object]]:
    path = resolve_catalog_path(catalog_path)
    if path.exists() and path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        validate_artifact_payload(payload, expected_family=FAMILY_SERVICE_CATALOG)
        payload = normalize_artifact_payload(
            payload,
            expected_family=FAMILY_SERVICE_CATALOG,
            default_model_type=CATALOG_TYPE,
            producer="tools.nmap_service_catalog",
        )
        if payload.get("catalog_type") != CATALOG_TYPE:
            raise ValueError(f"invalid service catalog artifact: {path}")
        entries = payload.get("entries", {})
        if not isinstance(entries, dict):
            raise ValueError(f"invalid service catalog entries in: {path}")
        return {str(key): dict(value) for key, value in entries.items()}

    if path.name == DEFAULT_PROBES_PATH.name:
        entries = _parse_probe_catalog(path)
        _parse_services_catalog(Path(services_path), entries)
        return _normalize_entries(entries)
    return {}


def lookup_product(
    text: str,
    catalog_path: str | Path | None = DEFAULT_CATALOG_PATH,
    services_path: str | Path = DEFAULT_SERVICES_PATH,
) -> dict[str, object]:
    if not text:
        return {}
    catalog = load_catalog(catalog_path, services_path)
    lowered = _alias_key(text)
    if lowered in catalog:
        return dict(catalog[lowered])

    is_hex_probe = lowered.startswith("hex ")
    matches: list[tuple[int, dict[str, object]]] = []
    for key, value in catalog.items():
        if is_hex_probe and key.isdigit():
            continue
        if key and key in lowered:
            matches.append((len(key), dict(value)))
    if matches:
        matches.sort(key=lambda item: item[0], reverse=True)
        return matches[0][1]
    return {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Betta-Morpho's internal service-catalog artifact from local Nmap databases.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    build_cmd = subcommands.add_parser("build", help="Build the internal service-catalog JSON artifact")
    build_cmd.add_argument("--output", default=str(DEFAULT_CATALOG_PATH), help="Output artifact path")
    build_cmd.add_argument("--probes", default=str(DEFAULT_PROBES_PATH), help="Path to nmap-service-probes")
    build_cmd.add_argument("--services", default=str(DEFAULT_SERVICES_PATH), help="Path to nmap-services")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "build":
        payload = build_catalog(output_path=args.output, probes_path=args.probes, services_path=args.services)
        entries = payload.get("entries", {})
        count = len(entries) if isinstance(entries, dict) else 0
        print(f"entries={count} output={args.output}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
