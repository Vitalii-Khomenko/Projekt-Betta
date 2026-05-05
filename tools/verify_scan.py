# =============================================================================
# verify_scan.py  -  Verify Betta-Morpho scan results against targeted Nmap runs
# =============================================================================
# Usage:
#   python tools/verify_scan.py --scan-csv data/scans/session_result.csv --target 10.10.10.5
#   python tools/verify_scan.py --help
#
# Key options:
#   --scan-csv PATH         Betta-Morpho result CSV to verify
#   --service-catalog PATH  Internal service catalog used during normalization
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 01.04.2026
# =============================================================================
"""Nmap verification helpers for Betta-Morpho scan outputs."""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET

try:
    from tools.path_naming import infer_session_prefix
except ImportError:
    from path_naming import infer_session_prefix

try:
    from tools.service_sigs import detect_service
except ImportError:
    from service_sigs import detect_service

try:
    from tools.nmap_service_catalog import SERVICE_CATALOG_ENV
except ImportError:
    from nmap_service_catalog import SERVICE_CATALOG_ENV


def _clean_training_text(value: str) -> str:
    parts = [part.strip() for part in value.split("|") if part.strip()]
    filtered = [part for part in parts if not part.lower().startswith("model=")]
    return " | ".join(filtered)


# ---------------------------------------------------------------------------
# Nmap flag presets available to callers (launcher menu, CLI, API)
# ---------------------------------------------------------------------------
NMAP_PRESETS: list[tuple[str, str, str, list[str]]] = [
    (
        "0",
        "fast-start",
        "Fast Start verification  (-sC -sV -Pn)",
        ["-sC", "-sV", "-Pn"],
    ),
    (
        "1",
        "deep",
        "Deep recon  (-sV -sC -T5 -Pn -vv)",
        ["-sV", "-sC", "-T5", "-Pn", "-vv"],
    ),
    (
        "2",
        "quick",
        "Quick version scan  (-sV -T4 -Pn)",
        ["-sV", "-T4", "-Pn"],
    ),
    (
        "3",
        "stealth",
        "Stealth SYN + version  (-sS -sV -T2 -Pn)",
        ["-sS", "-sV", "-T2", "-Pn"],
    ),
    (
        "4",
        "scripts-only",
        "Scripts + version, no timing pressure  (-sV -sC -Pn)",
        ["-sV", "-sC", "-Pn"],
    ),
    (
        "5",
        "aggressive",
        "Aggressive all-in  (-A -T5 -Pn -vv)",
        ["-A", "-T5", "-Pn", "-vv"],
    ),
    (
        "6",
        "udp",
        "UDP service scan  (-sU -sV -T4 -Pn)",
        ["-sU", "-sV", "-T4", "-Pn"],
    ),
    (
        "7",
        "os-detect",
        "OS + version detection  (-O -sV -T4 -Pn)",
        ["-O", "-sV", "-T4", "-Pn"],
    ),
    (
        "8",
        "vuln",
        "Vuln scripts  (-sV --script=vuln -T4 -Pn)",
        ["-sV", "--script=vuln", "-T4", "-Pn"],
    ),
]

NMAP_DEFAULT_PRESET = "deep"
NMAP_DEFAULT_TIMEOUT_SECONDS = 900


def resolve_nmap_flags(preset_name: str, extra: str = "") -> list[str]:
    """Return the nmap flag list for *preset_name*, optionally appending extra tokens."""
    flags: list[str] = []
    for _, name, _, flag_list in NMAP_PRESETS:
        if name == preset_name:
            flags = list(flag_list)
            break
    extra_tokens = [t for t in extra.strip().split() if t]
    return flags + extra_tokens


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Nmap only against ports found open by Betta-Morpho and save a comparison report."
    )
    parser.add_argument("--scan-csv", required=True, help="Path to Betta-Morpho result CSV")
    parser.add_argument("--target", help="Target IP or hostname; inferred from Betta-Morpho CSV if omitted")
    parser.add_argument("--output-dir", help="Directory for verification artifacts")
    parser.add_argument("--nmap-bin", default="nmap", help="Nmap executable path")
    parser.add_argument("--nmap-preset", default=NMAP_DEFAULT_PRESET,
                        help=f"Named nmap flag preset ({', '.join(n for _, n, _, _ in NMAP_PRESETS)})")
    parser.add_argument("--nmap-extra", default="",
                        help="Extra nmap flags appended after the preset, space-separated (e.g. '--script=banner -v')")
    parser.add_argument("--nmap-timeout", type=int, default=NMAP_DEFAULT_TIMEOUT_SECONDS,
                        help=f"Abort Nmap verification after N seconds (default: {NMAP_DEFAULT_TIMEOUT_SECONDS})")
    parser.add_argument("--service-catalog", default="artifacts/service_catalog.json", help="Internal service catalog artifact used for normalization")
    return parser.parse_args()


def infer_target_and_ports(scan_csv: Path) -> tuple[str, list[int], dict[int, dict[str, str]]]:
    with scan_csv.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        target = ""
        ports: set[int] = set()
        port_rows: dict[int, dict[str, str]] = {}
        for row in reader:
            if not target:
                target = row.get("asset_ip", "").strip()
            if row.get("protocol_flag", "").strip().upper() == "SYN_ACK":
                port = int(row.get("target_port", "0") or 0)
                ports.add(port)
                port_rows[port] = row
    if not target:
        raise ValueError(f"could not infer target from {scan_csv}")
    ports.discard(0)
    if not ports:
        raise ValueError(f"no open SYN_ACK ports found in {scan_csv}")
    return target, sorted(ports), port_rows


def run_nmap(
    nmap_bin: str,
    target: str,
    ports: list[int],
    output_dir: Path,
    session_prefix: str,
    nmap_preset: str = NMAP_DEFAULT_PRESET,
    nmap_extra: str = "",
    timeout_seconds: int = NMAP_DEFAULT_TIMEOUT_SECONDS,
) -> Path:
    if shutil.which(nmap_bin) is None:
        raise FileNotFoundError(f"nmap executable not found: {nmap_bin}")

    output_dir.mkdir(parents=True, exist_ok=True)
    base = output_dir / f"{session_prefix}_nmap_verify"
    flags = resolve_nmap_flags(nmap_preset, nmap_extra)
    command = [
        nmap_bin,
        "-p",
        ",".join(str(port) for port in ports),
        *flags,
        target,
        "-oA",
        str(base),
    ]
    print(f"[nmap] running: {' '.join(command)}", flush=True)
    subprocess.run(command, check=True, timeout=timeout_seconds)
    return base.parent / f"{base.name}.xml"


def _normalize_nmap_os_hint(ostype: str, cpes: list[str]) -> str:
    normalized_ostype = ostype.strip()
    if normalized_ostype:
        return normalized_ostype

    for cpe in cpes:
        lowered = cpe.lower()
        if lowered.startswith("cpe:/o:linux:"):
            return "Linux"
        if "microsoft:windows" in lowered:
            return "Windows"
        if "apple:mac_os" in lowered or "apple:macos" in lowered or "apple:darwin" in lowered:
            return "macOS"
        if "cisco:" in lowered or "junos" in lowered or "routeros" in lowered:
            return "Cisco/Network"
    return ""


def parse_nmap_xml(xml_path: Path) -> dict[int, dict[str, str]]:
    root = ET.parse(xml_path).getroot()
    results: dict[int, dict[str, str]] = {}
    for port_node in root.findall("./host/ports/port"):
        state_node = port_node.find("state")
        service_node = port_node.find("service")
        if state_node is None:
            continue
        port = int(port_node.attrib["portid"])
        service_parts = []
        if service_node is not None:
            for key in ("name", "product", "version", "extrainfo"):
                value = service_node.attrib.get(key, "").strip()
                if value:
                    service_parts.append(value)
        service_name = service_node.attrib.get("name", "").strip() if service_node is not None else ""
        product = service_node.attrib.get("product", "").strip() if service_node is not None else ""
        version = service_node.attrib.get("version", "").strip() if service_node is not None else ""
        extrainfo = service_node.attrib.get("extrainfo", "").strip() if service_node is not None else ""
        ostype = service_node.attrib.get("ostype", "").strip() if service_node is not None else ""
        service_cpes: list[str] = []
        if service_node is not None:
            for cpe_node in service_node.findall("cpe"):
                if cpe_node.text:
                    service_cpes.append(cpe_node.text.strip())
        cpe = next((value for value in service_cpes if value.startswith("cpe:/a:")), "")
        if not cpe and service_cpes:
            cpe = service_cpes[0]
        results[port] = {
            "state": state_node.attrib.get("state", "unknown"),
            "service": " | ".join(service_parts),
            "service_name": service_name,
            "product": product,
            "version": version,
            "extrainfo": extrainfo,
            "cpe": cpe,
            "ostype": _normalize_nmap_os_hint(ostype, service_cpes),
        }
    return results


def write_comparison(
    output_dir: Path,
    session_prefix: str,
    target: str,
    betta_ports: list[int],
    betta_rows: dict[int, dict[str, str]],
    nmap_results: dict[int, dict[str, str]],
) -> tuple[Path, Path]:
    nmap_ports = sorted(port for port, data in nmap_results.items() if data.get("state") == "open")
    betta_set = set(betta_ports)
    nmap_set = set(nmap_ports)
    verified_os_hints = sorted(
        {
            str(data.get("ostype", "")).strip()
            for port, data in nmap_results.items()
            if port in nmap_set and str(data.get("ostype", "")).strip()
        }
    )

    rows = []
    training_rows = []
    for port in sorted(betta_set | nmap_set):
        in_betta = port in betta_set
        nmap_data = nmap_results.get(port, {"state": "missing", "service": ""})
        in_nmap = nmap_data.get("state") == "open"
        status = "match" if in_betta and in_nmap else "betta_morpho_only" if in_betta else "nmap_only"
        betta_row = betta_rows.get(port, {})
        betta_banner = betta_row.get("banner", "")
        betta_detected = detect_service(
            port,
            banner=" ".join(
                part
                for part in (
                    betta_row.get("service_version", ""),
                    betta_row.get("service", ""),
                    betta_row.get("technology", ""),
                    betta_banner,
                )
                if part
            ),
        )
        nmap_detected = detect_service(port, nmap_service=nmap_data.get("service", ""))
        nmap_service_name = nmap_data.get("product", "") or nmap_detected.get("name", "") or nmap_data.get("service_name", "")
        nmap_service_version = " ".join(
            part for part in (nmap_service_name, nmap_data.get("version", "")) if part
        ).strip() or nmap_detected.get("display", "")
        rows.append(
            {
                "port": port,
                "betta_morpho_found": "yes" if in_betta else "no",
                "nmap_state": nmap_data.get("state", "missing"),
                "status": status,
                "betta_morpho_service": betta_detected.get("display", ""),
                "betta_morpho_banner": betta_banner,
                "normalized_nmap_service": nmap_service_version,
                "nmap_service": nmap_data.get("service", ""),
                "nmap_cpe": nmap_data.get("cpe", ""),
                "nmap_ostype": nmap_data.get("ostype", ""),
            }
        )

        if in_betta and in_nmap:
            training_rows.append(
                {
                    "asset_ip": target,
                    "target_port": port,
                    "protocol_flag": betta_row.get("protocol_flag", "SYN_ACK"),
                    "banner": betta_banner,
                    "service": nmap_service_name or betta_detected.get("name", ""),
                    "service_version": nmap_service_version or betta_detected.get("display", ""),
                    "technology": _clean_training_text(betta_row.get("technology", "")),
                    "cpe": nmap_data.get("cpe", "") or betta_detected.get("cpe", ""),
                    "label_source": "nmap_verified",
                }
            )

    comparison_csv = output_dir / f"{session_prefix}_comparison.csv"
    with comparison_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "port", "betta_morpho_found", "nmap_state", "status",
                "betta_morpho_service", "betta_morpho_banner", "normalized_nmap_service", "nmap_service", "nmap_cpe", "nmap_ostype",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    comparison_json = output_dir / f"{session_prefix}_comparison.json"
    training_csv = output_dir / f"{session_prefix}_service_training.csv"
    with training_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "asset_ip", "target_port", "protocol_flag", "banner", "service",
                "service_version", "technology", "cpe", "label_source",
            ],
        )
        writer.writeheader()
        writer.writerows(training_rows)

    summary = {
        "target": target,
        "betta_morpho_open_ports": betta_ports,
        "nmap_open_ports": nmap_ports,
        "matched_ports": sorted(betta_set & nmap_set),
        "betta_morpho_only_ports": sorted(betta_set - nmap_set),
        "nmap_only_ports": sorted(nmap_set - betta_set),
        "verified_os_hints": verified_os_hints,
        "rows": rows,
        "service_training_csv": str(training_csv),
        "service_training_rows": len(training_rows),
    }
    comparison_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return comparison_csv, comparison_json


def verify_betta_morpho_csv(
    scan_csv: str | Path,
    target: str | None = None,
    output_dir: str | Path | None = None,
    nmap_bin: str = "nmap",
    service_catalog: str | Path | None = None,
    nmap_preset: str = NMAP_DEFAULT_PRESET,
    nmap_extra: str = "",
    nmap_timeout: int = NMAP_DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    if service_catalog is not None:
        os.environ[SERVICE_CATALOG_ENV] = str(Path(service_catalog))
    scan_csv_path = Path(scan_csv)
    if not scan_csv_path.exists():
        raise FileNotFoundError(f"Betta-Morpho CSV not found: {scan_csv_path}")

    inferred_target, betta_ports, betta_rows = infer_target_and_ports(scan_csv_path)
    resolved_target = target or inferred_target
    session_prefix = infer_session_prefix(scan_csv_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    resolved_output_dir = (
        Path(output_dir)
        if output_dir
        else scan_csv_path.parent / f"{session_prefix}_nmap_verify_{timestamp}"
    )

    xml_path = run_nmap(
        nmap_bin,
        resolved_target,
        betta_ports,
        resolved_output_dir,
        session_prefix,
        nmap_preset=nmap_preset,
        nmap_extra=nmap_extra,
        timeout_seconds=nmap_timeout,
    )
    nmap_results = parse_nmap_xml(xml_path)
    comparison_csv, comparison_json = write_comparison(
        resolved_output_dir,
        session_prefix,
        resolved_target,
        betta_ports,
        betta_rows,
        nmap_results,
    )
    summary = json.loads(comparison_json.read_text(encoding="utf-8"))
    summary["comparison_csv"] = str(comparison_csv)
    summary["comparison_json"] = str(comparison_json)
    summary["nmap_xml"] = str(xml_path)
    summary["output_dir"] = str(resolved_output_dir)
    return summary


def main() -> int:
    args = parse_args()
    try:
        summary = verify_betta_morpho_csv(
            scan_csv=args.scan_csv,
            target=args.target,
            output_dir=args.output_dir,
            nmap_bin=args.nmap_bin,
            service_catalog=args.service_catalog,
            nmap_preset=args.nmap_preset,
            nmap_extra=args.nmap_extra,
            nmap_timeout=args.nmap_timeout,
        )
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 2
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired, ET.ParseError) as exc:
        print(f"ERROR: verification failed: {exc}")
        return 1

    print(f"target={summary['target']}")
    print(f"betta_morpho_open_ports={','.join(str(port) for port in summary['betta_morpho_open_ports'])}")
    print(f"nmap_matched_ports={','.join(str(port) for port in summary['matched_ports']) or '-'}")
    print(f"betta_morpho_only_ports={','.join(str(port) for port in summary['betta_morpho_only_ports']) or '-'}")
    print(f"nmap_only_ports={','.join(str(port) for port in summary['nmap_only_ports']) or '-'}")
    print(f"comparison_csv={summary['comparison_csv']}")
    print(f"comparison_json={summary['comparison_json']}")
    print(f"service_training_csv={summary['service_training_csv']}")
    print(f"nmap_xml={summary['nmap_xml']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
