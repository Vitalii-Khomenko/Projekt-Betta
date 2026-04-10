#!/usr/bin/env python3
# =============================================================================
# scanner.py  -  Betta-Morpho SNN scanner CLI and reporting pipeline
# =============================================================================
# Usage:
#   python training/tools/scanner.py scan --target 10.10.10.5 [options]
#   python training/tools/scanner.py --help
#
# Key options:
#   --service-artifact PATH   Load the separate service-fingerprint artifact
#   --service-catalog PATH    Override the internal service catalog artifact
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.4.0
# Created : 01.04.2026
# =============================================================================
"""Betta-Morpho SNN scanner CLI facade and reporting pipeline."""
from __future__ import annotations

import argparse
import csv
import json
import os
import random
import socket as _socket
import sqlite3
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.tools.scanner_engine import SpikeScanEngine, train_scanner_snn
from training.tools.scanner_enrichment import enrich_port_results, export_active_learning_rows
from training.tools.scanner_probes import discover_hosts, parse_ports, parse_targets, retry_filtered_tcp_with_source_port, udp_connect_probe, udp_probe
from training.tools.scanner_support import Panel, Prompt, RICH, SCAPY_AVAILABLE, Table, _C, _print, detect_service, load_service_artifact, RAW_AVAILABLE
from training.tools.scanner_types import MAX_MANUAL_SPEED_LEVEL, MIN_MANUAL_SPEED_LEVEL, PROFILES, PortResult
from training.tools.scanner_utils import _normalize_result_text_fields, _shannon_entropy
from tools.host_discovery import default_artifact_path, discover_from_port_results, export_discovery_csv, export_discovery_html
from tools.nmap_service_catalog import SERVICE_CATALOG_ENV
from tools.path_naming import build_report_bundle_paths, build_scan_output_paths, infer_session_prefix


def _configure_stdio_utf8() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue


_configure_stdio_utf8()

_CSV_FIELDS = [
    "timestamp_us",
    "asset_ip",
    "target_port",
    "protocol_flag",
    "inter_packet_time_us",
    "payload_size",
    "rtt_us",
    "label",
    "os_hint",
    "banner",
    "service",
    "service_version",
    "technology",
    "cpe",
    "cve_hint",
    "service_prediction",
    "service_confidence",
    "response_entropy",
    "tcp_window",
    "scan_note",
]

_WELL_KNOWN: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MS-RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-sub",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2222: "SSH-alt",
    3306: "MySQL",
    3389: "RDP",
    4444: "C2/Meterp",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    7080: "HTTP-alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    9300: "ES-Transport",
    27017: "MongoDB",
    27016: "MongoDB-s",
    49152: "WinEphemeral",
}


def _result_to_csv_row(result: PortResult) -> dict[str, object]:
    _normalize_result_text_fields(result)
    label = "filtered"
    if result.protocol_flag == "SYN_ACK":
        label = "normal" if result.rtt_us < 50_000 else "delayed"
    return {
        "timestamp_us": result.timestamp_us,
        "asset_ip": result.host,
        "target_port": result.port,
        "protocol_flag": result.protocol_flag,
        "inter_packet_time_us": 0,
        "payload_size": result.payload_size,
        "rtt_us": round(result.rtt_us, 1),
        "label": label,
        "os_hint": result.os_hint,
        "banner": result.banner.replace("\r", " ").replace("\n", " ")[:120],
        "service": result.service,
        "service_version": result.service_version,
        "technology": result.technology,
        "cpe": result.cpe,
        "cve_hint": result.cve_hint,
        "service_prediction": result.service_prediction,
        "service_confidence": round(result.service_confidence, 3),
        "response_entropy": round(result.response_entropy, 3),
        "tcp_window": result.tcp_window,
        "scan_note": result.scan_note,
    }


def _write_csv_rows(results: list[PortResult], path: Path, mode: str, include_header: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open(mode, newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=_CSV_FIELDS)
        if include_header:
            writer.writeheader()
        for result in results:
            writer.writerow(_result_to_csv_row(result))


def append_csv_results(results: list[PortResult], path: Path, include_header: bool = False) -> None:
    """Append scan rows to an existing telemetry CSV."""

    if not results:
        return
    _write_csv_rows(results, path, mode="a", include_header=include_header)


def export_csv(results: list[PortResult], path: Path, announce: bool = True) -> None:
    """Write scan results in the Betta-Morpho telemetry CSV schema."""

    _write_csv_rows(results, path, mode="w", include_header=True)
    if announce:
        _print(f"[bold green]Exported[/] {len(results)} rows: {path}")


def export_html(
    results: list[PortResult],
    path: Path,
    verification_summary: dict | None = None,
    announce: bool = True,
) -> None:
    """Write a self-contained HTML scan report."""

    import html as _html

    for result in results:
        _normalize_result_text_fields(result)

    open_results = [result for result in results if result.state == "open"]
    closed_results = [result for result in results if result.state == "closed"]
    filtered_results = [result for result in results if result.state == "filtered"]
    open_filtered_results = [result for result in results if result.state == "open|filtered"]
    target = results[0].host if results else "unknown"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(results)
    cve_hits = sum(1 for result in results if result.cve_hint)
    verification_rows: dict[int, dict] = {
        int(row.get("port", 0)): row
        for row in (verification_summary or {}).get("rows", [])
        if int(row.get("port", 0)) > 0
    }
    verified_os_hints = [
        str(value).strip()
        for value in (verification_summary or {}).get("verified_os_hints", [])
        if str(value).strip()
    ]
    verified_host_os_hint = verified_os_hints[0] if verified_os_hints else ""
    mismatch_count = sum(
        1
        for row in verification_rows.values()
        if str(row.get("status", "")).strip() and str(row.get("status", "")) != "match"
    )

    verification_panel = ""
    verification_columns = ""
    mismatch_button = ""
    if verification_summary:
        matched_ports = ", ".join(str(port) for port in verification_summary.get("matched_ports", [])) or "-"
        betta_only_ports = ", ".join(str(port) for port in verification_summary.get("betta_morpho_only_ports", [])) or "-"
        nmap_only_ports = ", ".join(str(port) for port in verification_summary.get("nmap_only_ports", [])) or "-"
        verification_columns = "<th>Nmap Verify</th><th>Nmap Service</th>"
        mismatch_button = f'<button class="filter-btn" data-filter="mismatch">Mismatches ({mismatch_count})</button>'
        verification_panel = f"""
<div class="summary">
  <b>Nmap Control:</b> verified only Betta-Morpho-open ports &nbsp;|&nbsp;
  <b>Matched:</b> {len(verification_summary.get('matched_ports', []))} &nbsp;|&nbsp;
  <b>Betta-Morpho only:</b> {len(verification_summary.get('betta_morpho_only_ports', []))} &nbsp;|&nbsp;
  <b>Nmap only:</b> {len(verification_summary.get('nmap_only_ports', []))}
  <div class="meta" style="margin-top:8px">Matched ports: {matched_ports}</div>
  <div class="meta">Betta-Morpho only: {betta_only_ports}</div>
  <div class="meta">Nmap only: {nmap_only_ports}</div>
</div>"""

    def state_value(result: PortResult) -> str:
        return "open" if result.protocol_flag == "SYN_ACK" else result.state

    def row_color(result: PortResult) -> str:
        state = state_value(result)
        if state == "open":
            return "#d4edda" if result.rtt_us < 50_000 else "#fff3cd"
        if state == "closed":
            return "#eef2f7"
        if state == "open|filtered":
            return "#e2f0ff"
        return "#f8d7da"

    def sort_key(result: PortResult) -> tuple[int, int, int]:
        verify_status = str(verification_rows.get(result.port, {}).get("status", ""))
        mismatch_priority = 0 if verify_status and verify_status != "match" else 1
        state_priority = {"open": 0, "open|filtered": 1, "filtered": 2, "closed": 3}.get(state_value(result), 4)
        return (mismatch_priority, state_priority, result.port)

    rows_html = ""
    for result in sorted(results, key=sort_key):
        rtt_ms = f"{result.rtt_us / 1000:.1f}"
        banner = _html.escape(result.banner[:80]) if result.banner else ""
        technology = _html.escape(result.technology[:100]) if result.technology else ""
        scan_note = _html.escape(result.scan_note[:120]) if result.scan_note else ""
        entropy = f"{result.response_entropy:.2f}" if result.response_entropy else ""
        tcp_window = str(result.tcp_window) if result.tcp_window else ""
        cve_hint = _html.escape(result.cve_hint[:120]) if result.cve_hint else ""
        state = state_value(result)
        verify_row = verification_rows.get(result.port, {})
        verify_status_raw = str(verify_row.get("status", ""))
        verify_status = _html.escape(verify_status_raw)
        verify_os_hint_raw = str(verify_row.get("nmap_ostype", "")).strip()
        os_hint_value = result.os_hint or verify_os_hint_raw
        if not os_hint_value and state == "open":
            os_hint_value = verified_host_os_hint
        os_hint = _html.escape(os_hint_value)
        detected = detect_service(result.port, banner=result.banner)
        normalized_service = result.service_version or result.service or detected.get("display") or _WELL_KNOWN.get(result.port, "")
        verify_service_raw = str(verify_row.get("nmap_service", ""))
        verify_service_normalized = str(verify_row.get("normalized_nmap_service", ""))
        verify_service = _html.escape(verify_service_normalized or verify_service_raw)
        search_blob = _html.escape(
            f"{result.port} {normalized_service} {state} {result.protocol} {result.banner} {result.technology} {result.scan_note} {result.cve_hint} {result.service_prediction} {os_hint_value} {verify_status} {verify_service_raw} {verify_service_normalized}".lower()
        )
        rows_html += (
            f'<tr class="result-row" data-state="{_html.escape(state)}" '
            f'data-verify="{_html.escape(verify_status_raw or "match")}" '
            f'data-search="{search_blob}" style="background:{row_color(result)}">'
            f"<td>{result.port}</td><td>{_html.escape(normalized_service)}</td><td><b>{_html.escape(state)}</b></td>"
            f"<td>{_html.escape(result.protocol.upper())}</td><td>{rtt_ms}</td>"
            f"<td>{os_hint}</td><td>{technology}</td><td>{entropy}</td><td>{tcp_window}</td><td>{scan_note}</td><td>{cve_hint}</td><td style='font-family:monospace;font-size:12px'>{banner}</td>"
            + (
                f"<td>{verify_status}</td><td title='{_html.escape(verify_service_raw)}'>{verify_service}</td>"
                if verification_summary
                else ""
            )
            + "</tr>\n"
        )

    html_content = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Betta-Morpho Report - {_html.escape(target)}</title>
<style>
  :root{{--open:#d4edda;--delayed:#fff3cd;--closed:#eef2f7;--filtered:#f8d7da;--maybe:#e2f0ff;--ink:#1f2937;--muted:#6b7280;--panel:#ffffff;--line:#d7dee7;--accent:#1d4ed8;}}
  body{{font-family:Arial,sans-serif;margin:24px;background:#f5f5f5;color:var(--ink)}}
  h1{{color:#333}}
  .summary{{background:#fff;padding:12px 20px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.15)}}
  .controls{{display:flex;flex-wrap:wrap;gap:10px;align-items:center;background:var(--panel);padding:12px 16px;border-radius:6px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.15)}}
  .filters{{display:flex;flex-wrap:wrap;gap:8px}}
  .filter-btn{{border:1px solid var(--line);background:#f8fafc;color:var(--ink);padding:8px 12px;border-radius:999px;cursor:pointer;font-size:13px}}
  .filter-btn.active{{background:var(--accent);border-color:var(--accent);color:#fff}}
  .search{{margin-left:auto;display:flex;align-items:center;gap:8px}}
  .search input{{padding:8px 10px;border:1px solid var(--line);border-radius:8px;min-width:240px}}
  .meta{{font-size:12px;color:var(--muted)}}
  table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.15);border-radius:6px;overflow:hidden}}
  th{{background:#343a40;color:#fff;padding:10px 12px;text-align:left;font-size:13px}}
  td{{padding:8px 12px;border-bottom:1px solid #dee2e6;font-size:13px}}
  tr:last-child td{{border-bottom:none}}
  .legend{{margin-top:12px;font-size:12px;color:#666}}
  .legend span{{display:inline-block;width:14px;height:14px;margin-right:4px;vertical-align:middle;border-radius:2px}}
  .hidden-row{{display:none}}
</style></head>
<body>
<h1>Betta-Morpho Scan Report</h1>
<div class="summary">
  <b>Target:</b> {_html.escape(target)} &nbsp;|&nbsp;
  <b>Date:</b> {generated_at} &nbsp;|&nbsp;
  <b>Probed:</b> {total} &nbsp;|&nbsp;
  <b>Open:</b> {len(open_results)} &nbsp;|&nbsp;
  <b>Closed:</b> {len(closed_results)} &nbsp;|&nbsp;
  <b>Filtered:</b> {len(filtered_results)} &nbsp;|&nbsp;
  <b>CVE Hints:</b> {cve_hits}
</div>
{verification_panel}
<div class="controls">
  <div class="filters">
    <button class="filter-btn active" data-filter="all">All ({total})</button>
    <button class="filter-btn" data-filter="open">Open ({len(open_results)})</button>
    <button class="filter-btn" data-filter="closed">Closed ({len(closed_results)})</button>
    <button class="filter-btn" data-filter="filtered">Filtered ({len(filtered_results)})</button>
    <button class="filter-btn" data-filter="open|filtered">Open|Filtered ({len(open_filtered_results)})</button>
    {mismatch_button}
  </div>
  <div class="search">
    <label for="report-search" class="meta">Search</label>
    <input id="report-search" type="search" placeholder="port, service, banner, technology, cve, protocol">
  </div>
  <div id="visible-count" class="meta">Showing {total} of {total} rows</div>
</div>
<table>
<tr><th>Port</th><th>Service</th><th>State</th><th>Proto</th><th>RTT ms</th><th>OS Hint</th><th>Technology</th><th>Entropy</th><th>TCP Window</th><th>Scan Note</th><th>CVE Hint</th><th>Banner</th>{verification_columns}</tr>
{rows_html}
</table>
<div class="legend">
  <span style="background:#d4edda"></span>open / fast RTT &nbsp;
  <span style="background:#fff3cd"></span>open / delayed RTT &nbsp;
  <span style="background:#eef2f7"></span>closed &nbsp;
  <span style="background:#f8d7da"></span>filtered &nbsp;
  <span style="background:#e2f0ff"></span>open|filtered
</div>
<script>
(() => {{
  const rows = Array.from(document.querySelectorAll('.result-row'));
  const buttons = Array.from(document.querySelectorAll('.filter-btn'));
  const search = document.getElementById('report-search');
  const visibleCount = document.getElementById('visible-count');
  let activeFilter = 'all';

  function applyFilters() {{
    const query = (search.value || '').trim().toLowerCase();
    let visible = 0;
    for (const row of rows) {{
      const matchesState = activeFilter === 'all'
        || row.dataset.state === activeFilter
        || (activeFilter === 'mismatch' && row.dataset.verify && row.dataset.verify !== 'match');
      const matchesSearch = !query || row.dataset.search.includes(query);
      const show = matchesState && matchesSearch;
      row.classList.toggle('hidden-row', !show);
      if (show) visible += 1;
    }}
    visibleCount.textContent = `Showing ${{visible}} of {total} rows`;
  }}

  for (const button of buttons) {{
    button.addEventListener('click', () => {{
      activeFilter = button.dataset.filter;
      for (const other of buttons) other.classList.toggle('active', other === button);
      applyFilters();
    }});
  }}

  search.addEventListener('input', applyFilters);
  applyFilters();
}})();
</script>
</body></html>"""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")
    if announce:
        _print(f"[bold green]HTML report:[/] {path}")


def _format_elapsed(seconds: float) -> str:
    total_seconds = max(0, int(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


class ScanCheckpointWriter:
    """Persist periodic scan checkpoints to reduce data loss on long runs."""

    def __init__(
        self,
        result_csv: Path | None,
        html_path: Path | None,
        progress_log: Path | None,
        checkpoint_every: int,
        total_ports: int,
    ) -> None:
        self.result_csv = result_csv
        self.html_path = html_path
        self.progress_log = progress_log
        self.checkpoint_every = max(0, checkpoint_every)
        self.total_ports = max(0, total_ports)
        self.enabled = bool(self.checkpoint_every and self.total_ports > self.checkpoint_every)
        self.started_at = datetime.now()
        self._started_perf = time.monotonic()
        self._written_rows = 0
        self._checkpoint_count = 0

    def start(self, target: str, profile: str, target_count: int) -> None:
        for path in (self.progress_log,):
            if path is None:
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
        if self.enabled:
            for path in (self.result_csv, self.html_path):
                if path is not None and path.exists():
                    path.unlink()
        message = (
            f"[bold cyan][Betta-Morpho] Scan start:[/] "
            f"{self.started_at.strftime('%Y-%m-%d %H:%M:%S')}  "
            f"target={target}  targets={target_count}  ports={self.total_ports}  profile={profile}"
        )
        _print(message)
        self._append_log(
            "SCAN_START",
            {
                "target": target,
                "targets": target_count,
                "ports": self.total_ports,
                "profile": profile,
                "started_at": self.started_at.isoformat(timespec="seconds"),
            },
        )

    def checkpoint(self, host: str, scanned_ports: int, cumulative_results: list[PortResult]) -> None:
        if not self.enabled:
            return
        new_rows = cumulative_results[self._written_rows :]
        if self.result_csv is not None and new_rows:
            append_csv_results(new_rows, self.result_csv, include_header=self._written_rows == 0)
            self._written_rows = len(cumulative_results)
        if self.html_path is not None:
            export_html(cumulative_results, self.html_path, announce=False)
        elapsed = time.monotonic() - self._started_perf
        open_so_far = sum(1 for result in cumulative_results if result.protocol_flag == "SYN_ACK")
        self._checkpoint_count += 1
        _print(
            "[dim][Betta-Morpho] checkpoint[/] "
            + f"{scanned_ports}/{self.total_ports} ports  elapsed={_format_elapsed(elapsed)}  "
            + f"open={open_so_far}  host={host}"
        )
        self._append_log(
            "CHECKPOINT",
            {
                "host": host,
                "scanned_ports": scanned_ports,
                "total_ports": self.total_ports,
                "open_ports": open_so_far,
                "elapsed": _format_elapsed(elapsed),
                "elapsed_seconds": round(elapsed, 1),
                "checkpoint_index": self._checkpoint_count,
            },
        )

    def finish(self, total_results: int) -> None:
        elapsed = time.monotonic() - self._started_perf
        self._append_log(
            "SCAN_FINISH",
            {
                "elapsed": _format_elapsed(elapsed),
                "elapsed_seconds": round(elapsed, 1),
                "checkpoint_count": self._checkpoint_count,
                "written_rows": self._written_rows,
                "result_rows": total_results,
            },
        )
        _print(
            f"[dim][Betta-Morpho] Scan elapsed:[/] {_format_elapsed(elapsed)}"
            + (f"  checkpoints={self._checkpoint_count}" if self.enabled else "")
        )

    def _append_log(self, tag: str, fields: dict[str, object]) -> None:
        if self.progress_log is None:
            return
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        payload = " ".join(f"{key}={value}" for key, value in fields.items())
        with self.progress_log.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} [{tag}] {payload}\n")


def display_results(results: list[PortResult]) -> None:
    open_results = [result for result in results if result.state == "open"]
    if not open_results:
        _print("[yellow]No open ports found.[/]")
        return

    if not RICH or Table is None or _C is None:
        for result in open_results:
            service_str = f"  service={result.service_version or result.service}" if (result.service_version or result.service) else ""
            banner_str = f"  banner={result.banner[:40]!r}" if result.banner else ""
            tech_str = f"  tech={result.technology[:50]!r}" if result.technology else ""
            entropy_str = f"  entropy={result.response_entropy:.2f}" if result.response_entropy else ""
            window_str = f"  window={result.tcp_window}" if result.tcp_window else ""
            note_str = f"  note={result.scan_note[:60]!r}" if result.scan_note else ""
            cve_str = f"  cve={result.cve_hint[:60]!r}" if result.cve_hint else ""
            os_str = f"  os={result.os_hint}" if result.os_hint else ""
            print(f"  OPEN {result.host}:{result.port}/{result.protocol}  {result.protocol_flag}  {result.rtt_us:.0f}us{os_str}{service_str}{tech_str}{entropy_str}{window_str}{note_str}{cve_str}{banner_str}")
        print(f"  {len(open_results)} open / {len(results)} probed")
        return

    table = Table(title="Open Ports", header_style="bold cyan", show_lines=False)
    table.add_column("Host")
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Flag")
    table.add_column("RTT us", justify="right")
    table.add_column("Service")
    table.add_column("OS Hint")
    table.add_column("Technology")
    table.add_column("Entropy")
    table.add_column("TCP Window")
    table.add_column("Scan Note")
    table.add_column("CVE Hint")
    table.add_column("Banner")
    for result in sorted(open_results, key=lambda item: (item.host, item.port)):
        table.add_row(
            result.host,
            str(result.port),
            result.protocol.upper(),
            "[green]open[/]",
            result.protocol_flag,
            f"{result.rtt_us:.0f}",
            (result.service_version or result.service)[:32],
            result.os_hint,
            result.technology[:36] if result.technology else "",
            f"{result.response_entropy:.2f}" if result.response_entropy else "",
            str(result.tcp_window) if result.tcp_window else "",
            result.scan_note[:36] if result.scan_note else "",
            result.cve_hint[:36] if result.cve_hint else "",
            result.banner[:60] if result.banner else "",
        )
    _C.print(table)
    _C.print(f"Total: [bold green]{len(open_results)}[/] open / {len(results)} probed")


def interactive_scanner() -> int:
    if not SCAPY_AVAILABLE:
        print("ERROR: scapy not installed - pip install scapy")
        return 1

    if RICH and Panel is not None and _C is not None:
        _C.print(
            Panel(
                "[bold cyan]SNN Network Scanner[/]\n"
                "The neuromorphic network decides every probe: timing, technique, and target.\n"
                "[dim]Windows: Npcap required  |  Linux: root / cap_net_raw[/]",
                subtitle="Betta-Morpho",
            )
        )
    else:
        print("=== SNN Network Scanner ===")

    def ask(prompt: str, default: str = "") -> str:
        if RICH and Prompt is not None:
            return Prompt.ask(prompt, default=default) if default else Prompt.ask(prompt)
        value = input(f"{prompt} [{default}]: " if default else f"{prompt}: ").strip()
        return value or default

    target_spec = ask("Target(s) [IP / CIDR / range 10.10.0.1-20 / comma list]")
    port_spec = ask("Ports [top100 / top20 / 22,80 / 1-1024]", "top100")
    profile_name = ask("Scan mode / speed [paranoid/sneaky/polite/normal/aggressive/x5/x10/x15]", "normal")
    manual_speed_raw = ask("Manual speed level override 1-100 (blank = preset only)", "")
    speed_level = None
    if manual_speed_raw:
        speed_level = max(MIN_MANUAL_SPEED_LEVEL, min(MAX_MANUAL_SPEED_LEVEL, int(manual_speed_raw)))
    artifact_str = ask("Scanner artifact (blank = use default init)", "")
    use_decoys = ask("Decoy IPs-> [y/N]", "n").lower().startswith("y")
    skip_discovery = ask("Skip host discovery-> [y/N]", "n").lower().startswith("y")
    output_str = ask("Export CSV path (blank to skip)", "")

    if not target_spec:
        _print("[red]No target specified.[/]")
        return 1

    artifact_path = Path(artifact_str) if artifact_str else None
    targets = parse_targets(target_spec)
    ports = parse_ports(port_spec)
    engine = SpikeScanEngine(profile=profile_name, artifact=artifact_path, speed_level=speed_level)
    decoys = _random_decoys(3) if use_decoys else None

    _print(
        f"\n[bold]Targets:[/] {len(targets)}  [bold]Ports:[/] {len(ports)}  "
        f"[bold]Mode:[/] {profile_name}"
        + (f"  [bold]Manual speed:[/] {speed_level}" if speed_level is not None else "")
        + f"  beta={engine.profile.beta}\n"
    )

    if not skip_discovery and len(targets) > 1:
        targets = discover_hosts(targets, timeout=2.0)
        if not targets:
            _print("[yellow]No live hosts found.[/]")
            return 0

    all_results: list[PortResult] = []
    for host in targets:
        _print(f"[bold cyan]SNN scanning[/] {host} ...")
        host_results = engine.scan(host, ports, decoys=decoys)
        enrich_port_results(host_results)
        all_results.extend(host_results)
        display_results(host_results)

    if output_str:
        export_csv(all_results, Path(output_str))
        _print(
            f"\n[dim]Tip - classify with SNN:\n"
            f"  python launcher.py evaluate --data {output_str} --artifact artifacts/snn_model.json[/]"
        )
    return 0


def _random_decoys(n: int = 3) -> list[str]:
    return [f"10.{random.randint(0, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}" for _ in range(n)]


def _can_bind_source_port(port: int, sock_type: int) -> tuple[bool, str]:
    probe = _socket.socket(_socket.AF_INET, sock_type)
    try:
        probe.bind(("", port))
        return True, ""
    except OSError as exc:
        return False, f"{exc.__class__.__name__}: {exc}"
    finally:
        probe.close()


def _do_classify(data_path: Path, artifact_path: Path, output_path: Path) -> None:
    """Load classifier artifact and add predicted_label to a scan CSV."""

    with artifact_path.open(encoding="utf-8") as handle:
        artifact = json.load(handle)
    class_names = artifact.get("class_names", ["normal", "delayed", "filtered"])
    beta = float(artifact.get("beta", 0.82))
    threshold = float(artifact.get("threshold", 1.0))
    steps = int(artifact.get("steps", 12))
    weights_in = np.array(artifact["input_layer"]["weight"], dtype=np.float32)
    bias_in = np.array(artifact["input_layer"]["bias"], dtype=np.float32)
    weights_out = np.array(artifact["output_layer"]["weight"], dtype=np.float32)
    bias_out = np.array(artifact["output_layer"]["bias"], dtype=np.float32)

    def _encode(row: dict[str, str]) -> np.ndarray:
        flag = row.get("protocol_flag", "TIMEOUT").strip().upper()
        rtt = float(row.get("rtt_us", 0))
        inter_packet = float(row.get("inter_packet_time_us", 0))
        payload_size = float(row.get("payload_size", 0))
        return np.array(
            [
                1.0 if flag == "SYN_ACK" else 0.0,
                1.0 if flag == "RST" else 0.0,
                1.0 if flag == "TIMEOUT" else 0.0,
                1.0 if flag == "UDP_RESPONSE" else 0.0,
                1.0 if flag == "ICMP_UNREACHABLE" else 0.0,
                1.0 if flag == "ICMP_REPLY" else 0.0,
                1.0 - min(inter_packet / max(1.0, 1_000_000.0), 1.0),
                min(payload_size / 1500.0, 1.0),
                1.0 - min(rtt / max(1.0, 500_000.0), 1.0),
            ],
            dtype=np.float32,
        )

    def _infer(row: dict[str, str]) -> str:
        features = _encode(row)
        spikes = np.zeros((steps, len(features)), dtype=np.float32)
        for index, value in enumerate(features):
            if value > 0:
                spike_time = int(round((1.0 - value) * (steps - 1)))
                spikes[min(spike_time, steps - 1), index] = 1.0
        hidden_voltage = np.zeros(weights_in.shape[0], dtype=np.float32)
        output_voltage = np.zeros(weights_out.shape[0], dtype=np.float32)
        spike_count = np.zeros(weights_out.shape[0], dtype=np.float32)
        for spike in spikes:
            hidden_voltage = beta * hidden_voltage + weights_in @ spike + bias_in
            hidden_spikes = (hidden_voltage > threshold).astype(np.float32)
            hidden_voltage *= 1.0 - hidden_spikes
            output_voltage = beta * output_voltage + weights_out @ hidden_spikes + bias_out
            output_spikes = (output_voltage > threshold).astype(np.float32)
            output_voltage *= 1.0 - output_spikes
            spike_count += output_spikes
        return class_names[int(np.argmax(spike_count + 0.01 * output_voltage))]

    with data_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    if "predicted_label" not in fieldnames:
        fieldnames.append("predicted_label")
    for row in rows:
        row["predicted_label"] = _infer(row)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    _print(f"[bold green]Classified[/] {len(rows)} rows -> {output_path}")


def _session_output_path(output_csv: str | Path, suffix: str, extension: str) -> Path:
    output_path = Path(output_csv)
    prefix = infer_session_prefix(output_path)
    if (
        prefix == output_path.parent.name
        and output_path.name != "result.csv"
        and not output_path.stem.endswith("_result")
    ):
        prefix = output_path.stem
    return output_path.parent / f"{prefix}_{suffix}{extension}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SNN-driven network scanner - the neural network decides every probe")
    subcommands = parser.add_subparsers(dest="cmd")

    scan_cmd = subcommands.add_parser("scan", help="Run an SNN-driven host/port scan")
    scan_cmd.add_argument("--target", required=True, help="IP / CIDR / range / comma list")
    scan_cmd.add_argument("--ports", default="top100")
    scan_cmd.add_argument("--profile", default="normal", choices=list(PROFILES), help="Scan mode / speed preset")
    scan_cmd.add_argument(
        "--speed-level",
        type=int,
        default=None,
        metavar="N",
        help=f"Manual speed override from {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL}; overrides pacing and parallelism while keeping the selected profile behavior",
    )
    scan_cmd.add_argument("--artifact", help="Path to trained scanner artifact JSON")
    scan_cmd.add_argument("--service-artifact", help="Optional service-fingerprint artifact JSON for enriched app-layer classification")
    scan_cmd.add_argument("--service-catalog", default=str(PROJECT_ROOT / "artifacts" / "service_catalog.json"), help="Internal service catalog artifact used for service normalization")
    scan_cmd.add_argument("--decoys", action="store_true")
    scan_cmd.add_argument("--no-discovery", action="store_true")
    scan_cmd.add_argument("--output", help="Export results CSV")
    scan_cmd.add_argument("--save-weights", metavar="PATH", help="Save adapted SNN weights to JSON after scan")
    scan_cmd.add_argument(
        "--checkpoint-every",
        type=int,
        default=1000,
        metavar="N",
        help="Save partial CSV/HTML progress every N scanned ports when the scan scope exceeds N",
    )
    scan_cmd.add_argument("--ports-udp", default="", help="UDP ports to probe, for example 53,161,500")
    scan_cmd.add_argument("--spoof-ttl", type=int, default=None, metavar="N", help="Override outgoing IP TTL")
    scan_cmd.add_argument("--jitter-ms", type=int, default=0, metavar="N", help="Max random inter-batch pause in ms")
    scan_cmd.add_argument("--source-port", type=int, default=None, metavar="N", help="Bind outgoing TCP/UDP probes to source port N")
    scan_cmd.add_argument("--retry-source-port", type=int, default=None, metavar="N", help="Retry filtered TCP ports with source port N")
    scan_cmd.add_argument("--active-learning-output", metavar="PATH", help="Write low-confidence service predictions to PATH")
    scan_cmd.add_argument("--active-learning-threshold", type=float, default=0.65, metavar="F", help="Confidence threshold for active-learning export")
    scan_cmd.add_argument("--html", metavar="PATH", help="Write a self-contained HTML report to PATH")
    scan_cmd.add_argument("--progress-log", metavar="PATH", help="Append scan start/checkpoint timing to PATH")
    scan_cmd.add_argument("--connect-only", action="store_true", help="Force TCP connect probes instead of raw packet probes")
    scan_cmd.add_argument("--verify-with-nmap", action="store_true", help="Run targeted Nmap verification against Betta-Morpho-open ports after the scan")
    scan_cmd.add_argument("--no-classify", action="store_true", help="Skip auto-classification after the scan")
    scan_cmd.add_argument(
        "--report",
        metavar="CLASSIFIER_ARTIFACT",
        help=(
            "Auto-pipeline: create output dir with "
            "YYYYMMDD_HHMMSS_TARGET_result.csv/report.html/classified.csv/hostnames.csv. "
            "Use --verify-with-nmap separately if you also want targeted Nmap verification."
        ),
    )
    scan_cmd.add_argument("--discover-hostnames", action="store_true", help="Run passive hostname discovery from the resulting scan evidence")
    scan_cmd.add_argument("--host-discovery-artifact", metavar="PATH", help="Optional passive-host-discovery artifact JSON")
    scan_cmd.add_argument("--host-discovery-output", metavar="PATH", help="Write discovered hostname candidates to PATH")
    scan_cmd.add_argument("--host-discovery-html", metavar="PATH", help="Write hostname discovery HTML report to PATH")

    classify_cmd = subcommands.add_parser("classify-results", help="Load scan CSV and add predicted_label via the SNN classifier")
    classify_cmd.add_argument("--data", required=True, help="Input scan CSV path")
    classify_cmd.add_argument("--artifact", required=True, help="SNN model JSON artifact")
    classify_cmd.add_argument("--output", required=True, help="Output CSV path with predicted_label")

    train_cmd = subcommands.add_parser("train", help="Train the scanner SNN on synthetic scenarios")
    train_cmd.add_argument("--profile", default="normal", choices=list(PROFILES), help="Scan mode / speed preset used for scenario generation")
    train_cmd.add_argument("--scenarios", type=int, default=800)
    train_cmd.add_argument("--epochs", type=int, default=30)
    train_cmd.add_argument("--lr", type=float, default=0.01)
    train_cmd.add_argument("--artifact", default="artifacts/scanner_model.json")
    train_cmd.add_argument("--seed", type=int, default=42)

    return parser


def main() -> int:
    if len(sys.argv) == 1:
        return interactive_scanner()

    args = build_parser().parse_args()

    if args.cmd == "train":
        _print(f"\n[bold]Training SNN scanner[/]  profile={args.profile}  scenarios={args.scenarios}  epochs={args.epochs}")
        engine = SpikeScanEngine(profile=args.profile, seed=args.seed)
        accuracy = train_scanner_snn(engine, scenarios=args.scenarios, epochs=args.epochs, lr=args.lr, seed=args.seed)
        engine.save_artifact(Path(args.artifact), meta={"training_scenarios": args.scenarios, "accuracy": round(accuracy, 4)})
        _print(f"[bold green]Done[/]  accuracy={accuracy:.3f}")
        return 0

    if args.cmd == "scan":
        if not SCAPY_AVAILABLE:
            print("ERROR: scapy not installed - pip install scapy")
            return 1

        os.environ[SERVICE_CATALOG_ENV] = str(Path(args.service_catalog))

        artifact = Path(args.artifact) if args.artifact else None
        service_artifact: dict | None = None
        verification_summary: dict | None = None

        if getattr(args, "service_artifact", None):
            try:
                service_artifact = load_service_artifact(args.service_artifact)
            except (FileNotFoundError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                _print(f"[yellow][Betta-Morpho] service-artifact skipped: {exc}[/]")

        report_classifier: Path | None = Path(args.report) if getattr(args, "report", None) else None

        if report_classifier is not None:
            output_paths = build_report_bundle_paths(
                PROJECT_ROOT / "data" / "scans",
                args.target,
                getattr(args, "output", None),
                getattr(args, "html", None),
                getattr(args, "progress_log", None),
                getattr(args, "active_learning_output", None),
            )
            report_dir = Path(output_paths["dir"])
            report_dir.mkdir(parents=True, exist_ok=True)
            args.output = str(output_paths["result_csv"])
            args.html = str(output_paths["report_html"])
            args.progress_log = str(output_paths["progress_log"])
            args.active_learning_output = str(output_paths["active_learning_csv"])
            if getattr(args, "discover_hostnames", False):
                args.host_discovery_output = str(output_paths["hostnames_csv"])
                args.host_discovery_html = str(output_paths["hostnames_html"])
            _print(f"[bold cyan][Betta-Morpho] Output dir:[/] {report_dir}")
        elif not args.output:
            output_paths = build_scan_output_paths(PROJECT_ROOT / "data" / "scans", args.target)
            report_dir = Path(output_paths["dir"])
            report_dir.mkdir(parents=True, exist_ok=True)
            args.output = str(output_paths["result_csv"])
            if not getattr(args, "html", None):
                args.html = str(output_paths["report_html"])
            if not getattr(args, "progress_log", None):
                args.progress_log = str(output_paths["progress_log"])
            if not getattr(args, "active_learning_output", None):
                args.active_learning_output = str(output_paths["active_learning_csv"])
            if getattr(args, "discover_hostnames", False):
                args.host_discovery_output = str(output_paths["hostnames_csv"])
                args.host_discovery_html = str(output_paths["hostnames_html"])
            _print(f"[bold cyan][Betta-Morpho] Output dir:[/] {report_dir}")
        elif not getattr(args, "progress_log", None):
            args.progress_log = str(_session_output_path(args.output, "progress", ".log"))
        if getattr(args, "discover_hostnames", False):
            if not getattr(args, "host_discovery_output", None):
                args.host_discovery_output = str(_session_output_path(args.output, "hostnames", ".csv"))
            if not getattr(args, "host_discovery_html", None):
                args.host_discovery_html = str(_session_output_path(args.output, "hostnames_report", ".html"))

        targets = parse_targets(args.target)
        ports = parse_ports(args.ports)
        source_ports_to_check = []
        if args.source_port is not None:
            source_ports_to_check.append(("primary", args.source_port, bool(args.ports_udp)))
        if args.retry_source_port is not None and args.retry_source_port != args.source_port:
            source_ports_to_check.append(("retry", args.retry_source_port, False))
        for role, requested_port, needs_udp in source_ports_to_check:
            tcp_ok, tcp_msg = _can_bind_source_port(requested_port, _socket.SOCK_STREAM)
            udp_ok, udp_msg = (True, "")
            if needs_udp:
                udp_ok, udp_msg = _can_bind_source_port(requested_port, _socket.SOCK_DGRAM)
            if not tcp_ok or not udp_ok:
                if not tcp_ok:
                    _print(f"[red][Betta-Morpho] Cannot bind {role} TCP source port {requested_port}:[/] {tcp_msg}")
                if not udp_ok:
                    _print(f"[red][Betta-Morpho] Cannot bind {role} UDP source port {requested_port}:[/] {udp_msg}")
                _print("[yellow][Betta-Morpho] This scan requires elevated privileges or NET_BIND_SERVICE for the requested source port.[/]")
                return 2

        engine = SpikeScanEngine(profile=args.profile, artifact=artifact, speed_level=args.speed_level)
        decoys = _random_decoys(3) if args.decoys else None
        udp_ports = parse_ports(args.ports_udp) if args.ports_udp else []

        stealth_info = []
        if args.spoof_ttl:
            stealth_info.append(f"spoof-ttl={args.spoof_ttl}")
        if args.jitter_ms:
            stealth_info.append(f"jitter={args.jitter_ms}ms")
        if udp_ports:
            stealth_info.append(f"udp={len(udp_ports)}ports")
        if args.retry_source_port is not None:
            stealth_info.append(f"retry-sp={args.retry_source_port}")

        _print(
            f"[bold]SNN scanner[/]  targets={len(targets)}  ports={len(ports)}  profile={args.profile}"
            + (f"  speed-level={args.speed_level}" if getattr(args, "speed_level", None) is not None else "")
            + f"  beta={engine.profile.beta}"
            + (f"  [{', '.join(stealth_info)}]" if stealth_info else "")
        )
        progress_writer = ScanCheckpointWriter(
            result_csv=Path(args.output) if args.output else None,
            html_path=Path(args.html) if getattr(args, "html", None) else None,
            progress_log=Path(args.progress_log) if getattr(args, "progress_log", None) else None,
            checkpoint_every=int(getattr(args, "checkpoint_every", 1000)),
            total_ports=len(ports),
        )
        progress_writer.start(args.target, args.profile, len(targets))

        if not args.no_discovery and len(targets) > 1:
            targets = discover_hosts(targets, timeout=2.0)
            if not targets:
                _print("[yellow]No live hosts.[/]")
                progress_writer.finish(0)
                return 0

        all_results: list[PortResult] = []
        total_hosts = len(targets)
        for index, host in enumerate(targets, start=1):
            if total_hosts > 1:
                _print(f"\n[bold cyan][Betta-Morpho] scanning[/] {host} ({index}/{total_hosts})")
            else:
                _print(f"\n[bold cyan]SNN scanning[/] {host} ...")

            def _checkpoint(scanned_ports: int, total_ports: int, partial_results: list[PortResult]) -> None:
                if total_ports <= 0:
                    return
                progress_writer.checkpoint(host, scanned_ports, all_results + partial_results)

            host_results = engine.scan(
                host,
                ports,
                decoys=decoys,
                spoof_ttl=args.spoof_ttl,
                jitter_ms=args.jitter_ms,
                force_connect=args.connect_only,
                source_port=args.source_port,
                checkpoint_interval=int(getattr(args, "checkpoint_every", 1000)),
                progress_callback=_checkpoint,
            )
            if udp_ports:
                _print(f"[dim]  UDP pass: {len(udp_ports)} ports ...[/]")
                for udp_port in udp_ports:
                    if RAW_AVAILABLE and not args.connect_only:
                        host_results.append(udp_probe(host, udp_port, engine.profile))
                    else:
                        host_results.append(udp_connect_probe(host, udp_port, timeout=engine.profile.probe_timeout, source_port=args.source_port))
            if args.retry_source_port is not None:
                _print(f"[dim]  Source-port retry: filtered TCP ports via {args.retry_source_port} ...[/]")
                retried_count, changed_count = retry_filtered_tcp_with_source_port(
                    host,
                    host_results,
                    timeout=engine.profile.probe_timeout,
                    source_port=args.retry_source_port,
                )
                _print(f"[dim]    retried={retried_count} changed={changed_count}[/]")

            enrich_port_results(host_results, service_artifact=service_artifact)
            all_results.extend(host_results)
            display_results(host_results)
            if args.jitter_ms and index < total_hosts:
                time.sleep(random.uniform(0, args.jitter_ms / 1000.0))

        if args.output:
            export_csv(all_results, Path(args.output))

        if service_artifact and getattr(args, "active_learning_output", None):
            try:
                export_active_learning_rows(all_results, Path(args.active_learning_output), threshold=float(args.active_learning_threshold))
            except (OSError, ValueError) as exc:
                _print(f"[yellow][Betta-Morpho] Active learning export skipped: {exc}[/]")

        should_verify_with_nmap = bool(getattr(args, "verify_with_nmap", False))
        if should_verify_with_nmap:
            if args.output:
                try:
                    import shutil

                    if shutil.which("nmap") is None:
                        _print("[yellow][Betta-Morpho] Nmap verification skipped: nmap not installed.[/]")
                    else:
                        from tools.verify_scan import verify_betta_morpho_csv

                        verification_summary = verify_betta_morpho_csv(
                            scan_csv=Path(args.output),
                            target=targets[0] if targets else args.target,
                            service_catalog=args.service_catalog,
                        )
                        _print(
                            "[bold green][Betta-Morpho] Nmap verify:[/] "
                            + f"matched={len(verification_summary.get('matched_ports', []))} "
                            + f"betta_only={len(verification_summary.get('betta_morpho_only_ports', []))} "
                            + f"nmap_only={len(verification_summary.get('nmap_only_ports', []))}"
                        )
                except (FileNotFoundError, ImportError, OSError, RuntimeError, ValueError) as exc:
                    _print(f"[yellow][Betta-Morpho] Nmap verification skipped: {exc}[/]")
            else:
                _print("[yellow][Betta-Morpho] Nmap verification skipped: requires --output or --report.[/]")

        if getattr(args, "html", None):
            export_html(all_results, Path(args.html), verification_summary=verification_summary)

        if getattr(args, "save_weights", None):
            engine.save_artifact(Path(args.save_weights))

        if report_classifier and report_classifier.exists() and args.output:
            try:
                classified_path = _session_output_path(args.output, "classified", ".csv")
                _do_classify(Path(args.output), report_classifier, classified_path)
                with classified_path.open(encoding="utf-8", newline="") as handle:
                    counts = Counter(
                        row.get("predicted_label", "")
                        for row in csv.DictReader(handle)
                        if row.get("protocol_flag") == "SYN_ACK"
                    )
                _print(f"[bold green][Betta-Morpho] classified:[/] " + "  ".join(f"{label}={count}" for label, count in sorted(counts.items())))
                _print("[bold cyan][Betta-Morpho] Report files:[/]")
                _print(f"  result.csv     : {args.output}")
                _print(f"  classified.csv : {classified_path}")
                _print(f"  report.html    : {args.html}")
                if getattr(args, "discover_hostnames", False):
                    _print(f"  hostnames.csv  : {args.host_discovery_output}")
                    _print(f"  hostnames.html : {args.host_discovery_html}")
                if verification_summary:
                    _print(f"  verify.json    : {verification_summary.get('comparison_json', '')}")
                    _print(f"  verify.csv     : {verification_summary.get('comparison_csv', '')}")
            except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
                _print(f"[yellow]classify step skipped: {exc}[/]")

        if args.output and artifact and not getattr(args, "no_classify", False):
            try:
                with artifact.open(encoding="utf-8") as handle:
                    artifact_payload = json.load(handle)
                if "input_layer" in artifact_payload:
                    classified_path = _session_output_path(args.output, "classified", ".csv")
                    _do_classify(Path(args.output), artifact, classified_path)
                    with classified_path.open(encoding="utf-8", newline="") as handle:
                        rows = list(csv.DictReader(handle))
                    predicted_counts = Counter(
                        row.get("predicted_label", "")
                        for row in rows
                        if row.get("protocol_flag") == "SYN_ACK"
                    )
                    summary = "  ".join(f"{label}={count}" for label, count in sorted(predicted_counts.items()))
                    _print(f"[bold green][Betta-Morpho] Auto-classify:[/] {summary}")
            except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
                _print(f"[yellow][Betta-Morpho] Auto-classify skipped: {exc}[/]")

        if getattr(args, "discover_hostnames", False):
            try:
                discovery_artifact_path: Path | None = None
                configured_artifact = getattr(args, "host_discovery_artifact", None)
                if configured_artifact:
                    candidate = Path(configured_artifact)
                    if candidate.exists():
                        discovery_artifact_path = candidate
                    else:
                        _print(f"[yellow][Betta-Morpho] Host discovery artifact skipped: not found: {candidate}[/]")
                else:
                    default_artifact = default_artifact_path()
                    if default_artifact.exists():
                        discovery_artifact_path = default_artifact

                hostname_rows = discover_from_port_results(all_results, artifact_path=discovery_artifact_path)
                if getattr(args, "host_discovery_output", None):
                    export_discovery_csv(hostname_rows, Path(args.host_discovery_output))
                if getattr(args, "host_discovery_html", None):
                    export_discovery_html(hostname_rows, Path(args.host_discovery_html))
                counts = Counter(row.get("predicted_label", "") for row in hostname_rows)
                _print(
                    "[bold green][Betta-Morpho] host discovery:[/] "
                    + f"candidates={len(hostname_rows)} "
                    + f"high_value={counts.get('high_value', 0)} "
                    + f"supporting={counts.get('supporting', 0)} "
                    + f"noise={counts.get('noise', 0)}"
                )
            except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
                _print(f"[yellow][Betta-Morpho] Host discovery skipped: {exc}[/]")

        try:
            from tools.scan_history import ScanHistory

            scan_id = ScanHistory(str(PROJECT_ROOT / "data" / "scan_history.db")).save_scan(
                targets[0] if targets else args.target,
                args.profile,
                all_results,
            )
            _print(f"[dim]Saved to scan history (scan #{scan_id})[/]")
        except (ImportError, OSError, sqlite3.Error, ValueError) as exc:
            _print(f"[yellow][Betta-Morpho] Scan history skipped: {exc}[/]")

        progress_writer.finish(len(all_results))

        return 0

    if args.cmd == "classify-results":
        data_path = Path(args.data)
        artifact_path = Path(args.artifact)
        output_path = Path(args.output)
        if not data_path.exists():
            print(f"ERROR: data file not found: {data_path}")
            return 1
        if not artifact_path.exists():
            print(f"ERROR: artifact not found: {artifact_path}")
            return 1
        _do_classify(data_path, artifact_path, output_path)
        return 0

    return interactive_scanner()


if __name__ == "__main__":
    raise SystemExit(main())
