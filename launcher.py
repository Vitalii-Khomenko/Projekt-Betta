"""
Betta-Morpho Universal Launcher
===============================
Single entry point for all project workflows: training, scanning, evaluation,
dataset generation, service fingerprinting, and Nmap verification.

Key commands:
    python launcher.py train           --data data/synthetic_dataset.csv --artifact artifacts/snn_model.json --epochs 40
    python launcher.py scan            --target 10.10.10.5 --ports top100 --profile normal --artifact artifacts/scanner_model.json
    python launcher.py evaluate        --data data/synthetic_dataset.csv --artifact artifacts/snn_model.json
    python launcher.py scan-train      --profile normal --scenarios 1600 --epochs 50 --artifact artifacts/scanner_model.json
    python launcher.py golden-dataset  --golden-output data/snn_training_batch.csv
    python launcher.py verify-betta-morpho --scan-csv data/scans/SCAN_DIR/YYYYMMDD_HHMMSS_IP_result.csv
    python launcher.py service-catalog-build --output artifacts/service_catalog.json
    python launcher.py service-train   data/scans --artifact artifacts/service_model.json
    python launcher.py discover-train  --data data/host_discovery_synthetic.csv --artifact artifacts/host_discovery_model.json
    python launcher.py discover-hostnames data/scans/SCAN_DIR/YYYYMMDD_HHMMSS_IP_result.csv --output data/scans/SCAN_DIR/YYYYMMDD_HHMMSS_IP_hostnames.csv
    python launcher.py service-classify --input data/scans/SCAN_DIR/YYYYMMDD_HHMMSS_IP_result.csv --artifact artifacts/service_model.json --output result_svc.csv
    python launcher.py benchmark-scans --baseline-csv data/scans/A_result.csv --candidate-csv data/scans/B_result.csv --register
    python launcher.py experiment-list --limit 10
    python launcher.py domain-summary
    python launcher.py replay-dir      --data-dir data/scans --artifact artifacts/snn_model.json
    python launcher.py live-capture    --interface eth0 --seconds 30
    python launcher.py pcap-to-csv     --pcap capture.pcap --output data/telemetry.csv

Output: scan results saved to data/scans/YYYYMMDD_HHMMSS_IP/ with matching YYYYMMDD_HHMMSS_IP_* artifact names by default.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.4.1
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Any, cast

from training.tools.scanner_types import MAX_MANUAL_SPEED_LEVEL, MIN_MANUAL_SPEED_LEVEL

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    Console = cast(Any, None)
    Panel = cast(Any, None)
    Prompt = cast(Any, None)
    Table = cast(Any, None)
    RICH_AVAILABLE = False

try:
    from tools.verify_scan import NMAP_PRESETS as _NMAP_PRESETS  # type: ignore[import]
except Exception:
    try:
        import sys as _sys
        import os as _os
        _sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))
        from verify_scan import NMAP_PRESETS as _NMAP_PRESETS  # type: ignore[import]
    except Exception:
        _NMAP_PRESETS = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parent
SPEC_PATH = ROOT / "docs" / "Engineering_Draft.md"
DEFAULT_DATASET = "data/synthetic_dataset.csv"
DEFAULT_REPLAY_DIR = "data/scans"
LAB_SERVICES_SCRIPT = "tools/lab_services.py"
LAB_EXERCISE_SCRIPT = "tools/lab_exercise.py"
CONSOLE = Console() if RICH_AVAILABLE and Console is not None else None


def preferred_python() -> str:
    if sys.prefix != sys.base_prefix:
        return sys.executable

    windows_candidate = ROOT / ".venv" / "Scripts" / "python.exe"
    linux_candidate = ROOT / ".venv" / "bin" / "python"
    if windows_candidate.exists():
        return str(windows_candidate)
    if linux_candidate.exists():
        return str(linux_candidate)
    return sys.executable


def run_script(script: str, arguments: list[str]) -> int:
    script_path = ROOT / script
    if not script_path.exists():
        print(f"ERROR: script not found: {script_path}")
        return 1
    try:
        return subprocess.call([preferred_python(), str(script_path)] + arguments, cwd=ROOT)
    except KeyboardInterrupt:
        print(f"Interrupted: {script}")
        return 130


def prompt_text(label: str, default: str) -> str:
    value = input(f"{label} [{default}]: ").strip()
    return value or default


def prompt_int(label: str, default: int) -> int:
    while True:
        raw = prompt_text(label, str(default))
        try:
            return int(raw)
        except ValueError:
            print("Please enter a whole number.")


def prompt_float(label: str, default: float) -> float:
    while True:
        raw = prompt_text(label, str(default))
        try:
            return float(raw)
        except ValueError:
            print("Please enter a numeric value.")


def prompt_bool(label: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(f"{label} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes", "1", "true"}


SCAN_MODE_INFO = [
    ("1", "paranoid", "Safe / stealth", "Very slow pacing. Use for cautious reconnaissance where low pressure matters more than speed."),
    ("2", "sneaky", "Stealth", "Low-noise scan for external probing when you still want some progress."),
    ("3", "polite", "Safe balanced", "Conservative everyday mode for careful but practical scans."),
    ("4", "normal", "Balanced", "Best default for most day-to-day scans and first-pass testing."),
    ("5", "aggressive", "Fast", "High-speed scan when time matters more than stealth."),
    ("6", "x5", "Very fast", "Good for LAN, localhost, and large stable ranges."),
    ("7", "x10", "Ultra fast", "High-throughput scanning for strong local or lab environments."),
    ("8", "x15", "Stress / max speed", "Fastest preset. Best for lab, localhost, LAN, and controlled stress testing."),
]

MANUAL_SCAN_MODE_OPTION = (
    "9",
    "manual-speed",
    f"Manual speed {MIN_MANUAL_SPEED_LEVEL}-{MAX_MANUAL_SPEED_LEVEL}",
    "Choose a base profile and then tune throughput yourself. Best when you want exact runtime pressure instead of a preset.",
)

MANUAL_SPEED_INFO = (
    f"Manual speed level is a throughput override from {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL}.\n"
    "- 1 = minimal pressure, long waits, low parallelism\n"
    "- 50 = balanced manual pacing\n"
    "- 100 = original maximum manual throughput for stress testing and fast lab scans\n"
    "- 300 = turbo manual throughput for controlled local and lab scans\n\n"
    "It keeps the selected profile's neural behavior, but overrides runtime pacing,\n"
    "timeouts, and parallelism."
)

TRANSPORT_MODE_INFO = [
    ("1", "auto", "Auto / raw when available", "Best default. Betta-Morpho uses raw SYN on raw-capable systems and falls back when needed."),
    ("2", "connect", "Connect-only", "Best for Windows, VPN, HTB, and when you want stable application-layer results fast."),
]

SCAN_SCOPE_INFO = [
    ("1", "tcp", "TCP only", "Classic TCP-focused scan. Best for most first passes."),
    ("2", "tcp_udp", "TCP + UDP", "Adds a focused UDP pass for ports like 53, 67, 68, 69, 123, 161, 500."),
    ("3", "advanced", "Advanced custom", "Same scanner, but with extra transport, timing, source-port, and output controls."),
]

REPORT_MODE_INFO = [
    ("1", "auto_report", "Auto report pipeline", "Best default. Creates a timestamped result directory with CSV, HTML report, classified CSV, progress log, and active-learning CSV."),
    ("2", "manual_output", "Manual CSV / HTML paths", "Use when you want exact output locations and still want structured exports."),
    ("3", "minimal", "Minimal output", "Use for lightweight runs or testing when you only need the essentials."),
]


def _choose_nmap_config() -> tuple[str, str]:
    """Interactive Nmap preset + extra flags chooser.
    Returns (preset_name, extra_flags_string).
    """
    presets = _NMAP_PRESETS if _NMAP_PRESETS is not None else []
    options: list[tuple[str, str, str]] = [
        (key, name, description)
        for key, name, description, _ in presets
    ]
    if options:
        _print_panel(
            "Nmap Verification Profile",
            "Choose a preset that matches your goal.\n"
            "You can add extra flags after the preset to extend or override behavior.\n"
            "Examples of extra flags: --script=banner  -v  --script=smb-vuln*  --version-intensity 9",
        )
        choice = _prompt_menu_choice("Choose Nmap Preset", options, "1")
        preset = next((name for key, name, _, _ in presets if key == choice), "deep")
    else:
        preset = "deep"
    extra = prompt_text(
        "Extra Nmap flags to append (blank = none, e.g. '--script=banner -v')", ""
    )
    chosen_desc = next((desc for _, name, desc, _ in presets if name == preset), preset)
    _print_panel(
        "Nmap Config Summary",
        f"Preset  : {preset}\n"
        f"Flags   : {chosen_desc}\n"
        f"Extra   : {extra or '(none)'}\n",
    )
    return preset, extra

PROJECT_LEARNING_TOPICS = {
    "1": (
        "Project Workflow",
        "Betta-Morpho has three practical stages:\n"
        "1. Prepare or generate data\n"
        "2. Train one or more models\n"
        "3. Run scans and review the artifacts\n\n"
        "The main artifacts are:\n"
        "- classifier model: transport / telemetry classifier\n"
        "- scanner model: probe strategy and pacing\n"
        "- service model: app-layer service labeling\n"
        "- service catalog: normalization rules and local service hints\n"
        "- host discovery model: passive hostname/domain ranking from scan evidence",
    ),
    "2": (
        "Models Guide",
        "Classifier SNN:\n"
        "- Learns from telemetry CSV rows\n"
        "- Used for classification and report labeling\n\n"
        "Scanner SNN:\n"
        "- Learns probe pacing and scan strategy\n"
        "- Controls how Betta-Morpho scans targets\n\n"
        "Service model:\n"
        "- Learns service fingerprints from past scan outputs\n"
        "- Helps label services on unusual ports or noisy banners\n\n"
        "Host discovery model:\n"
        "- Learns to rank hostnames and domains passively exposed by services\n"
        "- Helps separate high-value names from low-signal noise after a scan",
    ),
    "3": (
        "Scan Profiles",
        "Stealth-oriented modes:\n"
        "- paranoid, sneaky, polite\n\n"
        "General-purpose modes:\n"
        "- normal, aggressive\n\n"
        "Speed-oriented modes:\n"
        "- x5, x10, x15\n\n"
        "Manual speed override:\n"
        f"- {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL} as a runtime throughput scale layered on top of the chosen profile\n\n"
        "Use x15 or a high manual speed mostly for localhost, lab, LAN, or other stable environments where speed matters most.",
    ),
    "4": (
        "Transport and Protocols",
        "Auto / raw-capable mode:\n"
        "- Betta-Morpho tries raw SYN style probing where possible\n"
        "- Good on Linux when raw sockets are available\n\n"
        "Connect-only mode:\n"
        "- Uses full TCP connect probes\n"
        "- Best on Windows and often fastest in practice there\n\n"
        "UDP pass:\n"
        "- Separate targeted UDP probing\n"
        "- Useful for DNS, SNMP, NTP, IPsec, and similar services\n\n"
        + MANUAL_SPEED_INFO,
    ),
    "5": (
        "Reports and Verification",
        "Auto report pipeline writes a full scan folder with matching names:\n"
        "- result CSV\n"
        "- HTML report\n"
        "- classified CSV\n"
        "- progress log\n"
        "- active-learning CSV\n"
        "- hostnames CSV\n"
        "- hostnames HTML report\n\n"
        "Nmap verification is a separate step.\n"
        "You should enable it only when you really want a targeted control pass against Betta-Morpho-open ports.",
    ),
    "6": (
        "Output Artifacts",
        "By default Betta-Morpho writes scan sessions into data/scans/YYYYMMDD_HHMMSS_IP/.\n"
        "Files inside use the same prefix.\n\n"
        "Important files:\n"
        "- *_result.csv\n"
        "- *_report.html\n"
        "- *_classified.csv\n"
        "- *_progress.log\n"
        "- *_active_learning.csv\n"
        "- *_hostnames.csv\n"
        "- *_hostnames_report.html",
    ),
    "7": (
        "Stealth And Evasion Guide",
        "What stealth means in Betta-Morpho right now:\n\n"
        "Profiles:\n"
        "- paranoid / sneaky / polite = lower tempo and lower pressure\n"
        "- these are the first choice when you want quieter scans\n\n"
        "Decoys:\n"
        "- --decoys sends extra spoofed raw packets around the real probe\n"
        "- useful as noise, not as true anonymity\n\n"
        "TTL and jitter:\n"
        "- --spoof-ttl changes apparent packet TTL style\n"
        "- --jitter-ms adds timing variation so traffic looks less rigid\n\n"
        "Source-port tricks:\n"
        "- --source-port and --retry-source-port are specialized evasion tools\n"
        "- use them after baseline discovery, not as the default stealth mode\n\n"
        "Important limit:\n"
        "- Betta-Morpho can add stealth features and decoys\n"
        "- it does not make your real probing IP disappear in normal connect workflows",
    ),
}


def _print_panel(title: str, body: str, subtitle: str = "") -> None:
    if RICH_AVAILABLE and CONSOLE is not None and Panel is not None:
        CONSOLE.print(Panel(body, title=title, subtitle=subtitle))
        return
    print(f"\n=== {title} ===")
    print(body)
    if subtitle:
        print(f"[{subtitle}]")


def _choose_menu_option(title: str, options: list[tuple[str, str, str]], default: str) -> str:
    if RICH_AVAILABLE and CONSOLE is not None and Table is not None:
        table = Table(title=title, show_header=True, header_style="bold cyan")
        table.add_column("Key", style="bold")
        table.add_column("Option")
        table.add_column("Description")
        for key, label, description in options:
            table.add_row(key, label, description)
        CONSOLE.print(table)
    else:
        print(f"\n{title}")
        for key, label, description in options:
            print(f"{key}. {label} - {description}")
    return prompt_text("Select option", default)


def _prompt_menu_choice(title: str, options: list[tuple[str, str, str]], default: str) -> str:
    valid = {key for key, _, _ in options}
    while True:
        choice = _choose_menu_option(title, options, default)
        if choice in valid:
            return choice
        print(f"Unknown choice: {choice}. Please select one of: {', '.join(sorted(valid))}")


def _show_transport_guide() -> None:
    options = [(key, mode, f"{meaning}. {description}") for key, mode, meaning, description in TRANSPORT_MODE_INFO]
    _choose_menu_option("Transport Modes", options, "1")


def _show_scan_scope_guide() -> None:
    _print_panel(
        "Scan Scope Guide",
        "TCP only:\n"
        "- Best for most first scans\n"
        "- Faster and simpler to interpret\n\n"
        "TCP + UDP:\n"
        "- Adds targeted UDP checks such as 53, 123, 161, 500\n"
        "- Good when DNS, SNMP, NTP, or IPsec matter\n\n"
        "Advanced custom:\n"
        "- Same scan engine, but with more transport and output controls\n"
        "- Best when you want source ports, TTL, jitter, custom report paths, or active-learning output",
    )


def _show_report_guide() -> None:
    _print_panel(
        "Report Guide",
        "Auto report pipeline:\n"
        "- Best default for most real scans\n"
        "- Writes a full timestamped scan folder automatically\n"
        "- Can also include passive hostname discovery exports\n\n"
        "Manual output:\n"
        "- Best when you want exact file paths\n"
        "- Good for repeatable experiments or external automation\n\n"
        "Minimal output:\n"
        "- Best for quick tests and lightweight runs\n"
        "- Keeps the result set small unless you add more artifacts",
    )


def _show_question_hint(title: str, body: str) -> None:
    _print_panel(title, body)


def _show_learning_topic(topic_key: str) -> None:
    title, body = PROJECT_LEARNING_TOPICS[topic_key]
    _print_panel(title, body)


def _choose_scan_profile(default_key: str = "4") -> str:
    choice = _prompt_menu_choice(
        "Choose Scan Profile",
        [(key, mode, f"{meaning}. {description}") for key, mode, meaning, description in SCAN_MODE_INFO],
        default_key,
    )
    return next(mode for key, mode, _, _ in SCAN_MODE_INFO if key == choice)


def _choose_scan_runtime(default_key: str = "4") -> tuple[str, int | None]:
    options = [(key, mode, f"{meaning}. {description}") for key, mode, meaning, description in SCAN_MODE_INFO]
    options.append(
        (
            MANUAL_SCAN_MODE_OPTION[0],
            MANUAL_SCAN_MODE_OPTION[1],
            f"{MANUAL_SCAN_MODE_OPTION[2]}. {MANUAL_SCAN_MODE_OPTION[3]}",
        )
    )
    choice = _prompt_menu_choice("Choose Scan Profile / Speed", options, default_key)
    if choice == MANUAL_SCAN_MODE_OPTION[0]:
        _print_panel("Manual Speed", MANUAL_SPEED_INFO)
        profile = _choose_scan_profile("4")
        speed_level = max(
            MIN_MANUAL_SPEED_LEVEL,
            min(MAX_MANUAL_SPEED_LEVEL, prompt_int("Manual speed level", 50)),
        )
        return profile, speed_level
    profile = next(mode for key, mode, _, _ in SCAN_MODE_INFO if key == choice)
    return profile, None


def _choose_transport_mode(default_key: str = "1") -> str:
    choice = _prompt_menu_choice(
        "Choose Transport Mode",
        [(key, mode, f"{meaning}. {description}") for key, mode, meaning, description in TRANSPORT_MODE_INFO],
        default_key,
    )
    return next(mode for key, mode, _, _ in TRANSPORT_MODE_INFO if key == choice)


def _choose_scan_scope(default_key: str = "1") -> str:
    choice = _prompt_menu_choice(
        "Choose Scan Scope",
        [(key, scope, description) for key, scope, description, _ in SCAN_SCOPE_INFO],
        default_key,
    )
    return next(scope for key, scope, _, _ in SCAN_SCOPE_INFO if key == choice)


def _choose_report_mode(default_key: str = "1") -> str:
    choice = _prompt_menu_choice(
        "Choose Output / Report Style",
        [(key, label, description) for key, label, description, _ in REPORT_MODE_INFO],
        default_key,
    )
    return next(mode for key, mode, _, _ in REPORT_MODE_INFO if key == choice)


def _show_scan_mode_guide() -> None:
    _print_panel(
        "Scan Modes / Speed Presets",
        "\n".join(f"- {mode}: {meaning}. {description}" for _, mode, meaning, description in SCAN_MODE_INFO)
        + f"\n- manual-speed: choose menu item 9 to enter your own speed level from {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL}.",
    )


def _run_steps(steps: list[tuple[str, str, list[str]]]) -> int:
    for title, script, arguments in steps:
        _print_panel("Running Step", f"{title}\n\nCommand:\n{preferred_python()} {script} {' '.join(arguments)}")
        code = run_script(script, arguments)
        if code == 130:
            print(f"Step interrupted: {title}")
            return code
        if code != 0:
            print(f"Step failed: {title} (exit={code})")
            return code
    return 0


def _build_scan_args_interactive() -> list[str]:
    _print_panel(
        "Scanner Launch Wizard",
        "This launcher builds a real Betta-Morpho scan command.\n"
        "You will choose the scan scope, speed profile, transport mode, TCP and UDP targets,\n"
        "report behavior, service-model usage, and optional verification.",
        subtitle="The goal is clarity first: every stage below maps to real scanner capabilities.",
    )
    _show_scan_scope_guide()
    scan_scope = _choose_scan_scope("1")
    for key, scope, title, description in SCAN_SCOPE_INFO:
        if scope == scan_scope:
            _print_panel(title, description)
            break

    _show_question_hint(
        "Target And Ports",
        "Target can be a single IP, CIDR, range, or comma-separated list.\n"
        "Examples:\n"
        "- 127.0.0.1\n"
        "- 192.168.8.0/24\n"
        "- 10.10.10.5-25\n"
        "- 10.10.10.5,10.10.10.6\n\n"
        "For ports, start with top20 or top100 if you are learning or validating behavior.\n"
        "Type 'all' to scan the full port range 1-65535 without typing it manually.\n"
        "To load ports from a file, use the '@' prefix (e.g. @Ports/1000.txt).\n"
        "Use larger ranges after the workflow is stable.",
    )
    target = prompt_text("Target IP / CIDR / range / comma-list", "10.10.10.5")
    _raw_ports = prompt_text("TCP ports (top1000, top100, top20, 1-1000, 22,80,443, 'all')", "top1000")
    if _raw_ports.strip().lower() == "all":
        ports = "1-65535"
    elif _raw_ports.strip().lower() == "top1000":
        ports = "@Ports/1000.txt"
    else:
        ports = _raw_ports
    udp_ports = ""
    if scan_scope in {"tcp_udp", "advanced"}:
        _print_panel(
            "UDP Ports",
            "UDP probing is targeted, not a blind full-range replacement for TCP scanning.\n"
            "Use focused ports such as 53,67,68,69,123,161,500 or type 'top1000' to use the 1000.txt file.",
        )
        _raw_udp = prompt_text("UDP ports (top1000, comma list or ranges, blank to skip)", "top1000")
        if _raw_udp.strip().lower() == "top1000":
            udp_ports = "@Ports/1000.txt"
        else:
            udp_ports = _raw_udp
    _show_question_hint(
        "Speed Choice",
        "Preset speeds are easiest for most work.\n"
        f"Use option 9 if you want exact manual throughput tuning from {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL}.\n"
        "On Windows, connect mode with x10/x15 or a high manual speed is often the fastest practical option.",
    )
    profile, speed_level = _choose_scan_runtime("4")
    _show_question_hint(
        "Transport Choice",
        "Auto mode:\n"
        "- Good default on Linux or raw-capable environments\n\n"
        "Connect-only mode:\n"
        "- Usually best on Windows\n"
        "- Often best for VPN, HTB, and app-layer banner stability",
    )
    transport_mode = _choose_transport_mode("2" if sys.platform.startswith("win") else "1")
    _show_question_hint(
        "Artifacts",
        "Scanner artifact controls probe strategy.\n"
        "Service artifact improves service naming and app-layer labels.\n"
        "If you already trained both, keep both enabled for richer reports.",
    )
    scanner_artifact = prompt_text("Scanner artifact", "artifacts/scanner_model.json")
    service_artifact_default = "artifacts/service_model.json" if (ROOT / "artifacts" / "service_model.json").exists() else ""
    use_service_model = prompt_bool(
        "Use the separate service-fingerprint model for better app-layer labels.",
        bool(service_artifact_default),
    )
    service_artifact = prompt_text("Service artifact", service_artifact_default) if use_service_model else ""
    _show_report_guide()
    report_mode = _choose_report_mode("1")
    for key, mode, title, description in REPORT_MODE_INFO:
        if mode == report_mode:
            _print_panel(title, description)
            break

    report_artifact = ""
    output_csv = ""
    html_path = ""
    if report_mode == "auto_report":
        report_artifact = prompt_text("Classifier artifact used for auto-report/classified CSV", "artifacts/snn_model.json")
    elif report_mode == "manual_output":
        output_csv = prompt_text("Result CSV output", "data/scans/manual_result.csv")
        html_path = prompt_text("Optional HTML report output (blank to skip)", "data/scans/manual_report.html")
        if prompt_bool("Run classifier on the result CSV after the scan->", True):
            report_artifact = prompt_text("Classifier artifact", "artifacts/snn_model.json")
    else:
        output_csv = prompt_text("Result CSV output", "data/scans/manual_result.csv")
        if prompt_bool("Also generate an HTML report->", False):
            html_path = prompt_text("HTML report output", "data/scans/manual_report.html")
        if prompt_bool("Run classifier on the result CSV after the scan->", False):
            report_artifact = prompt_text("Classifier artifact", "artifacts/snn_model.json")

    host_discovery_enabled = prompt_bool("Run passive hostname discovery after the scan->", report_mode == "auto_report")
    host_discovery_artifact_default = "artifacts/host_discovery_model.json" if (ROOT / "artifacts" / "host_discovery_model.json").exists() else ""
    host_discovery_artifact = ""
    host_discovery_output = ""
    host_discovery_html = ""
    if host_discovery_enabled and prompt_bool("Use the passive host-discovery model artifact for ranking->", bool(host_discovery_artifact_default)):
        host_discovery_artifact = prompt_text("Host discovery artifact", host_discovery_artifact_default or "artifacts/host_discovery_model.json")

    _show_question_hint(
        "Verification And Safety",
        "Nmap verification is separate from Betta-Morpho reporting.\n"
        "Enable it only when you want a targeted control pass against Betta-Morpho-open ports.\n"
        "For long scans, checkpoints help prevent data loss and make recovery easier.",
    )
    verify_with_nmap = prompt_bool("Run targeted Nmap verification as a separate post-scan step->", False)
    nmap_preset = "deep"
    nmap_extra = ""
    if verify_with_nmap:
        nmap_preset, nmap_extra = _choose_nmap_config()
    checkpoint_every = prompt_int("Checkpoint every N ports", 1000)
    skip_discovery = prompt_bool("Skip host discovery->", False)
    use_decoys = prompt_bool("Enable decoy packets->", False)
    advanced_options = scan_scope == "advanced" or prompt_bool("Open advanced scan options->", False)

    spoof_ttl: int | None = None
    jitter_ms = 0
    source_port: int | None = None
    retry_source_port: int | None = None
    save_weights = ""
    progress_log = ""
    active_learning_output = ""
    active_learning_threshold = 0.65
    no_classify = False
    if advanced_options:
        _print_panel(
            "Advanced Scan Options",
            "These settings are optional. They are useful when you want tighter transport control,\n"
            "explicit output paths, source-port tricks, or extra scan diagnostics.",
        )
        if prompt_bool("Override outgoing TTL->", False):
            spoof_ttl = prompt_int("TTL value", 64)
        jitter_ms = prompt_int("Max jitter between batches in milliseconds", 0)
        if prompt_bool("Bind probes to a fixed source port->", False):
            source_port = prompt_int("Source port", 53)
        if prompt_bool("Retry filtered TCP ports with a second source port->", False):
            retry_source_port = prompt_int("Retry source port", 443)
        if prompt_bool("Save adapted scanner weights after the run->", False):
            save_weights = prompt_text("Save-weights artifact", "artifacts/scanner_adapted.json")
        if prompt_bool("Write active-learning service rows to a custom file->", False):
            active_learning_output = prompt_text("Active-learning CSV", "data/scans/manual_active_learning.csv")
            active_learning_threshold = prompt_float("Active-learning confidence threshold", 0.65)
        if host_discovery_enabled and prompt_bool("Write passive hostname discovery files to custom paths->", False):
            host_discovery_output = prompt_text("Hostname CSV", "data/scans/manual_hostnames.csv")
            host_discovery_html = prompt_text("Hostname HTML report", "data/scans/manual_hostnames_report.html")
        progress_log = prompt_text("Custom progress log path (blank = auto)", "")
        no_classify = prompt_bool("Skip auto-classification even if a classifier artifact is provided->", False)

    args = [
        "scan",
        "--target", target,
        "--ports", ports,
        "--profile", profile,
        "--artifact", scanner_artifact,
        "--checkpoint-every", str(checkpoint_every),
    ]
    if speed_level is not None:
        args.extend(["--speed-level", str(speed_level)])
    if udp_ports:
        args.extend(["--ports-udp", udp_ports])
    if use_service_model and service_artifact:
        args.extend(["--service-artifact", service_artifact])
    if report_artifact and report_mode == "auto_report":
        args.extend(["--report", report_artifact])
    elif output_csv:
        args.extend(["--output", output_csv])
        if report_artifact:
            args.extend(["--report", report_artifact])
    if html_path:
        args.extend(["--html", html_path])
    if host_discovery_enabled:
        args.append("--discover-hostnames")
    if host_discovery_artifact:
        args.extend(["--host-discovery-artifact", host_discovery_artifact])
    if host_discovery_output:
        args.extend(["--host-discovery-output", host_discovery_output])
    if host_discovery_html:
        args.extend(["--host-discovery-html", host_discovery_html])
    if verify_with_nmap:
        args.append("--verify-with-nmap")
        args.extend(["--nmap-preset", nmap_preset])
        if nmap_extra:
            args.extend(["--nmap-extra", nmap_extra])
    if transport_mode == "connect":
        args.append("--connect-only")
    if skip_discovery:
        args.append("--no-discovery")
    if use_decoys:
        args.append("--decoys")
    if spoof_ttl is not None:
        args.extend(["--spoof-ttl", str(spoof_ttl)])
    if jitter_ms:
        args.extend(["--jitter-ms", str(jitter_ms)])
    if source_port is not None:
        args.extend(["--source-port", str(source_port)])
    if retry_source_port is not None:
        args.extend(["--retry-source-port", str(retry_source_port)])
    if save_weights:
        args.extend(["--save-weights", save_weights])
    if progress_log:
        args.extend(["--progress-log", progress_log])
    if active_learning_output:
        args.extend(["--active-learning-output", active_learning_output])
        args.extend(["--active-learning-threshold", str(active_learning_threshold)])
    if no_classify:
        args.append("--no-classify")
    return args


def _build_fast_start_scan_args(target: str) -> list[str]:
    return [
        "scan",
        "--target", target,
        "--ports", "1-65535",
        "--profile", "aggressive",
        "--speed-level", str(MAX_MANUAL_SPEED_LEVEL),
        "--checkpoint-every", "0",
        "--no-discovery",
        "--minimal-output",
    ]


def _build_scan_args_from_namespace(args: argparse.Namespace) -> list[str]:
    scan_args: list[str] = [
        "scan",
        "--target", args.target,
        "--ports", args.ports,
        "--profile", args.profile,
        "--checkpoint-every", str(args.checkpoint_every),
    ]
    if getattr(args, "ports_udp", ""):
        scan_args.extend(["--ports-udp", args.ports_udp])
    if getattr(args, "speed_level", None) is not None:
        scan_args.extend(["--speed-level", str(args.speed_level)])
    if getattr(args, "artifact", None):
        scan_args.extend(["--artifact", args.artifact])
    if getattr(args, "service_artifact", None):
        scan_args.extend(["--service-artifact", args.service_artifact])
    if getattr(args, "service_catalog", None):
        scan_args.extend(["--service-catalog", args.service_catalog])
    if getattr(args, "transport", "auto") == "connect":
        scan_args.append("--connect-only")
    if getattr(args, "minimal_output", False):
        scan_args.append("--minimal-output")
    if getattr(args, "decoys", False):
        scan_args.append("--decoys")
    if getattr(args, "no_discovery", False):
        scan_args.append("--no-discovery")
    if getattr(args, "output", None):
        scan_args.extend(["--output", args.output])
    if getattr(args, "html", None):
        scan_args.extend(["--html", args.html])
    if getattr(args, "report", None):
        scan_args.extend(["--report", args.report])
    if getattr(args, "discover_hostnames", False):
        scan_args.append("--discover-hostnames")
    if getattr(args, "host_discovery_artifact", None):
        scan_args.extend(["--host-discovery-artifact", args.host_discovery_artifact])
    if getattr(args, "host_discovery_output", None):
        scan_args.extend(["--host-discovery-output", args.host_discovery_output])
    if getattr(args, "host_discovery_html", None):
        scan_args.extend(["--host-discovery-html", args.host_discovery_html])
    if getattr(args, "verify_with_nmap", False):
        scan_args.append("--verify-with-nmap")
        scan_args.extend(["--nmap-preset", getattr(args, "nmap_preset", "deep")])
        nmap_extra = getattr(args, "nmap_extra", "")
        if nmap_extra:
            scan_args.extend(["--nmap-extra", nmap_extra])
    if getattr(args, "save_weights", None):
        scan_args.extend(["--save-weights", args.save_weights])
    if getattr(args, "spoof_ttl", None) is not None:
        scan_args.extend(["--spoof-ttl", str(args.spoof_ttl)])
    if getattr(args, "jitter_ms", 0):
        scan_args.extend(["--jitter-ms", str(args.jitter_ms)])
    if getattr(args, "source_port", None) is not None:
        scan_args.extend(["--source-port", str(args.source_port)])
    if getattr(args, "retry_source_port", None) is not None:
        scan_args.extend(["--retry-source-port", str(args.retry_source_port)])
    if getattr(args, "active_learning_output", None):
        scan_args.extend(["--active-learning-output", args.active_learning_output])
        scan_args.extend(["--active-learning-threshold", str(args.active_learning_threshold)])
    if getattr(args, "progress_log", None):
        scan_args.extend(["--progress-log", args.progress_log])
    if getattr(args, "no_classify", False):
        scan_args.append("--no-classify")
    return scan_args


def _guided_classifier_training() -> tuple[str, str, list[str]]:
    _print_panel(
        "Classifier Training",
        "This trains the telemetry / transport classifier SNN.\n"
        "Use it when you want better row classification and stronger classified reports.\n\n"
        "Good defaults:\n"
        "- keep trainer=auto unless you are testing backends\n"
        "- start with the default synthetic dataset\n"
        "- raise epochs only after the data pipeline looks correct",
    )
    data_path = prompt_text("Training CSV for classifier SNN", DEFAULT_DATASET)
    artifact = prompt_text("Classifier artifact output", "artifacts/snn_model.json")
    trainer = prompt_text("Trainer backend (auto/prototype/torch)", "auto")
    epochs = prompt_int("Epochs", 30)
    steps = prompt_int("TTFS steps", 12)
    return (
        "Train classifier SNN",
        "training/train.py",
        [
            "--data", data_path,
            "--artifact", artifact,
            "--trainer", trainer,
            "--epochs", str(epochs),
            "--steps", str(steps),
        ],
    )


def _guided_scanner_training() -> tuple[str, str, list[str]]:
    _print_panel(
        "Scanner Strategy Training",
        "This trains the SNN that controls Betta-Morpho scan behavior.\n"
        "Use it when you want to improve probing strategy, pacing, and profile-specific behavior.\n\n"
        "Hint:\n"
        "- choose the profile that matches your intended runtime style\n"
        "- use more scenarios for broader behavior, not just more epochs",
    )
    _show_scan_mode_guide()
    profile = _choose_scan_profile("4")
    scenarios = prompt_int("Training scenarios", 800)
    epochs = prompt_int("Epochs", 30)
    lr = str(prompt_float("Learning rate", 0.01))
    artifact = prompt_text("Scanner artifact output", "artifacts/scanner_model.json")
    seed = prompt_int("Random seed", 42)
    return (
        "Train scanner strategy SNN",
        "training/tools/scanner.py",
        [
            "train",
            "--profile", profile,
            "--scenarios", str(scenarios),
            "--epochs", str(epochs),
            "--lr", lr,
            "--artifact", artifact,
            "--seed", str(seed),
        ],
    )


def _guided_service_training() -> tuple[str, str, list[str]]:
    _print_panel(
        "Service Model Training",
        "This trains the separate service-fingerprint model from past enriched scan outputs.\n"
        "Use it when you want better service naming on unusual ports and banners.\n\n"
        "Hint:\n"
        "- use directories with real scan outputs\n"
        "- verified rows are especially valuable, so the verified-weight parameter matters",
    )
    inputs = prompt_text("Input CSV or directory for service model", "data/scans")
    artifact = prompt_text("Service model artifact output", "artifacts/service_model.json")
    verified_weight = prompt_int("Weight for Nmap-verified rows", 3)
    return (
        "Train service-fingerprint model",
        "tools/service_fingerprint.py",
        [
            "train",
            inputs,
            "--artifact", artifact,
            "--service-catalog", "artifacts/service_catalog.json",
            "--verified-weight", str(verified_weight),
        ],
    )


def _guided_host_discovery_training() -> tuple[str, str, list[str]]:
    _print_panel(
        "Passive Host Discovery Training",
        "This trains the hostname/domain ranking SNN from passive scan evidence.\n"
        "Use it when you want better prioritization of names extracted from banners, redirects, TLS certs, and other scan-side clues.\n\n"
        "Hint:\n"
        "- start with the synthetic dataset if you want a clean baseline\n"
        "- later retrain from your own curated hostname evidence exports",
    )
    data_path = prompt_text("Training CSV for passive host discovery", "data/host_discovery_synthetic.csv")
    artifact = prompt_text("Host discovery artifact output", "artifacts/host_discovery_model.json")
    trainer = prompt_text("Trainer backend (auto/prototype/torch)", "auto")
    epochs = prompt_int("Epochs", 20)
    return (
        "Train passive host-discovery SNN",
        "tools/host_discovery.py",
        [
            "train",
            "--data", data_path,
            "--artifact", artifact,
            "--trainer", trainer,
            "--epochs", str(epochs),
        ],
    )


def _project_learning_menu() -> int:
    while True:
        _print_panel(
            "Project Learning",
            "This branch explains what the project can do and what each major stage means.\n"
            "Use it when you want to understand the workflow before training or scanning.",
        )
        choice = _prompt_menu_choice(
            "Project Learning Menu",
            [
                ("1", "Full workflow overview", "How data, models, scans, reports, and verification fit together"),
                ("2", "Models guide", "Classifier SNN, scanner SNN, service model, and service catalog"),
                ("3", "Scan profiles and speed modes", "paranoid through x15, with when-to-use guidance"),
                ("4", "Transport, raw/auto, connect, UDP", "How scan transport choices affect behavior"),
                ("5", "Reports and Nmap verification", "What report mode writes and when Nmap should be enabled"),
                ("6", "Output files and artifacts", "What gets written to data/scans and artifacts"),
                ("7", "Stealth and evasion guide", "Profiles, decoys, TTL, jitter, source-port tricks, and their real limits"),
                ("8", "Engineering spec path", "Print Engineering_Draft.md location"),
                ("0", "Back", "Return to the main launcher"),
            ],
            "1",
        )
        if choice == "0":
            return 0
        if choice == "8":
            print(SPEC_PATH)
            continue
        _show_learning_topic(choice)


def _data_tools_menu() -> int:
    while True:
        _print_panel(
            "Data Tools",
            "Use this branch when you need input data, evaluation runs, or telemetry conversion.\n\n"
            "Quick guidance:\n"
            "- synthetic telemetry: fast way to generate balanced classifier data\n"
            "- golden dataset: controlled timing dataset for SNN experiments\n"
            "- replay: batch-check many historical scan files\n"
            "- PCAP/live capture: convert network traffic into project telemetry",
        )
        choice = _prompt_menu_choice(
            "Data Tools",
            [
                ("1", "Generate synthetic telemetry", "Create balanced classifier training data"),
                ("2", "Generate golden timing dataset", "Create canonical and noisy SNN timing data"),
                ("3", "Evaluate dataset", "Run classifier evaluation on one CSV"),
                ("4", "Replay dataset directory", "Batch-evaluate many CSV files"),
                ("5", "Convert PCAP to CSV", "Turn offline packets into project telemetry"),
                ("6", "Live capture to CSV", "Capture packets live and store telemetry rows"),
                ("7", "Generate passive host-discovery dataset", "Create synthetic hostname/domain ranking data"),
                ("0", "Back", "Return to the training menu"),
            ],
            "1",
        )
        if choice == "0":
            return 0
        if choice == "1":
            return run_script(
                "training/generate_synthetic_data.py",
                [
                    "--output", prompt_text("Output CSV", DEFAULT_DATASET),
                    "--samples-per-class", str(prompt_int("Samples per class", 400)),
                    "--seed", str(prompt_int("Random seed", 7)),
                    "--assets", str(prompt_int("Asset count hint", 8)),
                ],
            )
        if choice == "2":
            arguments = [
                "--golden-output", prompt_text("Golden CSV", "data/snn_training_batch.csv"),
                "--samples", str(prompt_int("Massive sample count", 100000)),
                "--seed", str(prompt_int("Random seed", 42)),
            ]
            massive_output = prompt_text("Optional massive/noisy CSV output", "data/snn_massive_dataset.csv")
            if massive_output:
                arguments.extend(["--massive-output", massive_output])
            return run_script("tools/generate_snn_golden_dataset.py", arguments)
        if choice == "3":
            arguments = [
                "--data", prompt_text("Input CSV", DEFAULT_DATASET),
                "--artifact", prompt_text("Classifier artifact", "artifacts/snn_model.json"),
                "--preview", str(prompt_int("Preview rows", 5)),
            ]
            asset_filter = prompt_text("Optional asset IP filter", "")
            if asset_filter:
                arguments.extend(["--asset-ip", asset_filter])
            return run_script("training/evaluate.py", arguments)
        if choice == "4":
            return run_script(
                "training/replay_directory.py",
                [
                    "--data-dir", prompt_text("Dataset directory", DEFAULT_REPLAY_DIR),
                    "--artifact", prompt_text("Classifier artifact", "artifacts/snn_model.json"),
                ],
            )
        if choice == "5":
            arguments = [
                "--pcap", prompt_text("Input PCAP", "data/input.pcap"),
                "--output", prompt_text("Output CSV", "data/pcap_events.csv"),
                "--timeout-us", str(prompt_int("Timeout in microseconds", 2000000)),
            ]
            asset_filter = prompt_text("Optional asset IP filter", "")
            if asset_filter:
                arguments.extend(["--asset-ip", asset_filter])
            return run_script("training/tools/pcap_to_csv.py", arguments)
        if choice == "6":
            arguments = [
                "--interface", prompt_text("Interface", "eth0"),
                "--seconds", str(prompt_int("Capture seconds", 30)),
                "--output", prompt_text("Output CSV", "data/live/live_capture.csv"),
                "--timeout-us", str(prompt_int("Timeout in microseconds", 2000000)),
            ]
            asset_filter = prompt_text("Optional asset IP filter", "")
            if asset_filter:
                arguments.extend(["--asset-ip", asset_filter])
            return run_script("training/tools/live_capture_to_csv.py", arguments)
        if choice == "7":
            return run_script(
                "tools/host_discovery.py",
                [
                    "generate-synthetic",
                    "--output", prompt_text("Output CSV", "data/host_discovery_synthetic.csv"),
                    "--samples-per-class", str(prompt_int("Samples per class", 250)),
                    "--seed", str(prompt_int("Random seed", 7)),
                ],
            )


def _model_training_menu() -> int:
    while True:
        _print_panel(
            "Model Training",
            "This branch trains the project artifacts. Use the full pipeline if you want to refresh everything,\n"
            "or train individual models when only one part needs improvement.\n\n"
            "Practical rule:\n"
            "- classifier = row labeling and classified CSVs\n"
            "- scanner = scan behavior and probe strategy\n"
            "- service model = better service names in reports\n"
            "- host discovery model = better hostname/domain ranking after scans",
        )
        choice = _prompt_menu_choice(
            "Model Training Menu",
            [
                ("1", "Full training pipeline", "Classifier SNN -> scanner SNN -> service model -> host discovery model"),
                ("2", "Train classifier SNN", "Telemetry / transport classification model"),
                ("3", "Train scanner strategy SNN", "Probe pacing and scan behavior model"),
                ("4", "Train service-fingerprint model", "Service naming and app-layer enrichment model"),
                ("5", "Train passive host-discovery SNN", "Rank discovered hostnames/domains from scan evidence"),
                ("6", "Build service catalog", "Rebuild internal normalization catalog from Nmap files"),
                ("7", "Data preparation tools", "Generate, replay, evaluate, or import datasets"),
                ("0", "Back", "Return to the main launcher"),
            ],
            "1",
        )
        if choice == "0":
            return 0
        if choice == "1":
            steps = [
                _guided_classifier_training(),
                _guided_scanner_training(),
                _guided_service_training(),
                _guided_host_discovery_training(),
            ]
            if prompt_bool("Run the full training pipeline now->", True):
                return _run_steps(steps)
            return 0
        if choice == "2":
            return _run_steps([_guided_classifier_training()])
        if choice == "3":
            return _run_steps([_guided_scanner_training()])
        if choice == "4":
            return _run_steps([_guided_service_training()])
        if choice == "5":
            return _run_steps([_guided_host_discovery_training()])
        if choice == "6":
            return run_script(
                "tools/nmap_service_catalog.py",
                [
                    "build",
                    "--output", prompt_text("Output catalog", "artifacts/service_catalog.json"),
                    "--probes", prompt_text("nmap-service-probes path", "/usr/share/nmap/nmap-service-probes"),
                    "--services", prompt_text("nmap-services path", "/usr/share/nmap/nmap-services"),
                ],
            )
        if choice == "7":
            return _data_tools_menu()


def _scanner_launch_menu() -> int:
    while True:
        _print_panel(
            "Scanner Launch",
            "This branch is for real scanning work. It now separates transport, protocol, report, and verification decisions\n"
            "so the command you run matches the behavior you actually want.\n\n"
            "Practical rule:\n"
            "- use Fast Start when you only want an IP-to-open-ports scan\n"
            "- use Guided scan launch when you want reports, UDP, verification, or custom transport\n"
            "- use Verify previous scan only when you already have a result CSV\n"
            "- lab tools are best for safe local validation",
        )
        choice = _prompt_menu_choice(
            "Scanner Launch Menu",
            [
                ("1", "Fast Start", "Only ask for IP, then scan full TCP 1-65535 with aggressive speed 300 and open-port output"),
                ("2", "Guided scan launch", "Build a scan command with TCP, UDP, transport, report, and verification choices"),
                ("3", "Verify previous scan with Nmap", "Run Nmap only against Betta-Morpho-open ports from a saved CSV"),
                ("4", "Passive hostname discovery from saved scan", "Extract and rank hostnames/domains from existing scan results"),
                ("5", "Run lab services", "Start local lab listeners for scanner practice"),
                ("6", "Exercise lab traffic", "Generate controlled traffic against local lab services"),
                ("7", "Scan ports from file (1000 ports)", "Shortcut to scan using the predefined Ports/1000.txt list"),
                ("0", "Back", "Return to the main launcher"),
            ],
            "1",
        )
        if choice == "0":
            return 0
        if choice == "1":
            target = prompt_text("Target IP", "127.0.0.1")
            return run_script("training/tools/scanner.py", _build_fast_start_scan_args(target))
        if choice == "2":
            if prompt_bool("Run the guided scan now->", True):
                return _run_steps([("Run Betta-Morpho scan", "training/tools/scanner.py", _build_scan_args_interactive())])
            return 0
        if choice == "3":
            _print_panel(
                "Verify Previous Scan With Nmap",
                "This runs Nmap only against ports Betta-Morpho found open.\n"
                "Select a preset and optionally add extra flags to customize the verification.",
            )
            scan_csv = prompt_text(
                "Betta-Morpho result CSV",
                "data/scans/latest/YYYYMMDD_HHMMSS_IP_result.csv",
            )
            nmap_preset, nmap_extra = _choose_nmap_config()
            verify_args = ["--scan-csv", scan_csv, "--nmap-preset", nmap_preset]
            if nmap_extra:
                verify_args.extend(["--nmap-extra", nmap_extra])
            return run_script("tools/verify_scan.py", verify_args)
        if choice == "7":
            _print_panel(
                "Scan Ports From File",
                "This shortcut uses Ports/1000.txt which contains structured TCP and UDP port lists.\n"
                "The SNN scanner will iterate through both protocols using its neuromorphic timing."
            )
            target = prompt_text("Target IP", "10.129.51.85")
            profile = prompt_text("Scan profile (normal/aggressive/x5/x10/x15/sneaky)", "normal")
            transport = "connect" if prompt_bool("Use Connect-only mode (safer/faster for VMs)->", True) else "auto"
            
            scan_args = [
                "scan",
                "--target", target,
                "--profile", profile,
                "--ports", "@Ports/1000.txt",
                "--ports-udp", "@Ports/1000.txt",
                "--report", "artifacts/snn_model.json",
                "--verify-with-nmap",
                "--no-discovery"
            ]
            if transport == "connect":
                scan_args.append("--connect-only")

            if prompt_bool(f"Run scan against {target} with 1000 ports file now->", True):
                return run_script("training/tools/scanner.py", scan_args)
            return 0
        if choice == "4":
            arguments = [
                "discover",
                prompt_text("Input result CSV or directory", "data/scans"),
                "--output",
                prompt_text("Hostname output CSV", "data/scans/manual_hostnames.csv"),
            ]
            artifact_default = "artifacts/host_discovery_model.json" if (ROOT / "artifacts" / "host_discovery_model.json").exists() else ""
            if prompt_bool("Use host discovery model artifact for ranking->", bool(artifact_default)):
                artifact_path = prompt_text("Host discovery artifact", artifact_default or "artifacts/host_discovery_model.json")
                if artifact_path:
                    arguments.extend(["--artifact", artifact_path])
            if prompt_bool("Also write HTML report->", True):
                arguments.extend(["--html", prompt_text("Hostname HTML report", "data/scans/manual_hostnames_report.html")])
            return run_script("tools/host_discovery.py", arguments)
        if choice == "5":
            return run_script(LAB_SERVICES_SCRIPT, ["--host", prompt_text("Host", "127.0.0.1")])
        if choice == "6":
            return run_script(
                LAB_EXERCISE_SCRIPT,
                [
                    "--host", prompt_text("Host", "127.0.0.1"),
                    "--attempts", str(prompt_int("Attempts", 8)),
                ],
            )


def interactive_menu() -> int:
    while True:
        _print_panel(
            "Betta-Morpho Guided Launcher",
            "Fast path plus three guided branches:\n"
            "4. Fast Start scan\n"
            "1. Project learning and explanations\n"
            "2. Model training\n"
            "3. Scanner launch\n\n"
            "Each branch explains what the option does before you run it.",
            subtitle=f"Python: {preferred_python()}",
        )
        selection = _prompt_menu_choice(
            "Main Workflow Menu",
            [
                ("4", "Fast Start", "Only ask for IP, then scan full TCP 1-65535 with aggressive speed 300 and open-port output"),
                ("1", "Project learning", "Overview of workflow, artifacts, reports, transport, UDP, and verification"),
                ("2", "Model training", "Train classifier, scanner, service model, host discovery model, or prepare datasets"),
                ("3", "Scanner launch", "Run guided scans, verify past scans, discover hostnames, or use lab helpers"),
                ("0", "Exit", "Close the launcher"),
            ],
            "1",
        )
        if selection == "0":
            return 0
        if selection == "1":
            _project_learning_menu()
            continue
        if selection == "2":
            _model_training_menu()
            continue
        if selection == "3":
            _scanner_launch_menu()
            continue
        if selection == "4":
            target = prompt_text("Target IP", "127.0.0.1")
            return run_script("training/tools/scanner.py", _build_fast_start_scan_args(target))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Cross-platform launcher for neuromorphic cybersecurity workflows. "
            "Supported operations are dataset generation, training, evaluation, and batch replay."
        )
    )
    subparsers = parser.add_subparsers(dest="command")

    generate = subparsers.add_parser("generate", help="Generate synthetic telemetry")
    generate.add_argument("--output", default=DEFAULT_DATASET)
    generate.add_argument("--samples-per-class", type=int, default=400)
    generate.add_argument("--seed", type=int, default=7)
    generate.add_argument("--assets", type=int, default=8)

    golden_dataset = subparsers.add_parser(
        "golden-dataset",
        help="Generate the canonical golden SNN timing dataset and an optional large noisy expansion",
    )
    golden_dataset.add_argument("--golden-output", default="data/snn_training_batch.csv")
    golden_dataset.add_argument("--massive-output", default=None)
    golden_dataset.add_argument("--samples", type=int, default=100_000)
    golden_dataset.add_argument("--seed", type=int, default=42)

    train = subparsers.add_parser("train", help="Train and export a model artifact")
    train.add_argument("--data", default=DEFAULT_DATASET)
    train.add_argument("--artifact", default="artifacts/snn_model.json")
    train.add_argument("--trainer", choices=["auto", "prototype", "torch"], default="auto")
    train.add_argument("--epochs", type=int, default=30)
    train.add_argument("--steps", type=int, default=12)
    train.add_argument("--config")
    train.add_argument("--save-config")

    dashboard = subparsers.add_parser("dashboard", help="Open the interactive workflow wizard")
    subparsers.add_parser("wizard", help="Open the guided launcher for training and scanning")

    evaluate = subparsers.add_parser("evaluate", help="Evaluate one CSV dataset")
    evaluate.add_argument("--data", default=DEFAULT_DATASET)
    evaluate.add_argument("--artifact", default="artifacts/snn_model.json")
    evaluate.add_argument("--preview", type=int, default=5)
    evaluate.add_argument("--asset-ip")

    replay = subparsers.add_parser("replay-dir", help="Evaluate all CSV files in a directory")
    replay.add_argument("--data-dir", default=DEFAULT_REPLAY_DIR)
    replay.add_argument("--artifact", default="artifacts/snn_model.json")

    discover_generate = subparsers.add_parser("discover-generate", help="Generate synthetic passive hostname-discovery training data")
    discover_generate.add_argument("--output", default="data/host_discovery_synthetic.csv")
    discover_generate.add_argument("--samples-per-class", type=int, default=250)
    discover_generate.add_argument("--seed", type=int, default=7)

    discover_train = subparsers.add_parser("discover-train", help="Train the passive hostname-discovery SNN artifact")
    discover_train.add_argument("--data", default="data/host_discovery_synthetic.csv")
    discover_train.add_argument("--artifact", default="artifacts/host_discovery_model.json")
    discover_train.add_argument("--trainer", choices=["auto", "prototype", "torch"], default="auto")
    discover_train.add_argument("--epochs", type=int, default=20)
    discover_train.add_argument("--steps", type=int, default=12)
    discover_train.add_argument("--hidden-dim", type=int, default=12)
    discover_train.add_argument("--batch-size", type=int, default=64)
    discover_train.add_argument("--learning-rate", type=float, default=0.01)
    discover_train.add_argument("--beta", type=float, default=0.82)
    discover_train.add_argument("--threshold", type=float, default=1.0)
    discover_train.add_argument("--seed", type=int, default=7)

    discover_evaluate = subparsers.add_parser("discover-evaluate", help="Evaluate the passive hostname-discovery artifact")
    discover_evaluate.add_argument("--data", default="data/host_discovery_synthetic.csv")
    discover_evaluate.add_argument("--artifact", default="artifacts/host_discovery_model.json")
    discover_evaluate.add_argument("--preview", type=int, default=5)

    discover_hostnames = subparsers.add_parser("discover-hostnames", help="Extract passive hostname/domain candidates from saved scan CSVs")
    discover_hostnames.add_argument("inputs", nargs="+", help="Result CSV files or directories")
    discover_hostnames.add_argument("--artifact", default=None)
    discover_hostnames.add_argument("--output", required=True)
    discover_hostnames.add_argument("--html", default=None)

    pcap = subparsers.add_parser("pcap-to-csv", help="Convert offline PCAP traffic to telemetry CSV")
    pcap.add_argument("--pcap", required=True)
    pcap.add_argument("--output", required=True)
    pcap.add_argument("--timeout-us", type=int, default=2_000_000)
    pcap.add_argument("--asset-ip")

    live_capture = subparsers.add_parser("live-capture", help="Capture live traffic and convert it to telemetry CSV")
    live_capture.add_argument("--interface", required=True)
    live_capture.add_argument("--seconds", type=int, default=30)
    live_capture.add_argument("--output", required=True)
    live_capture.add_argument("--timeout-us", type=int, default=2_000_000)
    live_capture.add_argument("--asset-ip")
    live_capture.add_argument("--filter", default="tcp or udp or icmp")
    live_capture.add_argument("--save-pcap")

    lab_services = subparsers.add_parser("lab-services", help="Run local lab services for practical validation")
    lab_services.add_argument("--host", default="127.0.0.1")

    lab_exercise = subparsers.add_parser("lab-exercise", help="Generate controlled traffic against local lab services")
    lab_exercise.add_argument("--host", default="127.0.0.1")
    lab_exercise.add_argument("--attempts", type=int, default=8)

    spec = subparsers.add_parser("spec", help="Print the technical specification path")
    spec.add_argument("--print-only", action="store_true")

    scan_train = subparsers.add_parser(
        "scan-train",
        help="Train SNN scanner on synthetic scan scenarios",
    )
    scan_train.add_argument("--profile", default="normal",
                            choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "x5", "x10", "x15"],
                            help="Scan mode / speed preset used to generate training scenarios")
    scan_train.add_argument("--scenarios", type=int, default=800)
    scan_train.add_argument("--epochs", type=int, default=30)
    scan_train.add_argument("--lr", type=float, default=0.01)
    scan_train.add_argument("--artifact", default="artifacts/scanner_model.json")
    scan_train.add_argument("--seed", type=int, default=42)

    scan = subparsers.add_parser(
        "scan",
        help="SNN-driven host/port scan - the neural network decides every probe",
    )
    scan.add_argument("--target", default=None,
                      help="IP / CIDR / range / comma list")
    scan.add_argument("--ports", default="top100",
                      help="top100 | top20 | 22,80 | 1-1024")
    scan.add_argument("--ports-udp", default="",
                      help="Optional UDP ports, for example 53,123,161")
    scan.add_argument("--profile", default="normal",
                      choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "x5", "x10", "x15"],
                      help="Scan mode / speed preset")
    scan.add_argument("--speed-level", type=int, default=None,
                      help=f"Manual speed override from {MIN_MANUAL_SPEED_LEVEL} to {MAX_MANUAL_SPEED_LEVEL}")
    scan.add_argument("--transport", default="auto", choices=["auto", "connect"],
                      help="Transport behavior: auto/raw-capable or connect-only")
    scan.add_argument("--minimal-output", action="store_true",
                      help="Print only open ports with minimal fields")
    scan.add_argument("--artifact", default=None,
                      help="Trained scanner artifact JSON")
    scan.add_argument("--service-artifact", default=None,
                      help="Optional separate service-fingerprint artifact JSON")
    scan.add_argument("--service-catalog", default="artifacts/service_catalog.json",
                      help="Internal service catalog artifact used for normalization")
    scan.add_argument("--decoys", action="store_true",
                      help="Send decoy packets from spoofed IPs")
    scan.add_argument("--no-discovery", action="store_true",
                      help="Skip ICMP host discovery")
    scan.add_argument("--output", default=None,
                      help="Export results to CSV")
    scan.add_argument("--html", default=None,
                      help="Optional HTML report path")
    scan.add_argument("--report", default=None,
                      help="Auto report pipeline using the provided classifier artifact")
    scan.add_argument("--discover-hostnames", action="store_true",
                      help="Run passive hostname discovery from resulting scan evidence")
    scan.add_argument("--host-discovery-artifact", default=None,
                      help="Optional passive hostname-discovery artifact JSON")
    scan.add_argument("--host-discovery-output", default=None,
                      help="Write discovered hostname candidates to PATH")
    scan.add_argument("--host-discovery-html", default=None,
                      help="Write hostname discovery HTML report to PATH")
    scan.add_argument("--verify-with-nmap", action="store_true",
                      help="Run targeted Nmap verification after the scan")
    scan.add_argument("--nmap-preset", default="deep",
                      help="Named Nmap flag preset for verification (deep/quick/stealth/scripts-only/aggressive/udp/os-detect/vuln)")
    scan.add_argument("--nmap-extra", default="",
                      help="Extra Nmap flags appended after the preset, space-separated")
    scan.add_argument("--save-weights", default=None,
                      help="Save adapted scanner weights after the run")
    scan.add_argument("--spoof-ttl", type=int, default=None,
                      help="Override outgoing IP TTL")
    scan.add_argument("--jitter-ms", type=int, default=0,
                      help="Maximum random inter-batch pause in milliseconds")
    scan.add_argument("--source-port", type=int, default=None,
                      help="Bind outgoing TCP or UDP probes to source port N")
    scan.add_argument("--retry-source-port", type=int, default=None,
                      help="Retry filtered TCP ports with source port N")
    scan.add_argument("--active-learning-output", default=None,
                      help="Write low-confidence service rows to PATH")
    scan.add_argument("--active-learning-threshold", type=float, default=0.65,
                      help="Confidence threshold for active-learning export")
    scan.add_argument("--no-classify", action="store_true",
                      help="Skip auto-classification after the scan")
    scan.add_argument("--checkpoint-every", type=int, default=1000,
                      help="Save partial CSV/HTML progress every N scanned ports")
    scan.add_argument("--progress-log", default=None,
                      help="Append scan timing progress to PATH")
    scan.add_argument("--interactive", action="store_true",
                      help="Launch interactive TUI wizard")

    verify_betta_morpho = subparsers.add_parser(
        "verify-betta-morpho",
        help="Run Nmap only against ports found open by Betta-Morpho and save a comparison",
    )
    verify_betta_morpho.add_argument("--scan-csv", required=True,
                                     help="Path to Betta-Morpho result CSV")
    verify_betta_morpho.add_argument("--target", default=None,
                                     help="Override target IP or hostname")
    verify_betta_morpho.add_argument("--output-dir", default=None,
                                     help="Directory for verification artifacts")
    verify_betta_morpho.add_argument("--service-catalog", default="artifacts/service_catalog.json",
                                     help="Internal service catalog artifact used for normalization")

    service_catalog_build = subparsers.add_parser(
        "service-catalog-build",
        help="Build the internal service-catalog artifact from local Nmap probe databases",
    )
    service_catalog_build.add_argument("--output", default="artifacts/service_catalog.json")
    service_catalog_build.add_argument("--probes", default="/usr/share/nmap/nmap-service-probes")
    service_catalog_build.add_argument("--services", default="/usr/share/nmap/nmap-services")

    service_train = subparsers.add_parser(
        "service-train",
        help="Train a separate service-fingerprint artifact from enriched Betta-Morpho result CSVs",
    )
    service_train.add_argument("inputs", nargs="+", help="Result CSV files or directories")
    service_train.add_argument("--artifact", default="artifacts/service_model.json")
    service_train.add_argument("--service-catalog", default="artifacts/service_catalog.json")
    service_train.add_argument("--verified-weight", type=int, default=3)

    service_evaluate = subparsers.add_parser(
        "service-evaluate",
        help="Evaluate the service-fingerprint artifact on enriched Betta-Morpho result CSVs",
    )
    service_evaluate.add_argument("inputs", nargs="+", help="Result CSV files or directories")
    service_evaluate.add_argument("--artifact", required=True)
    service_evaluate.add_argument("--service-catalog", default="artifacts/service_catalog.json")

    service_classify = subparsers.add_parser(
        "service-classify",
        help="Add separate service-model predictions to one Betta-Morpho result CSV",
    )
    service_classify.add_argument("--input", required=True)
    service_classify.add_argument("--artifact", required=True)
    service_classify.add_argument("--output", required=True)

    artifact_validate = subparsers.add_parser(
        "artifact-validate",
        help="Validate one Betta-Morpho artifact against the unified artifact schema",
    )
    artifact_validate.add_argument("artifact", help="Artifact JSON file")
    artifact_validate.add_argument("--expected-family", default=None, help="Optional expected artifact family")

    benchmark_scans = subparsers.add_parser(
        "benchmark-scans",
        help="Compare two scan result CSV files and optionally register the benchmark",
    )
    benchmark_scans.add_argument("--baseline-csv", required=True)
    benchmark_scans.add_argument("--candidate-csv", required=True)
    benchmark_scans.add_argument("--baseline-progress-log")
    benchmark_scans.add_argument("--candidate-progress-log")
    benchmark_scans.add_argument("--baseline-label", default="baseline")
    benchmark_scans.add_argument("--candidate-label", default="candidate")
    benchmark_scans.add_argument("--domain", default="verified_real")
    benchmark_scans.add_argument("--output")
    benchmark_scans.add_argument("--register", action="store_true")
    benchmark_scans.add_argument("--registry", default="data/experiments.db")
    benchmark_scans.add_argument("--name", default="")

    experiment_list = subparsers.add_parser(
        "experiment-list",
        help="List recent experiment and benchmark runs from the SQLite registry",
    )
    experiment_list.add_argument("--db", default="data/experiments.db")
    experiment_list.add_argument("--limit", type=int, default=20)
    experiment_list.add_argument("--kind", default=None)

    experiment_show = subparsers.add_parser(
        "experiment-show",
        help="Show one experiment with its metrics and attached artifacts",
    )
    experiment_show.add_argument("--db", default="data/experiments.db")
    experiment_show.add_argument("--id", type=int, required=True)

    domain_summary = subparsers.add_parser(
        "domain-summary",
        help="Summarize benchmark metrics by domain such as synthetic, verified_real, and replay",
    )
    domain_summary.add_argument("--registry", default="data/experiments.db")
    domain_summary.add_argument("--kind", default="benchmark")
    domain_summary.add_argument("--output")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        raise SystemExit(interactive_menu())

    if args.command == "generate":
        raise SystemExit(
            run_script(
                "training/generate_synthetic_data.py",
                [
                    "--output",
                    args.output,
                    "--samples-per-class",
                    str(args.samples_per_class),
                    "--seed",
                    str(args.seed),
                    "--assets",
                    str(args.assets),
                ],
            )
        )

    if args.command == "golden-dataset":
        arguments = ["--golden-output", args.golden_output, "--samples", str(args.samples), "--seed", str(args.seed)]
        if args.massive_output:
            arguments.extend(["--massive-output", args.massive_output])
        raise SystemExit(run_script("tools/generate_snn_golden_dataset.py", arguments))

    if args.command == "train":
        arguments = []
        if args.config:
            arguments.extend(["--config", args.config])
        if args.save_config:
            arguments.extend(["--save-config", args.save_config])
        raise SystemExit(
            run_script(
                "training/train.py",
                arguments + [
                    "--data",
                    args.data,
                    "--artifact",
                    args.artifact,
                    "--trainer",
                    args.trainer,
                    "--epochs",
                    str(args.epochs),
                    "--steps",
                    str(args.steps),
                ],
            )
        )

    if args.command in {"dashboard", "wizard"}:
        raise SystemExit(interactive_menu())

    if args.command == "evaluate":
        raise SystemExit(
            run_script(
                "training/evaluate.py",
                [
                    "--data",
                    args.data,
                    "--artifact",
                    args.artifact,
                    "--preview",
                    str(args.preview),
                ] + (["--asset-ip", args.asset_ip] if args.asset_ip else []),
            )
        )

    if args.command == "replay-dir":
        raise SystemExit(
            run_script(
                "training/replay_directory.py",
                [
                    "--data-dir",
                    args.data_dir,
                    "--artifact",
                    args.artifact,
                ],
            )
        )

    if args.command == "discover-generate":
        raise SystemExit(
            run_script(
                "tools/host_discovery.py",
                [
                    "generate-synthetic",
                    "--output",
                    args.output,
                    "--samples-per-class",
                    str(args.samples_per_class),
                    "--seed",
                    str(args.seed),
                ],
            )
        )

    if args.command == "discover-train":
        raise SystemExit(
            run_script(
                "tools/host_discovery.py",
                [
                    "train",
                    "--data",
                    args.data,
                    "--artifact",
                    args.artifact,
                    "--trainer",
                    args.trainer,
                    "--epochs",
                    str(args.epochs),
                    "--steps",
                    str(args.steps),
                    "--hidden-dim",
                    str(args.hidden_dim),
                    "--batch-size",
                    str(args.batch_size),
                    "--learning-rate",
                    str(args.learning_rate),
                    "--beta",
                    str(args.beta),
                    "--threshold",
                    str(args.threshold),
                    "--seed",
                    str(args.seed),
                ],
            )
        )

    if args.command == "discover-evaluate":
        raise SystemExit(
            run_script(
                "tools/host_discovery.py",
                [
                    "evaluate",
                    "--data",
                    args.data,
                    "--artifact",
                    args.artifact,
                    "--preview",
                    str(args.preview),
                ],
            )
        )

    if args.command == "discover-hostnames":
        discover_args = [
            "discover",
            *args.inputs,
            "--output",
            args.output,
        ]
        if args.artifact:
            discover_args.extend(["--artifact", args.artifact])
        if args.html:
            discover_args.extend(["--html", args.html])
        raise SystemExit(run_script("tools/host_discovery.py", discover_args))

    if args.command == "pcap-to-csv":
        arguments = [
            "--pcap",
            args.pcap,
            "--output",
            args.output,
            "--timeout-us",
            str(args.timeout_us),
        ]
        if args.asset_ip:
            arguments.extend(["--asset-ip", args.asset_ip])
        raise SystemExit(run_script("training/tools/pcap_to_csv.py", arguments))

    if args.command == "live-capture":
        arguments = [
            "--interface",
            args.interface,
            "--seconds",
            str(args.seconds),
            "--output",
            args.output,
            "--timeout-us",
            str(args.timeout_us),
            "--filter",
            args.filter,
        ]
        if args.asset_ip:
            arguments.extend(["--asset-ip", args.asset_ip])
        if args.save_pcap:
            arguments.extend(["--save-pcap", args.save_pcap])
        raise SystemExit(run_script("training/tools/live_capture_to_csv.py", arguments))

    if args.command == "lab-services":
        raise SystemExit(
            run_script(
                LAB_SERVICES_SCRIPT,
                [
                    "--host",
                    args.host,
                ],
            )
        )

    if args.command == "lab-exercise":
        raise SystemExit(
            run_script(
                LAB_EXERCISE_SCRIPT,
                [
                    "--host",
                    args.host,
                    "--attempts",
                    str(args.attempts),
                ],
            )
        )

    if args.command == "spec":
        print(SPEC_PATH)

    if args.command == "scan-train":
        raise SystemExit(
            run_script(
                "training/tools/scanner.py",
                [
                    "train",
                    "--profile", args.profile,
                    "--scenarios", str(args.scenarios),
                    "--epochs", str(args.epochs),
                    "--lr", str(args.lr),
                    "--artifact", args.artifact,
                    "--seed", str(args.seed),
                ],
            )
        )

    if args.command == "scan":
        if getattr(args, "interactive", False) or args.target is None:
            raise SystemExit(_scanner_launch_menu())
        raise SystemExit(run_script("training/tools/scanner.py", _build_scan_args_from_namespace(args)))

    if args.command == "verify-betta-morpho":
        verify_args = ["--scan-csv", args.scan_csv]
        if args.target:
            verify_args.extend(["--target", args.target])
        if args.output_dir:
            verify_args.extend(["--output-dir", args.output_dir])
        if args.service_catalog:
            verify_args.extend(["--service-catalog", args.service_catalog])
        raise SystemExit(run_script("tools/verify_scan.py", verify_args))

    if args.command == "service-catalog-build":
        raise SystemExit(
            run_script(
                "tools/nmap_service_catalog.py",
                [
                    "build",
                    "--output",
                    args.output,
                    "--probes",
                    args.probes,
                    "--services",
                    args.services,
                ],
            )
        )

    if args.command == "service-train":
        raise SystemExit(
            run_script(
                "tools/service_fingerprint.py",
                [
                    "train",
                    *args.inputs,
                    "--artifact",
                    args.artifact,
                    "--service-catalog",
                    args.service_catalog,
                    "--verified-weight",
                    str(args.verified_weight),
                ],
            )
        )

    if args.command == "service-evaluate":
        raise SystemExit(
            run_script(
                "tools/service_fingerprint.py",
                [
                    "evaluate",
                    *args.inputs,
                    "--artifact",
                    args.artifact,
                    "--service-catalog",
                    args.service_catalog,
                ],
            )
        )

    if args.command == "service-classify":
        raise SystemExit(
            run_script(
                "tools/service_fingerprint.py",
                [
                    "classify",
                    "--input",
                    args.input,
                    "--artifact",
                    args.artifact,
                    "--output",
                    args.output,
                ],
            )
        )

    if args.command == "artifact-validate":
        arguments = [args.artifact]
        if args.expected_family:
            arguments.extend(["--expected-family", args.expected_family])
        raise SystemExit(run_script("tools/artifact_schema.py", arguments))

    if args.command == "benchmark-scans":
        benchmark_args = [
            "--baseline-csv",
            args.baseline_csv,
            "--candidate-csv",
            args.candidate_csv,
            "--baseline-label",
            args.baseline_label,
            "--candidate-label",
            args.candidate_label,
            "--domain",
            args.domain,
            "--registry",
            args.registry,
            "--name",
            args.name,
        ]
        if args.baseline_progress_log:
            benchmark_args.extend(["--baseline-progress-log", args.baseline_progress_log])
        if args.candidate_progress_log:
            benchmark_args.extend(["--candidate-progress-log", args.candidate_progress_log])
        if args.output:
            benchmark_args.extend(["--output", args.output])
        if args.register:
            benchmark_args.append("--register")
        raise SystemExit(run_script("tools/benchmark_scans.py", benchmark_args))

    if args.command == "experiment-list":
        experiment_args = ["--db", args.db, "list", "--limit", str(args.limit)]
        if args.kind:
            experiment_args.extend(["--kind", args.kind])
        raise SystemExit(run_script("tools/experiment_registry.py", experiment_args))

    if args.command == "experiment-show":
        raise SystemExit(
            run_script(
                "tools/experiment_registry.py",
                ["--db", args.db, "show", "--id", str(args.id)],
            )
        )

    if args.command == "domain-summary":
        domain_args = ["--registry", args.registry, "--kind", args.kind]
        if args.output:
            domain_args.extend(["--output", args.output])
        raise SystemExit(run_script("tools/domain_metrics.py", domain_args))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Betta-Morpho launcher interrupted by user.")
        raise SystemExit(130)
