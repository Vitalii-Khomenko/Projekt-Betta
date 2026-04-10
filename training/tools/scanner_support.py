#!/usr/bin/env python3
# =============================================================================
# scanner_support.py  -  Shared scanner capability checks and optional runtime helpers
# =============================================================================
# Usage:
#   python training/tools/scanner.py scan --target 10.10.10.5 [options]
#   python training/tools/scanner.py --help
#
# Key options:
#   --connect-only   Force TCP connect probes instead of raw packet probes
#   --report PATH    Export auto-generated report artifacts after a scan
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 01.04.2026
# =============================================================================
from __future__ import annotations

import importlib.util
import logging
import os
import re
import socket as _socket
import sys
from pathlib import Path
from typing import Any

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

ICMP: Any = None
IP: Any = None
TCP: Any = None
UDP: Any = None
conf: Any = None
send: Any = None
sr: Any = None
sr1: Any = None

try:
    from scapy.all import ICMP as _SCAPY_ICMP, IP as _SCAPY_IP, TCP as _SCAPY_TCP, UDP as _SCAPY_UDP, conf as _SCAPY_CONF, send as _SCAPY_SEND, sr as _SCAPY_SR, sr1 as _SCAPY_SR1  # type: ignore

    ICMP = _SCAPY_ICMP
    IP = _SCAPY_IP
    TCP = _SCAPY_TCP
    UDP = _SCAPY_UDP
    conf = _SCAPY_CONF
    send = _SCAPY_SEND
    sr = _SCAPY_SR
    sr1 = _SCAPY_SR1

    try:
        conf.verb = 0
    except AttributeError:
        pass
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def _raw_socket_works() -> bool:
    if not SCAPY_AVAILABLE:
        return False
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_RAW, _socket.IPPROTO_TCP):
            return True
    except (AttributeError, OSError, PermissionError):
        return False


RAW_AVAILABLE = _raw_socket_works()

SMBConnection: Any = None
SMBSessionError: Any = None

try:
    from impacket.smbconnection import SMBConnection as _IMPACKET_SMBConnection  # type: ignore
    try:
        from impacket.smbconnection import SessionError as _IMPACKET_SMBSessionError  # type: ignore
    except ImportError:
        _IMPACKET_SMBSessionError = None
    SMBConnection = _IMPACKET_SMBConnection
    SMBSessionError = _IMPACKET_SMBSessionError
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

Console: Any = None
Panel: Any = None
Prompt: Any = None
Table: Any = None

try:
    from rich.console import Console as _RichConsole
    from rich.panel import Panel as _RichPanel
    from rich.prompt import Prompt as _RichPrompt
    from rich.table import Table as _RichTable

    Console = _RichConsole
    Panel = _RichPanel
    Prompt = _RichPrompt
    Table = _RichTable
    _C: Any = Console(legacy_windows=False)
    RICH = True
except ImportError:
    _C = None
    RICH = False


def _print(message: str) -> None:
    if RICH and _C is not None:
        _C.print(message)
        return
    print(re.sub(r"\[/->[^\]]+\]", "", message))


ROOT_DIR = Path(__file__).resolve().parents[2]
TOOLS_DIR = ROOT_DIR / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))


def _load_tool_module(name: str, file_name: str):
    module_path = TOOLS_DIR / file_name
    if not module_path.exists():
        raise ImportError(f"missing tool module: {module_path}")
    spec = importlib.util.spec_from_file_location(name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load module {name} from {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


try:
    _service_sigs = _load_tool_module("service_sigs", "service_sigs.py")
    detect_service = _service_sigs.detect_service
except (AttributeError, FileNotFoundError, ImportError, OSError):
    def detect_service(port: int, banner: str = "", nmap_service: str = "") -> dict[str, str]:
        raw = (banner or nmap_service).strip()
        return {"name": raw, "version": "", "display": raw}


try:
    _cve_hints = _load_tool_module("cve_hints", "cve_hints.py")
    lookup_cve_hints = _cve_hints.lookup_cve_hints
    summarize_cve_hints = _cve_hints.summarize_cve_hints
except (AttributeError, FileNotFoundError, ImportError, OSError):
    def lookup_cve_hints(
        service: str = "",
        service_version: str = "",
        technology: str = "",
        banner: str = "",
        cpe: str = "",
    ) -> list[dict[str, str]]:
        return []

    def summarize_cve_hints(hints: list[dict[str, str]]) -> str:
        return ""


try:
    _service_fp = _load_tool_module("service_fingerprint", "service_fingerprint.py")
    load_service_artifact = _service_fp.load_service_artifact
    predict_service_row = _service_fp.predict_service_row
except (AttributeError, FileNotFoundError, ImportError, OSError):
    def load_service_artifact(path: str | Path) -> dict:
        raise RuntimeError("service fingerprint support unavailable")

    def predict_service_row(artifact: dict, row: dict[str, str]) -> tuple[str, float]:
        return "", 0.0

