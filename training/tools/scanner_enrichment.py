# =============================================================================
# scanner_enrichment.py  -  Protocol enrichment helpers for Betta-Morpho scans
# =============================================================================
# Usage:
#   python training/tools/scanner.py scan --target 10.10.10.5 [options]
#   python training/tools/scanner.py --help
#
# Key options:
#   --report PATH    Export enriched report artifacts after a scan
#   --ports SPEC     Scan ports, then enrich the discovered services
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.5
# =============================================================================
from __future__ import annotations

import csv
import re
import shutil
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    from ldap3 import ANONYMOUS as _LDAP_ANONYMOUS, BASE as _LDAP_BASE, Connection as _LDAPConnection, Server as _LDAPServer, Tls as _LDAPTls  # type: ignore
    from ldap3.core.exceptions import LDAPBindError as _LDAPBindError, LDAPExceptionError as _LDAPExceptionError, LDAPSocketOpenError as _LDAPSocketOpenError  # type: ignore
except ImportError:
    _LDAP_ANONYMOUS = None
    _LDAP_BASE = None
    _LDAPConnection = None
    _LDAPServer = None
    _LDAPTls = None
    _LDAPBindError = None
    _LDAPExceptionError = None
    _LDAPSocketOpenError = None

from training.tools.scanner_support import (
    IMPACKET_AVAILABLE,
    SMBConnection,
    SMBSessionError,
    _print,
    detect_service,
    lookup_cve_hints,
    predict_service_row,
    summarize_cve_hints,
)
from training.tools.scanner_types import PortResult
from training.tools.scanner_utils import _clean_probe_text, _format_probe_bytes, _normalize_result_text_fields, _update_entropy_from_text

try:
    from impacket.nmb import NetBIOSError as _IMPACKET_NetBIOSError  # type: ignore
except ImportError:
    _IMPACKET_NetBIOSError = None

NetBIOSError = _IMPACKET_NetBIOSError
LDAP_ANONYMOUS = _LDAP_ANONYMOUS
LDAP_BASE = _LDAP_BASE
LDAPConnection = _LDAPConnection
LDAPServer = _LDAPServer
LDAPTls = _LDAPTls
LDAPBindError = _LDAPBindError
LDAPExceptionError = _LDAPExceptionError
LDAPSocketOpenError = _LDAPSocketOpenError
LDAP_AVAILABLE = LDAPConnection is not None and LDAPServer is not None and LDAP_BASE is not None and LDAP_ANONYMOUS is not None

_HTTP_PORTS = {80, 81, 443, 591, 593, 5985, 8000, 8008, 8080, 8081, 8443, 8843, 8880, 8888, 9000, 9443}
_HTTPS_PORTS = {443, 5986, 8443, 8843, 9443}
_TLS_PORTS = {443, 465, 587, 636, 993, 995, 3269, 5986, 8443, 8843, 9443}
_SMTP_PORTS = {25, 465, 587, 2525}
_FTP_PORTS = {21, 2121}
_POP3_PORTS = {110, 995}
_IMAP_PORTS = {143, 993}
_LDAP_PORTS = {389, 636, 3268, 3269}
_LDAP_TLS_PORTS = {636, 3269}
_SMB_PORTS = {139, 445}
_RPC_HTTP_PORTS = {593}
_REDIS_PORTS = {6379, 6380}
_AD_CONTEXT_PORTS = {53, 88, 135, 139, 389, 445, 464, 593, 636, 2179, 3268, 3269, 3389, 5985, 9389}
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_CURL_BIN = shutil.which("curl")
_GENERIC_SERVICE_NAMES = {"ftp", "smtp", "http", "https", "pop3", "imap", "smb", "ssh", "dns"}
_SMB_DIALECT_NAMES = {
    "NT LM 0.12": "SMBv1",
    514: "SMB 2.0.2",
    528: "SMB 2.1",
    768: "SMB 3.0",
    785: "SMB 3.1.1",
}


def _canonical_service_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _should_http_probe(result: PortResult) -> bool:
    if result.protocol != "tcp" or result.state != "open":
        return False
    if result.port in _HTTP_PORTS:
        return True
    banner_lower = result.banner.lower()
    return any(token in banner_lower for token in ("http", "html", "server:", "https", "ssl"))


def _candidate_http_schemes(result: PortResult) -> list[str]:
    banner_lower = result.banner.lower()
    if result.port in _HTTPS_PORTS or any(token in banner_lower for token in ("https", "ssl", "tls")):
        return ["https", "http"]
    return ["http", "https"]


def _parse_http_payload(payload: str) -> tuple[str, str]:
    text = payload.replace("\r\n", "\n")
    blocks = text.split("\n\n")
    header_blocks: list[str] = []
    index = 0
    while index < len(blocks) and blocks[index].startswith("HTTP/"):
        header_blocks.append(blocks[index])
        index += 1
    headers = header_blocks[-1] if header_blocks else ""
    body = "\n\n".join(blocks[index:]) if index < len(blocks) else ""
    return headers, body


def _curl_http_probe(host: str, port: int, scheme: str, timeout: float = 4.0) -> dict[str, str]:
    if _CURL_BIN is None:
        return {}

    command = [
        _CURL_BIN,
        "-k",
        "-sS",
        "-L",
        "--max-time",
        str(max(1, int(timeout))),
        "--connect-timeout",
        "2",
        "-D",
        "-",
        f"{scheme}://{host}:{port}/",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 1.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return {}

    payload = completed.stdout or ""
    if not payload:
        return {}

    headers, body = _parse_http_payload(payload)
    header_lines = [line.strip() for line in headers.splitlines() if line.strip()]
    status = ""
    if header_lines:
        match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", header_lines[0])
        if match:
            status = match.group(1)

    server = ""
    location = ""
    for line in header_lines[1:]:
        if line.lower().startswith("server:"):
            server = line.split(":", 1)[1].strip()
            continue
        if line.lower().startswith("location:"):
            location = line.split(":", 1)[1].strip()

    title = ""
    title_match = _TITLE_RE.search(body[:4096])
    if title_match:
        title = _clean_probe_text(title_match.group(1), limit=80)

    if not any((status, server, title, location)):
        return {}

    return {
        "scheme": scheme.upper(),
        "status": status,
        "server": _clean_probe_text(server, limit=120),
        "title": title,
        "location": _clean_probe_text(location, limit=180),
    }


def _populate_service_metadata(result: PortResult) -> None:
    detected = detect_service(result.port, banner=result.banner)
    result.service = result.service or detected.get("name", "")
    result.service_version = result.service_version or detected.get("display", "")
    result.cpe = result.cpe or detected.get("cpe", "")


def _ldap_attr_text(attributes: dict[str, object], key: str, limit: int = 120) -> str:
    value = attributes.get(key)
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value if str(item).strip()]
        return _clean_probe_text(", ".join(items), limit=limit)
    return _clean_probe_text(str(value or ""), limit=limit)


def _probe_ldap_directory(result: PortResult, timeout: float = 3.0) -> dict[str, str]:
    if not LDAP_AVAILABLE or result.port not in _LDAP_PORTS or LDAPServer is None or LDAPConnection is None or LDAP_BASE is None:
        return {}

    import ssl

    use_tls = result.port in _LDAP_TLS_PORTS
    ldap_timeout = max(1, int(timeout))
    ldap_errors = tuple(
        exc
        for exc in (AttributeError, OSError, TimeoutError, TypeError, ValueError, struct.error, LDAPBindError, LDAPExceptionError, LDAPSocketOpenError)
        if exc is not None
    )
    connection = None
    try:
        tls_config = LDAPTls(validate=ssl.CERT_NONE) if use_tls and LDAPTls is not None else None
        server = LDAPServer(
            result.host,
            port=result.port,
            connect_timeout=ldap_timeout,
            use_ssl=use_tls,
            tls=tls_config,
            get_info='NO_INFO',
        )
        connection = LDAPConnection(server, authentication=LDAP_ANONYMOUS, receive_timeout=ldap_timeout)
        connection.open()
        if not connection.bind():
            return {}
        if not connection.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=LDAP_BASE,
            attributes=[
                "defaultNamingContext",
                "rootDomainNamingContext",
                "dnsHostName",
                "supportedLDAPVersion",
                "isGlobalCatalogReady",
                "vendorName",
                "vendorVersion",
            ],
        ):
            return {}
        if not connection.entries:
            return {}

        entry = connection.entries[0]
        attributes = getattr(entry, "entry_attributes_as_dict", {}) or {}
        default_naming_context = _ldap_attr_text(attributes, "defaultNamingContext", limit=100)
        root_domain_context = _ldap_attr_text(attributes, "rootDomainNamingContext", limit=100)
        dns_host_name = _ldap_attr_text(attributes, "dnsHostName", limit=100)
        ldap_versions = _ldap_attr_text(attributes, "supportedLDAPVersion", limit=40)
        vendor_name = _ldap_attr_text(attributes, "vendorName", limit=60)
        vendor_version = _ldap_attr_text(attributes, "vendorVersion", limit=40)
        global_catalog_ready = _ldap_attr_text(attributes, "isGlobalCatalogReady", limit=12).upper() == "TRUE"
        is_global_catalog = result.port in {3268, 3269} or global_catalog_ready
        active_directory_like = bool(default_naming_context.startswith("DC=") or root_domain_context.startswith("DC=") or dns_host_name)

        if result.port in {3268, 3269}:
            service = "globalcatLDAPssl" if use_tls else "globalcatLDAP"
            service_version = "Microsoft Windows Active Directory Global Catalog" + (" over TLS" if use_tls else "")
        elif use_tls:
            service = "ldapssl"
            service_version = "Microsoft Windows Active Directory LDAPS" if active_directory_like else "LDAPS"
        else:
            service = "ldap"
            service_version = "Microsoft Windows Active Directory LDAP" if active_directory_like else "LDAP"

        summary_parts = [
            "ldap-probe=ok",
            f"host={dns_host_name}" if dns_host_name else "",
            f"naming={default_naming_context or root_domain_context}" if (default_naming_context or root_domain_context) else "",
            f"versions={ldap_versions}" if ldap_versions else "",
            "gc=TRUE" if is_global_catalog else "",
            f"vendor={vendor_name} {vendor_version}".strip() if vendor_name or vendor_version else "",
        ]
        return {
            "service": service,
            "service_version": service_version,
            "technology": _clean_probe_text(" | ".join(part for part in summary_parts if part), limit=180),
            "cpe": "cpe:/o:microsoft:windows" if active_directory_like else "",
        }
    except ldap_errors:
        return {}
    finally:
        if connection is not None:
            try:
                connection.unbind()
            except ldap_errors:
                pass


def _socket_roundtrip(
    host: str,
    port: int,
    payload: bytes,
    timeout: float = 2.0,
    use_tls: bool = False,
    preserve_initial: bool = False,
) -> str:
    import socket as sock
    import ssl

    try:
        with sock.create_connection((host, port), timeout=timeout) as raw_sock:
            raw_sock.settimeout(timeout)
            connection = raw_sock
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                connection = context.wrap_socket(raw_sock, server_hostname=host)
                connection.settimeout(timeout)
            initial_response = b""
            try:
                initial_response = connection.recv(256)
            except (OSError, TimeoutError, ssl.SSLError):
                pass
            connection.sendall(payload)
            response = b""
            try:
                response = connection.recv(512)
            except (OSError, TimeoutError, ssl.SSLError):
                response = b""
            combined = response
            if preserve_initial:
                combined = initial_response + (b" | " + response if initial_response and response else response)
                if not combined:
                    combined = initial_response
            return _format_probe_bytes(combined, limit=150)
    except (OSError, TimeoutError, ssl.SSLError, ValueError):
        return ""


def _probe_tls_certificate(host: str, port: int, timeout: float = 3.0) -> dict[str, str]:
    import socket as sock
    import ssl

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with sock.create_connection((host, port), timeout=timeout) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                tls_version = str(tls_sock.version() or "")
                cipher_info = tls_sock.cipher() or ("", "", 0)
    except (OSError, TimeoutError, ssl.SSLError, ValueError):
        return {}

    if not cert:
        return {}

    def _flatten_name(name_parts: object) -> str:
        if not isinstance(name_parts, (list, tuple)):
            return ""
        items: list[str] = []
        for part in name_parts or []:
            if not isinstance(part, (list, tuple)):
                continue
            for key, value in part:
                if key in {"commonName", "organizationName"} and value:
                    items.append(value)
        return ", ".join(items[:2])

    return {
        "subject": _clean_probe_text(_flatten_name(cert.get("subject", [])), limit=100),
        "issuer": _clean_probe_text(_flatten_name(cert.get("issuer", [])), limit=100),
        "san": _clean_probe_text(
            ", ".join(
                str(item[1]).strip()
                for item in cert.get("subjectAltName", [])
                if isinstance(item, tuple) and len(item) == 2 and str(item[0]).lower() == "dns"
            )[:180],
            limit=180,
        ),
        "tls_version": _clean_probe_text(tls_version, limit=40),
        "cipher": _clean_probe_text(str(cipher_info[0] or ""), limit=80),
    }


def _format_smb_dialect(dialect: object) -> str:
    if isinstance(dialect, bytes):
        dialect = dialect.decode("utf-8", errors="replace")
    return _SMB_DIALECT_NAMES.get(dialect, str(dialect or "").strip())


def _probe_smb(result: PortResult, timeout: float = 3.0) -> dict[str, str]:
    if not IMPACKET_AVAILABLE or SMBConnection is None:
        return {}

    remote_name = result.host if result.port == 445 else "*SMBSERVER"
    connection = None
    auth_note = ""
    login_errors = tuple(exc for exc in (OSError, TimeoutError, SMBSessionError, NetBIOSError) if exc is not None)
    session_errors = tuple(
        exc for exc in (AttributeError, OSError, RuntimeError, TimeoutError, SMBSessionError, NetBIOSError) if exc is not None
    )
    try:
        connection = SMBConnection(
            remoteName=remote_name,
            remoteHost=result.host,
            sess_port=result.port,
            timeout=max(2, int(timeout)),
        )
        try:
            connection.login("", "")
            auth_note = "auth=anonymous"
        except login_errors as exc:
            auth_note = f"auth=denied:{exc.__class__.__name__}"

        dialect = _clean_probe_text(_format_smb_dialect(connection.getDialect()), limit=40)
        server_os = _clean_probe_text(str(connection.getServerOS() or ""), limit=80)
        server_name = _clean_probe_text(str(connection.getServerName() or ""), limit=80)
        server_domain = _clean_probe_text(str(connection.getServerDomain() or ""), limit=80)
        summary_parts = [
            "smb-probe=ok",
            f"dialect={dialect}" if dialect else "",
            f"os={server_os}" if server_os else "",
            f"server={server_name}" if server_name else "",
            f"domain={server_domain}" if server_domain else "",
            auth_note,
        ]
        technology = _clean_probe_text(" | ".join(part for part in summary_parts if part), limit=180)
        evidence = " ".join(
            part for part in (server_os, server_name, server_domain, result.banner, result.technology) if part
        ).lower()

        if "samba" in evidence or "smbd" in evidence:
            version = "Samba"
            version_match = re.search(r"samba(?:[/ |_:-]+(\d+(?:\.\d+)+(?:-[^\s|]+)?))", evidence, re.IGNORECASE)
            if version_match:
                version = f"Samba {version_match.group(1)}"
            elif dialect:
                version = f"Samba ({dialect})"
            return {
                "service": "Samba",
                "service_version": version,
                "technology": technology,
                "cpe": "cpe:/a:samba:samba",
            }

        service = "Microsoft Windows netbios-ssn" if result.port == 139 and "windows" in evidence else "SMB"
        service_version = f"{service} ({dialect})".strip() if dialect else service
        cpe = "cpe:/o:microsoft:windows" if "windows" in evidence or result.port == 139 else ""
        return {
            "service": service,
            "service_version": service_version,
            "technology": technology,
            "cpe": cpe,
        }
    except session_errors:
        return {}
    finally:
        if connection is not None:
            try:
                connection.close()
            except (AttributeError, OSError):
                pass


def _probe_rpc_over_http(result: PortResult, timeout: float = 3.0) -> dict[str, str]:
    if result.port not in _RPC_HTTP_PORTS:
        return {}

    payload = f"OPTIONS / HTTP/1.0\r\nHost: {result.host}\r\n\r\n".encode("ascii", errors="ignore")
    response = _socket_roundtrip(result.host, result.port, payload, timeout=timeout, preserve_initial=True)
    if not response:
        return {}

    lowered = response.lower()
    if "ncacn_http" in lowered:
        return {
            "service": "ncacn_http",
            "service_version": "Microsoft Windows RPC over HTTP 1.0",
            "technology": _clean_probe_text(f"rpc-http-probe=ok | {response}", limit=180),
            "cpe": "cpe:/o:microsoft:windows",
        }
    if "http" in lowered or "rpc" in lowered:
        return {
            "service": "http-rpc-epmap",
            "service_version": "RPC over HTTP",
            "technology": _clean_probe_text(f"rpc-http-probe=ok | {response}", limit=180),
            "cpe": "cpe:/o:microsoft:windows",
        }
    return {}


def _protocol_probe(result: PortResult) -> dict[str, str]:
    text = " ".join(part for part in (result.service, result.service_version, result.banner, result.technology) if part).lower()

    if result.port in _SMB_PORTS or any(token in text for token in ("smb", "netbios", "samba")):
        smb_details = _probe_smb(result)
        if smb_details:
            return smb_details

    if result.port in _LDAP_PORTS or any(token in text for token in ("ldap", "globalcat", "ldaps")):
        ldap_details = _probe_ldap_directory(result)
        if ldap_details:
            return ldap_details

    if result.port in _RPC_HTTP_PORTS or any(token in text for token in ("rpc over http", "http-rpc-epmap", "ncacn_http")):
        rpc_http_details = _probe_rpc_over_http(result)
        if rpc_http_details:
            return rpc_http_details

    if result.port in _SMTP_PORTS or any(token in text for token in ("smtp", "esmtp")):
        response = _socket_roundtrip(result.host, result.port, b"EHLO betta-morpho.local\r\nQUIT\r\n", use_tls=result.port == 465)
        return {"service": "SMTP", "technology": _clean_probe_text(response, limit=150)} if response else {}

    if result.port in _FTP_PORTS or "ftp" in text:
        response = _socket_roundtrip(result.host, result.port, b"FEAT\r\nQUIT\r\n")
        return {"service": "FTP", "technology": _clean_probe_text(response, limit=150)} if response else {}

    if result.port in _POP3_PORTS or "pop3" in text:
        response = _socket_roundtrip(result.host, result.port, b"CAPA\r\nQUIT\r\n", use_tls=result.port == 995)
        combined = " | ".join(part for part in (result.banner, response) if part)
        if combined:
            lowered = combined.lower()
            service = "Dovecot POP3" if "dovecot" in lowered else "Courier POP3" if "courier" in lowered else "POP3"
            return {"service": service, "service_version": service, "technology": _clean_probe_text(combined, limit=150)}

    if result.port in _IMAP_PORTS or "imap" in text:
        response = _socket_roundtrip(result.host, result.port, b"a001 CAPABILITY\r\na002 LOGOUT\r\n", use_tls=result.port == 993)
        combined = " | ".join(part for part in (result.banner, response) if part)
        if combined:
            lowered = combined.lower()
            service = "Dovecot IMAP" if "dovecot" in lowered else "Courier IMAP" if "courier" in lowered else "IMAP"
            return {"service": service, "service_version": service, "technology": _clean_probe_text(combined, limit=150)}

    if result.port in _REDIS_PORTS or "redis" in text:
        response = _socket_roundtrip(result.host, result.port, b"*1\r\n$4\r\nPING\r\n")
        return {"service": "Redis", "technology": _clean_probe_text(response, limit=150)} if response else {}

    return {}


def _apply_cve_hints(result: PortResult) -> None:
    hints = lookup_cve_hints(
        service=result.service,
        service_version=result.service_version,
        technology=result.technology,
        banner=result.banner,
        cpe=result.cpe,
    )
    result.cve_hint = summarize_cve_hints(hints)


def _apply_service_prediction(result: PortResult, service_artifact: dict | None) -> None:
    if not service_artifact:
        return
    prediction, confidence = predict_service_row(
        service_artifact,
        {
            "target_port": str(result.port),
            "service": result.service,
            "service_version": result.service_version,
            "technology": result.technology,
            "banner": result.banner,
        },
    )
    service_key = _canonical_service_name(result.service)
    prediction_key = _canonical_service_name(prediction)

    # Keep the report clean when the rule-based pipeline already identified a
    # specific service and the model only has a weak contradictory opinion.
    if (
        prediction
        and service_key
        and service_key != prediction_key
        and service_key not in _GENERIC_SERVICE_NAMES
        and confidence < 0.80
    ):
        return
    if prediction and confidence < 0.20:
        return

    result.service_prediction = prediction
    result.service_confidence = confidence
    if prediction and not result.service:
        result.service = prediction
        result.service_version = result.service_version or prediction
    if prediction and confidence >= 0.55:
        model_note = f"model={prediction} ({confidence:.2f})"
        if model_note not in result.technology:
            result.technology = _clean_probe_text(" | ".join(part for part in (result.technology, model_note) if part), limit=180)


def export_active_learning_rows(results: list[PortResult], path: Path, threshold: float = 0.65) -> int:
    fieldnames = [
        "asset_ip",
        "target_port",
        "protocol_flag",
        "service",
        "service_version",
        "technology",
        "banner",
        "service_prediction",
        "service_confidence",
        "response_entropy",
        "tcp_window",
        "scan_note",
    ]
    rows = []
    for result in results:
        if result.protocol_flag != "SYN_ACK" or not result.service_prediction or result.service_confidence >= threshold:
            continue
        service_key = _canonical_service_name(result.service)
        prediction_key = _canonical_service_name(result.service_prediction)
        if service_key and service_key == prediction_key:
            continue
        if service_key and service_key not in _GENERIC_SERVICE_NAMES:
            continue
        rows.append(
            {
                "asset_ip": result.host,
                "target_port": result.port,
                "protocol_flag": result.protocol_flag,
                "service": result.service,
                "service_version": result.service_version,
                "technology": result.technology,
                "banner": result.banner,
                "service_prediction": result.service_prediction,
                "service_confidence": f"{result.service_confidence:.3f}",
                "response_entropy": f"{result.response_entropy:.3f}",
                "tcp_window": result.tcp_window,
                "scan_note": result.scan_note,
            }
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    _print(f"[bold green]Active learning export:[/] {path} ({len(rows)} rows)")
    return len(rows)


def _apply_host_context_enrichment(results: list[PortResult]) -> None:
    if not results:
        return
    open_ports = {result.port for result in results if result.state == "open"}
    host_service_text = " ".join(
        part.lower()
        for result in results
        for part in (result.os_hint, result.service, result.service_version, result.banner, result.technology)
        if part
    )
    linux_markers = ("apache", "dovecot", "courier", "ubuntu", "debian", "linux", "samba")
    windows_markers = ("windows", "for_windows", "microsoft windows rpc", "microsoft-httpapi", "winrm")
    linux_like = any(token in host_service_text for token in linux_markers)
    windows_like = any(token in host_service_text for token in windows_markers)
    active_directory_like = windows_like and len(open_ports & _AD_CONTEXT_PORTS) >= 4
    for result in results:
        if result.port not in _SMB_PORTS or result.state != "open":
            if active_directory_like and result.state == "open":
                if result.port == 88:
                    result.service = result.service or "kerberos-sec"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows Kerberos"
                elif result.port == 389:
                    result.service = result.service or "ldap"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows Active Directory LDAP"
                elif result.port == 464:
                    result.service = result.service or "kpasswd5"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Kerberos password change"
                elif result.port == 593:
                    result.service = result.service or "http-rpc-epmap"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows RPC over HTTP 1.0"
                elif result.port == 636:
                    result.service = result.service or "ldapssl"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows Active Directory LDAPS"
                elif result.port == 2179:
                    result.service = result.service or "vmrdp"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft RDP for virtual machines"
                elif result.port == 3268:
                    result.service = result.service or "globalcatLDAP"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows Active Directory Global Catalog"
                elif result.port == 3269:
                    result.service = result.service or "globalcatLDAPssl"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Microsoft Windows Active Directory Global Catalog over TLS"
                elif result.port == 9389:
                    result.service = result.service or "adws"
                    if not result.service_version or result.service_version.lower() == result.service.lower():
                        result.service_version = "Active Directory Web Services"
                elif result.port >= 49152 and not result.service:
                    result.service = "Microsoft Windows RPC"
                    result.service_version = "Microsoft Windows RPC"
                if result.port in {88, 389, 464, 593, 636, 2179, 3268, 3269, 9389}:
                    result.cpe = result.cpe or "cpe:/o:microsoft:windows"
                    if "host-context=activedirectory" not in result.technology.lower():
                        result.technology = _clean_probe_text(
                            " | ".join(part for part in (result.technology, "host-context=ActiveDirectory") if part),
                            limit=180,
                        )
                elif result.port >= 49152 and result.service.startswith("Microsoft Windows RPC"):
                    result.cpe = result.cpe or "cpe:/o:microsoft:windows"
                    if "host-context=winephemeralrpc" not in result.technology.lower():
                        result.technology = _clean_probe_text(
                            " | ".join(part for part in (result.technology, "host-context=WinEphemeralRPC") if part),
                            limit=180,
                        )
            continue
        if "smb-probe=ok" in result.technology.lower():
            continue
        if linux_like and not windows_like:
            if result.port == 139:
                result.service = "Samba"
                if not result.service_version or result.service_version in {"Microsoft Windows netbios-ssn", "SMB"}:
                    result.service_version = "Samba netbios-ssn"
            else:
                result.service = "Samba"
                if not result.service_version or result.service_version in {"Microsoft Windows netbios-ssn", "SMB"}:
                    result.service_version = "Samba SMB"
            if not result.cpe:
                result.cpe = "cpe:/a:samba:samba"
            if "samba" not in result.technology.lower():
                result.technology = _clean_probe_text(" | ".join(part for part in (result.technology, "host-context=Samba") if part), limit=180)


def enrich_port_results(results: list[PortResult], service_artifact: dict | None = None) -> None:
    open_tcp = [result for result in results if result.state == "open" and result.protocol == "tcp"]
    if not open_tcp:
        return

    for result in open_tcp:
        _populate_service_metadata(result)

    def _probe(result: PortResult) -> PortResult:
        if _should_http_probe(result) and _CURL_BIN is not None:
            for scheme in _candidate_http_schemes(result):
                http_data = _curl_http_probe(result.host, result.port, scheme)
                if not http_data:
                    continue
                combined_hint = " ".join(
                    part
                    for part in (result.banner, http_data.get("server", ""), http_data.get("title", ""), http_data.get("scheme", ""))
                    if part
                )
                detected = detect_service(result.port, banner=combined_hint)
                result.service = detected.get("name", "") or http_data.get("scheme", "")
                result.service_version = detected.get("display", "") or http_data.get("server", "") or http_data.get("scheme", "")
                result.cpe = detected.get("cpe", "") or result.cpe
                summary_parts = []
                if http_data.get("status"):
                    summary_parts.append(f"{http_data['scheme']} {http_data['status']}")
                if http_data.get("server"):
                    summary_parts.append(http_data["server"])
                if http_data.get("title"):
                    summary_parts.append(f"title={http_data['title']}")
                if http_data.get("location"):
                    summary_parts.append(f"location={http_data['location']}")
                result.technology = _clean_probe_text(" | ".join(summary_parts), limit=180)
                if not result.banner and summary_parts:
                    result.banner = _clean_probe_text(" | ".join(summary_parts), limit=120)
                    result.payload_size = max(result.payload_size, len(result.banner))
                break

        protocol_details = _protocol_probe(result)
        if protocol_details.get("service") and (not result.service or result.service in {"POP3", "IMAP", "SMB", "Microsoft Windows netbios-ssn"}):
            result.service = protocol_details["service"]
        if protocol_details.get("service_version"):
            result.service_version = protocol_details["service_version"]
        if protocol_details.get("technology"):
            result.technology = _clean_probe_text(" | ".join(part for part in (result.technology, protocol_details["technology"]) if part), limit=180)
        if protocol_details.get("cpe"):
            result.cpe = protocol_details["cpe"]

        if result.port in _TLS_PORTS or result.service in {"HTTPS", "IMAPS", "POP3S"}:
            cert = _probe_tls_certificate(result.host, result.port)
            if cert.get("subject") or cert.get("issuer") or cert.get("san") or cert.get("tls_version") or cert.get("cipher"):
                cert_summary = " | ".join(
                    part
                    for part in (
                        f"tls={cert['tls_version']}" if cert.get("tls_version") else "",
                        f"cipher={cert['cipher']}" if cert.get("cipher") else "",
                        f"cert={cert['subject']}" if cert.get("subject") else "",
                        f"san={cert['san']}" if cert.get("san") else "",
                        f"issuer={cert['issuer']}" if cert.get("issuer") else "",
                    )
                    if part
                )
                result.technology = _clean_probe_text(" | ".join(part for part in (result.technology, cert_summary) if part), limit=180)

        _update_entropy_from_text(result, result.banner)
        _update_entropy_from_text(result, result.technology)
        _populate_service_metadata(result)
        _apply_cve_hints(result)
        _apply_service_prediction(result, service_artifact)
        _normalize_result_text_fields(result)
        return result

    with ThreadPoolExecutor(max_workers=min(16, len(open_tcp))) as pool:
        open_tcp[:] = list(pool.map(_probe, open_tcp))
    _apply_host_context_enrichment(open_tcp)
    for result in open_tcp:
        _normalize_result_text_fields(result)
