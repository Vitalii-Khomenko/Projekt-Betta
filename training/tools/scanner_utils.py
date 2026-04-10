from __future__ import annotations

import math
import socket as _socket
import time

from training.tools.scanner_types import PortResult


def _append_scan_note(result: PortResult, note: str) -> None:
    note = note.strip()
    if not note:
        return
    if result.scan_note:
        existing = {part.strip() for part in result.scan_note.split("|") if part.strip()}
        if note in existing:
            return
        result.scan_note = f"{result.scan_note} | {note}"
        return
    result.scan_note = note


def _shannon_entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts: dict[int, int] = {}
    for byte in payload:
        counts[byte] = counts.get(byte, 0) + 1
    total = len(payload)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _update_entropy_from_text(result: PortResult, text: str) -> None:
    if not text:
        return
    entropy = _shannon_entropy(text.encode("utf-8", errors="replace"))
    result.response_entropy = max(result.response_entropy, entropy)


def _is_binary_payload(payload: bytes) -> bool:
    if not payload:
        return False
    if b"\x00" in payload:
        return True
    printable = sum(1 for byte in payload if 32 <= byte < 127 or byte in {9, 10, 13})
    return (printable / len(payload)) < 0.85


def _hex_preview(payload: bytes, limit: int = 160) -> str:
    preview_bytes = payload[: max(1, min(len(payload), max(8, (limit - 4) // 2)))]
    text = f"hex:{preview_bytes.hex()}"
    if len(preview_bytes) < len(payload):
        text += "..."
    return text[:limit]


def _clean_probe_text(value: str, limit: int = 160, fallback: str = "") -> str:
    raw = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    cleaned_chars: list[str] = []
    suspicious = False
    for char in raw:
        if char == "\ufffd":
            suspicious = True
            continue
        if char.isprintable():
            cleaned_chars.append(char)
        else:
            suspicious = True
            cleaned_chars.append(" ")
    text = " ".join("".join(cleaned_chars).split())
    if not text:
        return fallback[:limit]
    if suspicious and fallback:
        return fallback[:limit]
    return text[:limit]


def _format_probe_bytes(payload: bytes, limit: int = 160) -> str:
    if not payload:
        return ""
    if _is_binary_payload(payload):
        return _hex_preview(payload, limit=limit)
    try:
        decoded = payload.decode("utf-8")
    except UnicodeDecodeError:
        return _hex_preview(payload, limit=limit)
    cleaned = _clean_probe_text(decoded, limit=limit)
    if not cleaned:
        return _hex_preview(payload, limit=limit)
    return cleaned


def _normalize_result_text_fields(result: PortResult) -> None:
    result.banner = _clean_probe_text(result.banner, limit=120, fallback="binary-banner" if result.banner else "")
    result.os_hint = _clean_probe_text(result.os_hint, limit=80)
    result.service = _clean_probe_text(result.service, limit=120, fallback="unknown-service" if result.service else "")
    result.service_version = _clean_probe_text(result.service_version, limit=160, fallback=result.service)
    result.technology = _clean_probe_text(result.technology, limit=180)
    result.cpe = _clean_probe_text(result.cpe, limit=120)
    result.cve_hint = _clean_probe_text(result.cve_hint, limit=160)
    result.service_prediction = _clean_probe_text(result.service_prediction, limit=120)
    result.scan_note = _clean_probe_text(result.scan_note, limit=180)


def _recv_banner_chunks(
    sock: _socket.socket,
    initial_wait: float = 0.05,
    read_timeout: float = 0.6,
    max_total_wait: float = 2.0,
) -> tuple[str, int]:
    deadline = time.monotonic() + max_total_wait
    chunks: list[bytes] = []
    if initial_wait > 0:
        time.sleep(initial_wait)
    while time.monotonic() < deadline:
        remaining = max(0.05, min(read_timeout, deadline - time.monotonic()))
        try:
            sock.settimeout(remaining)
            block = sock.recv(256)
        except TimeoutError:
            if chunks:
                break
            continue
        except OSError:
            break
        if not block:
            break
        chunks.append(block)
        payload = b"".join(chunks)
        if b"\n" in block or len(payload) >= 256:
            break
    if not chunks:
        return "", 0
    payload = b"".join(chunks)
    return _format_probe_bytes(payload), len(payload)
