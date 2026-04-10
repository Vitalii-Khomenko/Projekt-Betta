"""
Generate controlled TCP traffic against the local Betta-Morpho lab services.

This is a lightweight companion to tools/lab_services.py. It does not label
data; it simply exercises the configured service ports so local scans and
captures have realistic traffic to observe.
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.lab_services import SERVICES

DEFAULT_PORTS = [port for port, *_ in SERVICES]
CLOSED_PORTS = [19000, 19001, 19002, 19003, 19004]


def exercise_port(host: str, port: int, timeout: float) -> tuple[str, int]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            try:
                payload = conn.recv(128)
            except socket.timeout:
                payload = b""
            elapsed_ms = int((time.monotonic() - started) * 1000)
            print(f"[open]   {host}:{port:<5} banner={len(payload):>3}B rtt={elapsed_ms}ms")
            return "open", 1
    except OSError:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        print(f"[closed] {host}:{port:<5} banner=  0B rtt={elapsed_ms}ms")
        return "closed", 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Exercise the local Betta-Morpho lab services.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--attempts", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=0.3)
    args = parser.parse_args()

    probes = DEFAULT_PORTS + CLOSED_PORTS
    open_hits = 0
    total = 0

    for attempt in range(1, args.attempts + 1):
        print(f"\nAttempt {attempt}/{args.attempts}")
        for port in probes:
            _, count = exercise_port(args.host, port, args.timeout)
            open_hits += count
            total += 1
            time.sleep(0.03)

    print(f"\nCompleted {total} probes against {args.host}; open responses={open_hits}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
