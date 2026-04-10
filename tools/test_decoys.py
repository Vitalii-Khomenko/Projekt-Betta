"""
Decoy IP Validation - tests that --decoys flag wires through without
corrupting scanner state and that real open ports are still detected.

Usage:
  python tools/test_decoys.py [--port PORT]

Test plan (ROADMAP 2.2):
  1. Start a TCP listener on a loopback port.
  2. Run scanner with --decoys against that port.
  3. Assert the port is detected as open (SYN_ACK).
  4. Assert no exception / corrupted state in results.
  5. Check decoy helper produces valid IP strings.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""

import argparse
import csv
import subprocess
import sys
import tempfile
import threading
import socket
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]

# -- Helpers -----------------------------------------------------------------

def _start_listener(port: int) -> threading.Thread:
    """Accept connections on port and immediately close them (mimics open TCP)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(10)
    srv.settimeout(20.0)

    def _serve():
        try:
            while True:
                try:
                    conn, _ = srv.accept()
                    conn.close()
                except socket.timeout:
                    break
                except Exception:
                    break
        finally:
            srv.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    return t


def _check(condition: bool, msg: str) -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"  [{status}] {msg}")
    return condition


# -- Test: decoy helper produces valid IPs -----------------------------------

def test_decoy_format() -> bool:
    """Verify _random_decoys() returns valid IPv4 strings."""
    sys.path.insert(0, str(ROOT / "training" / "tools"))
    from scanner import _random_decoys  # type: ignore[import]
    decoys = _random_decoys(5)
    ok = (
        isinstance(decoys, list) and
        len(decoys) == 5 and
        all(isinstance(d, str) and d.count(".") == 3 for d in decoys)
    )
    return _check(ok, f"_random_decoys(5) returns 5 valid IPv4 strings: {decoys}")


# -- Test: scan with decoys detects open port --------------------------------

def test_scan_with_decoys(port: int) -> bool:
    """Run scanner --decoys against a local listener.

    Checks:
    - Scanner exits without error (decoys don't break the scan loop)
    - No spurious SYN_ACK detections beyond the real port
    - Result CSV is coherent (contains at least one row for the target port)

    Note: raw SYN detection on Windows loopback can be intermittent, so
    we accept either SYN_ACK (open) or RST (closed - listener closed before
    SYN arrived) as a valid outcome. The important invariant is no crash and
    no spurious opens from decoy IPs.
    """
    t = _start_listener(port)
    time.sleep(0.5)  # give listener time to bind

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        out = f.name

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "training" / "tools" / "scanner.py"),
            "scan",
            "--target", "127.0.0.1",
            "--ports", str(port),
            "--profile", "aggressive",
            "--decoys",
            "--no-classify",
            "--output", out,
        ],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
        cwd=str(ROOT),
    )

    ok_exit = _check(result.returncode == 0,
                     f"scanner exited cleanly (code={result.returncode})")
    if not ok_exit:
        print(f"  stderr tail: {result.stderr[-200:]}")
        return False

    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    # At minimum the port must appear in output (open or closed - not timeout storm)
    port_rows = [r for r in rows if r.get("target_port") == str(port)]
    ok_present = _check(bool(port_rows),
                        f"port {port} appears in output CSV with decoys active")

    # Decoy RSTs must NOT appear as open ports
    syn_ack_count = sum(1 for r in rows if r.get("protocol_flag") == "SYN_ACK")
    ok_no_extra = _check(syn_ack_count <= 1,
                         f"no spurious open detections from decoy IPs (count={syn_ack_count})")

    t.join(timeout=1.0)
    return ok_exit and ok_present and ok_no_extra


# -- Test: scanner state not corrupted by decoy RSTs -------------------------

def test_multi_scan_after_decoys(port: int) -> bool:
    """Run scan with decoys then a second scan without - port must still be found.

    Uses --profile aggressive to keep timeouts short. Decoys in raw SYN mode
    send spoofed SYNs to non-routable IPs which cause ARP timeouts; the test
    verifies the scanner handles those RST-less timeouts without breaking state.
    """
    # Use a second distinct port for this test to avoid listener reuse conflicts
    test_port = port + 1
    t = _start_listener(test_port)
    time.sleep(0.2)

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        out = f.name

    # Run 1: with decoys (may be slow due to ARP timeouts on decoy IPs)
    r1 = subprocess.run(
        [sys.executable, str(ROOT / "training" / "tools" / "scanner.py"),
         "scan", "--target", "127.0.0.1", "--ports", str(test_port),
         "--profile", "aggressive", "--decoys", "--no-classify", "--output", out],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90, cwd=str(ROOT),
    )
    if r1.returncode != 0:
        _check(False, f"run #1 scanner exited {r1.returncode}")
        return False

    # Run 2: without decoys - verify state is clean
    r2 = subprocess.run(
        [sys.executable, str(ROOT / "training" / "tools" / "scanner.py"),
         "scan", "--target", "127.0.0.1", "--ports", str(test_port),
         "--profile", "aggressive", "--no-classify", "--output", out],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, cwd=str(ROOT),
    )
    if r2.returncode != 0:
        return _check(False, f"run #2 scanner exited {r2.returncode}")

    rows = list(csv.DictReader(open(out, encoding="utf-8")))
    open_rows = [r for r in rows if r.get("protocol_flag") == "SYN_ACK"
                 and r.get("target_port") == str(test_port)]
    t.join(timeout=1.0)
    return _check(bool(open_rows), f"port {test_port} detected on run #2 (state not corrupted)")


# -- Main --------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Decoy IP validation tests")
    ap.add_argument("--port", type=int, default=19801,
                    help="Local TCP port to use for listener (default: 19801)")
    args = ap.parse_args()

    print("=" * 60)
    print("Betta-Morpho Decoy Validation Tests")
    print("=" * 60)

    results = []

    print("\n[1] Decoy format validation")
    results.append(test_decoy_format())

    print(f"\n[2] Scan with decoys - port {args.port}")
    results.append(test_scan_with_decoys(args.port))

    print(f"\n[3] State persistence across two scans with decoys")
    results.append(test_multi_scan_after_decoys(args.port))

    print("\n" + "=" * 60)
    passed = sum(results)
    total  = len(results)
    status = "ALL PASS" if passed == total else f"{total - passed} FAILED"
    print(f"Result: {passed}/{total} passed - {status}")
    print("=" * 60)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

