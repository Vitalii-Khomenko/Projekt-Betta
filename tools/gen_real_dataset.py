"""
Real Dataset Generator for Betta-Morpho classifier.

Creates three tiers of TCP services with ground-truth labels,
scans them multiple times with the Betta-Morpho scanner, and outputs
a labeled CSV for classifier retraining.

Labels:
  normal   - fast SYN-ACK (RTT < 5ms): healthy open service
  delayed  - slow SYN-ACK (RTT 80-500ms): IDS throttle / tarpit / load balancer
  filtered - connection accepted but hangs OR RST OR TIMEOUT: firewall DROP / blocked

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
import socket
import threading
import time
import random
import csv
import argparse
import sys
import os
from pathlib import Path

# -- Ground-truth tiers -------------------------------------------------------
# (port, label, delay_ms, banner)
TIER_NORMAL = [
    (19100, "normal", 0,   b"220 smtp-fast.lab\r\n"),
    (19101, "normal", 0,   b"+OK pop3-fast.lab\r\n"),
    (19102, "normal", 0,   b"SSH-2.0-OpenSSH_9.0\r\n"),
    (19103, "normal", 0,   b"HTTP/1.1 200 OK\r\nServer: nginx/1.24\r\n\r\n"),
    (19104, "normal", 0,   b"-NOAUTH Authentication required.\r\n"),  # Redis
    (19105, "normal", 0,   b'{"status":"green","cluster":"lab"}\r\n'),  # ES
    (19106, "normal", 0,   b"\x4a\x00\x00\x00\x0a8.0.35-lab\x00"),    # MySQL
    (19107, "normal", 0,   b"FATAL:  password authentication failed\r\n"),  # PG
    (19108, "normal", 2,   b"220 ftp-fast.lab\r\n"),
    (19109, "normal", 2,   b"* OK IMAP4rev1 ready\r\n"),
]

TIER_DELAYED = [
    (19200, "delayed", 90,  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nX-Tarpit: yes\r\n\r\n"),
    (19201, "delayed", 120, b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n\r\n"),
    (19202, "delayed", 150, b"SSH-2.0-OpenSSH_7.4\r\n"),
    (19203, "delayed", 200, b"220 smtp-slow.lab\r\n"),
    (19204, "delayed", 250, b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"),
    (19205, "delayed", 300, b"+OK pop3-slow\r\n"),
    (19206, "delayed", 350, b"HTTP/1.1 407 Proxy Auth\r\nProxy-Agent: Squid\r\n\r\n"),
    (19207, "delayed", 400, b'{"name":"slow-node","status":"yellow"}\r\n'),
    (19208, "delayed", 180, b"* OK [CAPABILITY IMAP4rev1] delayed\r\n"),
    (19209, "delayed", 80,  b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\n\r\n"),
]

TIER_FILTERED = [
    # Tarpit: accept connection, send nothing, hold for 2s then close
    (19300, "filtered", 2000, b""),
    (19301, "filtered", 2000, b""),
    (19302, "filtered", 2000, b""),
    (19303, "filtered", 2000, b""),
    (19304, "filtered", 2000, b""),
]

ALL_SERVICES = TIER_NORMAL + TIER_DELAYED + TIER_FILTERED
HOST = "127.0.0.1"


def serve(port: int, label: str, delay_ms: int, banner: bytes, stop: threading.Event):
    """Generic TCP listener: delay -> send banner -> close."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, port))
        srv.listen(128)
        srv.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                if delay_ms:
                    time.sleep(delay_ms / 1000.0)
                if banner:
                    try:
                        conn.sendall(banner)
                    except Exception:
                        pass
                conn.close()
            except socket.timeout:
                continue
        srv.close()
    except OSError:
        pass


def probe(port: int, timeout: float = 1.5) -> dict:
    """TCP connect probe - returns raw telemetry row."""
    ts = int(time.time() * 1_000_000)
    t0 = time.monotonic()
    try:
        with socket.create_connection((HOST, port), timeout=timeout) as s:
            rtt = (time.monotonic() - t0) * 1_000_000
            time.sleep(0.03)
            s.settimeout(0.4)
            banner = ""
            payload = 0
            try:
                raw = s.recv(256)
                banner = raw.decode("utf-8", errors="replace").strip()[:80]
                payload = len(raw)
            except Exception:
                pass
            return dict(timestamp_us=ts, asset_ip=HOST, target_port=port,
                        protocol_flag="SYN_ACK", inter_packet_time_us=0,
                        payload_size=payload, rtt_us=round(rtt, 1),
                        banner=banner)
    except ConnectionRefusedError:
        rtt = (time.monotonic() - t0) * 1_000_000
        return dict(timestamp_us=ts, asset_ip=HOST, target_port=port,
                    protocol_flag="RST", inter_packet_time_us=0,
                    payload_size=0, rtt_us=round(rtt, 1), banner="")
    except Exception:
        rtt = (time.monotonic() - t0) * 1_000_000
        return dict(timestamp_us=ts, asset_ip=HOST, target_port=port,
                    protocol_flag="TIMEOUT", inter_packet_time_us=0,
                    payload_size=0, rtt_us=round(rtt, 1), banner="")


def generate(rounds: int, output: Path) -> list[dict]:
    """
    Run `rounds` scan passes over all ports, collecting real telemetry.
    Each round adds small RTT jitter by adding random sleep between probes.
    """
    stop = threading.Event()
    print(f"[+] Starting {len(ALL_SERVICES)} lab services on {HOST}...")
    threads = []
    for port, label, delay_ms, banner in ALL_SERVICES:
        t = threading.Thread(target=serve, args=(port, label, delay_ms, banner, stop), daemon=True)
        t.start()
        threads.append(t)
    time.sleep(0.5)

    # Verify all listeners are up
    ok = sum(1 for p, *_ in ALL_SERVICES
             if socket.socket().connect_ex((HOST, p)) == 0)
    print(f"[+] {ok}/{len(ALL_SERVICES)} listeners active")

    # Build ground truth map
    gt: dict[int, str] = {port: label for port, label, *_ in ALL_SERVICES}
    # Add closed ports (RST) as filtered ground truth
    closed_ports = list(range(19400, 19410))
    for p in closed_ports:
        gt[p] = "filtered"

    all_ports = [p for p, *_ in ALL_SERVICES] + closed_ports
    rows = []

    print(f"[+] Scanning {len(all_ports)} ports x {rounds} rounds...")
    for rnd in range(1, rounds + 1):
        # Shuffle order each round for diversity
        ports_this_round = all_ports.copy()
        random.shuffle(ports_this_round)

        for port in ports_this_round:
            row = probe(port, timeout=1.5)
            row["label"] = gt[port]
            rows.append(row)
            # Small inter-probe jitter to vary inter_packet_time_us
            jitter = random.uniform(0, 3) / 1000.0
            if jitter > 0:
                time.sleep(jitter)

        # Update inter_packet_time_us based on timestamps
        if len(rows) > 1:
            for i in range(max(0, len(rows) - len(all_ports)), len(rows)):
                if i > 0:
                    rows[i]["inter_packet_time_us"] = max(0,
                        rows[i]["timestamp_us"] - rows[i-1]["timestamp_us"])

        print(f"  round {rnd}/{rounds}  collected={len(rows)}", flush=True)

    stop.set()

    # Write CSV
    fields = ["timestamp_us","asset_ip","target_port","protocol_flag",
              "inter_packet_time_us","payload_size","rtt_us","label","banner"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # Stats
    from collections import Counter
    label_c = Counter(r["label"] for r in rows)
    flag_c  = Counter(r["protocol_flag"] for r in rows)
    print(f"\n[+] Dataset saved: {output}")
    print(f"    Total rows:  {len(rows)}")
    print(f"    Labels:      {dict(label_c)}")
    print(f"    TCP flags:   {dict(flag_c)}")
    return rows


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=20,
                    help="scan passes over all ports (default 20 -> ~700 rows/class)")
    ap.add_argument("--output", default="data/real_dataset.csv")
    args = ap.parse_args()
    generate(args.rounds, Path(args.output))

