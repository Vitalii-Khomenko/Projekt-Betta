"""
Live Network Capture -> Telemetry CSV - training/tools/live_capture_to_csv.py
=============================================================================
Captures live traffic on a network interface for N seconds (via Scapy), then
converts the raw packets into the Betta-Morpho telemetry CSV format for classifier
training or offline replay.

Requires Scapy + root / CAP_NET_RAW:
  sudo pip install scapy
  # or: sudo setcap cap_net_raw+eip .venv/bin/python3

Key commands:
  python training/tools/live_capture_to_csv.py \
      --interface eth0 \
      --seconds 30 \
      --output data/live_capture.csv

  # Also via launcher:
  python launcher.py live-capture \
      --interface eth0 \
      --seconds 30

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from scapy.all import Packet, sniff, wrpcap  # type: ignore[import-untyped]

from pcap_to_csv import convert_pcap


def capture_packets(interface: str, seconds: int, packet_filter: str) -> list[Packet]:
    return list(
        sniff(
            iface=interface,
            filter=packet_filter,
            timeout=seconds,
            store=True,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture live defensive telemetry and convert it to CSV.")
    parser.add_argument("--interface", required=True, help="Capture interface name")
    parser.add_argument("--seconds", type=int, default=30, help="Capture duration in seconds")
    parser.add_argument("--output", required=True, help="Output CSV file")
    parser.add_argument("--timeout-us", type=int, default=2_000_000, help="Timeout threshold in microseconds")
    parser.add_argument("--asset-ip", help="Optional asset IP filter")
    parser.add_argument("--filter", default="tcp or udp or icmp", help="BPF filter expression")
    parser.add_argument("--save-pcap", help="Optional path to persist the captured PCAP")
    args = parser.parse_args()

    packets = capture_packets(args.interface, args.seconds, args.filter)
    if not packets:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(
            "timestamp_us,asset_ip,target_port,protocol_flag,inter_packet_time_us,payload_size,rtt_us,label\n",
            encoding="utf-8",
        )
        print(f"captured_packets=0 output={args.output}")
        return

    if args.save_pcap:
        save_path = Path(args.save_pcap)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(save_path), packets)
        pcap_path = save_path
    else:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as handle:
            pcap_path = Path(handle.name)
        wrpcap(str(pcap_path), packets)

    row_count = convert_pcap(pcap_path, Path(args.output), args.timeout_us, args.asset_ip)
    print(f"captured_packets={len(packets)} converted_rows={row_count} output={args.output}")


if __name__ == "__main__":
    main()

