"""
PCAP -> Telemetry CSV Converter - training/tools/pcap_to_csv.py
===============================================================
Reads a .pcap capture file (via Scapy) and emits a labeled CSV in the Betta-Morpho
telemetry format (timestamp_us, asset_ip, target_port, protocol_flag,
inter_packet_time_us, payload_size, rtt_us, label).

Requires Scapy: pip install scapy

Key commands:
  python training/tools/pcap_to_csv.py \
      --pcap capture.pcap \
      --output data/telemetry.csv

  # Also via launcher:
  python launcher.py pcap-to-csv \
      --pcap capture.pcap \
      --output data/telemetry.csv

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

from scapy.all import ICMP, IP, TCP, UDP, PcapReader  # type: ignore[import-untyped]


@dataclass
class PendingSyn:
    timestamp_us: int
    client_ip: str
    server_ip: str
    server_port: int


@dataclass
class PendingDatagram:
    timestamp_us: int
    client_ip: str
    server_ip: str
    server_port: int


@dataclass
class PendingIcmp:
    timestamp_us: int
    client_ip: str
    server_ip: str
    identifier: int


def tcp_flag_name(flags: int) -> str | None:
    syn = (flags & 0x02) != 0
    ack = (flags & 0x10) != 0
    rst = (flags & 0x04) != 0
    if syn and ack:
        return "SYN_ACK"
    if rst:
        return "RST"
    return None


def classify_label(protocol_flag: str, rtt_us: int, timeout_us: int) -> str:
    if protocol_flag == "TIMEOUT":
        return "filtered"
    if protocol_flag == "ICMP_UNREACHABLE":
        return "filtered"
    if protocol_flag == "RST":
        return "filtered" if rtt_us > timeout_us // 4 else "delayed"
    if rtt_us > timeout_us // 3:
        return "delayed"
    return "normal"


def flush_timeouts(
    pending_tcp: dict[tuple[str, str, int], PendingSyn],
    pending_udp: dict[tuple[str, str, int], PendingDatagram],
    pending_icmp: dict[tuple[str, str, int], PendingIcmp],
    now_us: int,
    timeout_us: int,
    last_event_ts: dict[tuple[str, int], int],
    rows: list[dict[str, str]],
    asset_ip_filter: str | None,
) -> None:
    expired_tcp = [key for key, syn in pending_tcp.items() if now_us - syn.timestamp_us >= timeout_us]
    expired_udp = [key for key, datagram in pending_udp.items() if now_us - datagram.timestamp_us >= timeout_us]
    expired_icmp = [key for key, request in pending_icmp.items() if now_us - request.timestamp_us >= timeout_us]

    for key in expired_tcp:
        syn = pending_tcp.pop(key)
        append_timeout_row(rows, syn.server_ip, syn.server_port, syn.timestamp_us, timeout_us, last_event_ts, asset_ip_filter)
    for key in expired_udp:
        datagram = pending_udp.pop(key)
        append_timeout_row(rows, datagram.server_ip, datagram.server_port, datagram.timestamp_us, timeout_us, last_event_ts, asset_ip_filter)
    for key in expired_icmp:
        request = pending_icmp.pop(key)
        append_timeout_row(rows, request.server_ip, 0, request.timestamp_us, timeout_us, last_event_ts, asset_ip_filter)


def append_timeout_row(
    rows: list[dict[str, str]],
    asset_ip: str,
    target_port: int,
    sent_timestamp_us: int,
    timeout_us: int,
    last_event_ts: dict[tuple[str, int], int],
    asset_ip_filter: str | None,
) -> None:
    if asset_ip_filter and asset_ip != asset_ip_filter:
        return
    event_key = (asset_ip, target_port)
    previous_ts = last_event_ts.get(event_key, sent_timestamp_us)
    inter_packet_us = max(sent_timestamp_us - previous_ts, 0)
    last_event_ts[event_key] = sent_timestamp_us
    rows.append(
        {
            "timestamp_us": str(sent_timestamp_us + timeout_us),
            "asset_ip": asset_ip,
            "target_port": str(target_port),
            "protocol_flag": "TIMEOUT",
            "inter_packet_time_us": str(inter_packet_us),
            "payload_size": "0",
            "rtt_us": str(timeout_us),
            "label": classify_label("TIMEOUT", timeout_us, timeout_us),
        }
    )


def convert_pcap(pcap_path: Path, output_path: Path, timeout_us: int, asset_ip_filter: str | None) -> int:
    pending_tcp: dict[tuple[str, str, int], PendingSyn] = {}
    pending_udp: dict[tuple[str, str, int], PendingDatagram] = {}
    pending_icmp: dict[tuple[str, str, int], PendingIcmp] = {}
    last_event_ts: dict[tuple[str, int], int] = {}
    rows: list[dict[str, str]] = []

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP not in packet:
                continue

            ip_layer = packet[IP]
            timestamp_us = int(float(packet.time) * 1_000_000)
            flush_timeouts(pending_tcp, pending_udp, pending_icmp, timestamp_us, timeout_us, last_event_ts, rows, asset_ip_filter)

            src_ip = str(ip_layer.src)
            dst_ip = str(ip_layer.dst)
            if TCP in packet:
                tcp_layer = packet[TCP]
                flags = int(tcp_layer.flags)
                payload_size = len(bytes(tcp_layer.payload))

                if (flags & 0x02) != 0 and (flags & 0x10) == 0:
                    pending_tcp[(src_ip, dst_ip, int(tcp_layer.dport))] = PendingSyn(
                        timestamp_us=timestamp_us,
                        client_ip=src_ip,
                        server_ip=dst_ip,
                        server_port=int(tcp_layer.dport),
                    )
                    continue

                protocol_flag = tcp_flag_name(flags)
                if protocol_flag is None:
                    continue

                key = (dst_ip, src_ip, int(tcp_layer.sport))
                syn = pending_tcp.pop(key, None)
                if syn is None:
                    continue
                append_response_row(rows, syn.server_ip, syn.server_port, syn.timestamp_us, timestamp_us, payload_size, protocol_flag, timeout_us, last_event_ts, asset_ip_filter)
                continue

            if UDP in packet:
                udp_layer = packet[UDP]
                payload_size = len(bytes(udp_layer.payload))
                request_key = (src_ip, dst_ip, int(udp_layer.dport))
                response_key = (dst_ip, src_ip, int(udp_layer.sport))
                if response_key in pending_udp:
                    probe = pending_udp.pop(response_key)
                    append_response_row(rows, probe.server_ip, probe.server_port, probe.timestamp_us, timestamp_us, payload_size, "UDP_RESPONSE", timeout_us, last_event_ts, asset_ip_filter)
                    continue
                pending_udp[request_key] = PendingDatagram(
                    timestamp_us=timestamp_us,
                    client_ip=src_ip,
                    server_ip=dst_ip,
                    server_port=int(udp_layer.dport),
                )
                continue

            if ICMP in packet:
                icmp_layer = packet[ICMP]
                icmp_type = int(icmp_layer.type)
                if icmp_type == 8:
                    pending_icmp[(src_ip, dst_ip, int(getattr(icmp_layer, "id", 0)))] = PendingIcmp(
                        timestamp_us=timestamp_us,
                        client_ip=src_ip,
                        server_ip=dst_ip,
                        identifier=int(getattr(icmp_layer, "id", 0)),
                    )
                    continue
                if icmp_type == 0:
                    key = (dst_ip, src_ip, int(getattr(icmp_layer, "id", 0)))
                    request = pending_icmp.pop(key, None)
                    if request is None:
                        continue
                    payload_size = len(bytes(icmp_layer.payload))
                    append_response_row(rows, request.server_ip, 0, request.timestamp_us, timestamp_us, payload_size, "ICMP_REPLY", timeout_us, last_event_ts, asset_ip_filter)
                    continue
                if icmp_type in {3, 11} and IP in icmp_layer:
                    embedded_ip = icmp_layer[IP]
                    if TCP in embedded_ip:
                        embedded_tcp = embedded_ip[TCP]
                        key = (str(embedded_ip.src), str(embedded_ip.dst), int(embedded_tcp.dport))
                        syn = pending_tcp.pop(key, None)
                        if syn is not None:
                            append_response_row(rows, syn.server_ip, syn.server_port, syn.timestamp_us, timestamp_us, 0, "ICMP_UNREACHABLE", timeout_us, last_event_ts, asset_ip_filter)
                            continue
                    if UDP in embedded_ip:
                        embedded_udp = embedded_ip[UDP]
                        key = (str(embedded_ip.src), str(embedded_ip.dst), int(embedded_udp.dport))
                        probe = pending_udp.pop(key, None)
                        if probe is not None:
                            append_response_row(rows, probe.server_ip, probe.server_port, probe.timestamp_us, timestamp_us, 0, "ICMP_UNREACHABLE", timeout_us, last_event_ts, asset_ip_filter)
                            continue

    flush_timeouts(pending_tcp, pending_udp, pending_icmp, sys.maxsize, timeout_us, last_event_ts, rows, asset_ip_filter)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["timestamp_us", "asset_ip", "target_port", "protocol_flag", "inter_packet_time_us", "payload_size", "rtt_us", "label"],
        )
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def append_response_row(
    rows: list[dict[str, str]],
    asset_ip: str,
    target_port: int,
    request_ts_us: int,
    response_ts_us: int,
    payload_size: int,
    protocol_flag: str,
    timeout_us: int,
    last_event_ts: dict[tuple[str, int], int],
    asset_ip_filter: str | None,
) -> None:
    if asset_ip_filter and asset_ip != asset_ip_filter:
        return
    event_key = (asset_ip, target_port)
    previous_ts = last_event_ts.get(event_key, request_ts_us)
    inter_packet_us = max(response_ts_us - previous_ts, 0)
    last_event_ts[event_key] = response_ts_us
    rtt_us = max(response_ts_us - request_ts_us, 0)
    rows.append(
        {
            "timestamp_us": str(response_ts_us),
            "asset_ip": asset_ip,
            "target_port": str(target_port),
            "protocol_flag": protocol_flag,
            "inter_packet_time_us": str(inter_packet_us),
            "payload_size": str(payload_size),
            "rtt_us": str(rtt_us),
            "label": classify_label(protocol_flag, rtt_us, timeout_us),
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert offline PCAP traffic to defensive telemetry CSV.")
    parser.add_argument("--pcap", required=True, help="Input PCAP file")
    parser.add_argument("--output", required=True, help="Output CSV file")
    parser.add_argument("--timeout-us", type=int, default=2_000_000, help="Timeout threshold in microseconds for unresolved SYN events")
    parser.add_argument("--asset-ip", help="Optional asset IP filter")
    args = parser.parse_args()

    row_count = convert_pcap(Path(args.pcap), Path(args.output), args.timeout_us, args.asset_ip)
    print(f"converted_rows={row_count} output={args.output}")


if __name__ == "__main__":
    main()
