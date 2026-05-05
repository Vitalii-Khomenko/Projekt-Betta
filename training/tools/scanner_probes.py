#!/usr/bin/env python3
# =============================================================================
# scanner_probes.py  -  Raw and connect probe implementations for Betta-Morpho scans
# =============================================================================
# Usage:
#   python training/tools/scanner.py scan --target 10.10.10.5 [options]
#   python training/tools/scanner.py --help
#
# Key options:
#   --connect-only   Force TCP connect probes instead of raw packet probes
#   --ports-udp      Enable UDP probing alongside TCP probing
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 2.3.3
# Created : 01.04.2026
# =============================================================================
from __future__ import annotations

import ipaddress
import random
import time
from pathlib import Path
from typing import Optional

from training.tools.scanner_support import ICMP, IP, TCP, UDP, SCAPY_AVAILABLE, _print, send, sr, sr1
from training.tools.scanner_types import PortResult, SNNProfile, TOP100_PORTS, TOP20_PORTS
from training.tools.scanner_utils import _append_scan_note, _clean_probe_text, _format_probe_bytes, _normalize_result_text_fields, _recv_banner_chunks, _shannon_entropy

MIN_PORT = 1
MAX_PORT = 65535
MAX_TARGETS = 4096

try:
    import dns.exception as dns_exception
    import dns.flags as dns_flags
    import dns.message as dns_message
    import dns.query as dns_query
    import dns.rdataclass as dns_rdataclass
    import dns.rdatatype as dns_rdatatype
    import dns.rcode as dns_rcode

    DNSPYTHON_AVAILABLE = True
except ImportError:
    dns_exception = None
    dns_flags = None
    dns_message = None
    dns_query = None
    dns_rdataclass = None
    dns_rdatatype = None
    dns_rcode = None
    DNSPYTHON_AVAILABLE = False


UDP_PAYLOADS = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03", # DNS version.bind CH TXT
    123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", # NTP v4 Client
    137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01", # NetBIOS NBSTAT
    161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x13\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00", # SNMP v2c public GetRequest sysDescr
    500: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x28\x00\x00\x00\x0c\x00\x00\x00\x01\x01\x00\x00\x10", # IKEv1
    623: b"\x06\x00\xff\x0f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x81\x14", # IPMI Ping
    1194: b"\x38\x01\x00\x00\x00\x00\x00\x00\x00", # OpenVPN ping
    1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n", # SSDP
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09\x5f\x73\x65\x72\x76\x69\x63\x65\x73\x07\x5f\x64\x6e\x73\x2d\x73\x64\x04\x5f\x75\x64\x70\x05\x6c\x6f\x63\x61\x6c\x00\x00\x0c\x00\x01", # mDNS
}


def connect_probe(host: str, port: int, timeout: float = 1.0, source_port: Optional[int] = None) -> PortResult:
    import socket as sock

    _validate_port(port, "tcp")
    ts_us = int(time.time() * 1_000_000)
    t0 = time.monotonic()
    probe_host = host.strip("[]")
    is_v6 = ":" in probe_host
    try:
        if is_v6:
            stream = sock.socket(sock.AF_INET6, sock.SOCK_STREAM)
            stream.settimeout(timeout)
            if source_port is not None:
                stream.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
                stream.bind(("::", source_port, 0, 0))
            stream.connect((probe_host, port, 0, 0))
            connection = stream
        elif source_port is not None:
            stream = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            stream.settimeout(timeout)
            stream.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
            stream.bind(("", source_port))
            stream.connect((probe_host, port))
            connection = stream
        else:
            connection = sock.create_connection((probe_host, port), timeout=timeout)
        with connection as stream:
            rtt_us = (time.monotonic() - t0) * 1_000_000
            banner, payload_size = _recv_banner_chunks(stream)
            entropy = _shannon_entropy(banner.encode("utf-8", errors="replace")) if banner else 0.0
            result = PortResult(
                host,
                port,
                "open",
                "tcp",
                "SYN_ACK",
                rtt_us,
                payload_size,
                ts_us,
                banner=banner,
                response_entropy=entropy,
            )
            _normalize_result_text_fields(result)
            return result
    except ConnectionRefusedError:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        return PortResult(host, port, "closed", "tcp", "RST", rtt_us, 0, ts_us)
    except PermissionError as exc:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        return PortResult(
            host,
            port,
            "filtered",
            "tcp",
            "TIMEOUT",
            rtt_us,
            0,
            ts_us,
            technology=f"socket-error={exc.__class__.__name__}:{exc.errno}",
        )
    except (OSError, TimeoutError):
        rtt_us = (time.monotonic() - t0) * 1_000_000
        return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)


async def _async_connect_probe(host: str, port: int, timeout: float, ts_us: int) -> PortResult:
    import asyncio
    import time
    _validate_port(port, "tcp")
    t0 = time.monotonic()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        rtt_us = (time.monotonic() - t0) * 1_000_000
        from training.tools.scanner_utils import _format_probe_bytes, _shannon_entropy
        
        banner = ""
        payload_size = 0
        entropy = 0.0
        try:
            block = await asyncio.wait_for(reader.read(256), timeout=2.0)
            if block:
                banner = _format_probe_bytes(block)
                payload_size = len(block)
                entropy = _shannon_entropy(block)
        except Exception:
            pass
            
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortResult(host, port, "open", "tcp", "SYN_ACK", rtt_us, payload_size, ts_us, banner=banner, response_entropy=entropy)
    except asyncio.TimeoutError:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)
    except OSError as exc:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        flag = "RST" if "refused" in str(exc).lower() else "TIMEOUT"
        state = "closed" if flag == "RST" else "filtered"
        return PortResult(host, port, state, "tcp", flag, rtt_us, 0, ts_us)
    except Exception:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)


def async_batch_connect_probe(host: str, ports: list[int], timeout: float = 1.0) -> list[PortResult]:
    import asyncio
    import time
    ts_us = int(time.time() * 1_000_000)
    
    async def _run():
        sem = asyncio.Semaphore(max(1, len(ports)))
        async def _bounded_probe(p: int):
            async with sem:
                return await _async_connect_probe(host, p, timeout, ts_us)
                
        tasks = []
        for p in ports:
            tasks.append(asyncio.create_task(_bounded_probe(p)))
            await asyncio.sleep(0.001)
        return await asyncio.gather(*tasks)
        
    return asyncio.run(_run())


def retry_filtered_tcp_with_source_port(
    host: str,
    results: list[PortResult],
    timeout: float,
    source_port: int,
) -> tuple[int, int]:
    retried = 0
    changed = 0
    for index, original in enumerate(results):
        if original.protocol != "tcp" or original.state != "filtered":
            continue
        retried += 1
        follow_up = connect_probe(host, original.port, timeout=timeout, source_port=source_port)
        retry_note = f"retry-source-port={source_port}"
        if follow_up.state != original.state or follow_up.protocol_flag != original.protocol_flag:
            _append_scan_note(follow_up, retry_note)
            _append_scan_note(follow_up, f"initial={original.state}:{original.protocol_flag}")
            results[index] = follow_up
            changed += 1
        else:
            _append_scan_note(original, retry_note)
    return retried, changed


def _tcp_reply_matches_probe(response, host: str, source_port: int, target_port: int) -> bool:
    if response is None or not response.haslayer(TCP):  # type: ignore[operator]
        return False
    if response.haslayer(IP) and str(response[IP].src) != host:  # type: ignore[operator,index]
        return False
    tcp_layer = response[TCP]  # type: ignore[index]
    try:
        return int(getattr(tcp_layer, "sport", 0) or 0) == target_port and int(getattr(tcp_layer, "dport", 0) or 0) == source_port
    except (TypeError, ValueError):
        return False


def _tcp_flag_bits(response) -> int:
    if response is None or not response.haslayer(TCP):  # type: ignore[operator]
        return 0
    try:
        return int(response[TCP].flags)  # type: ignore[index]
    except (TypeError, ValueError):
        return 0


def _reply_matches_probe(response, host: str, source_port: int, target_port: int) -> bool:
    if response is None:
        return False
    if _tcp_reply_matches_probe(response, host, source_port, target_port):
        return True
    if response.haslayer(ICMP) and response.haslayer(IP):  # type: ignore[operator]
        return str(response[IP].src) == host  # type: ignore[index]
    return False


def _os_hint_from_response(response) -> str:
    if response is None or not response.haslayer(IP):  # type: ignore[operator]
        return ""
    ttl = response[IP].ttl  # type: ignore[index]
    if ttl <= 64:
        return "Linux/macOS"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Network"
    return "Unknown"


def syn_probe(
    host: str,
    port: int,
    profile: SNNProfile,
    decoys: Optional[list[str]] = None,
    spoof_ttl: Optional[int] = None,
) -> PortResult:
    _validate_port(port, "tcp")
    ts_us = int(time.time() * 1_000_000)
    sport = random.randint(1024, 65535)
    ttl_out = spoof_ttl if spoof_ttl is not None else profile.ttl

    if decoys:
        for decoy in decoys:
            decoy_packet = IP(dst=host, src=decoy, ttl=ttl_out) / TCP(  # type: ignore[operator]
                dport=port,
                sport=random.randint(1024, 65535),
                flags="S",
                seq=random.randint(0, 0xFFFFFFFF),
            )
            sr1(decoy_packet, timeout=0.1, verbose=0)  # type: ignore[misc]

    packet = IP(dst=host, ttl=ttl_out) / TCP(  # type: ignore[operator]
        dport=port,
        sport=sport,
        flags="S",
        seq=random.randint(0, 0xFFFFFFFF),
    )
    t0 = time.monotonic()
    response = sr1(packet, timeout=profile.probe_timeout, verbose=0)  # type: ignore[misc]
    rtt_us = (time.monotonic() - t0) * 1_000_000

    if response is None:
        return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)

    os_hint = _os_hint_from_response(response)

    if response.haslayer(TCP):  # type: ignore[operator]
        if not _tcp_reply_matches_probe(response, host, sport, port):
            return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us, os_hint=os_hint, scan_note="ignored-unmatched-tcp")
        flags = _tcp_flag_bits(response)
        payload_length = len(bytes(response[TCP].payload)) if response[TCP].payload else 0  # type: ignore[index]
        tcp_window = int(getattr(response[TCP], "window", 0) or 0)  # type: ignore[index]
        if (flags & 0x12) == 0x12:
            try:
                send(  # type: ignore[misc]
                    IP(dst=host, ttl=profile.ttl) / TCP(  # type: ignore[operator]
                        dport=port,
                        sport=sport,
                        flags="R",
                        seq=response[TCP].ack,  # type: ignore[index]
                    ),
                    verbose=0,
                )
            except (AttributeError, OSError, RuntimeError, ValueError):
                pass
            return PortResult(host, port, "open", "tcp", "SYN_ACK", rtt_us, payload_length, ts_us, os_hint=os_hint, tcp_window=tcp_window)
        if flags & 0x04:
            return PortResult(host, port, "closed", "tcp", "RST", rtt_us, payload_length, ts_us, os_hint=os_hint, tcp_window=tcp_window)

    if response.haslayer(ICMP) and response[ICMP].type == 3:  # type: ignore[operator,index]
        return PortResult(host, port, "filtered", "tcp", "ICMP_UNREACHABLE", rtt_us, 0, ts_us, os_hint=os_hint)

    return PortResult(host, port, "filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us, os_hint=os_hint)


def batch_syn_probe(
    host: str,
    ports: list[int],
    profile: SNNProfile,
    decoys: Optional[list[str]] = None,
    spoof_ttl: Optional[int] = None,
) -> list[PortResult]:
    if not ports:
        return []
    for port in ports:
        _validate_port(port, "tcp")

    ttl_out = spoof_ttl if spoof_ttl is not None else profile.ttl
    timeout = max(float(profile.probe_timeout), 1.0)
    packets = []
    ts_map: dict[int, int] = {}

    if decoys:
        decoy_packets = []
        for decoy in decoys:
            for port in ports:
                decoy_packets.append(
                    IP(dst=host, src=decoy, ttl=ttl_out) / TCP(  # type: ignore[operator]
                        dport=port,
                        sport=random.randint(1024, 65535),
                        flags="S",
                        seq=random.randint(0, 0xFFFFFFFF),
                    )
                )
        if decoy_packets:
            try:
                send(decoy_packets, verbose=0)  # type: ignore[misc]
            except (AttributeError, OSError, RuntimeError, ValueError):
                pass

    for port in ports:
        sport = random.randint(1024, 65535)
        packet = IP(dst=host, ttl=ttl_out) / TCP(  # type: ignore[operator]
            dport=port,
            sport=sport,
            flags="S",
            seq=random.randint(0, 0xFFFFFFFF),
        )
        ts_map[port] = int(time.time() * 1_000_000)
        packets.append(packet)

    try:
        answered, unanswered = sr(packets, timeout=timeout, inter=0, retry=0, verbose=0)  # type: ignore[misc]
    except (AttributeError, OSError, RuntimeError, ValueError):
        return [syn_probe(host, port, profile, decoys=None, spoof_ttl=spoof_ttl) for port in ports]

    results_by_port: dict[int, PortResult] = {}

    for sent_packet, response in answered:
        try:
            port = int(sent_packet[TCP].dport)  # type: ignore[index]
            sport = int(sent_packet[TCP].sport)  # type: ignore[index]
        except (TypeError, ValueError, KeyError, AttributeError):
            continue

        ts_us = ts_map.get(port, int(time.time() * 1_000_000))
        sent_time = float(getattr(sent_packet, "sent_time", 0.0) or 0.0)
        response_time = float(getattr(response, "time", 0.0) or 0.0)
        rtt_us = max((response_time - sent_time) * 1_000_000, 0.0) if sent_time and response_time else 0.0
        os_hint = _os_hint_from_response(response)

        if response.haslayer(TCP):  # type: ignore[operator]
            if not _tcp_reply_matches_probe(response, host, sport, port):
                continue
            flags = _tcp_flag_bits(response)
            payload_length = len(bytes(response[TCP].payload)) if response[TCP].payload else 0  # type: ignore[index]
            tcp_window = int(getattr(response[TCP], "window", 0) or 0)  # type: ignore[index]
            if (flags & 0x12) == 0x12:
                try:
                    send(  # type: ignore[misc]
                        IP(dst=host, ttl=profile.ttl) / TCP(  # type: ignore[operator]
                            dport=port,
                            sport=sport,
                            flags="R",
                            seq=response[TCP].ack,  # type: ignore[index]
                        ),
                        verbose=0,
                    )
                except (AttributeError, OSError, RuntimeError, ValueError):
                    pass
                results_by_port[port] = PortResult(
                    host, port, "open", "tcp", "SYN_ACK", rtt_us, payload_length, ts_us, os_hint=os_hint, tcp_window=tcp_window
                )
                continue
            if flags & 0x04:
                results_by_port[port] = PortResult(
                    host, port, "closed", "tcp", "RST", rtt_us, payload_length, ts_us, os_hint=os_hint, tcp_window=tcp_window
                )
                continue

        if response.haslayer(ICMP) and response[ICMP].type == 3:  # type: ignore[operator,index]
            results_by_port[port] = PortResult(host, port, "filtered", "tcp", "ICMP_UNREACHABLE", rtt_us, 0, ts_us, os_hint=os_hint)

    for sent_packet in unanswered:
        try:
            port = int(sent_packet[TCP].dport)  # type: ignore[index]
        except (TypeError, ValueError, KeyError, AttributeError):
            continue
        if port not in results_by_port:
            ts_us = ts_map.get(port, int(time.time() * 1_000_000))
            results_by_port[port] = PortResult(host, port, "filtered", "tcp", "TIMEOUT", timeout * 1_000_000, 0, ts_us)

    results: list[PortResult] = []
    for port in ports:
        result = results_by_port.get(port)
        if result is None:
            ts_us = ts_map.get(port, int(time.time() * 1_000_000))
            result = PortResult(host, port, "filtered", "tcp", "TIMEOUT", timeout * 1_000_000, 0, ts_us)
        _normalize_result_text_fields(result)
        results.append(result)
    return results


def udp_probe(host: str, port: int, profile: SNNProfile) -> PortResult:
    _validate_port(port, "udp")
    ts_us = int(time.time() * 1_000_000)
    payload = UDP_PAYLOADS.get(port, b"\x00")
    packet = IP(dst=host, ttl=profile.ttl) / UDP(dport=port) / payload  # type: ignore[operator]
    t0 = time.monotonic()
    response = sr1(packet, timeout=profile.probe_timeout, verbose=0)  # type: ignore[misc]
    rtt_us = (time.monotonic() - t0) * 1_000_000

    if response is None:
        return PortResult(host, port, "open|filtered", "udp", "TIMEOUT", rtt_us, 0, ts_us)
    if response.haslayer(UDP):  # type: ignore[operator]
        return PortResult(host, port, "open", "udp", "UDP_RESPONSE", rtt_us, len(bytes(response[UDP].payload)), ts_us)  # type: ignore[index]
    if response.haslayer(ICMP) and response[ICMP].type == 3:  # type: ignore[operator,index]
        code = response[ICMP].code  # type: ignore[index]
        state = "closed" if code == 3 else "filtered"
        return PortResult(host, port, state, "udp", "ICMP_UNREACHABLE", rtt_us, 0, ts_us)

    return PortResult(host, port, "open|filtered", "udp", "TIMEOUT", rtt_us, 0, ts_us)


def _probe_dns_version(host: str, port: int = 53, timeout: float = 2.0) -> dict[str, str]:
    if (
        not DNSPYTHON_AVAILABLE
        or dns_exception is None
        or dns_flags is None
        or dns_message is None
        or dns_query is None
        or dns_rdataclass is None
        or dns_rdatatype is None
        or dns_rcode is None
    ):
        return {}

    queries = [
        ("version.bind", dns_rdataclass.CH, dns_rdatatype.TXT),
        ("hostname.bind", dns_rdataclass.CH, dns_rdatatype.TXT),
        ("id.server", dns_rdataclass.CH, dns_rdatatype.TXT),
        (".", dns_rdataclass.IN, dns_rdatatype.NS),
    ]
    observations: list[str] = []

    for qname, qclass, qtype in queries:
        try:
            message = dns_message.make_query(qname, qtype, qclass)
            message.flags &= ~dns_flags.RD
            response = dns_query.udp(message, host, port=port, timeout=timeout, ignore_unexpected=True)
        except dns_exception.Timeout:
            continue
        except (dns_exception.DNSException, OSError) as exc:
            observations.append(f"dns-error={exc.__class__.__name__}")
            continue

        rcode_name = dns_rcode.to_text(response.rcode())
        observations.append(f"rcode={rcode_name}")

        txt_values: list[str] = []
        for answer in response.answer:
            for item in answer:
                if hasattr(item, "strings"):
                    txt_values.extend(
                        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                        for part in item.strings
                    )
                elif hasattr(item, "target"):
                    txt_values.append(str(item.target).rstrip("."))
                else:
                    txt_values.append(str(item))

        if txt_values:
            value = _clean_probe_text(" | ".join(v for v in txt_values if v), limit=160)
            detail = {
                "service": "DNS",
                "service_version": value,
                "technology": f"dns-query={qname} | rcode={rcode_name}",
            }
            if "bind" in value.lower():
                detail["cpe"] = "cpe:/a:isc:bind"
            return detail

        if qname == "." and rcode_name in {"NOERROR", "REFUSED"}:
            return {
                "service": "DNS",
                "service_version": "DNS",
                "technology": _clean_probe_text(f"dns-query=root-ns | rcode={rcode_name}", limit=160),
            }

    if observations:
        return {
            "service": "DNS",
            "service_version": "DNS",
            "technology": _clean_probe_text(" | ".join(observations), limit=160),
        }
    return {}


def udp_connect_probe(host: str, port: int, timeout: float = 2.0, source_port: Optional[int] = None) -> PortResult:
    import socket as sock

    _validate_port(port, "udp")
    ts_us = int(time.time() * 1_000_000)
    t0 = time.monotonic()
    if port == 53:
        dns_info = _probe_dns_version(host, port=port, timeout=timeout)
        if dns_info:
            rtt_us = (time.monotonic() - t0) * 1_000_000
            banner = dns_info.get("service_version", "")
            return PortResult(
                host,
                port,
                "open",
                "udp",
                "UDP_RESPONSE",
                rtt_us,
                len(banner),
                ts_us,
                banner=banner,
                service=dns_info.get("service", ""),
                service_version=dns_info.get("service_version", ""),
                technology=dns_info.get("technology", ""),
                cpe=dns_info.get("cpe", ""),
            )

    try:
        with sock.socket(sock.AF_INET, sock.SOCK_DGRAM) as probe:
            probe.settimeout(timeout)
            if source_port is not None:
                probe.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
                probe.bind(("", source_port))
            payload = UDP_PAYLOADS.get(port, b"\x00")
            probe.sendto(payload, (host, port))
            try:
                data, _ = probe.recvfrom(256)
                rtt_us = (time.monotonic() - t0) * 1_000_000
                result = PortResult(
                    host,
                    port,
                    "open",
                    "udp",
                    "UDP_RESPONSE",
                    rtt_us,
                    len(data),
                    ts_us,
                    banner=_format_probe_bytes(data, limit=120),
                )
                _normalize_result_text_fields(result)
                return result
            except sock.timeout:
                rtt_us = (time.monotonic() - t0) * 1_000_000
                return PortResult(host, port, "open|filtered", "udp", "TIMEOUT", rtt_us, 0, ts_us)
    except OSError as exc:
        rtt_us = (time.monotonic() - t0) * 1_000_000
        flag = "ICMP_UNREACHABLE" if "refused" in str(exc).lower() else "TIMEOUT"
        return PortResult(host, port, "closed", "udp", flag, rtt_us, 0, ts_us)


def raw_tcp_probe(host: str, port: int, flags: str, profile: SNNProfile) -> PortResult:
    ts_us = int(time.time() * 1_000_000)
    sport = random.randint(1024, 65535)
    packet = IP(dst=host, ttl=profile.ttl) / TCP(  # type: ignore[operator]
        dport=port,
        sport=sport,
        flags=flags,
        seq=random.randint(0, 0xFFFFFFFF),
    )
    t0 = time.monotonic()
    response = sr1(packet, timeout=profile.probe_timeout, verbose=0)  # type: ignore[misc]
    rtt_us = (time.monotonic() - t0) * 1_000_000

    if response is None:
        return PortResult(host, port, "open|filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)
    if response.haslayer(TCP) and _tcp_reply_matches_probe(response, host, sport, port):  # type: ignore[operator]
        if _tcp_flag_bits(response) & 0x04:
            return PortResult(host, port, "closed", "tcp", "RST", rtt_us, 0, ts_us, tcp_window=int(getattr(response[TCP], "window", 0) or 0))  # type: ignore[index]
        return PortResult(host, port, "open|filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)
    if response.haslayer(ICMP) and response[ICMP].type == 3:  # type: ignore[operator,index]
        return PortResult(host, port, "filtered", "tcp", "ICMP_UNREACHABLE", rtt_us, 0, ts_us)
    return PortResult(host, port, "open|filtered", "tcp", "TIMEOUT", rtt_us, 0, ts_us)


def icmp_ping(host: str, timeout: float = 2.0) -> bool:
    if not SCAPY_AVAILABLE:
        return False
    response = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=0)  # type: ignore[misc,operator]
    return response is not None


def discover_hosts(targets: list[str], timeout: float = 2.0) -> list[str]:
    _print(f"[bold cyan]Host discovery:[/] probing {len(targets)} targets ...")
    live_hosts: list[str] = []
    for host in targets:
        if icmp_ping(host, timeout):
            live_hosts.append(host)
            _print(f"  [green]UP[/]  {host}")
        else:
            _print(f"  [dim]DOWN[/] {host}")
    _print(f"  {len(live_hosts)} live host(s)\n")
    return live_hosts


def parse_targets(spec: str, max_targets: int = MAX_TARGETS) -> list[str]:
    targets: list[str] = []

    def add_target(target: str) -> None:
        if max_targets > 0 and len(targets) >= max_targets:
            raise ValueError(f"too many targets resolved from {spec!r}: limit is {max_targets}")
        targets.append(target)

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            network = ipaddress.ip_network(part, strict=False)
            if max_targets > 0 and network.num_addresses > max_targets + 2:
                raise ValueError(f"CIDR {part!r} is too large: limit is {max_targets} hosts")
            for ip in network.hosts():
                add_target(str(ip))
        elif "-" in part:
            base, _, end = part.rpartition("-")
            prefix = ".".join(base.split(".")[:-1])
            low = int(base.split(".")[-1])
            for octet in range(low, int(end) + 1):
                add_target(f"{prefix}.{octet}")
        else:
            add_target(part)
    return targets


def _validate_port(port: int, source: str) -> int:
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"invalid {source} port {port}: expected {MIN_PORT}-{MAX_PORT}")
    return port


def _parse_ports_from_file(path: Path, protocol: str = "tcp") -> list[int]:
    """Reads ports from a file, optionally filtering by protocol (TCP/UDP) headers."""
    lines = path.read_text().splitlines()
    target_proto = protocol.upper()
    current_proto = "TCP"  # Default if no header
    relevant_lines = []
    has_headers = any(line.strip().upper() in {"TCP", "UDP"} for line in lines)

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.upper() in {"TCP", "UDP"}:
            current_proto = line.upper()
            continue
        if not has_headers or current_proto == target_proto:
            relevant_lines.append(line)

    return parse_ports(",".join(relevant_lines), protocol=protocol)


def parse_ports(spec: str, protocol: str = "tcp") -> list[int]:
    """Parses a port specification string (top100, 22,80, 1-1024, or @file.txt)."""
    if spec.startswith("@"):
        return _parse_ports_from_file(Path(spec[1:]), protocol=protocol)

    lowered = spec.lower()
    if lowered in {"top100", "top-100"}:
        return list(TOP100_PORTS)
    if lowered in {"top20", "top-20"}:
        return list(TOP20_PORTS)
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            try:
                low_port = _validate_port(int(low), protocol)
                high_port = _validate_port(int(high), protocol)
                if high_port < low_port:
                    raise ValueError(f"invalid {protocol} port range {part!r}: high port is below low port")
                ports.extend(range(low_port, high_port + 1))
            except (ValueError, TypeError):
                raise
        else:
            try:
                ports.append(_validate_port(int(part), protocol))
            except (ValueError, TypeError):
                raise
    return sorted(set(ports))
