"""
Lab services - realistic TCP listeners with authentic banners.
Each port mimics a real service so Betta-Morpho banner grabbing can identify it.

Usage: python tools/lab_services.py [--host 127.0.0.1]

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import signal
import socket
import sys
import threading
import time

# (port, service_name, banner_bytes, delay_ms)
# delay_ms > 0 simulates slow / delayed services such as load balancers or tarpits.
BASE_SERVICES = [
    (21,    "FTP",           b"220 ProFTPD 1.3.6 Server (Betta-Morpho-Lab) [127.0.0.1]\r\n", 0),
    (22,    "SSH",           b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", 0),
    (25,    "SMTP",          b"220 betta-morpho-lab.local ESMTP Postfix (Ubuntu)\r\n", 0),
    (80,    "HTTP",          b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\nX-Powered-By: Betta-Morpho-Lab\r\n\r\n", 120),
    (110,   "POP3",          b"+OK POP3 server ready <betta-morpho-lab@127.0.0.1>\r\n", 0),
    (143,   "IMAP",          b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n", 0),
    (443,   "HTTPS",         b"\x16\x03\x01", 120),
    (8080,  "HTTP-Proxy",    b"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Agent: Squid/5.7\r\n\r\n", 100),
    (8443,  "HTTPS-alt",     b"\x16\x03\x03", 100),
    (1433,  "MSSQL",         b"\x04\x01\x00\x2b\x00\x00\x01\x00", 0),
    (1521,  "Oracle",        b"(DESCRIPTION=(ERR=1153)(VSNNUM=318767104))\r\n", 0),
    (2222,  "SSH-alt",       b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n", 0),
    (3306,  "MySQL",         b"\x4a\x00\x00\x00\x0a" + b"8.0.32-Betta-Morpho-Lab\x00", 0),
    (4444,  "C2/Custom",     b"", 0),
    (5432,  "PostgreSQL",    b"FATAL: password authentication required\r\n", 0),
    (5601,  "Kibana",        b"HTTP/1.1 302 Found\r\nLocation: /app/home\r\nkbn-name: kibana\r\n\r\n", 80),
    (6379,  "Redis",         b"-NOAUTH Authentication required.\r\n", 0),
    (9200,  "Elasticsearch", b'{"name":"betta-node","cluster_name":"betta-cluster"}\r\n', 0),
    (27017, "MongoDB",       b"\x3a\x00\x00\x00\x00\x00\x00\x00" + b"ismaster", 0),
    (49152, "WinRM/Custom",  b"HTTP/1.1 405 Method Not Allowed\r\nServer: Microsoft-HTTPAPI/2.0\r\n\r\n", 0),
]

EXTRA_SERVICES = [
    (1883,  "MQTT",          b"\x20\x02\x00\x00", 0),
    (5000,  "Flask-HTTP",    b"HTTP/1.1 200 OK\r\nServer: Werkzeug/3.0 Python/3.12\r\n\r\n", 40),
    (5001,  "Kestrel-HTTP",  b"HTTP/1.1 200 OK\r\nServer: Kestrel\r\n\r\n", 40),
    (5060,  "SIP",           b"SIP/2.0 200 OK\r\nServer: Asterisk PBX\r\n\r\n", 0),
    (5671,  "AMQPS",         b"AMQP\x00\x01\x00\x00", 80),
    (5672,  "AMQP",          b"AMQP\x00\x00\x09\x01", 0),
    (5900,  "VNC",           b"RFB 003.008\n", 0),
    (7001,  "WebLogic",      b"HTTP/1.1 200 OK\r\nServer: Oracle WebLogic Server 12c\r\n\r\n", 90),
    (7474,  "Neo4j",         b"HTTP/1.1 200 OK\r\nServer: Neo4j/5.18\r\n\r\n", 60),
    (8090,  "Atlassian",     b"HTTP/1.1 200 OK\r\nServer: AtlassianProxy/1.19.3.1\r\n\r\n", 60),
    (8181,  "Admin-HTTP",    b"HTTP/1.1 200 OK\r\nServer: Jetty(11.0.20)\r\n\r\n", 40),
    (8500,  "Consul",        b"HTTP/1.1 200 OK\r\nServer: Consul/1.17.2\r\n\r\n", 0),
    (9001,  "Mgmt-HTTP",     b"HTTP/1.1 200 OK\r\nServer: TornadoServer/6.4\r\n\r\n", 0),
    (9042,  "Cassandra",     b"\x84\x00\x00\x00", 0),
    (9092,  "Kafka",         b"\x00\x00\x00\x12\x00\x03\x00\x00\x00\x00\x00\x01\x00\x00", 0),
    (10000, "Webmin",        b"HTTP/1.0 200 Document follows\r\nServer: MiniServ/2.105\r\n\r\n", 0),
    (11211, "Memcached",     b"STAT pid 4242\r\nEND\r\n", 0),
    (11214, "MemcachedTLS",  b"STAT ssl true\r\nEND\r\n", 70),
    (15672, "RabbitMQ",      b"HTTP/1.1 200 OK\r\nServer: Cowboy\r\n\r\n", 0),
    (18080, "HTTP-Alt2",     b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.4\r\n\r\n", 50),
    (18081, "HTTP-Admin",    b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.25.4\r\n\r\n", 50),
    (18443, "HTTPS-Alt2",    b"\x16\x03\x03", 90),
    (20000, "Custom-App",    b"BETTA-MORPHO-CTRL READY\r\n", 0),
    (25565, "Minecraft",     b"\x0f\x00\x2f\x09localhost\x63\xdd\x01", 0),
    (61616, "ActiveMQ",      b"ActiveMQ\x00\x01", 0),
]

SERVICES = BASE_SERVICES + EXTRA_SERVICES


def serve(host: str, port: int, name: str, banner: bytes, delay_ms: int, stop: threading.Event) -> None:
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(64)
        srv.settimeout(1.0)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                if delay_ms:
                    time.sleep(delay_ms / 1000.0)
                if banner:
                    try:
                        conn.sendall(banner)
                    except OSError:
                        pass
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                continue
        srv.close()
    except OSError as exc:
        print(f"  [!] {name}:{port} - {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Betta-Morpho Lab Services with banners")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    stop = threading.Event()
    ok: list[int] = []
    fail: list[int] = []

    for port, name, banner, delay in SERVICES:
        thread = threading.Thread(target=serve, args=(args.host, port, name, banner, delay, stop), daemon=True)
        thread.start()

    time.sleep(0.4)

    for port, name, _, delay in SERVICES:
        probe = socket.socket()
        probe.settimeout(0.5)
        result = probe.connect_ex((args.host, port))
        probe.close()
        status = "OK  " if result == 0 else "FAIL"
        label = "delayed" if delay > 0 else "normal"
        line = f"  [{status}] :{port:>5}  {name:18}  label={label}"
        if result == 0:
            ok.append(port)
        else:
            fail.append(port)
        print(line)

    print(f"\n  {len(ok)}/{len(SERVICES)} listeners active on {args.host}")
    if fail:
        print(f"  Failed ports: {fail} (may already be in use by the system)")
    print("\nPress Ctrl+C to stop.\n")

    def shutdown(sig: int, frame: object) -> None:
        del sig, frame
        print("\n[*] Stopping lab services...")
        stop.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()

