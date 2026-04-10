"""
Service Banner Signatures - tools/service_sigs.py
=================================================
Regex-based banner detection library. detect_service(banner) returns a
(service_name, version) tuple by matching known protocol signatures against
raw TCP banner strings collected during a scan.

Also integrates with nmap_service_catalog.py to enrich matches with product
names from the Nmap probes database.

Not called directly - imported by tools/service_fingerprint.py and
training/tools/scanner.py.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import re

try:
    from tools.nmap_service_catalog import lookup_product
except ImportError:
    from nmap_service_catalog import lookup_product


def _catalog_cpe(catalog: dict[str, object]) -> str:
    cpe = str(catalog.get("cpe", "")).strip()
    if cpe:
        return cpe
    cpes_value = catalog.get("cpes")
    if isinstance(cpes_value, list) and cpes_value:
        return str(cpes_value[0]).strip()
    return ""


_HEX_BANNER_RE = re.compile(r"^hex:([0-9a-f]+)(?:\.\.\.)?$", re.IGNORECASE)


_PORT_HINTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "Microsoft Windows RPC",
    139: "Microsoft Windows netbios-ssn",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    903: "VMware Authentication Daemon",
    913: "VMware Authentication Daemon",
    993: "IMAPS",
    1433: "Microsoft SQL Server",
    1521: "Oracle TNS",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5040: "Microsoft HTTPAPI",
    5357: "Microsoft HTTPAPI",
    5432: "PostgreSQL",
    5671: "AMQPS",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    61616: "ActiveMQ",
    6379: "Redis",
    7680: "Delivery Optimization",
    8080: "HTTP",
    8443: "HTTPS",
    8500: "Consul",
    8843: "HTTPS",
    8880: "HTTP",
    9001: "Tornado",
    9042: "Cassandra",
    9092: "Kafka",
    9200: "Elasticsearch",
    10000: "Webmin",
    11211: "Memcached",
    11214: "Memcached",
    15672: "RabbitMQ",
    18443: "HTTPS",
    20000: "Betta-Morpho Control",
    25565: "Minecraft",
    27017: "MongoDB",
    47001: "WinRM-HTTP",
    49152: "Microsoft HTTPAPI",
    49664: "Microsoft Windows RPC",
    49665: "Microsoft Windows RPC",
    49666: "Microsoft Windows RPC",
    49667: "Microsoft Windows RPC",
    49668: "Microsoft Windows RPC",
    49669: "Microsoft Windows RPC",
    49670: "Microsoft Windows RPC",
}

_SIGNATURES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"msrpc|microsoft windows rpc", re.IGNORECASE), "Microsoft Windows RPC"),
    (re.compile(r"netbios-ssn|microsoft windows netbios-ssn", re.IGNORECASE), "Microsoft Windows netbios-ssn"),
    (re.compile(r"ms-sql-s|microsoft sql server|sql server", re.IGNORECASE), "Microsoft SQL Server"),
    (re.compile(r"samba(?:[/ |:-]+(\d+(?:\.\d+)+(?:-[^.\s|]+)?))?|smbd", re.IGNORECASE), "Samba"),
    (re.compile(r"dovecot\s+pop3d|dovecot.*pop3|pop3.*dovecot", re.IGNORECASE), "Dovecot POP3"),
    (re.compile(r"dovecot\s+imapd|dovecot.*imap|imap.*dovecot", re.IGNORECASE), "Dovecot IMAP"),
    (re.compile(r"courier\s+pop3|courier-pop3|pop3.*courier", re.IGNORECASE), "Courier POP3"),
    (re.compile(r"courier\s+imap|courier-imap|imap4rev1.*courier|imap.*courier", re.IGNORECASE), "Courier IMAP"),
    (re.compile(r"microsoft-ds|smb|samba", re.IGNORECASE), "SMB"),
    (re.compile(r"openssh(?:[_ /|-]+(\d+(?:\.\d+)*(?:p\d+)?))?", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"apache tomcat(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Apache Tomcat"),
    (re.compile(r"apache(?: httpd)?(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Apache httpd"),
    (re.compile(r"nginx(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "nginx"),
    (re.compile(r"microsoft-iis(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"caddy(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Caddy"),
    (re.compile(r"gunicorn(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Gunicorn"),
    (re.compile(r"uvicorn(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Uvicorn"),
    (re.compile(r"jetty(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Jetty"),
    (re.compile(r"nagios(?:[- ]nsca)?(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Nagios NSCA"),
    (re.compile(r"mqtt", re.IGNORECASE), "MQTT"),
    (re.compile(r"amqp|rabbitmq", re.IGNORECASE), "AMQP"),
    (re.compile(r"cassandra", re.IGNORECASE), "Cassandra"),
    (re.compile(r"kafka", re.IGNORECASE), "Kafka"),
    (re.compile(r"activemq", re.IGNORECASE), "ActiveMQ"),
    (re.compile(r"minecraft", re.IGNORECASE), "Minecraft"),
    (re.compile(r"betta-morpho-ctrl\s+ready|betta-morpho\s+ctrl\s+ready", re.IGNORECASE), "Betta-Morpho Control"),
    (re.compile(r"microsoft-httpapi", re.IGNORECASE), "Microsoft HTTPAPI"),
    (re.compile(r'"cluster_name"\s*:\s*"[^"]+"|"tagline"\s*:\s*"you know, for search"', re.IGNORECASE), "Elasticsearch"),
    (re.compile(r"ismaster|hello", re.IGNORECASE), "MongoDB"),
    (re.compile(r"miniserv|webmin", re.IGNORECASE), "Webmin"),
    (re.compile(r"memcached|stat\s+(?:pid|ssl)", re.IGNORECASE), "Memcached"),
    (re.compile(r"asterisk|sip/2\.0", re.IGNORECASE), "SIP"),
    (re.compile(r"tornadoserver|tornado", re.IGNORECASE), "Tornado"),
    (re.compile(r"consul", re.IGNORECASE), "Consul"),
    (re.compile(r"cowboy", re.IGNORECASE), "RabbitMQ"),
    (re.compile(r"rfb\s+\d{3}\.\d{3}", re.IGNORECASE), "VNC"),
    (re.compile(r"\(description=\(err=\d+\)\(vsnnum=\d+\)\)", re.IGNORECASE), "Oracle TNS"),
    (re.compile(r"oracle weblogic", re.IGNORECASE), "Oracle WebLogic Server"),
    (re.compile(r"neo4j", re.IGNORECASE), "Neo4j"),
    (re.compile(r"vmware authentication daemon(?: version ([0-9.]+))?", re.IGNORECASE), "VMware Authentication Daemon"),
    (re.compile(r"redis(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "Redis"),
    (re.compile(r"postgres(?:ql)?(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"mysql(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "MySQL"),
    (re.compile(r"mongodb(?:[/ |:-]+(\d+(?:\.\d+)+))?", re.IGNORECASE), "MongoDB"),
]


def _decode_hex_banner(text: str) -> str:
    match = _HEX_BANNER_RE.match(text.strip())
    if not match:
        return ""
    try:
        raw = bytes.fromhex(match.group(1))
    except ValueError:
        return ""
    decoded = "".join(chr(byte) if 32 <= byte < 127 else " " for byte in raw)
    return " ".join(decoded.split())


def detect_service(port: int, banner: str = "", nmap_service: str = "") -> dict[str, str]:
    text = " ".join(part for part in [banner, nmap_service] if part).strip()
    decoded_hex = _decode_hex_banner(text)
    signature_text = " | ".join(part for part in (decoded_hex, text) if part)
    for pattern, name in _SIGNATURES:
        match = pattern.search(signature_text)
        if match:
            version = (match.group(1) or "").strip() if match.lastindex else ""
            display = f"{name} {version}".strip()
            catalog = lookup_product(display or name)
            cpe = _catalog_cpe(catalog) if catalog else ""
            return {"name": name, "version": version, "display": display, "cpe": cpe}

    lowered = signature_text.lower()
    if lowered.startswith("hex:160303"):
        return {"name": "HTTPS", "version": "", "display": "HTTPS", "cpe": ""}
    if lowered.startswith("hex:4a0000000a"):
        return {"name": "MySQL", "version": "", "display": "MySQL", "cpe": ""}
    if lowered.startswith("hex:84000000"):
        return {"name": "Cassandra", "version": "", "display": "Cassandra", "cpe": ""}
    if lowered.startswith("hex:0f002f"):
        return {"name": "Minecraft", "version": "", "display": "Minecraft", "cpe": ""}
    if lowered.startswith("hex:4163746976654d51") or decoded_hex.lower().startswith("activemq"):
        return {"name": "ActiveMQ", "version": "", "display": "ActiveMQ", "cpe": ""}
    if lowered.startswith("+ok") and "pop3" in lowered:
        return {"name": "POP3", "version": "", "display": "POP3", "cpe": ""}
    if "password authentication required" in lowered:
        return {"name": "PostgreSQL", "version": "", "display": "PostgreSQL", "cpe": ""}
    if "ibm-db2-admin" in lowered or "db2" in lowered:
        catalog = lookup_product("IBM Db2 Admin")
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": "IBM Db2 Admin", "version": "", "display": "IBM Db2 Admin", "cpe": cpe}
    if "ssh" in lowered:
        catalog = lookup_product(text or "SSH")
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": "SSH", "version": "", "display": "SSH", "cpe": cpe}
    if "microsoft windows rpc" in lowered or port == 135:
        catalog = lookup_product(text or "Microsoft Windows RPC")
        cpe = _catalog_cpe(catalog) if catalog else "cpe:/o:microsoft:windows"
        return {"name": "Microsoft Windows RPC", "version": "", "display": "Microsoft Windows RPC", "cpe": cpe}
    if port in {49664, 49665, 49666, 49667, 49668, 49669, 49670} and not text:
        catalog = lookup_product("Microsoft Windows RPC")
        cpe = _catalog_cpe(catalog) if catalog else "cpe:/o:microsoft:windows"
        return {"name": "Microsoft Windows RPC", "version": "", "display": "Microsoft Windows RPC", "cpe": cpe}
    if "netbios" in lowered or port == 139:
        catalog = lookup_product(text or "Microsoft Windows netbios-ssn")
        cpe = _catalog_cpe(catalog) if catalog else "cpe:/o:microsoft:windows"
        return {"name": "Microsoft Windows netbios-ssn", "version": "", "display": "Microsoft Windows netbios-ssn", "cpe": cpe}
    if "dovecot" in lowered and ("pop3" in lowered or port == 110):
        return {"name": "Dovecot POP3", "version": "", "display": "Dovecot POP3", "cpe": ""}
    if "dovecot" in lowered and ("imap" in lowered or port in {143, 993}):
        return {"name": "Dovecot IMAP", "version": "", "display": "Dovecot IMAP", "cpe": ""}
    if "courier" in lowered and ("pop3" in lowered or port == 110):
        return {"name": "Courier POP3", "version": "", "display": "Courier POP3", "cpe": ""}
    if "courier" in lowered and ("imap" in lowered or port in {143, 993}):
        return {"name": "Courier IMAP", "version": "", "display": "Courier IMAP", "cpe": ""}
    if "microsoft-ds" in lowered or (port == 445 and "http" not in lowered):
        catalog = lookup_product(text or "microsoft-ds")
        cpe = _catalog_cpe(catalog) if catalog else "cpe:/o:microsoft:windows"
        return {"name": "SMB", "version": "", "display": "SMB", "cpe": cpe}
    if "sql server" in lowered or "ms-sql-s" in lowered or port == 1433:
        catalog = lookup_product(text or "Microsoft SQL Server")
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": "Microsoft SQL Server", "version": "", "display": "Microsoft SQL Server", "cpe": cpe}
    if "http" in lowered:
        scheme = "HTTPS" if port in {443, 8443, 8843, 9443} or "ssl" in lowered else "HTTP"
        catalog = lookup_product(text or scheme)
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": scheme, "version": "", "display": scheme, "cpe": cpe}
    if port == 903 or port == 913:
        return {"name": "VMware Authentication Daemon", "version": "", "display": "VMware Authentication Daemon", "cpe": ""}
    if port == 9200 and ("cluster_name" in lowered or text.startswith("{")):
        return {"name": "Elasticsearch", "version": "", "display": "Elasticsearch", "cpe": ""}
    if port in {11211, 11214} and ("stat" in lowered or text):
        return {"name": "Memcached", "version": "", "display": "Memcached", "cpe": ""}
    if port == 25565:
        return {"name": "Minecraft", "version": "", "display": "Minecraft", "cpe": ""}
    if port in {5671, 5672}:
        return {"name": "AMQP", "version": "", "display": "AMQP", "cpe": ""}
    if port == 9042:
        return {"name": "Cassandra", "version": "", "display": "Cassandra", "cpe": ""}
    if port == 9092:
        return {"name": "Kafka", "version": "", "display": "Kafka", "cpe": ""}
    if port == 8500:
        return {"name": "Consul", "version": "", "display": "Consul", "cpe": ""}
    if port == 9001:
        return {"name": "Tornado", "version": "", "display": "Tornado", "cpe": ""}
    if port == 15672:
        return {"name": "RabbitMQ", "version": "", "display": "RabbitMQ", "cpe": ""}
    if port == 10000:
        return {"name": "Webmin", "version": "", "display": "Webmin", "cpe": ""}
    if port == 20000:
        return {"name": "Betta-Morpho Control", "version": "", "display": "Betta-Morpho Control", "cpe": ""}
    if port == 49152 and "microsoft-httpapi" in lowered:
        return {"name": "Microsoft HTTPAPI", "version": "", "display": "Microsoft HTTPAPI", "cpe": ""}

    hint = _PORT_HINTS.get(port, "")
    if hint:
        catalog = lookup_product(hint)
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": hint, "version": "", "display": hint, "cpe": cpe}

    catalog_source = decoded_hex or text
    catalog = lookup_product(catalog_source)
    if catalog:
        product = str(catalog.get("product", ""))
        cpe = _catalog_cpe(catalog)
        version_match = re.search(r"(\d+(?:\.\d+)+(?:p\d+)?)", catalog_source)
        version = version_match.group(1) if version_match else ""
        display = f"{product} {version}".strip() if version else product
        return {"name": product, "version": version, "display": display, "cpe": cpe}

    raw = (banner or nmap_service).strip()
    if raw:
        short = (decoded_hex or raw).split("|")[0].strip()
        catalog = lookup_product(short)
        cpe = _catalog_cpe(catalog) if catalog else ""
        return {"name": short, "version": "", "display": short, "cpe": cpe}
    return {"name": "", "version": "", "display": "", "cpe": ""}
