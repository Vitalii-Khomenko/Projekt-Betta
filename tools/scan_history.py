"""
ScanHistory - SQLite-backed persistent store for Betta-Morpho scan results.

Schema:
  scans(id, target, profile, timestamp, total_probed, total_open)
  ports(scan_id, port, proto, state, rtt_us, os_hint, banner, label)

Usage:
  python tools/scan_history.py --list
  python tools/scan_history.py --target 10.10.10.5
  python tools/scan_history.py --scan-id 3

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
import sqlite3
import argparse
import sys
import csv
from datetime import UTC, datetime
from pathlib import Path
from xml.etree import ElementTree as ET


class ScanHistory:
    def __init__(self, db_path: str = "data/scan_history.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db = db_path
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db)

    def _init_db(self) -> None:
        with self._conn() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    target       TEXT    NOT NULL,
                    profile      TEXT    NOT NULL,
                    source       TEXT    DEFAULT 'scanner',
                    timestamp    TEXT    NOT NULL,
                    total_probed INTEGER DEFAULT 0,
                    total_open   INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS ports (
                    scan_id  INTEGER NOT NULL REFERENCES scans(id),
                    port     INTEGER NOT NULL,
                    proto    TEXT    DEFAULT 'tcp',
                    state    TEXT    DEFAULT 'unknown',
                    rtt_us   REAL    DEFAULT 0,
                    service  TEXT    DEFAULT '',
                    os_hint  TEXT    DEFAULT '',
                    banner   TEXT    DEFAULT '',
                    label    TEXT    DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_ports_scan ON ports(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            """)
            scan_columns = {row[1] for row in con.execute("PRAGMA table_info(scans)")}
            if "source" not in scan_columns:
                con.execute("ALTER TABLE scans ADD COLUMN source TEXT DEFAULT 'scanner'")
            port_columns = {row[1] for row in con.execute("PRAGMA table_info(ports)")}
            if "service" not in port_columns:
                con.execute("ALTER TABLE ports ADD COLUMN service TEXT DEFAULT ''")

    @staticmethod
    def _label_for_state(state: str, rtt_us: float) -> str:
        if state == "open":
            return "normal" if rtt_us < 50_000 else "delayed"
        return "filtered"

    @staticmethod
    def _normalize_record(record: dict) -> dict:
        return {
            "port": int(record.get("port", 0)),
            "proto": str(record.get("proto", "tcp")),
            "state": str(record.get("state", "unknown")),
            "rtt_us": float(record.get("rtt_us", 0.0)),
            "service": str(record.get("service", "")),
            "os_hint": str(record.get("os_hint", "")),
            "banner": str(record.get("banner", ""))[:200],
            "label": str(record.get("label", "")),
            "protocol_flag": str(record.get("protocol_flag", "")),
            "timestamp_us": int(record.get("timestamp_us", int(datetime.now(UTC).timestamp() * 1_000_000))),
            "inter_packet_time_us": float(record.get("inter_packet_time_us", 0.0)),
            "payload_size": float(record.get("payload_size", 0.0)),
        }

    def save_scan_records(self, target: str, profile: str, records: list[dict], source: str = "scanner") -> int:
        """Persist normalized records from any scan source."""
        ts         = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")
        normalized = [self._normalize_record(record) for record in records]
        total_open = sum(1 for record in normalized if record["state"] == "open")
        with self._conn() as con:
            cur = con.execute(
                "INSERT INTO scans(target, profile, source, timestamp, total_probed, total_open) "
                "VALUES (?,?,?,?,?,?)",
                (target, profile, source, ts, len(normalized), total_open),
            )
            if cur.lastrowid is None:
                raise RuntimeError("failed to insert scan row")
            scan_id = int(cur.lastrowid)
            con.executemany(
                "INSERT INTO ports(scan_id,port,proto,state,rtt_us,service,os_hint,banner,label) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [
                    (
                        scan_id,
                        record["port"],
                        record["proto"],
                        record["state"],
                        record["rtt_us"],
                        record["service"],
                        record["os_hint"],
                        record["banner"],
                        record["label"],
                    )
                    for record in normalized
                ],
            )
        return scan_id

    def save_scan(self, target: str, profile: str, results: list) -> int:
        """Persist a scanner-native run. results is a list of PortResult objects."""
        records = []
        for result in results:
            state = getattr(result, "state", "")
            rtt_us = float(getattr(result, "rtt_us", 0.0))
            records.append({
                "port": getattr(result, "port", 0),
                "proto": getattr(result, "protocol", "tcp"),
                "state": state,
                "rtt_us": rtt_us,
                "service": getattr(result, "service_version", "") or getattr(result, "service", ""),
                "os_hint": getattr(result, "os_hint", ""),
                "banner": getattr(result, "banner", "") or "",
                "label": self._label_for_state(state, rtt_us),
                "protocol_flag": getattr(result, "protocol_flag", ""),
                "timestamp_us": getattr(result, "timestamp_us", int(datetime.now(UTC).timestamp() * 1_000_000)),
                "inter_packet_time_us": 0.0,
                "payload_size": float(getattr(result, "payload_size", 0.0)),
            })
        return self.save_scan_records(target, profile, records, source="scanner")

    def append_training_rows(self, csv_path: str | Path, target: str, records: list[dict]) -> int:
        """Append normalized scan records to the project telemetry CSV schema."""
        normalized = [self._normalize_record(record) for record in records]
        output_path = Path(csv_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = [
            "timestamp_us", "asset_ip", "target_port", "protocol_flag",
            "inter_packet_time_us", "payload_size", "rtt_us", "label",
        ]
        write_header = not output_path.exists() or output_path.stat().st_size == 0
        with output_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            for record in normalized:
                protocol_flag = record["protocol_flag"] or self._protocol_flag_from_state(record["state"], "")
                writer.writerow({
                    "timestamp_us": record["timestamp_us"],
                    "asset_ip": target,
                    "target_port": record["port"],
                    "protocol_flag": protocol_flag,
                    "inter_packet_time_us": record["inter_packet_time_us"],
                    "payload_size": record["payload_size"],
                    "rtt_us": round(record["rtt_us"], 1),
                    "label": record["label"] or self._label_for_state(record["state"], record["rtt_us"]),
                })
        return len(normalized)

    @staticmethod
    def _protocol_flag_from_state(state: str, reason: str) -> str:
        reason_l = reason.lower()
        if state == "open":
            return "SYN_ACK"
        if state == "closed":
            return "RST" if "refused" in reason_l or "reset" in reason_l else "TIMEOUT"
        if state == "filtered":
            return "ICMP_UNREACHABLE" if "unreach" in reason_l else "TIMEOUT"
        return "TIMEOUT"

    def import_nmap_xml(
        self,
        xml_path: str | Path,
        profile: str = "nmap-top1000",
        training_csv: str | Path | None = None,
    ) -> tuple[int, int, str]:
        """Import a single-host Nmap XML report into SQLite and optionally append training rows."""
        xml_file = Path(xml_path)
        root = ET.parse(xml_file).getroot()
        host = root.find("host")
        if host is None:
            raise ValueError(f"no host node found in {xml_file}")

        address = host.find("address")
        if address is None or not address.attrib.get("addr"):
            raise ValueError(f"no host address found in {xml_file}")
        target = address.attrib["addr"]

        finished = root.find("runstats/finished")
        fallback_ts = int(datetime.now(UTC).timestamp() * 1_000_000)
        finished_us = int(finished.attrib.get("time", "0")) * 1_000_000 if finished is not None else fallback_ts

        times = host.find("times")
        srtt_us = float(times.attrib.get("srtt", "0")) if times is not None else 0.0

        records: list[dict] = []
        extraports = host.find("ports/extraports")
        if extraports is not None:
            state = extraports.attrib.get("state", "unknown")
            reasons = extraports.findall("extrareasons")
            for reason_node in reasons:
                reason = reason_node.attrib.get("reason", "")
                for port in self._parse_port_ranges(reason_node.attrib.get("ports", "")):
                    records.append({
                        "port": port,
                        "proto": reason_node.attrib.get("proto", "tcp"),
                        "state": state,
                        "rtt_us": srtt_us,
                        "service": "",
                        "os_hint": "",
                        "banner": "",
                        "label": self._label_for_state(state, srtt_us),
                        "protocol_flag": self._protocol_flag_from_state(state, reason),
                        "timestamp_us": finished_us,
                        "inter_packet_time_us": 0.0,
                        "payload_size": 0.0,
                    })

        for port_node in host.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            if state_node is None:
                continue
            state = state_node.attrib.get("state", "unknown")
            reason = state_node.attrib.get("reason", "")
            service = service_node.attrib.get("name", "") if service_node is not None else ""
            payload_size = float(len(service)) if service else 0.0
            records.append({
                "port": int(port_node.attrib.get("portid", "0")),
                "proto": port_node.attrib.get("protocol", "tcp"),
                "state": state,
                "rtt_us": srtt_us,
                "service": service,
                "os_hint": "",
                "banner": service,
                "label": self._label_for_state(state, srtt_us),
                "protocol_flag": self._protocol_flag_from_state(state, reason),
                "timestamp_us": finished_us,
                "inter_packet_time_us": 0.0,
                "payload_size": payload_size,
            })

        if not records:
            raise ValueError(f"no port records found in {xml_file}")

        scan_id = self.save_scan_records(target, profile, records, source="nmap")
        if training_csv is not None:
            self.append_training_rows(training_csv, target, records)
        return scan_id, len(records), target

    @staticmethod
    def _parse_port_ranges(spec: str) -> list[int]:
        ports: list[int] = []
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                low, _, high = part.partition("-")
                ports.extend(range(int(low), int(high) + 1))
            else:
                ports.append(int(part))
        return ports

    def get_scans(self, target: str | None = None, limit: int = 20) -> list[dict]:
        """Return recent scan summaries, optionally filtered by target."""
        sql = "SELECT id,target,profile,source,timestamp,total_probed,total_open FROM scans"
        params: list = []
        if target:
            sql += " WHERE target=?"
            params.append(target)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as con:
            rows = con.execute(sql, params).fetchall()
        return [
              dict(id=r[0], target=r[1], profile=r[2], source=r[3],
                  timestamp=r[4], total_probed=r[5], total_open=r[6])
            for r in rows
        ]

    def get_ports(self, scan_id: int) -> list[dict]:
        """Return all ports for a given scan_id."""
        with self._conn() as con:
            rows = con.execute(
                "SELECT port,proto,state,rtt_us,service,os_hint,banner FROM ports "
                "WHERE scan_id=-> ORDER BY port",
                (scan_id,),
            ).fetchall()
        return [
            dict(port=r[0], proto=r[1], state=r[2],
                 rtt_us=r[3], service=r[4], os_hint=r[5], banner=r[6])
            for r in rows
        ]

    def get_target_profile(self, target: str) -> dict:
        """
        Aggregate all scans for a target:
        - which ports appeared open and how often
        - OS hints observed
        - RTT trend (avg per port)
        """
        scans = self.get_scans(target, limit=100)
        if not scans:
            return {"target": target, "scans": 0, "ports": {}}

        port_data: dict[int, dict] = {}
        for scan in scans:
            for p in self.get_ports(scan["id"]):
                if p["state"] != "open":
                    continue
                port = p["port"]
                if port not in port_data:
                    port_data[port] = {"seen": 0, "rtts": [], "banners": set(),
                                       "os_hints": set()}
                port_data[port]["seen"] += 1
                port_data[port]["rtts"].append(p["rtt_us"])
                if p["banner"]:
                    port_data[port]["banners"].add(p["banner"][:60])
                if p["os_hint"]:
                    port_data[port]["os_hints"].add(p["os_hint"])

        profile = {}
        for port, d in sorted(port_data.items()):
            avg_rtt = sum(d["rtts"]) / len(d["rtts"]) if d["rtts"] else 0
            profile[port] = {
                "seen":    d["seen"],
                "scans":   len(scans),
                "freq":    round(d["seen"] / len(scans), 2),
                "avg_rtt": round(avg_rtt / 1000, 1),
                "banners": list(d["banners"])[:3],
                "os":      list(d["os_hints"]),
            }
        return {"target": target, "scans": len(scans), "ports": profile}


def _cli() -> None:
    ap = argparse.ArgumentParser(description="Betta-Morpho scan history viewer")
    ap.add_argument("--db",       default="data/scan_history.db")
    ap.add_argument("--list",     action="store_true", help="List recent scans")
    ap.add_argument("--target",   help="Filter by target IP")
    ap.add_argument("--scan-id",  type=int, help="Show ports for scan ID")
    ap.add_argument("--profile",  action="store_true",
                    help="Show aggregated target profile (requires --target)")
    ap.add_argument("--limit",    type=int, default=20)
    ap.add_argument("--import-nmap-xml", help="Import Nmap XML results into SQLite history")
    ap.add_argument("--profile-name", default="nmap-top1000",
                    help="Profile name recorded for imported scan results")
    ap.add_argument("--append-training-csv",
                    help="Append imported scan rows to a telemetry CSV for future training")
    args = ap.parse_args()

    h = ScanHistory(args.db)

    if args.import_nmap_xml:
        scan_id, imported, target = h.import_nmap_xml(
            args.import_nmap_xml,
            profile=args.profile_name,
            training_csv=args.append_training_csv,
        )
        print(f"Imported Nmap XML for {target}: scan #{scan_id}, {imported} port rows")
        if args.append_training_csv:
            print(f"Appended training rows to {args.append_training_csv}")
        return

    if args.scan_id:
        ports = h.get_ports(args.scan_id)
        print(f"Scan #{args.scan_id} - {len(ports)} ports")
        open_p = [p for p in ports if p["state"] == "open"]
        print(f"{'PORT':>6}  {'PROTO':5}  {'STATE':12}  {'RTT ms':>7}  {'SERVICE':16}  BANNER")
        print("-" * 70)
        for p in sorted(open_p, key=lambda x: x["port"]):
            b = (p["banner"] or "")[:35].replace("\n", " ")
            print(f"  {p['port']:>5}  {p['proto']:5}  {p['state']:12}  "
                  f"{p['rtt_us']/1000:>7.1f}  {(p['service'] or '')[:16]:16}  {b}")
        return

    if args.profile and args.target:
        prof = h.get_target_profile(args.target)
        print(f"Target profile: {prof['target']}  ({prof['scans']} scans)")
        print(f"{'PORT':>6}  {'FREQ':5}  {'AVG RTT':>8}  {'SEEN':5}  BANNERS")
        print("-" * 70)
        for port, d in prof["ports"].items():
            b = (d["banners"][0] if d["banners"] else "")[:30]
            print(f"  {port:>5}  {d['freq']:5.2f}  {d['avg_rtt']:>7.1f}ms"
                  f"  {d['seen']:>3}/{d['scans']:<3}  {b}")
        return

    scans = h.get_scans(target=args.target, limit=args.limit)
    if not scans:
        print("No scans in history.")
        return
    print(f"{'ID':>4}  {'TARGET':18}  {'PROFILE':12}  {'SOURCE':8}  {'TIMESTAMP':19}  "
          f"{'PROBED':>7}  {'OPEN':>5}")
    print("-" * 90)
    for s in scans:
        print(f"  {s['id']:>3}  {s['target']:18}  {s['profile']:12}  {s['source']:8}  "
              f"{s['timestamp']:19}  {s['total_probed']:>7}  {s['total_open']:>5}")


if __name__ == "__main__":
    _cli()
