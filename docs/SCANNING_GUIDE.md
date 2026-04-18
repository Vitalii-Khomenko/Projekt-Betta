# Scanning Guide

This guide covers the practical scan workflows for Betta-Morpho.

## Main Entry Points

Use either:

- `python launcher.py scan`
- `python launcher.py wizard`
- `python training/tools/scanner.py scan`

The launcher is the recommended entry point.

## Transport Modes

### Auto

Best default on Linux when raw sockets are available.

- uses raw SYN style probing when the environment supports it
- falls back automatically when raw probing is unavailable

### Connect

Best default on Windows and often the most stable mode for app-layer enrichment.

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports top100 \
  --transport connect
```

Connect mode is also the easiest way to get consistent application follow-up on services such as HTTP, WinRM, LDAP, and RPC-over-HTTP.

## Speed Profiles

Main presets:

- `paranoid`
- `sneaky`
- `polite`
- `normal`
- `aggressive`
- `x5`
- `x10`
- `x15`

Rule of thumb:

- `paranoid`, `sneaky`, `polite` for quieter scans
- `normal` for most day-to-day work
- `aggressive`, `x5`, `x10`, `x15` for lab, localhost, LAN, and controlled stress testing

Manual speed override also exists:

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-5000 \
  --profile normal \
  --speed-level 80
```

## Checkpoints and Progress Logs

Long scans can save partial output every 1000 ports.

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-5000 \
  --profile x10 \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

Scan using a predefined port file (TCP/UDP sections supported):

```bash
python launcher.py scan \
  --target 10.129.51.85 \
  --ports @Ports/1000.txt \
  --ports-udp @Ports/1000.txt \
  --profile normal
```

What this gives you:

- partial result persistence
- periodic HTML/CSV updates
- progress log with elapsed time

## Recommended Practical Recipes

### Windows Local Fast

```bash
python launcher.py scan \
  --target 127.0.0.1 \
  --ports top20 \
  --profile x15 \
  --transport connect \
  --report artifacts/snn_model.json
```

### Linux Raw Balanced

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-5000 \
  --profile normal \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

### Linux Connect Fast

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-5000 \
  --profile x15 \
  --transport connect \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

## Service Identification

Betta-Morpho does not rely on a single naming source.

- first it applies an internal service catalog built from local Nmap databases in `artifacts/service_catalog.json`
- then it adds protocol-aware follow-up where the target responds
- current follow-up paths include HTTP and WinRM headers, TLS certificates, SMB negotiation, LDAP rootDSE on `389/3268`, and RPC over HTTP on `593`
- some dynamic or opaque ports still need external verification, especially when the service does not expose an easy banner

Rebuild the internal catalog from the local Nmap installation when needed:

```bash
python launcher.py service-catalog-build \
  --output artifacts/service_catalog.json
```

### Full Port Sweep

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-65535 \
  --profile x10 \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

## Scanning from Port Files

Betta-Morpho supports loading ports from external files using the `@` prefix. This is especially useful for large, curated port sets or when reusing specific lists across multiple targets.

### File Format

The parser supports both simple newline/comma separated lists and structured files with `TCP` and `UDP` headers:

```text
TCP
21,22,23,80,443

UDP
53,67,68,123,161
```

If no headers are found, the entire file is treated as a single list for the requested protocol.

### Usage Examples

**CLI:**
```bash
python launcher.py scan \
  --target 10.129.51.85 \
  --ports @Ports/1000.txt \
  --ports-udp @Ports/1000.txt
```

**Interactive Wizard:**
When prompted for ports, type the path with the `@` prefix:
`TCP ports (top100, ...): @Ports/1000.txt`

## UDP

Focused UDP probing is available as an additional pass.
Betta-Morpho uses targeted payloads for common UDP services to elicit responses and improve accuracy:

- DNS (Version query)
- NTP (v4 Client probe)
- SNMP (v2c sysDescr query)
- NetBIOS (NBSTAT probe)
- OpenVPN, mDNS, SSDP, IPMI, IKEv1
- Generic payloads for unknown ports

Direct scanner example:

```bash
python training/tools/scanner.py scan \
  --target 10.129.41.202 \
  --ports top100 \
  --ports-udp 53,123,161 \
  --report artifacts/snn_model.json
```

## Stealth Features

Main ideas:

- **Dynamic Auto-Tuning**: The SNN engine monitors for long timeout streaks (WAF or rate-limiting detection) and will automatically downgrade the profile to `sneaky` to maintain stealth.
- `paranoid / sneaky / polite` reduce scan pressure manually.
- `--decoys` adds noise around the real probe path.
- `--spoof-ttl` and `--jitter-ms` make traffic less rigid.
- `--source-port` and `--retry-source-port` are specialized follow-up tricks.

Important:

- these are research and controlled-testing features
- they are not a substitute for authorization

## Verification

Verify Betta-Morpho-open ports with Nmap after the scan:

```bash
python launcher.py verify-betta-morpho \
  --scan-csv data/scans/SESSION/SESSION_result.csv
```

This verification step is especially useful for:

- dynamic Windows RPC ports
- ports that only expose generic `tcpwrapped` or minimal banners
- confirming product names after Betta-Morpho already narrowed the target port set

Or in one workflow:

```bash
python training/tools/scanner.py scan \
  --target 10.129.41.202 \
  --ports 1-1000 \
  --report artifacts/snn_model.json \
  --verify-with-nmap
```

## JSON Export

Betta-Morpho automatically generates a structured `_result.json` file alongside the CSV when you specify the `--output` or `--report` flag. This JSON export allows for easy programmatic ingestion into other tools like Nuclei, Metasploit, or custom vulnerability management dashboards.

## Passive Hostname Discovery

Betta-Morpho can also extract hostname and domain candidates from the scan evidence it already collected.
This is a post-scan passive step, not a brute-force enumeration step.

Run it on a saved scan:

```bash
python launcher.py discover-hostnames \
  data/scans/SESSION/SESSION_result.csv \
  --artifact artifacts/host_discovery_model.json \
  --output data/scans/SESSION/SESSION_hostnames.csv
```

Or attach it directly to the scan workflow:

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports top100 \
  --report artifacts/snn_model.json \
  --discover-hostnames \
  --host-discovery-artifact artifacts/host_discovery_model.json
```

## Reports And Artifacts

Typical scan output directory includes:

- `*_result.csv`
- `*_report.html`
- `*_classified.csv`
- `*_active_learning.csv`
- `*_progress.log`
- `*_comparison.csv`
- `*_comparison.json`
- `*_hostnames.csv`
- `*_hostnames_report.html`

## Related Reading

- [SCAN_SPEED_THEORY_EN.md](SCAN_SPEED_THEORY_EN.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [HOST_DISCOVERY_GUIDE.md](HOST_DISCOVERY_GUIDE.md)
