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

### Full Port Sweep

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-65535 \
  --profile x10 \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

## UDP

Focused UDP probing is available as an additional pass.

Use it for cases such as:

- DNS
- NTP
- SNMP
- IPsec-related ports

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

- `paranoid / sneaky / polite` reduce scan pressure
- `--decoys` adds noise around the real probe path
- `--spoof-ttl` and `--jitter-ms` make traffic less rigid
- `--source-port` and `--retry-source-port` are specialized follow-up tricks

Important:

- these are research and controlled-testing features
- they are not a substitute for authorization

## Verification

Verify Betta-Morpho-open ports with Nmap after the scan:

```bash
python launcher.py verify-betta-morpho \
  --scan-csv data/scans/SESSION/SESSION_result.csv
```

Or in one workflow:

```bash
python training/tools/scanner.py scan \
  --target 10.129.41.202 \
  --ports 1-1000 \
  --report artifacts/snn_model.json \
  --verify-with-nmap
```

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
- `*_hostnames.csv`
- `*_hostnames_report.html`

## Related Reading

- [SCAN_SPEED_THEORY_EN.md](SCAN_SPEED_THEORY_EN.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [HOST_DISCOVERY_GUIDE.md](HOST_DISCOVERY_GUIDE.md)
