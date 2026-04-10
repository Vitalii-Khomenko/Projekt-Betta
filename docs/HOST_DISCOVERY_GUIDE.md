# Host Discovery Guide

This guide covers Betta-Morpho's passive hostname and domain discovery workflow.

## What It Does

The passive host discovery module extracts names that services already expose during a normal scan:

- HTTP redirects and URLs
- TLS certificate subject and SAN values
- banner text
- service-version and technology fields
- SMB-style server naming hints

It does not do wordlist brute force.

## Main Commands

Generate a synthetic training dataset:

```bash
python launcher.py discover-generate \
  --output data/host_discovery_synthetic.csv
```

Train the SNN:

```bash
python launcher.py discover-train \
  --data data/host_discovery_synthetic.csv \
  --artifact artifacts/host_discovery_model.json
```

Evaluate the SNN:

```bash
python launcher.py discover-evaluate \
  --data data/host_discovery_synthetic.csv \
  --artifact artifacts/host_discovery_model.json
```

Extract names from a saved scan:

```bash
python launcher.py discover-hostnames \
  data/scans/SESSION/SESSION_result.csv \
  --artifact artifacts/host_discovery_model.json \
  --output data/scans/SESSION/SESSION_hostnames.csv \
  --html data/scans/SESSION/SESSION_hostnames_report.html
```

Attach it to the scan pipeline:

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports top100 \
  --report artifacts/snn_model.json \
  --discover-hostnames \
  --host-discovery-artifact artifacts/host_discovery_model.json
```

## Output Files

Typical outputs:

- `*_hostnames.csv`
- `*_hostnames_report.html`

The CSV contains:

- `asset_ip`
- `candidate_name`
- `root_domain`
- `source_kinds`
- `source_ports`
- `evidence_count`
- `predicted_label`
- `confidence`
- `evidence`

## Label Meanings

- `high_value`: likely entrypoints, identity hosts, management, or important infrastructure names
- `supporting`: useful real names, but not obviously the first place to look
- `noise`: generic or low-signal extracted names

## Good Uses

- post-scan review
- lab environment mapping
- ranking names from reports before deeper manual analysis

## Related Reading

- [SCANNING_GUIDE.md](SCANNING_GUIDE.md)
- [TRAINING_GUIDE.md](TRAINING_GUIDE.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
