# CLI Reference

This is the compact command map for the main Betta-Morpho entry points.

## Launcher Commands

### Core

- `python launcher.py wizard`
- `python launcher.py dashboard`
- `python launcher.py spec`

### Data and Training

- `python launcher.py generate --output FILE --samples-per-class N`
- `python launcher.py golden-dataset --golden-output FILE`
- `python launcher.py train --data FILE --artifact FILE`
- `python launcher.py evaluate --data FILE --artifact FILE`
- `python launcher.py replay-dir --data-dir DIR --artifact FILE`
- `python launcher.py scan-train --profile PROFILE --artifact FILE`
- `python launcher.py discover-generate --output FILE --samples-per-class N`
- `python launcher.py discover-train --data FILE --artifact FILE`
- `python launcher.py discover-evaluate --data FILE --artifact FILE`

### Scanning

- `python launcher.py scan --target IP --ports LIST`
- `python launcher.py verify-betta-morpho --scan-csv FILE`
- `python launcher.py discover-hostnames INPUTS... --output FILE`
- `python launcher.py lab-services --host 127.0.0.1`
- `python launcher.py lab-exercise --host 127.0.0.1`

### Service Fingerprinting

- `python launcher.py service-catalog-build --output FILE`
- `python launcher.py service-train INPUTS... --artifact FILE`
- `python launcher.py service-evaluate INPUTS... --artifact FILE`
- `python launcher.py service-classify --input FILE --artifact FILE --output FILE`

### Benchmarking And Registry

- `python launcher.py artifact-validate FILE --expected-family FAMILY`
- `python launcher.py benchmark-scans --baseline-csv FILE --candidate-csv FILE`
- `python launcher.py experiment-list --limit N`
- `python launcher.py experiment-show --id N`
- `python launcher.py domain-summary`

## Direct Scanner Commands

### Scan

```bash
python training/tools/scanner.py scan \
  --target 10.129.41.202 \
  --ports 1-1000 \
  --profile normal \
  --report artifacts/snn_model.json
```

Useful flags:

- `--transport connect`
- `--ports-udp 53,123,161`
- `--checkpoint-every 1000`
- `--progress-log FILE`
- `--speed-level 1..100`
- `--service-artifact FILE`
- `--service-catalog FILE`
- `--active-learning-output FILE`
- `--verify-with-nmap`
- `--save-weights FILE`
- `--discover-hostnames`
- `--host-discovery-artifact FILE`
- `--host-discovery-output FILE`
- `--host-discovery-html FILE`

### Train Scanner Strategy

```bash
python training/tools/scanner.py train \
  --profile normal \
  --artifact artifacts/scanner_model.json
```

### Classify Results

```bash
python training/tools/scanner.py classify-results \
  --data data/scans/SESSION/SESSION_result.csv \
  --artifact artifacts/snn_model.json \
  --output data/scans/SESSION/SESSION_classified.csv
```

### Passive Host Discovery

```bash
python launcher.py discover-hostnames \
  data/scans/SESSION/SESSION_result.csv \
  --artifact artifacts/host_discovery_model.json \
  --output data/scans/SESSION/SESSION_hostnames.csv \
  --html data/scans/SESSION/SESSION_hostnames_report.html
```

### Service Catalog Refresh

```bash
python launcher.py service-catalog-build \
  --output artifacts/service_catalog.json
```

Use this when you want Betta-Morpho's port and alias fallback to reflect the local Nmap databases currently installed on the host.

## Rust Runtime

### Scan

```bash
./rust-runtime/target/release/betta-morpho scan --target 10.129.41.202
```

### Replay

```bash
./rust-runtime/target/release/betta-morpho replay \
  --model artifacts/snn_model.json \
  --data data/scans/SESSION/SESSION_result.csv
```

## Static Analysis And Tests

```bash
pyright
python -m unittest tools.test_launcher_smoke
python -m unittest tools.test_scanner_telemetry
python -m unittest tools.test_service_fingerprint
python tools/test_decoys.py --port 19801
```

## Related Guides

- [QUICKSTART.md](QUICKSTART.md)
- [SCANNING_GUIDE.md](SCANNING_GUIDE.md)
- [TRAINING_GUIDE.md](TRAINING_GUIDE.md)
- [HOST_DISCOVERY_GUIDE.md](HOST_DISCOVERY_GUIDE.md)
