# Quickstart

This guide is for the shortest path from clone to useful output.

## 1. Install

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m pip install pyright
```

### Linux

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/pip install pyright
```

Optional raw mode on Linux:

```bash
sudo setcap cap_net_raw+eip .venv/bin/python3
```

## 2. Open The Wizard

```bash
python launcher.py wizard
```

If you prefer direct commands, use the sections below.

## 3. First Local Scan

Windows or Linux connect-mode first pass:

```bash
python launcher.py scan \
  --target 127.0.0.1 \
  --ports top20 \
  --profile x15 \
  --transport connect \
  --report artifacts/snn_model.json
```

This writes a session directory under `data/scans/`.

## 4. Generate Training Data

Balanced synthetic dataset:

```bash
python training/generate_synthetic_data.py \
  --output data/synthetic_dataset.csv \
  --samples-per-class 1000 \
  --assets 8 \
  --seed 42
```

Small smoke dataset:

```bash
python training/generate_synthetic_data.py \
  --output data/synthetic_small.csv \
  --samples-per-class 50 \
  --assets 3 \
  --seed 7
```

## 5. Train Classifier

```bash
python training/train.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json
```

Evaluate:

```bash
python training/evaluate.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json
```

## 6. Train Scanner Strategy Artifact

```bash
python launcher.py scan-train \
  --profile normal \
  --artifact artifacts/scanner_model.json
```

## 7. Run A Larger Practical Scan

```bash
python launcher.py scan \
  --target 10.129.41.202 \
  --ports 1-5000 \
  --profile x10 \
  --checkpoint-every 1000 \
  --report artifacts/snn_model.json
```

## 8. Verify With Nmap

```bash
python launcher.py verify-betta-morpho \
  --scan-csv data/scans/SESSION/SESSION_result.csv
```

## 9. Compare Two Runs

```bash
python launcher.py benchmark-scans \
  --baseline-csv data/scans/A/A_result.csv \
  --candidate-csv data/scans/B/B_result.csv \
  --register
```

## 10. Where To Go Next

- [SCANNING_GUIDE.md](SCANNING_GUIDE.md)
- [TRAINING_GUIDE.md](TRAINING_GUIDE.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
