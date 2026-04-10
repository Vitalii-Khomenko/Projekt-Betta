# Training Guide

This guide covers classifier data generation, training, evaluation, replay, and related artifacts.

## Main Model Families

Betta-Morpho uses separate artifact families:

- classifier artifact
- scanner strategy artifact
- service fingerprint artifact
- service catalog artifact

Do not treat them as one interchangeable model.

## Synthetic Dataset Generation

Balanced synthetic dataset:

```bash
python training/generate_synthetic_data.py \
  --output data/synthetic_dataset.csv \
  --samples-per-class 1000 \
  --assets 8 \
  --seed 42
```

Smaller dataset:

```bash
python training/generate_synthetic_data.py \
  --output data/synthetic_small.csv \
  --samples-per-class 100 \
  --assets 3 \
  --seed 7
```

Useful parameters:

- `--samples-per-class`
- `--assets`
- `--seed`

## Real Dataset Generation

Generate labeled local telemetry from lab services:

```bash
python tools/gen_real_dataset.py \
  --rounds 25 \
  --output data/real_dataset.csv
```

## Golden Timing Dataset

```bash
python launcher.py golden-dataset \
  --golden-output data/snn_training_batch.csv
```

## Classifier Training

Standard training:

```bash
python training/train.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json \
  --trainer auto
```

Prototype-only training:

```bash
python training/train.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json \
  --trainer prototype
```

Torch-only training:

```bash
python training/train.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json \
  --trainer torch
```

Training now validates the dataset before starting and will fail early if required labels are missing.

## Evaluation

```bash
python training/evaluate.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json \
  --preview 5
```

Host-specific filter:

```bash
python training/evaluate.py \
  --data data/synthetic_dataset.csv \
  --artifact artifacts/snn_model.json \
  --asset-ip 10.42.0.10
```

Evaluator behavior:

- computes metrics only on labeled rows
- reports skipped unlabeled rows instead of silently mixing them into the metric path

## Replay Over Scan Outputs

```bash
python training/replay_directory.py \
  --data-dir data/scans \
  --artifact artifacts/snn_model.json
```

Replay behavior:

- searches recursively
- skips files with no labeled rows
- still aggregates labeled files normally

## Scanner Strategy Training

```bash
python launcher.py scan-train \
  --profile normal \
  --artifact artifacts/scanner_model.json
```

## Service Model Training

```bash
python launcher.py service-train data/scans \
  --artifact artifacts/service_model.json \
  --service-catalog artifacts/service_catalog.json \
  --verified-weight 3
```

Evaluate:

```bash
python launcher.py service-evaluate data/scans \
  --artifact artifacts/service_model.json \
  --service-catalog artifacts/service_catalog.json
```

## Benchmark And Registry Layer

Compare two runs:

```bash
python launcher.py benchmark-scans \
  --baseline-csv data/scans/A/A_result.csv \
  --candidate-csv data/scans/B/B_result.csv \
  --register
```

List experiments:

```bash
python launcher.py experiment-list --limit 10
```

Aggregate by domain:

```bash
python launcher.py domain-summary
```

## Related Reading

- [SCANNING_GUIDE.md](SCANNING_GUIDE.md)
- [CLI_REFERENCE.md](CLI_REFERENCE.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
