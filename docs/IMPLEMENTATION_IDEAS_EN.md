# Implementation Ideas

This file reflects the current repository state after the infrastructure, quality, legal, and documentation passes completed on 2026-04-04.

## Implemented

### 1. Scanner Modularization

Status: Implemented

What is in the repo now:

- `training/tools/scanner.py` is the CLI and report facade
- `training/tools/scanner_engine.py` contains SNN runtime and scanner training logic
- `training/tools/scanner_probes.py` contains raw, connect, and UDP probe implementations
- `training/tools/scanner_enrichment.py` contains enrichment and active-learning export logic
- `training/tools/scanner_support.py`, `scanner_types.py`, and `scanner_utils.py` hold shared helpers

### 2. Project Packaging Layer

Status: Implemented

What is in the repo now:

- top-level `pyproject.toml`
- editable install via `pip install -e .`
- console scripts for launcher, scanner, and verifier
- `.editorconfig` to keep encoding defaults stable
- `MANIFEST.in` so legal and packaging-critical files ship with distributions

### 3. Lightweight Experiment / Benchmark Layer

Status: Implemented

What is in the repo now:

- `tools/benchmark_scans.py` builds JSON benchmark manifests from two result CSV files
- `tools/experiment_registry.py` stores research runs in `data/experiments.db`
- `tools/domain_metrics.py` aggregates benchmark metrics by domain
- launcher commands expose the same layer through:
  - `benchmark-scans`
  - `experiment-list`
  - `experiment-show`
  - `domain-summary`

### 4. Tiny Prototype Training Run In CI

Status: Implemented

What is in the repo now:

- CI generates a tiny synthetic dataset
- CI trains a prototype classifier artifact
- CI evaluates the tiny artifact end-to-end
- CI also exercises editable install and static analysis

### 5. Unified Artifact Schema

Status: Implemented

What is in the repo now:

- `tools/artifact_schema.py` defines one shared metadata convention
- classifier artifacts use the shared schema
- scanner artifacts use the shared schema
- service-model artifacts use the shared schema
- service catalog artifacts use the shared schema
- benchmark manifests also use the shared schema
- `launcher.py artifact-validate ...` validates artifact JSON files

### 6. Synthetic / Real / Replay Domain Tracking

Status: Implemented

What is in the repo now:

- benchmark manifests include a `domain` field
- the experiment registry stores domain per benchmark run
- `tools/domain_metrics.py` summarizes metrics separately for:
  - `synthetic`
  - `verified_real`
  - `replay`
  - custom domains if needed

### 7. Training Pipeline Hardening

Status: Implemented

What is in the repo now:

- project-root-aware path resolution in train, evaluate, synthetic generation, and replay tools
- real use of synthetic `--assets`
- dataset validation before training starts
- evaluation that skips unlabeled rows correctly
- replay that tolerates mixed scan directories instead of breaking on unlabeled files

### 8. Static Analysis Cleanup

Status: Implemented

What is in the repo now:

- `pyrightconfig.json` aligned to the real project environment
- repository-level `pyright` clean state
- CI enforces static analysis as part of quality checks

### 9. Documentation Restructure

Status: Implemented

What is in the repo now:

- a shorter `README.md` as the entry point
- purpose-specific guides under `docs/`
- `docs/QUICKSTART.md`
- `docs/SCANNING_GUIDE.md`
- `docs/TRAINING_GUIDE.md`
- `docs/CLI_REFERENCE.md`
- `docs/ARCHITECTURE.md`

### 10. Legal and Governance Surface

Status: Implemented

What is in the repo now:

- Apache-2.0 licensing
- `NOTICE`
- `DISCLAIMER.md`
- `AUTHORIZED_USE_POLICY.md`
- `TRADEMARKS.md`
- `CONTRIBUTING.md`
- `DCO`

## Partially Implemented

### 11. Turn Nmap Verification Into a Learning Loop

Status: Partially implemented

Already done:

- `tools/verify_scan.py` writes session-prefixed `service_training` CSV artifacts
- scanner flow writes session-prefixed `active_learning` CSV artifacts
- service fingerprint training reuses verified scan rows
- missing `nmap` now fails gracefully instead of raising a traceback

Still missing:

- automatic review queue management
- promotion workflow into a curated training store
- threshold-based or scheduled retraining

### 12. Operator Dashboard

Status: Partially implemented

Already done:

- launcher has a practical interactive menu
- experiment listing, benchmark manifests, scan history, and report artifacts exist

Still missing:

- one consolidated dashboard view for recent scans, benchmark deltas, verification outcomes, and model state

## Still Open Ideas

### 13. Benchmark Extensions Against External Baselines

Why it still matters:

- the benchmark layer compares Betta-Morpho runs well, but it still does not automatically ingest richer external baselines such as Nmap XML or service-version detail

Possible next step:

- extend `benchmark_scans.py` with Nmap XML ingestion and packet / service-version comparison

### 14. Plugin System For Enrichers

Why it still matters:

- enrichment remains the most extensible part of the scanner pipeline

Possible next step:

- define a simple plugin interface and isolate optional dependencies per plugin

### 15. Python and Rust Runtime Contract Tightening

Why it still matters:

- the Rust path is strategically important, but artifact expectations and runtime telemetry contracts still need a tighter long-term compatibility story

Possible next step:

- define a narrower artifact/runtime compatibility matrix and explicit validation for Rust-consumed data

## Best Current Next Picks

If only three ideas are pursued next, the highest-leverage combination is now:

1. automate the Nmap verification -> curated training -> retraining loop
2. extend benchmarks to compare Betta-Morpho directly against external baselines such as Nmap XML
3. add a compact operator dashboard on top of the experiment registry and benchmark manifests
