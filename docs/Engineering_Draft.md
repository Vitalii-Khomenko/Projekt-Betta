# ENGINEERING DRAFT: BETTA-MORPHO

Version: 2.3.0  
Status: Working engineering draft  
Last updated: 2026-04-04

## 1. Project Intent

Betta-Morpho is a research-oriented network reconnaissance platform built around one practical thesis:

- the model should influence scanner behavior, experiment flow, and follow-up logic, not only classify results after the fact

The project combines:

- Python orchestration, training, verification, and reporting
- a modular Python scanner for rapid experimentation
- a Rust runtime path for lower-level and faster execution
- replay, benchmarking, and registry tooling for research repeatability

Primary use cases:

- authorized security testing
- lab and HTB-style research
- telemetry generation for model experiments
- iterative scanner behavior development

## 2. Engineering Shape

Betta-Morpho currently operates as six cooperating layers:

1. Training layer  
   Synthetic data generation, prototype and torch training, evaluation, and replay.

2. Scanner orchestration layer  
   Python scanner modules for probe planning, transport choice, checkpointing, enrichment, reporting, and export.

3. Runtime execution layer  
   Python and Rust execution paths for connect scans, raw probing, and classifier support.

4. Verification and feedback layer  
   Tools that compare Betta-Morpho output with Nmap and emit reusable service-training artifacts.

5. Research and benchmarking layer  
   Benchmark manifests, experiment registry storage, and domain metrics for comparing runs over time.

6. Documentation and governance layer  
   Project docs, legal boundaries, contribution rules, and safe-use policy.

## 3. Current Python Scanner Layout

The scanner path is intentionally modular.

Core modules:

- `training/tools/scanner.py`  
  CLI facade, wizard integration, checkpoint export, report generation, classify-results helper

- `training/tools/scanner_engine.py`  
  `SpikeScanEngine`, profile handling, synthetic scanner training logic, progress callbacks

- `training/tools/scanner_probes.py`  
  TCP connect probes, raw probe batches, UDP probes, target parsing, port parsing, discovery helpers

- `training/tools/scanner_enrichment.py`  
  HTTP and TLS follow-up, SMB enrichment, service prediction, CVE hints, active-learning export

- `training/tools/scanner_support.py`  
  optional dependency loading, console integration, raw capability checks, graceful fallback helpers

- `training/tools/scanner_types.py`  
  shared dataclasses, profile presets, speed-level controls, scanner constants

- `training/tools/scanner_utils.py`  
  banner reading, entropy helpers, shared text normalization, safe string export

This split keeps transport work, enrichment logic, and reporting changes isolated enough for ongoing research.

## 4. Runtime Behavior Model

At the Python layer, scan behavior is driven by `SpikeScanEngine`.

The engine currently provides:

- profile-specific timing behavior
- speed presets and manual `speed-level` override from `1..100`
- connect-mode and raw-mode execution paths
- synthetic scanner training support
- batch-oriented scanning with checkpoint callbacks

Named speed profiles:

- `paranoid`
- `sneaky`
- `polite`
- `normal`
- `aggressive`
- `x5`
- `x10`
- `x15`

The current design treats these profiles as operational presets, not model families.

## 5. Scan Session Flow

A typical scanner run now follows this sequence:

1. Parse targets, ports, transport, and profile.
2. Resolve artifacts and report destination.
3. Start scan timing and create a session prefix.
4. Run probes across the selected port set.
5. Write checkpoint progress every configured threshold, typically `1000` ports.
6. Enrich open services using protocol-aware follow-up logic.
7. Export final session artifacts.
8. Optionally persist history and registry metadata.
9. Optionally verify against Nmap.

Outputs usually land under:

- `data/scans/<timestamp>_<target>/`

Common outputs:

- `<session_prefix>_result.csv`
- `<session_prefix>_report.html`
- `<session_prefix>_classified.csv`
- `<session_prefix>_active_learning.csv`
- `<session_prefix>_progress.log`

This checkpointed export path exists specifically to reduce data loss during long scans.

## 6. Verification and Learning Loop

Verification is handled by:

- `tools/verify_scan.py`

Current verification goals:

- compare Betta-Morpho open ports with Nmap-confirmed findings
- identify matched, Betta-only, and Nmap-only results
- write operator-facing comparison outputs
- emit `<session_prefix>_service_training.csv` for later model improvement

The practical learning loop today is:

- run scan
- compare with external verification
- keep session artifacts
- feed verified service rows into later service-model training

This loop exists, but the final curated promotion and retraining workflow is still only partially automated.

## 7. Service Enrichment

The enrichment layer turns open-port detection into operator-useful context.

Current enrichment responsibilities:

- banner capture
- safe binary-banner normalization
- service normalization
- HTTP probing
- TLS certificate inspection
- SMB follow-up
- CVE hint lookup
- service-model predictions
- active-learning export for uncertain rows

This area remains one of the best extension points in the project and should stay modular.

## 8. Artifact System

The repository intentionally uses multiple artifact families rather than one universal model file.

Main artifact categories:

- classifier artifacts  
  Example: `artifacts/snn_model.json`

- scanner artifacts  
  Example: `artifacts/scanner_model.json`

- service fingerprint artifacts  
  Example: `artifacts/service_model.json`

- service catalog artifacts  
  Example: `artifacts/service_catalog.json`

- benchmark manifests  
  Example: `data/benchmarks/*.json`

Artifact metadata is now governed by a shared schema layer in `tools/artifact_schema.py`.

That gives the project:

- explicit artifact families
- versioned metadata fields
- validation tooling via `launcher.py artifact-validate`
- a cleaner contract between Python-side generation and later runtime use

## 9. Training and Data Pipeline

The training path now covers:

- synthetic dataset generation
- replay of historical scan directories
- classifier training
- scanner training
- service-model training
- evaluation on labeled rows

Recent hardening already in place:

- project-root-aware path resolution
- real use of synthetic `--assets`
- validation for undersized or incomplete training datasets
- evaluation that skips unlabeled rows correctly
- replay that tolerates mixed scan directories instead of failing on unlabeled files

This makes the training path much safer for repeatable local and CI smoke runs.

## 10. Research and Benchmarking Layer

Betta-Morpho now includes an explicit research layer.

Main components:

- `tools/benchmark_scans.py`
- `tools/experiment_registry.py`
- `tools/domain_metrics.py`

Current capabilities:

- compare two result sets and write benchmark manifests
- store experiment metadata in `data/experiments.db`
- summarize results by domain such as:
  - `synthetic`
  - `verified_real`
  - `replay`

This is an important shift: the project is no longer only producing scan artifacts, it is also producing research records.

## 11. Packaging, Entry Points, and Docs

The project supports editable installation through:

- `pyproject.toml`

Recommended setup:

```bash
python -m venv .venv
.venv/bin/pip install -e .
```

Windows equivalent:

```bat
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e .
```

Current console entry points:

- `betta-morpho-launcher`
- `betta-morpho-scanner`
- `betta-morpho-verify`

Documentation is now split by purpose:

- `README.md` for short onboarding
- `docs/QUICKSTART.md`
- `docs/SCANNING_GUIDE.md`
- `docs/TRAINING_GUIDE.md`
- `docs/CLI_REFERENCE.md`
- `docs/ARCHITECTURE.md`

## 12. Quality and Reliability Principles

The current engineering direction follows these practical rules:

- optional dependencies should fail clearly
- missing external tools should produce operator-friendly errors
- scan outputs should be replayable and comparable
- long scans should checkpoint artifacts to reduce loss
- artifacts should validate against a shared schema
- docs should stay readable in terminals and editors
- static analysis should stay clean enough to trust IDE feedback

Current quality guardrails already in place:

- `pyright` clean repository state
- CI editable-install path
- CI tiny prototype training smoke
- unit coverage for launcher, scanner telemetry, artifact schema, benchmark registry, and training helpers

## 13. Legal and Operator Boundaries

Betta-Morpho now carries a clearer project boundary than earlier drafts.

Relevant repository controls:

- `LICENSE` uses Apache-2.0
- `NOTICE`
- `DISCLAIMER.md`
- `AUTHORIZED_USE_POLICY.md`
- `TRADEMARKS.md`
- `CONTRIBUTING.md`
- `DCO`

That governance layer matters because this is a security research project, not only a codebase.

## 14. Near-Term Priorities

The highest-value remaining improvements are:

1. automate the full verification-to-curation-to-retraining loop
2. extend benchmark ingestion to richer external baselines such as Nmap XML
3. add one consolidated operator dashboard on top of registry and benchmark data
4. continue tightening Python and Rust artifact/runtime contracts
5. design a plugin interface for future enrichers and optional protocol modules

## 15. Engineering Position

Betta-Morpho should be treated as a serious research platform, not a one-file scanner.

The project is strongest when used as:

- a modular scanner research environment
- a telemetry and artifact generation pipeline
- a benchmarkable experiment platform
- a bridge between model-guided scanning and traditional external verification

That is the design direction this draft recommends preserving.
