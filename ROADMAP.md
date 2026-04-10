# Betta-Morpho Roadmap

This roadmap reflects the current repository direction after the 2026-04-04
infrastructure, documentation, legal, and quality passes.

It is intentionally forward-looking. Completed work is listed only when it
matters for understanding what the next steps depend on.

## Current Position

Betta-Morpho is no longer a single experimental scanner script.

The project now already has:

- a modular Python scanner pipeline
- classifier, scanner, and service-model artifact families
- checkpointed long-scan exports and progress logging
- benchmarking and experiment registry tooling
- replay and training utilities
- editable packaging and console entry points
- split documentation under `docs/`
- Apache-2.0 licensing and explicit authorized-use boundaries

That means the next roadmap should optimize for research quality, operator
clarity, and runtime maturity rather than for basic project scaffolding.

## Recently Completed Foundations

These are the major foundations that are already in place and should now be
treated as the baseline:

### Research Traceability

- unified artifact schema in `tools/artifact_schema.py`
- benchmark manifests in `tools/benchmark_scans.py`
- SQLite-backed experiment registry in `tools/experiment_registry.py`
- domain summaries in `tools/domain_metrics.py`

### Scanner Runtime Maturity

- modular scanner layout under `training/tools/`
- raw, connect, and UDP paths split from orchestration logic
- checkpoint saves every configurable port interval
- progress logs and session-prefixed scan artifacts
- practical speed presets plus manual `speed-level`

### Training Pipeline Hardening

- project-root-aware path resolution
- real support for synthetic `--assets`
- dataset validation before training
- evaluation that correctly skips unlabeled rows
- replay that tolerates mixed scan directories

### Project Quality And Governance

- `pyright` clean repository state
- tiny prototype training smoke in CI
- shorter root `README` plus focused guides in `docs/`
- Apache-2.0, `NOTICE`, `DISCLAIMER.md`, `AUTHORIZED_USE_POLICY.md`,
  `TRADEMARKS.md`, `CONTRIBUTING.md`, and `DCO`

## Tier 1: Highest-Leverage Next Work

### 1. Automate The Verification-To-Retraining Loop

Status: Partially implemented

Why it matters:

- the project already produces `service_training` and `active_learning` CSVs
- verified rows already improve later service-model training
- the remaining gap is operational automation, not missing raw data

What should happen next:

- define a curated reviewed-training store
- add a promotion step from session artifacts into that store
- support scheduled or threshold-based retraining
- record which verified datasets produced which service-model artifacts

Success criteria:

- a verified scan can move into retraining without manual file juggling
- experiment metadata records the lineage between scan, verification, and artifact

### 2. Extend Benchmarks Against External Baselines

Status: Open

Why it matters:

- current benchmarks compare Betta-Morpho runs well
- they still do not automatically ingest richer external baselines such as Nmap XML

What should happen next:

- ingest Nmap XML or normalized Nmap exports
- compare service agreement and version agreement, not only open-port overlap
- capture timing and packet-level deltas where logs make that possible

Success criteria:

- one benchmark manifest can compare Betta-Morpho, connect fallback, raw mode, and Nmap

### 3. Build A Compact Operator Dashboard

Status: Partially implemented

Why it matters:

- the project has artifacts, registry data, scan history, and benchmark manifests
- it does not yet present those in one operator-facing view

What should happen next:

- show recent scans and benchmark deltas
- show verification mismatches first
- show current classifier / scanner / service-model artifact versions
- show quick links into HTML reports and training outputs

Success criteria:

- one view answers "what changed, what regressed, and what should be retrained?"

## Tier 2: Runtime And Platform Maturity

### 4. Tighten Python And Rust Runtime Contracts

Status: Open

Why it matters:

- the Rust path is strategically important for faster runtime execution
- artifact compatibility and telemetry assumptions should become more explicit

What should happen next:

- define clearer artifact/runtime compatibility expectations
- validate Rust-consumed metadata more strictly
- align telemetry fields used by Python replay and Rust replay

### 5. Introduce A Plugin Interface For Enrichers

Status: Open

Why it matters:

- enrichment is the most natural extension point in the scanner pipeline
- optional protocol support should not keep bloating core scanner modules

What should happen next:

- define a small enricher interface
- isolate optional dependencies per protocol family
- let experimental enrichers live outside the scanner core

### 6. Expand CI Around Realistic Research Paths

Status: Partially implemented

Why it matters:

- CI already proves packaging, pyright, tests, and tiny classifier training
- it does not yet validate benchmark commands, registry persistence, or service-model retraining flows deeply

What should happen next:

- add benchmark smoke checks
- add experiment-registry write/read smoke coverage
- add a small service-model training/evaluate smoke path

## Tier 3: Research Directions

### 7. Real-Target Calibration Beyond Synthetic And Replay Data

Why it matters:

- synthetic and replay datasets are useful, but real target telemetry still changes model behavior the most

Possible direction:

- expand verified-real datasets
- track which domains each artifact performs well on
- compare synthetic-only, replay-heavy, and verified-real-heavy training mixes

### 8. IPv6 Runtime Maturity

Why it matters:

- Python-side support is further along than Rust-side support
- IPv6-only environments are a real operational case

Possible direction:

- continue aligning raw/runtime support for IPv6 in the Rust path
- add replay and benchmark coverage for IPv6 sessions

### 9. Continuous-Time And Adaptive Scanning Research

Why it matters:

- Betta-Morpho is still a research platform, not only an operator tool

Possible direction:

- continuous-time spiking formulations
- adaptive timing against latency regimes
- adversarial IDS-aware scanning policies
- cross-target transfer of learned scanner behavior

## Known Constraints

These are the important current limits that should stay visible:

| Constraint | Impact | Current mitigation |
|---|---|---|
| Raw mode remains environment-sensitive | Speed and accuracy depend on OS, privileges, and network path | Use connect mode as a control path and benchmark both |
| `--source-port` connect scans serialize intentionally | Lower throughput in that evasion workflow | Keep it narrow and use only where the bypass is relevant |
| UDP inference is still thinner than TCP coverage | More `open\|filtered` ambiguity | Use narrow UDP scopes and protocol-aware follow-up |
| Rust runtime parity is incomplete | Some features still land in Python first | Keep artifact contracts and replay schema aligned |
| Verification loop is not fully automated | More manual curation between scan and retraining | Tier 1.1 |
| Registry and benchmarks are present but not yet dashboarded | Harder to review recent changes at a glance | Tier 1.3 |

## Recommended Execution Order

If only three roadmap items are tackled next, the highest-leverage order is:

1. automate verification-to-retraining lineage
2. extend benchmarks to richer external baselines
3. add a compact operator dashboard on top of registry and benchmark data

That sequence strengthens the project as both a scanner and a research platform.
