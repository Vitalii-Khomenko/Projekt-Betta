"""Compare two Betta-Morpho scan outputs and persist benchmark metrics."""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path
from typing import Any

try:
    from tools.artifact_schema import FAMILY_BENCHMARK, attach_artifact_metadata
    from tools.experiment_registry import DEFAULT_REGISTRY_PATH, ExperimentRegistry, RegistryArtifact
except ImportError:
    from artifact_schema import FAMILY_BENCHMARK, attach_artifact_metadata
    from experiment_registry import DEFAULT_REGISTRY_PATH, ExperimentRegistry, RegistryArtifact

OPEN_PROTOCOL_FLAGS = {"SYN_ACK", "UDP_RESPONSE", "ICMP_REPLY"}


def _load_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [dict(row) for row in reader]


def _is_open(row: dict[str, str]) -> bool:
    protocol_flag = str(row.get("protocol_flag", "")).upper()
    state = str(row.get("state", "")).lower()
    return protocol_flag in OPEN_PROTOCOL_FLAGS or state == "open"


def _open_port_map(rows: list[dict[str, str]]) -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = {}
    for row in rows:
        if not _is_open(row):
            continue
        try:
            port = int(row.get("target_port", "0") or 0)
        except ValueError:
            continue
        if port <= 0:
            continue
        result[port] = row
    return result


def _normalize_service(value: str) -> str:
    cleaned = re.sub(r"\s+", " ", value.strip().lower())
    return re.sub(r"[^a-z0-9.+/_ -]+", "", cleaned)


def _best_service_label(row: dict[str, str]) -> str:
    for key in ("service_prediction", "service", "service_version"):
        value = str(row.get(key, "")).strip()
        if value:
            return _normalize_service(value)
    return ""


def _extract_elapsed_seconds(progress_log: str | Path | None) -> float | None:
    if not progress_log:
        return None
    path = Path(progress_log)
    if not path.exists():
        return None
    elapsed: float | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.search(r"elapsed_seconds=([0-9]+(?:\.[0-9]+)?)", line)
        if match:
            elapsed = float(match.group(1))
    return elapsed


def compare_scan_results(
    *,
    baseline_csv: str | Path,
    candidate_csv: str | Path,
    baseline_progress_log: str | Path | None = None,
    candidate_progress_log: str | Path | None = None,
) -> dict[str, Any]:
    baseline_rows = _load_csv(baseline_csv)
    candidate_rows = _load_csv(candidate_csv)
    baseline_open = _open_port_map(baseline_rows)
    candidate_open = _open_port_map(candidate_rows)
    baseline_ports = set(baseline_open)
    candidate_ports = set(candidate_open)
    overlap = baseline_ports & candidate_ports
    baseline_only = sorted(baseline_ports - candidate_ports)
    candidate_only = sorted(candidate_ports - baseline_ports)

    service_overlap = 0
    service_matches = 0
    for port in sorted(overlap):
        baseline_service = _best_service_label(baseline_open[port])
        candidate_service = _best_service_label(candidate_open[port])
        if not baseline_service or not candidate_service:
            continue
        service_overlap += 1
        if baseline_service == candidate_service:
            service_matches += 1

    baseline_elapsed = _extract_elapsed_seconds(baseline_progress_log)
    candidate_elapsed = _extract_elapsed_seconds(candidate_progress_log)
    recall = len(overlap) / len(baseline_ports) if baseline_ports else 1.0
    precision = len(overlap) / len(candidate_ports) if candidate_ports else 1.0
    result: dict[str, Any] = {
        "baseline": {
            "path": str(Path(baseline_csv)),
            "open_ports": sorted(baseline_ports),
            "open_count": len(baseline_ports),
            "elapsed_seconds": baseline_elapsed,
        },
        "candidate": {
            "path": str(Path(candidate_csv)),
            "open_ports": sorted(candidate_ports),
            "open_count": len(candidate_ports),
            "elapsed_seconds": candidate_elapsed,
        },
        "metrics": {
            "matched_open_count": float(len(overlap)),
            "baseline_only_count": float(len(baseline_only)),
            "candidate_only_count": float(len(candidate_only)),
            "recall_vs_baseline": float(recall),
            "precision_vs_baseline": float(precision),
            "service_precision_on_overlap": float(service_matches / service_overlap) if service_overlap else 1.0,
        },
        "differences": {
            "baseline_only_ports": baseline_only,
            "candidate_only_ports": candidate_only,
        },
    }
    if baseline_elapsed is not None and candidate_elapsed is not None and baseline_elapsed > 0:
        result["metrics"]["candidate_speedup_vs_baseline"] = float(baseline_elapsed / candidate_elapsed)
    return result


def build_benchmark_manifest(
    *,
    baseline_csv: str | Path,
    candidate_csv: str | Path,
    baseline_label: str,
    candidate_label: str,
    domain: str,
    baseline_progress_log: str | Path | None = None,
    candidate_progress_log: str | Path | None = None,
) -> dict[str, Any]:
    comparison = compare_scan_results(
        baseline_csv=baseline_csv,
        candidate_csv=candidate_csv,
        baseline_progress_log=baseline_progress_log,
        candidate_progress_log=candidate_progress_log,
    )
    manifest = {
        "benchmark_kind": "scan-comparison",
        "benchmark_version": 1,
        "domain": domain,
        "baseline_label": baseline_label,
        "candidate_label": candidate_label,
        **comparison,
    }
    return attach_artifact_metadata(
        manifest,
        FAMILY_BENCHMARK,
        model_type="scan-comparison",
        producer="tools.benchmark_scans",
        extra_metadata={"baseline_label": baseline_label, "candidate_label": candidate_label},
    )


def register_manifest(
    manifest: dict[str, Any],
    *,
    registry_path: str | Path = DEFAULT_REGISTRY_PATH,
    name: str = "",
) -> int:
    metrics = {
        key: float(value)
        for key, value in dict(manifest.get("metrics", {})).items()
        if isinstance(value, (int, float))
    }
    registry = ExperimentRegistry(registry_path)
    return registry.register_experiment(
        name=name or f"{manifest.get('candidate_label', 'candidate')} vs {manifest.get('baseline_label', 'baseline')}",
        kind="benchmark",
        domain=str(manifest.get("domain", "unknown")),
        metadata={
            "baseline_label": manifest.get("baseline_label", ""),
            "candidate_label": manifest.get("candidate_label", ""),
            "baseline_csv": manifest.get("baseline", {}).get("path", ""),
            "candidate_csv": manifest.get("candidate", {}).get("path", ""),
            "differences": manifest.get("differences", {}),
        },
        metrics=metrics,
        artifacts=[
            RegistryArtifact(role="baseline_scan", path=str(manifest.get("baseline", {}).get("path", ""))),
            RegistryArtifact(role="candidate_scan", path=str(manifest.get("candidate", {}).get("path", ""))),
        ],
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Benchmark one Betta-Morpho scan output against another.")
    parser.add_argument("--baseline-csv", required=True, help="Baseline result CSV")
    parser.add_argument("--candidate-csv", required=True, help="Candidate result CSV")
    parser.add_argument("--baseline-progress-log", help="Optional baseline progress log")
    parser.add_argument("--candidate-progress-log", help="Optional candidate progress log")
    parser.add_argument("--baseline-label", default="baseline", help="Human-readable baseline label")
    parser.add_argument("--candidate-label", default="candidate", help="Human-readable candidate label")
    parser.add_argument("--domain", default="verified_real", help="Benchmark domain: synthetic, verified_real, replay, or custom")
    parser.add_argument("--output", help="Optional manifest JSON output path")
    parser.add_argument("--register", action="store_true", help="Store this benchmark in the experiment registry")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH), help="Experiment registry SQLite path")
    parser.add_argument("--name", default="", help="Optional benchmark name for the experiment registry")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    manifest = build_benchmark_manifest(
        baseline_csv=args.baseline_csv,
        candidate_csv=args.candidate_csv,
        baseline_label=args.baseline_label,
        candidate_label=args.candidate_label,
        domain=args.domain,
        baseline_progress_log=args.baseline_progress_log,
        candidate_progress_log=args.candidate_progress_log,
    )
    if args.register:
        experiment_id = register_manifest(manifest, registry_path=args.registry, name=args.name)
        manifest["experiment_id"] = experiment_id
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
