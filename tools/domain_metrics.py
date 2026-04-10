"""Summarize benchmark quality across synthetic, replayed, and verified-real domains."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

try:
    from tools.experiment_registry import DEFAULT_REGISTRY_PATH, ExperimentRegistry
except ImportError:
    from experiment_registry import DEFAULT_REGISTRY_PATH, ExperimentRegistry


def build_domain_summary(registry_path: str | Path = DEFAULT_REGISTRY_PATH, *, kind: str = "benchmark") -> dict[str, Any]:
    registry = ExperimentRegistry(registry_path)
    return registry.aggregate_metrics_by_domain(kind=kind)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Aggregate Betta-Morpho experiment metrics by data domain.")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY_PATH), help="Experiment registry SQLite path")
    parser.add_argument("--kind", default="benchmark", help="Experiment kind to summarize")
    parser.add_argument("--output", help="Optional JSON output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    summary = build_domain_summary(args.registry, kind=args.kind)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
