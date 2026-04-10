"""Unified artifact schema helpers for Betta-Morpho."""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ARTIFACT_SCHEMA_VERSION = 1

FAMILY_CLASSIFIER = "classifier-snn"
FAMILY_SCANNER = "scanner-snn"
FAMILY_SERVICE = "service-fingerprint"
FAMILY_SERVICE_CATALOG = "service-catalog"
FAMILY_BENCHMARK = "benchmark-report"
FAMILY_DEFENSE_DETECTOR = "defense-detector"


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def infer_legacy_family(payload: dict[str, Any]) -> str:
    if payload.get("benchmark_kind") == "scan-comparison":
        return FAMILY_BENCHMARK
    if "catalog_type" in payload:
        return FAMILY_SERVICE_CATALOG
    if payload.get("model_type") == "service-fingerprint-naive-bayes":
        return FAMILY_SERVICE
    if payload.get("model_type") == "defense-session-centroid":
        return FAMILY_DEFENSE_DETECTOR
    if "scanner_version" in payload or payload.get("actions"):
        return FAMILY_SCANNER
    if "input_layer" in payload and "output_layer" in payload and "class_names" in payload:
        return FAMILY_CLASSIFIER
    return "unknown"


def attach_artifact_metadata(
    payload: dict[str, Any],
    family: str,
    *,
    model_type: str,
    producer: str,
    schema_version: int = ARTIFACT_SCHEMA_VERSION,
    extra_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    enriched = dict(payload)
    enriched.setdefault("artifact_family", family)
    enriched.setdefault("artifact_schema_version", int(schema_version))
    enriched.setdefault("artifact_created_at", utc_now_iso())
    enriched.setdefault("artifact_producer", producer)
    enriched.setdefault("model_type", model_type)
    metadata = dict(enriched.get("artifact_metadata", {}))
    if extra_metadata:
        metadata.update(extra_metadata)
    if metadata:
        enriched["artifact_metadata"] = metadata
    return enriched


def normalize_artifact_payload(
    payload: dict[str, Any],
    *,
    expected_family: str | None = None,
    default_model_type: str = "",
    producer: str = "",
) -> dict[str, Any]:
    family = str(payload.get("artifact_family") or infer_legacy_family(payload))
    if expected_family and family not in {"unknown", expected_family}:
        raise ValueError(f"artifact family mismatch: expected {expected_family}, got {family}")
    normalized = dict(payload)
    normalized.setdefault("artifact_family", expected_family or family)
    normalized.setdefault("artifact_schema_version", ARTIFACT_SCHEMA_VERSION)
    normalized.setdefault("artifact_created_at", "")
    normalized.setdefault("artifact_producer", producer)
    if default_model_type:
        normalized.setdefault("model_type", default_model_type)
    normalized.setdefault("artifact_metadata", {})
    return normalized


def validate_artifact_payload(payload: dict[str, Any], expected_family: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("artifact payload must be a JSON object")
    normalized = normalize_artifact_payload(payload, expected_family=expected_family)
    schema_version = int(normalized.get("artifact_schema_version", 0) or 0)
    if schema_version < 1:
        raise ValueError(f"invalid artifact schema version: {schema_version}")
    return {
        "artifact_family": normalized.get("artifact_family", ""),
        "artifact_schema_version": schema_version,
        "model_type": normalized.get("model_type", ""),
        "legacy": "artifact_family" not in payload,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Betta-Morpho artifact metadata.")
    parser.add_argument("artifact", help="Path to an artifact JSON file")
    parser.add_argument("--expected-family", default=None, help="Optional expected artifact family")
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    payload = json.loads(Path(args.artifact).read_text(encoding="utf-8"))
    info = validate_artifact_payload(payload, expected_family=args.expected_family)
    print(
        f"family={info['artifact_family']} schema_version={info['artifact_schema_version']} "
        f"model_type={info['model_type']} legacy={info['legacy']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
