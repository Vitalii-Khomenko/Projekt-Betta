"""
Passive Host Discovery SNN schema and feature encoding.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.artifact_schema import (
    FAMILY_HOST_DISCOVERY,
    attach_artifact_metadata,
    normalize_artifact_payload,
    validate_artifact_payload,
)

LABEL_ORDER = ["high_value", "supporting", "noise"]
SOURCE_ORDER = [
    "banner",
    "technology",
    "service",
    "service_version",
    "scan_note",
    "tls_san",
    "tls_subject",
    "http_location",
    "http_url",
    "smb_context",
]
NUMERIC_COLUMNS = ["name_length", "label_depth", "evidence_count", "source_port_count", "digit_ratio"]
_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".lab", ".home.arpa", ".htb")
_AUTH_TOKENS = ("auth", "login", "sso", "adfs", "idp", "oauth", "oidc", "kerb", "kerberos", "vpn")
_INFRA_TOKENS = ("dc", "ldap", "dns", "sql", "db", "fs", "file", "mail", "smtp", "mq", "redis", "git", "jenkins")
_WEB_TOKENS = ("www", "web", "api", "app", "portal", "login", "grafana", "wiki", "docs", "console", "admin")
_ADMIN_TOKENS = ("admin", "manage", "console", "panel", "gateway", "vpn")
_NAME_RE = re.compile(r"[a-z0-9-]+", re.IGNORECASE)


@dataclass(frozen=True)
class RangeSpec:
    min: float
    max: float

    def normalize(self, value: float) -> float:
        span = self.max - self.min
        if span <= 0:
            return 0.0
        normalized = (value - self.min) / span
        return max(0.0, min(1.0, normalized))

    def to_dict(self) -> dict[str, float]:
        return {"min": self.min, "max": self.max}


@dataclass(frozen=True)
class LayerSpec:
    weight: list[list[float]]
    bias: list[float]

    def to_dict(self) -> dict[str, list[list[float]] | list[float]]:
        return {"weight": self.weight, "bias": self.bias}


@dataclass(frozen=True)
class HostDiscoverySample:
    candidate_name: str
    source_kinds: list[str]
    evidence_count: int
    source_port_count: int
    label: str = ""
    asset_ip: str = ""
    root_domain: str = ""


@dataclass(frozen=True)
class HostDiscoveryArtifact:
    trainer: str
    steps: int
    beta: float
    threshold: float
    class_names: list[str]
    feature_ranges: dict[str, RangeSpec]
    input_layer: LayerSpec
    output_layer: LayerSpec
    prototypes: dict[str, list[float]] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "trainer": self.trainer,
            "steps": self.steps,
            "beta": self.beta,
            "threshold": self.threshold,
            "class_names": self.class_names,
            "feature_ranges": {name: spec.to_dict() for name, spec in self.feature_ranges.items()},
            "input_layer": self.input_layer.to_dict(),
            "output_layer": self.output_layer.to_dict(),
        }
        if self.prototypes is not None:
            payload["prototypes"] = self.prototypes
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> HostDiscoveryArtifact:
        return cls(
            trainer=str(payload.get("trainer", "prototype")),
            steps=int(payload["steps"]),
            beta=float(payload["beta"]),
            threshold=float(payload["threshold"]),
            class_names=[str(item) for item in payload["class_names"]],
            feature_ranges={
                str(name): RangeSpec(min=float(spec["min"]), max=float(spec["max"]))
                for name, spec in dict(payload["feature_ranges"]).items()
            },
            input_layer=LayerSpec(
                weight=[[float(value) for value in row] for row in payload["input_layer"]["weight"]],
                bias=[float(value) for value in payload["input_layer"]["bias"]],
            ),
            output_layer=LayerSpec(
                weight=[[float(value) for value in row] for row in payload["output_layer"]["weight"]],
                bias=[float(value) for value in payload["output_layer"]["bias"]],
            ),
            prototypes=(
                {
                    str(name): [float(value) for value in values]
                    for name, values in dict(payload.get("prototypes", {})).items()
                }
                if payload.get("prototypes") is not None
                else None
            ),
        )


def _normalized_name(value: str) -> str:
    return value.strip().lower()


def _label_depth(name: str) -> int:
    cleaned = _normalized_name(name)
    return len([part for part in cleaned.split(".") if part])


def _digit_ratio(name: str) -> float:
    cleaned = _normalized_name(name)
    if not cleaned:
        return 0.0
    digits = sum(1 for char in cleaned if char.isdigit())
    return digits / len(cleaned)


def _token_hits(name: str, tokens: tuple[str, ...]) -> float:
    lowered = _normalized_name(name)
    return 1.0 if any(token in lowered for token in tokens) else 0.0


def _is_internal_name(name: str) -> float:
    lowered = _normalized_name(name)
    return 1.0 if lowered.endswith(_INTERNAL_SUFFIXES) else 0.0


def _has_dash(name: str) -> float:
    return 1.0 if "-" in name else 0.0


def _has_dot(name: str) -> float:
    return 1.0 if "." in name else 0.0


def _numeric_value(sample: HostDiscoverySample, column: str) -> float:
    name = _normalized_name(sample.candidate_name)
    if column == "name_length":
        return float(len(name))
    if column == "label_depth":
        return float(_label_depth(name))
    if column == "evidence_count":
        return float(sample.evidence_count)
    if column == "source_port_count":
        return float(sample.source_port_count)
    if column == "digit_ratio":
        return float(_digit_ratio(name))
    raise KeyError(column)


def compute_feature_ranges(rows: list[HostDiscoverySample]) -> dict[str, RangeSpec]:
    result: dict[str, RangeSpec] = {}
    for column in NUMERIC_COLUMNS:
        values = [_numeric_value(row, column) for row in rows]
        low = min(values)
        high = max(values)
        if low == high:
            high = low + 1.0
        result[column] = RangeSpec(min=low, max=high)
    return result


def encode_features(sample: HostDiscoverySample, ranges: dict[str, RangeSpec]) -> list[float]:
    name = _normalized_name(sample.candidate_name)
    sources = {item.strip().lower() for item in sample.source_kinds if item.strip()}
    source_flags = [1.0 if source in sources else 0.0 for source in SOURCE_ORDER]
    numeric_features = [ranges[column].normalize(_numeric_value(sample, column)) for column in NUMERIC_COLUMNS]
    lexical_features = [
        _has_dot(name),
        _has_dash(name),
        _is_internal_name(name),
        _token_hits(name, _AUTH_TOKENS),
        _token_hits(name, _INFRA_TOKENS),
        _token_hits(name, _WEB_TOKENS),
        _token_hits(name, _ADMIN_TOKENS),
        1.0 if _label_depth(name) >= 3 else 0.0,
        1.0 if len(_NAME_RE.findall(name)) >= 2 else 0.0,
    ]
    return source_flags + numeric_features + lexical_features


def build_spike_train(features: list[float], steps: int) -> list[list[float]]:
    spikes = [[0.0 for _ in features] for _ in range(steps)]
    for feature_index, value in enumerate(features):
        if value <= 0.0:
            continue
        spike_step = min(steps - 1, round((1.0 - value) * (steps - 1)))
        spikes[spike_step][feature_index] = 1.0
    return spikes


def load_rows(path: str | Path) -> list[HostDiscoverySample]:
    rows: list[HostDiscoverySample] = []
    with Path(path).open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        for raw_row in reader:
            source_kinds = [
                item.strip().lower()
                for item in str(raw_row.get("source_kinds", "")).replace(",", ";").split(";")
                if item.strip()
            ]
            rows.append(
                HostDiscoverySample(
                    candidate_name=str(raw_row.get("candidate_name", "")).strip().lower(),
                    source_kinds=source_kinds,
                    evidence_count=int(raw_row.get("evidence_count", "0") or 0),
                    source_port_count=int(raw_row.get("source_port_count", "0") or 0),
                    label=str(raw_row.get("label", "")).strip().lower(),
                    asset_ip=str(raw_row.get("asset_ip", "")).strip(),
                    root_domain=str(raw_row.get("root_domain", "")).strip().lower(),
                )
            )
    if not rows:
        raise ValueError(f"no rows found in {path}")
    return rows


def save_artifact(path: str | Path, artifact: HostDiscoveryArtifact) -> None:
    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = attach_artifact_metadata(
        artifact.to_dict(),
        FAMILY_HOST_DISCOVERY,
        model_type="passive-host-discovery-snn",
        producer="tools.host_discovery",
        extra_metadata={"trainer_backend": artifact.trainer},
    )
    artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_artifact(path: str | Path) -> HostDiscoveryArtifact:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_artifact_payload(payload, expected_family=FAMILY_HOST_DISCOVERY)
    normalized = normalize_artifact_payload(
        payload,
        expected_family=FAMILY_HOST_DISCOVERY,
        default_model_type="passive-host-discovery-snn",
        producer="tools.host_discovery",
    )
    return HostDiscoveryArtifact.from_dict(normalized)
