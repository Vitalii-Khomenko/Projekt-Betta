"""
Core Schema & Feature Encoding - training/src/snn_cyber/schema.py
==================================================================
Defines the shared data structures and encoding logic used across all training
and inference code:

  EventSample    - one row from the telemetry CSV (timestamp, IP, port, RTT, ...)
  RangeSpec      - min/max range for a single feature; .normalize() -> [0, 1]
  ModelArtifact  - serializable classifier artifact (weights, ranges, metadata)

Key functions:
  load_event_rows(csv_path)         -> list[EventSample]
  compute_feature_ranges(rows)      -> dict[str, RangeSpec]   (data-driven min/max)
  encode_features(sample, ranges)   -> list[float]            (normalised [0,1])
  build_spike_train(features, steps)-> list[list[float]]      (TTFS encoding)
  load_artifact(path) / save_artifact(artifact, path)

Feature order: timestamp_us, target_port, protocol_flag (one-hot  - 6),
               inter_packet_time_us, payload_size, rtt_us

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools.artifact_schema import (
    FAMILY_CLASSIFIER,
    attach_artifact_metadata,
    normalize_artifact_payload,
    validate_artifact_payload,
)

FLAG_ORDER = ["SYN_ACK", "RST", "TIMEOUT", "UDP_RESPONSE", "ICMP_UNREACHABLE", "ICMP_REPLY"]
LABEL_ORDER = ["normal", "delayed", "filtered"]
NUMERIC_COLUMNS = ["inter_packet_time_us", "payload_size", "rtt_us"]


@dataclass(frozen=True)
class EventSample:
    timestamp_us: int
    protocol_flag: str
    inter_packet_time_us: float
    payload_size: float
    rtt_us: float
    label: str
    asset_ip: str = ""
    target_port: int = 0


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
class ModelArtifact:
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
    def from_dict(cls, payload: dict[str, Any]) -> ModelArtifact:
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


def load_artifact(path: str | Path) -> ModelArtifact:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_artifact_payload(payload, expected_family=FAMILY_CLASSIFIER)
    normalized = normalize_artifact_payload(
        payload,
        expected_family=FAMILY_CLASSIFIER,
        default_model_type="telemetry-snn-classifier",
        producer="training.train",
    )
    return ModelArtifact.from_dict(normalized)


def save_artifact(path: str | Path, artifact: ModelArtifact) -> None:
    artifact_path = Path(path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = attach_artifact_metadata(
        artifact.to_dict(),
        FAMILY_CLASSIFIER,
        model_type="telemetry-snn-classifier",
        producer="training.train",
        extra_metadata={"trainer_backend": artifact.trainer},
    )
    artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_event_rows(path: str | Path) -> list[EventSample]:
    rows: list[EventSample] = []
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for raw_row in reader:
            rows.append(
                EventSample(
                    timestamp_us=int(raw_row["timestamp_us"]),
                    protocol_flag=raw_row["protocol_flag"].strip().upper(),
                    inter_packet_time_us=float(raw_row["inter_packet_time_us"]),
                    payload_size=float(raw_row["payload_size"]),
                    rtt_us=float(raw_row["rtt_us"]),
                    label=raw_row.get("label", "normal").strip().lower(),
                    asset_ip=raw_row.get("asset_ip", "").strip(),
                    target_port=int(raw_row.get("target_port", "0") or 0),
                )
            )
    if not rows:
        raise ValueError(f"no rows found in {path}")
    return rows


def compute_feature_ranges(rows: list[EventSample]) -> dict[str, RangeSpec]:
    result: dict[str, RangeSpec] = {}
    for column in NUMERIC_COLUMNS:
        values = [float(getattr(row, column)) for row in rows]
        low = min(values)
        high = max(values)
        if low == high:
            high = low + 1.0
        result[column] = RangeSpec(min=low, max=high)
    return result


def encode_features(sample: EventSample, ranges: dict[str, RangeSpec]) -> list[float]:
    flags = [1.0 if sample.protocol_flag == flag else 0.0 for flag in FLAG_ORDER]
    inter_packet = 1.0 - ranges["inter_packet_time_us"].normalize(sample.inter_packet_time_us)
    payload = ranges["payload_size"].normalize(sample.payload_size)
    rtt = 1.0 - ranges["rtt_us"].normalize(sample.rtt_us)
    return flags + [inter_packet, payload, rtt]


def build_spike_train(features: list[float], steps: int) -> list[list[float]]:
    spikes = [[0.0 for _ in features] for _ in range(steps)]
    for feature_index, value in enumerate(features):
        if value <= 0.0:
            continue
        spike_step = min(steps - 1, round((1.0 - value) * (steps - 1)))
        spikes[spike_step][feature_index] = 1.0
    return spikes

