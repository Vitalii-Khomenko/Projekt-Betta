"""
Training Configuration - training/src/snn_cyber/config.py
==========================================================
TrainConfig dataclass that holds all hyperparameters for the SNN classifier
training loop.  Supports loading from YAML or JSON files and saving back.

Key commands:
  # Load config from YAML:
  from snn_cyber.config import load_train_config
  cfg = load_train_config("training/train_config.yaml")

  # Override via CLI (see train.py --help for flags):
  python training/train.py --hidden-dim 32 --epochs 40 --lr 0.001

Used by training/train.py.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class TrainConfig:
    data: str
    artifact: str
    epochs: int = 25
    steps: int = 12
    hidden_dim: int = 12
    batch_size: int = 64
    learning_rate: float = 0.01
    beta: float = 0.82
    threshold: float = 1.0
    seed: int = 7
    trainer: str = "auto"


def _read_structured_file(path: Path) -> dict[str, Any]:
    raw_text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(raw_text)
    else:
        payload = json.loads(raw_text)
    if not isinstance(payload, dict):
        raise ValueError(f"config file must contain an object: {path}")
    return payload


def load_train_config(path: str | Path) -> TrainConfig:
    payload = _read_structured_file(Path(path))
    return TrainConfig(
        data=str(payload["data"]),
        artifact=str(payload["artifact"]),
        epochs=int(payload.get("epochs", 25)),
        steps=int(payload.get("steps", 12)),
        hidden_dim=int(payload.get("hidden_dim", 12)),
        batch_size=int(payload.get("batch_size", 64)),
        learning_rate=float(payload.get("learning_rate", 0.01)),
        beta=float(payload.get("beta", 0.82)),
        threshold=float(payload.get("threshold", 1.0)),
        seed=int(payload.get("seed", 7)),
        trainer=str(payload.get("trainer", "auto")),
    )


def save_train_config(path: str | Path, config: TrainConfig) -> None:
    config_path = Path(path)
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(config)
    if config_path.suffix.lower() in {".yaml", ".yml"}:
        config_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        return
    config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

