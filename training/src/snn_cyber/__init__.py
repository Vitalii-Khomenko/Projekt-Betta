"""
snn_cyber package exports for the Betta-Morpho classifier library.

Config helpers are loaded lazily so inference-only workflows do not require
optional YAML dependencies at import time.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .schema import EventSample, ModelArtifact, RangeSpec, compute_feature_ranges, load_artifact, load_event_rows, save_artifact

if TYPE_CHECKING:
    from .config import TrainConfig, load_train_config, save_train_config

_CONFIG_EXPORTS = {"TrainConfig", "load_train_config", "save_train_config"}


def __getattr__(name: str) -> Any:
    if name in _CONFIG_EXPORTS:
        from . import config as _config

        return getattr(_config, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "EventSample",
    "ModelArtifact",
    "RangeSpec",
    "TrainConfig",
    "compute_feature_ranges",
    "load_artifact",
    "load_event_rows",
    "load_train_config",
    "save_artifact",
    "save_train_config",
]
