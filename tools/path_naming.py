"""Shared path and artifact naming helpers for Betta-Morpho."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path


def sanitize_target(value: str) -> str:
    cleaned = value.strip().strip("[]")
    for token in ("/", "\\", ":", " "):
        cleaned = cleaned.replace(token, "_")
    while "__" in cleaned:
        cleaned = cleaned.replace("__", "_")
    return cleaned or "unknown_target"


def build_session_prefix(target: str, timestamp: str | None = None) -> str:
    stamp = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{stamp}_{sanitize_target(target)}"


def build_scan_output_paths(base_dir: Path, target: str, timestamp: str | None = None) -> dict[str, Path | str]:
    prefix = build_session_prefix(target, timestamp=timestamp)
    output_dir = base_dir / prefix
    return {
        "prefix": prefix,
        "dir": output_dir,
        "result_csv": output_dir / f"{prefix}_result.csv",
        "report_html": output_dir / f"{prefix}_report.html",
        "progress_log": output_dir / f"{prefix}_progress.log",
        "active_learning_csv": output_dir / f"{prefix}_active_learning.csv",
        "classified_csv": output_dir / f"{prefix}_classified.csv",
    }


def select_scan_output_base_dir(default_base_dir: Path, *preferred_paths: str | Path | None) -> Path:
    for candidate in preferred_paths:
        if not candidate:
            continue
        path = Path(candidate)
        return path if not path.suffix else path.parent
    return default_base_dir


def build_report_bundle_paths(
    default_base_dir: Path,
    target: str,
    *preferred_paths: str | Path | None,
    timestamp: str | None = None,
) -> dict[str, Path | str]:
    base_dir = select_scan_output_base_dir(default_base_dir, *preferred_paths)
    return build_scan_output_paths(base_dir, target, timestamp=timestamp)


def infer_session_prefix(path: Path) -> str:
    stem = path.stem
    for suffix in (
        "_result",
        "_report",
        "_progress",
        "_active_learning",
        "_classified",
        "_comparison",
        "_service_training",
        "_nmap_verify",
    ):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return path.parent.name or stem


def is_result_csv_name(name: str) -> bool:
    return name == "result.csv" or name.endswith("_result.csv")


def is_service_training_csv_name(name: str) -> bool:
    return name == "service_training.csv" or name.endswith("_service_training.csv")
