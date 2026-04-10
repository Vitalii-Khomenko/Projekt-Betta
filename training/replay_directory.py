"""
Batch Replay - training/replay_directory.py
============================================
Runs classifier inference over all result CSV files found in a directory tree
(e.g. data/scans/) and prints per-file accuracy + confusion matrix.

Key commands:
  python training/replay_directory.py \
      --data-dir data/scans \
      --artifact artifacts/snn_model.json

  # Also via launcher:
  python launcher.py replay-dir \
      --data-dir data/scans \
      --artifact artifacts/snn_model.json

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
PROJECT_ROOT = ROOT.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from snn_cyber.inference import predict_sample
from snn_cyber.metrics import compute_metrics, format_confusion_matrix
from snn_cyber.schema import LABEL_ORDER, load_artifact, load_event_rows
from tools.path_naming import is_result_csv_name


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Batch replay an artifact across a directory of CSV datasets.")
    parser.add_argument("--data-dir", required=True, help="Directory containing CSV files; searched recursively")
    parser.add_argument("--artifact", required=True, help="Model artifact JSON")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    artifact = load_artifact(_resolve_project_path(args.artifact))
    data_dir = _resolve_project_path(args.data_dir)
    csv_files = sorted(path for path in data_dir.rglob("*.csv") if is_result_csv_name(path.name))
    if not csv_files:
        raise FileNotFoundError(f"no csv files found in {data_dir}")

    all_truth: list[int] = []
    all_predicted: list[int] = []
    for csv_path in csv_files:
        rows = load_event_rows(csv_path)
        truth: list[int] = []
        predicted: list[int] = []
        skipped_unlabeled = 0
        for row in rows:
            predicted_index, _ = predict_sample(artifact, row)
            if row.label and row.label in LABEL_ORDER:
                truth.append(LABEL_ORDER.index(row.label))
                predicted.append(predicted_index)
            else:
                skipped_unlabeled += 1
        if not truth:
            relative_path = csv_path.relative_to(data_dir)
            print(f"file={relative_path} skipped=no-labeled-rows")
            continue
        metrics = compute_metrics(truth, predicted, artifact.class_names)
        all_truth.extend(truth)
        all_predicted.extend(predicted)
        relative_path = csv_path.relative_to(data_dir)
        print(f"file={relative_path} samples={metrics.samples} accuracy={metrics.accuracy:.3f} macro_f1={metrics.macro_f1:.3f}")
        if skipped_unlabeled:
            print(f"  unlabeled_rows_skipped={skipped_unlabeled}")

    if not all_truth:
        raise ValueError(f"no labeled rows found under {data_dir}")
    aggregate = compute_metrics(all_truth, all_predicted, artifact.class_names)
    print(
        f"aggregate samples={aggregate.samples} accuracy={aggregate.accuracy:.3f} "
        f"macro_precision={aggregate.macro_precision:.3f} macro_recall={aggregate.macro_recall:.3f} "
        f"macro_f1={aggregate.macro_f1:.3f}"
    )
    print(format_confusion_matrix(aggregate.confusion_matrix, aggregate.labels))


if __name__ == "__main__":
    main()

