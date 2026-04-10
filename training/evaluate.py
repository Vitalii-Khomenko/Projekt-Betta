"""
Betta-Morpho Classifier Evaluator - training/evaluate.py
================================================
Loads a trained classifier artifact and a labeled CSV, runs inference on every
row, and prints accuracy, macro F1, and a per-class confusion matrix.

Key commands:
  python training/evaluate.py \
      --data data/synthetic_dataset.csv \
      --artifact artifacts/snn_model.json

  # Also via launcher:
  python launcher.py evaluate \
      --data data/synthetic_dataset.csv \
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
PROJECT_ROOT = ROOT.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from snn_cyber.inference import predict_sample
from snn_cyber.metrics import compute_metrics, format_confusion_matrix
from snn_cyber.schema import LABEL_ORDER, load_artifact, load_event_rows


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate an exported SNN artifact on telemetry CSV files.")
    parser.add_argument("--data", required=True, help="Input CSV file")
    parser.add_argument("--artifact", required=True, help="Model artifact JSON")
    parser.add_argument("--preview", type=int, default=5, help="Number of rows to preview")
    parser.add_argument("--asset-ip", help="Optional asset IP filter for offline host-specific analysis")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    artifact = load_artifact(_resolve_project_path(args.artifact))
    rows = load_event_rows(_resolve_project_path(args.data))
    if args.asset_ip:
        rows = [row for row in rows if row.asset_ip == args.asset_ip]
        if not rows:
            raise ValueError(f"no rows found for asset_ip={args.asset_ip}")

    truth: list[int] = []
    predicted_total: list[int] = []
    predicted_labeled: list[int] = []

    for index, row in enumerate(rows):
        predicted_index, logits = predict_sample(artifact, row)
        predicted_total.append(predicted_index)
        if row.label and row.label in LABEL_ORDER:
            truth.append(LABEL_ORDER.index(row.label))
            predicted_labeled.append(predicted_index)
        if index < args.preview:
            print(
                f"row={index} asset={row.asset_ip or '-'} port={row.target_port or 0} "
                f"truth={row.label or '->'} pred={artifact.class_names[predicted_index]} logits={logits}"
            )

    if truth:
        metrics = compute_metrics(truth, predicted_labeled, artifact.class_names)
        print(
            f"samples={metrics.samples} accuracy={metrics.accuracy:.3f} "
            f"macro_precision={metrics.macro_precision:.3f} macro_recall={metrics.macro_recall:.3f} macro_f1={metrics.macro_f1:.3f}"
        )
        unlabeled_count = len(predicted_total) - len(predicted_labeled)
        if unlabeled_count:
            print(f"unlabeled_rows_skipped={unlabeled_count}")
        print(format_confusion_matrix(metrics.confusion_matrix, metrics.labels))
    else:
        print(f"samples={len(predicted_total)} (unlabeled - predictions only, no accuracy computed)")


if __name__ == "__main__":
    main()

