"""
Evaluation Metrics - training/src/snn_cyber/metrics.py
=======================================================
Computes accuracy, per-class precision/recall/F1, macro F1, and a confusion
matrix from lists of ground-truth and predicted label indices.

Used by training/train.py and training/evaluate.py.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EvaluationMetrics:
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    confusion_matrix: list[list[int]]
    labels: list[str]
    samples: int


def build_confusion_matrix(true_labels: list[int], predicted_labels: list[int], class_count: int) -> list[list[int]]:
    matrix = [[0 for _ in range(class_count)] for _ in range(class_count)]
    for truth, prediction in zip(true_labels, predicted_labels):
        matrix[truth][prediction] += 1
    return matrix


def compute_metrics(true_labels: list[int], predicted_labels: list[int], labels: list[str]) -> EvaluationMetrics:
    if len(true_labels) != len(predicted_labels):
        raise ValueError("label arrays must have equal length")
    class_count = len(labels)
    matrix = build_confusion_matrix(true_labels, predicted_labels, class_count)
    samples = len(true_labels)
    accuracy = sum(matrix[index][index] for index in range(class_count)) / max(samples, 1)

    precisions: list[float] = []
    recalls: list[float] = []
    f1_scores: list[float] = []
    for index in range(class_count):
        true_positive = matrix[index][index]
        predicted_total = sum(matrix[row][index] for row in range(class_count))
        actual_total = sum(matrix[index][column] for column in range(class_count))
        precision = true_positive / predicted_total if predicted_total else 0.0
        recall = true_positive / actual_total if actual_total else 0.0
        f1 = (2.0 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        precisions.append(precision)
        recalls.append(recall)
        f1_scores.append(f1)

    return EvaluationMetrics(
        accuracy=accuracy,
        macro_precision=sum(precisions) / max(class_count, 1),
        macro_recall=sum(recalls) / max(class_count, 1),
        macro_f1=sum(f1_scores) / max(class_count, 1),
        confusion_matrix=matrix,
        labels=labels,
        samples=samples,
    )


def format_confusion_matrix(matrix: list[list[int]], labels: list[str]) -> str:
    header = ["truth\\pred"] + labels
    widths = [max(len(str(cell)) for cell in column) for column in zip(header, *([[labels[index]] + row for index, row in enumerate(matrix)]))]
    lines = []
    lines.append("  ".join(value.ljust(width) for value, width in zip(header, widths)))
    for label, row in zip(labels, matrix):
        values = [label] + [str(cell) for cell in row]
        lines.append("  ".join(value.ljust(width) for value, width in zip(values, widths)))
    return "\n".join(lines)

