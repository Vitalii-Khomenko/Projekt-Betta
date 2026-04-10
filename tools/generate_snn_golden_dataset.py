"""
SNN Golden Dataset Generator - tools/generate_snn_golden_dataset.py
====================================================================
Generates a small deterministic "golden" CSV dataset used to validate scanner
SNN oracle-policy training.  Also generates a larger randomised "massive"
dataset for offline scanner SNN training without a live target.

Key commands:
  python tools/generate_snn_golden_dataset.py \
      --golden-output data/snn_training_batch.csv

  # Run validation suite against generated data:
  python -m unittest tools.test_golden_dataset

Used by tools/test_golden_dataset.py and the scanner SNN training pipeline.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import csv
import math
import random
from pathlib import Path


SIMULATION_STEPS = 100
TAU_MICROS = 50_000.0
GOLDEN_ROWS = [
    (1, 80, 2105, 4, "NORMAL"),
    (2, 443, 1950, 3, "NORMAL"),
    (3, 8080, 2400, 4, "NORMAL"),
    (4, 22, 2010, 3, "NORMAL"),
    (5, 21, 1800, 3, "NORMAL"),
    (6, 3389, 45000, 59, "JITTER_NORMAL"),
    (7, 8443, 48000, 61, "JITTER_NORMAL"),
    (8, 80, 2200, 4, "NORMAL"),
    (9, 443, 1850, 3, "NORMAL"),
    (10, 8022, 250000, 99, "DELAYED_TARPIT"),
    (11, 8023, 245000, 99, "DELAYED_TARPIT"),
    (12, 8024, 260000, 99, "DELAYED_TARPIT"),
    (13, 8025, 300000, 99, "DELAYED_TARPIT"),
    (14, 80, 2150, 4, "NORMAL"),
    (15, 9000, 0, -1, "FILTERED_DROP"),
    (16, 9001, 0, -1, "FILTERED_DROP"),
    (17, 9002, 0, -1, "FILTERED_DROP"),
    (18, 9003, 0, -1, "FILTERED_DROP"),
    (19, 443, 1900, 3, "NORMAL"),
    (20, 135, 800, 1, "REJECTED_RST"),
    (21, 139, 750, 1, "REJECTED_RST"),
    (22, 445, 820, 1, "REJECTED_RST"),
    (23, 1433, 790, 1, "REJECTED_RST"),
    (24, 80, 2300, 4, "NORMAL"),
    (25, 8022, 255000, 99, "DELAYED_TARPIT"),
    (26, 9000, 0, -1, "FILTERED_DROP"),
    (27, 135, 810, 1, "REJECTED_RST"),
    (28, 22, 1980, 3, "NORMAL"),
    (29, 3389, 46000, 60, "JITTER_NORMAL"),
    (30, 8080, 2350, 4, "NORMAL"),
]

MASSIVE_PATTERNS = [
    {"port": 80, "label": "NORMAL", "mean": 2_000.0, "stddev": 200.0},
    {"port": 3389, "label": "JITTER_NORMAL", "mean": 47_000.0, "stddev": 4_000.0},
    {"port": 8022, "label": "DELAYED_TARPIT", "mean": 250_000.0, "stddev": 15_000.0},
    {"port": 9000, "label": "FILTERED_DROP", "mean": 0.0, "stddev": 0.0},
    {"port": 445, "label": "REJECTED_RST", "mean": 800.0, "stddev": 50.0},
]


def compute_spike_step(rtt_micros: int) -> int:
    if rtt_micros <= 0:
        return -1
    spike = SIMULATION_STEPS * (1.0 - math.exp(-rtt_micros / TAU_MICROS))
    return max(0, min(SIMULATION_STEPS - 1, int(spike)))


def write_rows(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["id", "port", "rtt_micros", "spike_step", "label"])
        writer.writeheader()
        writer.writerows(rows)


def build_golden_rows() -> list[dict[str, object]]:
    return [
        {
            "id": row_id,
            "port": port,
            "rtt_micros": rtt_micros,
            "spike_step": spike_step,
            "label": label,
        }
        for row_id, port, rtt_micros, spike_step, label in GOLDEN_ROWS
    ]


def build_massive_rows(samples: int, seed: int) -> list[dict[str, object]]:
    rng = random.Random(seed)
    rows: list[dict[str, object]] = []
    for row_id in range(1, samples + 1):
        pattern = MASSIVE_PATTERNS[(row_id - 1) % len(MASSIVE_PATTERNS)]
        if pattern["label"] == "FILTERED_DROP":
            rtt_micros = 0
        else:
            rtt_micros = max(0, int(rng.gauss(pattern["mean"], pattern["stddev"])))
        rows.append(
            {
                "id": row_id,
                "port": pattern["port"],
                "rtt_micros": rtt_micros,
                "spike_step": compute_spike_step(rtt_micros),
                "label": pattern["label"],
            }
        )
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate the canonical golden SNN timing dataset and an optional large noisy expansion."
    )
    parser.add_argument("--golden-output", default="data/snn_training_batch.csv")
    parser.add_argument("--massive-output", default=None)
    parser.add_argument("--samples", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    golden_rows = build_golden_rows()
    write_rows(Path(args.golden_output), golden_rows)
    print(f"golden_rows={len(golden_rows)} output={args.golden_output}")

    if args.massive_output:
        massive_rows = build_massive_rows(args.samples, args.seed)
        write_rows(Path(args.massive_output), massive_rows)
        print(f"massive_rows={len(massive_rows)} output={args.massive_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

