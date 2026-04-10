"""
Golden Dataset Unit Tests - tools/test_golden_dataset.py
=========================================================
Unit tests for tools/generate_snn_golden_dataset.py.  Verifies that the golden
and massive row generators produce valid CSV output with expected structure,
TTFS spike-step values, and label distributions.

Key commands:
  python -m unittest tools.test_golden_dataset
  python tools/test_golden_dataset.py

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.generate_snn_golden_dataset import (
    build_golden_rows,
    build_massive_rows,
    compute_spike_step,
    write_rows,
)


class GoldenDatasetTests(unittest.TestCase):
    def test_spike_formula_matches_known_rows(self) -> None:
        self.assertEqual(compute_spike_step(2105), 4)
        self.assertEqual(compute_spike_step(800), 1)
        self.assertEqual(compute_spike_step(250000), 99)
        self.assertEqual(compute_spike_step(0), -1)

    def test_golden_rows_match_expected_size(self) -> None:
        rows = build_golden_rows()
        self.assertEqual(len(rows), 30)
        self.assertEqual(rows[0]["label"], "NORMAL")
        self.assertEqual(rows[-1]["spike_step"], 4)

    def test_massive_rows_cover_all_classes(self) -> None:
        rows = build_massive_rows(25, seed=7)
        labels = {row["label"] for row in rows}
        self.assertEqual(labels, {"NORMAL", "JITTER_NORMAL", "DELAYED_TARPIT", "FILTERED_DROP", "REJECTED_RST"})
        filtered = [row for row in rows if row["label"] == "FILTERED_DROP"]
        self.assertTrue(all(row["spike_step"] == -1 for row in filtered))

    def test_write_rows_persists_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = Path(tmp_dir) / "golden.csv"
            write_rows(path, build_golden_rows())
            with path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 30)
        self.assertEqual(rows[0]["port"], "80")


if __name__ == "__main__":
    unittest.main()

