"""Unit tests for training data helpers and validation guards."""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRAINING_SRC = ROOT / "training" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(TRAINING_SRC) not in sys.path:
    sys.path.insert(0, str(TRAINING_SRC))

from snn_cyber.schema import EventSample
from training.generate_synthetic_data import build_asset_pool
from training.train import _validate_training_rows


class TrainingPipelineTests(unittest.TestCase):
    def test_build_asset_pool_returns_unique_count(self) -> None:
        pool = build_asset_pool(random.Random(7), 5)
        self.assertEqual(len(pool), 5)
        self.assertEqual(len(set(pool)), 5)

    def test_validate_training_rows_requires_all_labels(self) -> None:
        rows = [
            EventSample(1, "SYN_ACK", 10.0, 20.0, 30.0, "normal", "10.0.0.1", 80),
            EventSample(2, "SYN_ACK", 12.0, 22.0, 32.0, "delayed", "10.0.0.2", 443),
        ]
        with self.assertRaisesRegex(ValueError, "missing required labels"):
            _validate_training_rows(rows)


if __name__ == "__main__":
    unittest.main()
