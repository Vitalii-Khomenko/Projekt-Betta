"""
EventDataset - training/src/snn_cyber/dataset.py
=================================================
PyTorch Dataset that wraps a list of EventSample rows and converts each row
into a TTFS spike train tensor for training the SpikingClassifier.

Used internally by training/train.py - not called directly.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import torch
from torch.utils.data import Dataset

from .schema import LABEL_ORDER, EventSample, RangeSpec, encode_features


def feature_vector(sample: EventSample, ranges: dict[str, RangeSpec]) -> torch.Tensor:
    return torch.tensor(encode_features(sample, ranges), dtype=torch.float32)


class EventDataset(Dataset[tuple[torch.Tensor, torch.Tensor]]):
    def __init__(self, rows: list[EventSample], ranges: dict[str, RangeSpec], steps: int):
        self.rows = rows
        self.ranges = ranges
        self.steps = steps

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        sample = self.rows[index]
        features = feature_vector(sample, self.ranges)
        spikes = torch.zeros(self.steps, features.numel(), dtype=torch.float32)
        for feature_index, value in enumerate(features):
            if value <= 0.0:
                continue
            spike_step = int(round((1.0 - float(value)) * (self.steps - 1)))
            spikes[spike_step, feature_index] = 1.0
        label_index = LABEL_ORDER.index(sample.label)
        return spikes, torch.tensor(label_index, dtype=torch.long)

