"""
Torch dataset for passive hostname discovery training.
"""
from __future__ import annotations

import torch
from torch.utils.data import Dataset

from .schema import LABEL_ORDER, HostDiscoverySample, RangeSpec, encode_features


class HostDiscoveryDataset(Dataset[tuple[torch.Tensor, torch.Tensor]]):
    def __init__(self, rows: list[HostDiscoverySample], ranges: dict[str, RangeSpec], steps: int):
        self.rows = rows
        self.ranges = ranges
        self.steps = steps

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, index: int) -> tuple[torch.Tensor, torch.Tensor]:
        sample = self.rows[index]
        features = torch.tensor(encode_features(sample, self.ranges), dtype=torch.float32)
        spikes = torch.zeros(self.steps, features.numel(), dtype=torch.float32)
        for feature_index, value in enumerate(features):
            if value <= 0.0:
                continue
            spike_step = int(round((1.0 - float(value)) * (self.steps - 1)))
            spikes[spike_step, feature_index] = 1.0
        label_index = LABEL_ORDER.index(sample.label)
        return spikes, torch.tensor(label_index, dtype=torch.long)
