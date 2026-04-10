"""
SpikingClassifier Model - training/src/snn_cyber/model.py
==========================================================
PyTorch Spiking Neural Network (SNN) classifier with Leaky Integrate-and-Fire
(LIF) neurons and surrogate-gradient backpropagation.  Two fully-connected
layers: input->hidden (LIF) and hidden->output (LIF with spike-rate readout).

Architecture: input_features -> hidden_dim (LIF) -> num_classes (LIF)
Spike encoding: TTFS (Time-to-First-Spike) over T steps
Training loss: cross-entropy on cumulative output spike counts

Used exclusively by training/train.py.  Not called directly.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import torch
from torch import nn
from typing import Any


class SurrogateSpike(torch.autograd.Function):
    @staticmethod
    def forward(ctx, input_tensor: torch.Tensor) -> torch.Tensor:
        ctx.save_for_backward(input_tensor)
        return (input_tensor > 0).to(input_tensor.dtype)

    @staticmethod
    def backward(ctx: Any, grad_outputs: torch.Tensor) -> tuple[torch.Tensor, ...]:
        (input_tensor,) = ctx.saved_tensors
        scale = torch.sigmoid(input_tensor)
        gradient = scale * (1.0 - scale)
        return (grad_outputs * gradient * 4.0,)


spike_fn = SurrogateSpike.apply


class SpikingClassifier(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, beta: float, threshold: float):
        super().__init__()
        self.input_layer = nn.Linear(input_dim, hidden_dim)
        self.output_layer = nn.Linear(hidden_dim, output_dim)
        self.beta = beta
        self.threshold = threshold

    def forward(self, spikes: torch.Tensor) -> torch.Tensor:
        batch_size, steps, _ = spikes.shape
        hidden_membrane = torch.zeros(batch_size, self.input_layer.out_features, device=spikes.device)
        output_membrane = torch.zeros(batch_size, self.output_layer.out_features, device=spikes.device)
        output_spike_count = torch.zeros_like(output_membrane)

        for step in range(steps):
            input_current = self.input_layer(spikes[:, step, :])
            hidden_membrane = hidden_membrane * self.beta + input_current
            hidden_spikes = spike_fn(hidden_membrane - self.threshold)
            hidden_membrane = hidden_membrane * (1.0 - hidden_spikes.detach())

            output_current = self.output_layer(hidden_spikes)
            output_membrane = output_membrane * self.beta + output_current
            output_spikes = spike_fn(output_membrane - self.threshold)
            output_membrane = output_membrane * (1.0 - output_spikes.detach())
            output_spike_count = output_spike_count + output_spikes

        return output_spike_count + 0.01 * output_membrane

