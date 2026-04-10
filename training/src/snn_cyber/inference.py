"""
Classifier Inference - training/src/snn_cyber/inference.py
===========================================================
Runs a forward pass on a trained ModelArtifact and returns the predicted class
index and confidence score.  Supports both 'torch' and 'prototype' artifact
types - no GPU required for prototype inference.

Used by train.py (evaluation), evaluate.py, scanner.py (--report pipeline),
and the Rust replay binary via the exported JSON artifact.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

from .schema import EventSample, ModelArtifact, build_spike_train, encode_features


def infer_from_features(artifact: ModelArtifact, feature_vector: list[float]) -> tuple[int, list[float]]:
    if artifact.trainer == "prototype" and artifact.prototypes is not None:
        logits = []
        for class_name in artifact.class_names:
            prototype = artifact.prototypes[class_name]
            distance = sum((value - center) ** 2 for value, center in zip(feature_vector, prototype))
            logits.append(-distance)
        predicted = max(range(len(logits)), key=lambda index: logits[index])
        return predicted, logits

    spike_train = build_spike_train(feature_vector, artifact.steps)
    hidden_membrane = [0.0 for _ in artifact.input_layer.bias]
    output_membrane = [0.0 for _ in artifact.output_layer.bias]
    output_spike_count = [0.0 for _ in artifact.output_layer.bias]

    for step_input in spike_train:
        input_current = [
            sum(weight * value for weight, value in zip(row, step_input)) + bias
            for row, bias in zip(artifact.input_layer.weight, artifact.input_layer.bias)
        ]
        for index, current in enumerate(input_current):
            hidden_membrane[index] = hidden_membrane[index] * artifact.beta + current
        hidden_spikes = [1.0 if value > artifact.threshold else 0.0 for value in hidden_membrane]
        for index, spike in enumerate(hidden_spikes):
            hidden_membrane[index] *= 1.0 - spike

        output_current = [
            sum(weight * value for weight, value in zip(row, hidden_spikes)) + bias
            for row, bias in zip(artifact.output_layer.weight, artifact.output_layer.bias)
        ]
        for index, current in enumerate(output_current):
            output_membrane[index] = output_membrane[index] * artifact.beta + current
        output_spikes = [1.0 if value > artifact.threshold else 0.0 for value in output_membrane]
        for index, spike in enumerate(output_spikes):
            output_membrane[index] *= 1.0 - spike
            output_spike_count[index] += spike

    logits = [spike_count + 0.01 * membrane for spike_count, membrane in zip(output_spike_count, output_membrane)]
    predicted = max(range(len(logits)), key=lambda index: logits[index])
    return predicted, logits


def predict_sample(artifact: ModelArtifact, sample: EventSample) -> tuple[int, list[float]]:
    return infer_from_features(artifact, encode_features(sample, artifact.feature_ranges))

