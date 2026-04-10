"""
Betta-Morpho Classifier Trainer - training/train.py
==========================================
Trains the SNN port-state classifier (normal / delayed / filtered) on labeled
network telemetry.  Supports two backends: PyTorch surrogate-gradient (default)
and a prototype/centroid fallback that requires no GPU.

Key commands:
  # Standard training on the balanced synthetic dataset
  python training/train.py \
      --data data/synthetic_dataset.csv \
      --artifact artifacts/snn_model.json \
      --trainer auto --epochs 40 --steps 12 --hidden-dim 16 \
      --batch-size 64 --learning-rate 0.01 --beta 0.82 --threshold 1.0 --seed 42

  # Save effective config for reproducibility
  python training/train.py --data ... --artifact ... --save-config configs/run.yaml

  # Force prototype backend (no PyTorch required)
  python training/train.py --data ... --artifact ... --trainer prototype

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
PROJECT_ROOT = ROOT.parent
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from snn_cyber.inference import infer_from_features
from snn_cyber.metrics import compute_metrics
from snn_cyber.schema import LABEL_ORDER, EventSample, LayerSpec, ModelArtifact, compute_feature_ranges, encode_features, load_event_rows, save_artifact


@dataclass(frozen=True)
class TrainingSummary:
    trainer: str
    accuracy: float
    macro_f1: float


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def _validate_training_rows(rows: list[EventSample]) -> None:
    if len(rows) < 2:
        raise ValueError("training requires at least 2 labeled rows")
    present_labels = {row.label for row in rows}
    missing_labels = [label for label in LABEL_ORDER if label not in present_labels]
    if missing_labels:
        missing = ", ".join(missing_labels)
        raise ValueError(f"training data is missing required labels: {missing}")


def build_prototype_artifact(rows: list[EventSample], steps: int, beta: float, threshold: float) -> ModelArtifact:
    ranges = compute_feature_ranges(rows)
    grouped: dict[str, list[list[float]]] = {label: [] for label in LABEL_ORDER}
    for row in rows:
        grouped[row.label].append(encode_features(row, ranges))

    prototypes: dict[str, list[float]] = {}
    for label, vectors in grouped.items():
        dimensions = len(vectors[0])
        prototypes[label] = [sum(vector[index] for vector in vectors) / len(vectors) for index in range(dimensions)]

    hidden_dim = len(next(iter(prototypes.values())))
    input_weight = [[0.0 for _ in range(hidden_dim)] for _ in range(hidden_dim)]
    for index in range(hidden_dim):
        input_weight[index][index] = 2.0

    output_weight: list[list[float]] = []
    output_bias: list[float] = []
    for label in LABEL_ORDER:
        prototype = prototypes[label]
        output_weight.append([1.6 * value for value in prototype])
        output_bias.append(-0.2)

    return ModelArtifact(
        trainer="prototype",
        steps=steps,
        beta=beta,
        threshold=threshold,
        class_names=list(LABEL_ORDER),
        feature_ranges=ranges,
        input_layer=LayerSpec(weight=input_weight, bias=[0.0 for _ in range(hidden_dim)]),
        output_layer=LayerSpec(weight=output_weight, bias=output_bias),
        prototypes=prototypes,
    )


def evaluate_artifact(rows: list[EventSample], artifact: ModelArtifact) -> TrainingSummary:
    truth: list[int] = []
    predicted: list[int] = []
    for row in rows:
        predicted_index, _ = infer_from_features(artifact, encode_features(row, artifact.feature_ranges))
        truth.append(LABEL_ORDER.index(row.label))
        predicted.append(predicted_index)
    metrics = compute_metrics(truth, predicted, artifact.class_names)
    return TrainingSummary(trainer=artifact.trainer, accuracy=metrics.accuracy, macro_f1=metrics.macro_f1)


def train_with_torch(rows: list[EventSample], args: argparse.Namespace) -> ModelArtifact | None:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, random_split

        from snn_cyber.dataset import EventDataset
        from snn_cyber.model import SpikingClassifier
    except Exception as error:
        print(f"torch trainer unavailable, falling back to prototype trainer: {error}")
        return None

    torch.manual_seed(args.seed)
    ranges = compute_feature_ranges(rows)
    dataset = EventDataset(rows, ranges, args.steps)
    validation_size = max(1, int(len(dataset) * 0.2))
    train_size = len(dataset) - validation_size
    train_set, validation_set = random_split(
        dataset,
        [train_size, validation_size],
        generator=torch.Generator().manual_seed(args.seed),
    )

    train_loader = DataLoader(train_set, batch_size=args.batch_size, shuffle=True)
    validation_loader = DataLoader(validation_set, batch_size=args.batch_size)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    input_dim = len(encode_features(rows[0], ranges))
    model = SpikingClassifier(input_dim, args.hidden_dim, len(LABEL_ORDER), args.beta, args.threshold).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(1, args.epochs + 1):
        model.train()
        running_loss = 0.0
        examples = 0
        for spikes, labels in train_loader:
            spikes = spikes.to(device)
            labels = labels.to(device)
            optimizer.zero_grad(set_to_none=True)
            logits = model(spikes)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()
            batch_size = int(labels.size(0))
            running_loss += float(loss.item()) * batch_size
            examples += batch_size

        model.eval()
        validation_truth: list[int] = []
        validation_predicted: list[int] = []
        validation_loss = 0.0
        validation_examples = 0
        with torch.no_grad():
            for spikes, labels in validation_loader:
                spikes = spikes.to(device)
                labels = labels.to(device)
                logits = model(spikes)
                loss = criterion(logits, labels)
                batch_size = int(labels.size(0))
                validation_loss += float(loss.item()) * batch_size
                validation_examples += batch_size
                validation_truth.extend(int(value) for value in labels.cpu().tolist())
                validation_predicted.extend(int(value) for value in logits.argmax(dim=1).cpu().tolist())

        metrics = compute_metrics(validation_truth, validation_predicted, list(LABEL_ORDER))
        train_loss = running_loss / max(examples, 1)
        avg_validation_loss = validation_loss / max(validation_examples, 1)
        print(
            f"epoch={epoch:02d} train_loss={train_loss:.4f} "
            f"val_loss={avg_validation_loss:.4f} val_acc={metrics.accuracy:.3f} val_f1={metrics.macro_f1:.3f}"
        )

    return ModelArtifact(
        trainer="torch",
        steps=args.steps,
        beta=args.beta,
        threshold=args.threshold,
        class_names=list(LABEL_ORDER),
        feature_ranges=ranges,
        input_layer=LayerSpec(
            weight=[[float(value) for value in row] for row in model.input_layer.weight.detach().cpu().tolist()],
            bias=[float(value) for value in model.input_layer.bias.detach().cpu().tolist()],
        ),
        output_layer=LayerSpec(
            weight=[[float(value) for value in row] for row in model.output_layer.weight.detach().cpu().tolist()],
            bias=[float(value) for value in model.output_layer.bias.detach().cpu().tolist()],
        ),
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train a neuromorphic classifier on defensive network telemetry.")
    parser.add_argument("--config", help="Optional YAML or JSON config file")
    parser.add_argument("--save-config", help="Optional YAML or JSON path to save the effective training config")
    parser.add_argument("--data", default="data/synthetic_dataset.csv", help="Input CSV data")
    parser.add_argument("--artifact", default="artifacts/snn_model.json", help="Output model artifact JSON")
    parser.add_argument("--epochs", type=int, default=25, help="Training epochs for the torch path")
    parser.add_argument("--steps", type=int, default=12, help="TTFS time steps")
    parser.add_argument("--hidden-dim", type=int, default=12, help="Hidden neuron count for the torch path")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size for the torch path")
    parser.add_argument("--learning-rate", type=float, default=0.01, help="Adam learning rate for the torch path")
    parser.add_argument("--beta", type=float, default=0.82, help="Membrane decay factor")
    parser.add_argument("--threshold", type=float, default=1.0, help="LIF threshold")
    parser.add_argument("--seed", type=int, default=7, help="Random seed")
    parser.add_argument("--trainer", choices=["auto", "prototype", "torch"], default="auto", help="Training backend")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    from snn_cyber.config import TrainConfig, load_train_config, save_train_config

    if args.config:
        config = load_train_config(_resolve_project_path(args.config))
        args.data = config.data
        args.artifact = config.artifact
        args.epochs = config.epochs
        args.steps = config.steps
        args.hidden_dim = config.hidden_dim
        args.batch_size = config.batch_size
        args.learning_rate = config.learning_rate
        args.beta = config.beta
        args.threshold = config.threshold
        args.seed = config.seed
        args.trainer = config.trainer

    effective_config = TrainConfig(
        data=args.data,
        artifact=args.artifact,
        epochs=args.epochs,
        steps=args.steps,
        hidden_dim=args.hidden_dim,
        batch_size=args.batch_size,
        learning_rate=args.learning_rate,
        beta=args.beta,
        threshold=args.threshold,
        seed=args.seed,
        trainer=args.trainer,
    )
    if args.save_config:
        save_train_config(_resolve_project_path(args.save_config), effective_config)

    data_path = _resolve_project_path(args.data)
    artifact_path = _resolve_project_path(args.artifact)
    rows = load_event_rows(data_path)
    _validate_training_rows(rows)

    artifact: ModelArtifact | None = None
    if args.trainer in {"auto", "torch"}:
        artifact = train_with_torch(rows, args)
        if args.trainer == "torch" and artifact is None:
            raise RuntimeError("torch trainer requested explicitly but is unavailable")

    if artifact is None:
        artifact = build_prototype_artifact(rows, args.steps, args.beta, args.threshold)

    summary = evaluate_artifact(rows, artifact)
    save_artifact(artifact_path, artifact)
    print(f"trainer={summary.trainer} accuracy={summary.accuracy:.3f} macro_f1={summary.macro_f1:.3f}")
    print(f"rows={len(rows)} data={data_path}")
    print(f"exported artifact to {artifact_path}")


if __name__ == "__main__":
    main()

