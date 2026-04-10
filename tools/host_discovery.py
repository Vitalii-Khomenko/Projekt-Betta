"""
Passive hostname discovery training and inference utilities for Betta-Morpho.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import math
import random
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "training" / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from snn_cyber.metrics import compute_metrics, format_confusion_matrix
from snn_cyber.model import SpikingClassifier
from snn_host_discovery.dataset import HostDiscoveryDataset
from snn_host_discovery.inference import infer_from_features, predict_sample
from snn_host_discovery.schema import (
    LABEL_ORDER,
    HostDiscoveryArtifact,
    HostDiscoverySample,
    LayerSpec,
    compute_feature_ranges,
    encode_features,
    load_artifact,
    load_rows,
    save_artifact,
)
from tools.path_naming import is_result_csv_name

VERSION = "2.4.0"
DEFAULT_ARTIFACT = "artifacts/host_discovery_model.json"
DEFAULT_DATASET = "data/host_discovery_synthetic.csv"

_URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://([a-z0-9.-]+)")
_FQDN_RE = re.compile(
    r"(?i)(?<![a-z0-9-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62})(?![a-z0-9-])"
)
_SHORT_HOST_RE = re.compile(r"(?i)\b(?:dc|fs|sql|db|mail|mx|ns|web|app|api|vpn|adm|admin|git|ci|mq|srv)\d{0,3}\b")
_KEY_VALUE_RE = re.compile(r"(?i)\b([a-z_]+)=([^|;,]+)")
_HTTP_HINT_FIELDS = {"banner", "technology", "scan_note"}
_GENERIC_SKIP = {
    "apache",
    "nginx",
    "microsoft",
    "windows",
    "linux",
    "issuer",
    "subject",
    "cipher",
    "tls",
    "http",
    "https",
    "smtp",
    "imap",
    "pop3",
    "localhost",
    "workgroup",
    "default",
    "unknown",
}
_HIGH_VALUE_HINTS = ("login", "auth", "sso", "vpn", "portal", "adfs", "idp", "dc", "domain", "ldap", "admin")
_SUPPORTING_HINTS = ("wiki", "grafana", "git", "ci", "docs", "api", "app", "web", "mail", "db", "sql", "mq")
_INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan", ".lab", ".htb", ".home.arpa")


@dataclass
class CandidateEvidence:
    asset_ip: str
    candidate_name: str
    root_domain: str
    source_kinds: set[str]
    source_ports: set[int]
    evidence: list[str]


def default_artifact_path() -> Path:
    return ROOT / DEFAULT_ARTIFACT


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _root_domain(name: str) -> str:
    labels = [part for part in name.split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return name


def _clean_candidate(name: str) -> str:
    cleaned = name.strip().strip("[](){}<>.,;:'\"").lower()
    while ".." in cleaned:
        cleaned = cleaned.replace("..", ".")
    return cleaned


def _is_probably_ip(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value))


def _allow_single_label(value: str) -> bool:
    if value in _GENERIC_SKIP:
        return False
    return bool(_SHORT_HOST_RE.fullmatch(value))


def _is_candidate_name(value: str) -> bool:
    if not value:
        return False
    if _is_probably_ip(value):
        return False
    if value in _GENERIC_SKIP:
        return False
    if "." in value:
        labels = [part for part in value.split(".") if part]
        if len(labels) < 2:
            return False
        return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)
    return _allow_single_label(value)


def _extract_candidates(text: str, base_source: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    lowered = text.lower()
    for match in _URL_RE.finditer(lowered):
        candidate = _clean_candidate(match.group(1))
        if _is_candidate_name(candidate):
            found.append((candidate, "http_url" if base_source in _HTTP_HINT_FIELDS else base_source))
    for key, raw_value in _KEY_VALUE_RE.findall(lowered):
        value = _clean_candidate(raw_value)
        if key in {"location", "redirect", "host"} and _is_candidate_name(value):
            found.append((value, "http_location"))
            continue
        if key in {"san", "altname", "dns"}:
            for item in re.split(r"[\s,]+", value):
                cleaned = _clean_candidate(item)
                if _is_candidate_name(cleaned):
                    found.append((cleaned, "tls_san"))
            continue
        if key in {"cert", "subject"} and _is_candidate_name(value):
            found.append((value, "tls_subject"))
            continue
        if key in {"server", "hostname", "machine"} and _is_candidate_name(value):
            found.append((value, "smb_context"))
    for match in _FQDN_RE.finditer(lowered):
        candidate = _clean_candidate(match.group(1))
        if _is_candidate_name(candidate):
            found.append((candidate, base_source))
    for match in _SHORT_HOST_RE.finditer(lowered):
        candidate = _clean_candidate(match.group(0))
        if _is_candidate_name(candidate):
            found.append((candidate, "smb_context" if base_source == "technology" else base_source))
    unique: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in found:
        if item in seen:
            continue
        seen.add(item)
        unique.append(item)
    return unique


def _iter_scan_rows(items: list[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[Path] = set()
    for item in items:
        path = _resolve_project_path(item)
        candidates: list[Path] = []
        if path.is_dir():
            candidates = [candidate for candidate in sorted(path.rglob("*.csv")) if is_result_csv_name(candidate.name)]
        elif path.is_file():
            candidates = [path]
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            with candidate.open(newline="", encoding="utf-8-sig") as handle:
                rows.extend(dict(row) for row in csv.DictReader(handle))
    return rows


def _build_sample(
    candidate_name: str,
    source_kinds: Iterable[str],
    evidence_count: int,
    source_port_count: int,
    *,
    asset_ip: str = "",
    root_domain: str = "",
    label: str = "",
) -> HostDiscoverySample:
    return HostDiscoverySample(
        candidate_name=candidate_name,
        source_kinds=sorted({item.strip().lower() for item in source_kinds if item.strip()}),
        evidence_count=evidence_count,
        source_port_count=source_port_count,
        label=label,
        asset_ip=asset_ip,
        root_domain=root_domain or _root_domain(candidate_name),
    )


def _logits_to_confidence(logits: list[float]) -> float:
    if not logits:
        return 0.0
    max_logit = max(logits)
    values = [math.exp(value - max_logit) for value in logits]
    total = sum(values) or 1.0
    return max(values) / total


def heuristic_label(sample: HostDiscoverySample) -> str:
    lowered = sample.candidate_name.lower()
    if any(token in lowered for token in _HIGH_VALUE_HINTS):
        return "high_value"
    if "." in lowered and lowered.endswith(_INTERNAL_SUFFIXES):
        return "supporting" if sample.evidence_count <= 1 else "high_value"
    if any(token in lowered for token in _SUPPORTING_HINTS):
        return "supporting"
    if sample.evidence_count >= 2 and "." in lowered:
        return "supporting"
    return "noise"


def predict_candidate(
    sample: HostDiscoverySample,
    artifact: HostDiscoveryArtifact | None,
) -> tuple[str, float]:
    if artifact is None:
        return heuristic_label(sample), 0.0
    predicted_index, logits = predict_sample(artifact, sample)
    return artifact.class_names[predicted_index], _logits_to_confidence(logits)


def discover_from_scan_rows(
    rows: list[dict[str, str]],
    artifact: HostDiscoveryArtifact | None = None,
) -> list[dict[str, str]]:
    aggregated: dict[tuple[str, str], CandidateEvidence] = {}
    for row in rows:
        asset_ip = str(row.get("asset_ip", "")).strip()
        port = int(row.get("target_port", "0") or 0)
        for field in ("banner", "technology", "service", "service_version", "scan_note"):
            text = str(row.get(field, "") or "").strip()
            if not text:
                continue
            for candidate_name, source_kind in _extract_candidates(text, field):
                key = (asset_ip, candidate_name)
                candidate = aggregated.setdefault(
                    key,
                    CandidateEvidence(
                        asset_ip=asset_ip,
                        candidate_name=candidate_name,
                        root_domain=_root_domain(candidate_name),
                        source_kinds=set(),
                        source_ports=set(),
                        evidence=[],
                    ),
                )
                candidate.source_kinds.add(source_kind)
                if port > 0:
                    candidate.source_ports.add(port)
                snippet = f"{field}:{text[:120]}"
                if snippet not in candidate.evidence:
                    candidate.evidence.append(snippet)
    discovered: list[dict[str, str]] = []
    for candidate in sorted(aggregated.values(), key=lambda item: (item.asset_ip, item.candidate_name)):
        sample = _build_sample(
            candidate.candidate_name,
            candidate.source_kinds,
            evidence_count=len(candidate.evidence),
            source_port_count=len(candidate.source_ports),
            asset_ip=candidate.asset_ip,
            root_domain=candidate.root_domain,
        )
        predicted_label, confidence = predict_candidate(sample, artifact)
        discovered.append(
            {
                "asset_ip": candidate.asset_ip,
                "candidate_name": candidate.candidate_name,
                "root_domain": candidate.root_domain,
                "source_kinds": ";".join(sorted(candidate.source_kinds)),
                "source_ports": ";".join(str(port) for port in sorted(candidate.source_ports)),
                "evidence_count": str(len(candidate.evidence)),
                "source_port_count": str(len(candidate.source_ports)),
                "predicted_label": predicted_label,
                "confidence": f"{confidence:.3f}",
                "evidence": " || ".join(candidate.evidence[:4]),
            }
        )
    return discovered


def discover_from_port_results(
    results: Iterable[object],
    artifact_path: str | Path | None = None,
) -> list[dict[str, str]]:
    artifact = None
    if artifact_path:
        path = Path(artifact_path)
        if path.exists():
            artifact = load_artifact(path)
    rows = [
        {
            "asset_ip": str(getattr(result, "host", "")),
            "target_port": str(getattr(result, "port", 0)),
            "banner": str(getattr(result, "banner", "")),
            "technology": str(getattr(result, "technology", "")),
            "service": str(getattr(result, "service", "")),
            "service_version": str(getattr(result, "service_version", "")),
            "scan_note": str(getattr(result, "scan_note", "")),
        }
        for result in results
        if str(getattr(result, "state", "")) == "open"
    ]
    return discover_from_scan_rows(rows, artifact=artifact)


def export_discovery_csv(rows: list[dict[str, str]], path: Path) -> None:
    fieldnames = [
        "asset_ip",
        "candidate_name",
        "root_domain",
        "source_kinds",
        "source_ports",
        "evidence_count",
        "source_port_count",
        "predicted_label",
        "confidence",
        "evidence",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_discovery_html(rows: list[dict[str, str]], path: Path) -> None:
    counts = Counter(row["predicted_label"] for row in rows)
    row_html = ""
    for row in rows:
        row_html += (
            "<tr>"
            f"<td>{html.escape(row['asset_ip'])}</td>"
            f"<td>{html.escape(row['candidate_name'])}</td>"
            f"<td>{html.escape(row['root_domain'])}</td>"
            f"<td>{html.escape(row['predicted_label'])}</td>"
            f"<td>{html.escape(row['confidence'])}</td>"
            f"<td>{html.escape(row['source_kinds'])}</td>"
            f"<td>{html.escape(row['source_ports'])}</td>"
            f"<td>{html.escape(row['evidence'])}</td>"
            "</tr>\n"
        )
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Betta-Morpho Passive Host Discovery</title>
  <style>
    body{{font-family:Arial,sans-serif;margin:24px;background:#f4f6f8;color:#1f2937}}
    .summary{{background:#fff;padding:14px 18px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.12);margin-bottom:16px}}
    table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.12)}}
    th{{background:#243b53;color:#fff;padding:10px;text-align:left}}
    td{{padding:8px 10px;border-bottom:1px solid #dde3ea;font-size:13px;vertical-align:top}}
  </style>
</head>
<body>
  <h1>Betta-Morpho Passive Host Discovery</h1>
  <div class="summary">
    <b>Total candidates:</b> {len(rows)} &nbsp;|&nbsp;
    <b>High value:</b> {counts.get("high_value", 0)} &nbsp;|&nbsp;
    <b>Supporting:</b> {counts.get("supporting", 0)} &nbsp;|&nbsp;
    <b>Noise:</b> {counts.get("noise", 0)}
  </div>
  <table>
    <tr><th>Asset IP</th><th>Candidate</th><th>Root Domain</th><th>Label</th><th>Confidence</th><th>Sources</th><th>Ports</th><th>Evidence</th></tr>
    {row_html}
  </table>
</body>
</html>"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_content, encoding="utf-8")


def _random_sources(rng: random.Random, label: str) -> tuple[list[str], int, int]:
    base = {
        "high_value": ["technology", "http_location", "tls_san"],
        "supporting": ["technology", "banner", "http_url"],
        "noise": ["technology", "banner"],
    }[label]
    source_count = rng.randint(1, min(3, len(base)))
    return rng.sample(base, source_count), rng.randint(1, 3 if label != "noise" else 2), rng.randint(1, 2)


def generate_synthetic_dataset(path: Path, samples_per_class: int, seed: int) -> int:
    rng = random.Random(seed)
    domains = ["lab.local", "academy.htb", "corp.internal", "dev.lab.local"]
    templates = {
        "high_value": [
            "login.{domain}",
            "auth.{domain}",
            "portal.{domain}",
            "vpn.{domain}",
            "adfs.{domain}",
            "dc01.{domain}",
            "admin-gateway.{domain}",
            "sso.{domain}",
        ],
        "supporting": [
            "wiki.{domain}",
            "grafana.{domain}",
            "git.{domain}",
            "docs.{domain}",
            "api.{domain}",
            "mail.{domain}",
            "ci.{domain}",
            "web02.{domain}",
        ],
        "noise": [
            "localhost",
            "apache",
            "nginx",
            "default",
            "issuer",
            "cipher",
            "server",
            "workgroup",
        ],
    }
    rows: list[dict[str, str]] = []
    for label in LABEL_ORDER:
        for _ in range(samples_per_class):
            template = rng.choice(templates[label])
            domain = rng.choice(domains)
            name = template.format(domain=domain)
            sources, evidence_count, port_count = _random_sources(rng, label)
            rows.append(
                {
                    "asset_ip": f"10.10.{rng.randint(10, 99)}.{rng.randint(2, 254)}",
                    "candidate_name": name,
                    "root_domain": _root_domain(name),
                    "source_kinds": ";".join(sorted(sources)),
                    "evidence_count": str(evidence_count),
                    "source_port_count": str(port_count),
                    "label": label,
                }
            )
    rng.shuffle(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["asset_ip", "candidate_name", "root_domain", "source_kinds", "evidence_count", "source_port_count", "label"],
        )
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def _validate_training_rows(rows: list[HostDiscoverySample]) -> None:
    if len(rows) < len(LABEL_ORDER):
        raise ValueError("training requires multiple labeled rows")
    present_labels = {row.label for row in rows}
    missing_labels = [label for label in LABEL_ORDER if label not in present_labels]
    if missing_labels:
        raise ValueError(f"training data is missing required labels: {', '.join(missing_labels)}")


def build_prototype_artifact(rows: list[HostDiscoverySample], steps: int, beta: float, threshold: float) -> HostDiscoveryArtifact:
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

    return HostDiscoveryArtifact(
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


def train_with_torch(rows: list[HostDiscoverySample], args: argparse.Namespace) -> HostDiscoveryArtifact | None:
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, random_split
    except Exception as exc:
        print(f"torch trainer unavailable, falling back to prototype trainer: {exc}")
        return None

    torch.manual_seed(args.seed)
    ranges = compute_feature_ranges(rows)
    dataset = HostDiscoveryDataset(rows, ranges, args.steps)
    validation_size = max(1, int(len(dataset) * 0.2))
    train_size = len(dataset) - validation_size
    train_set, validation_set = random_split(
        dataset,
        [train_size, validation_size],
        generator=torch.Generator().manual_seed(args.seed),
    )
    train_loader = DataLoader(train_set, batch_size=args.batch_size, shuffle=True)
    validation_loader = DataLoader(validation_set, batch_size=args.batch_size)
    input_dim = len(encode_features(rows[0], ranges))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = SpikingClassifier(input_dim, args.hidden_dim, len(LABEL_ORDER), args.beta, args.threshold).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.learning_rate)
    criterion = nn.CrossEntropyLoss()

    for epoch in range(1, args.epochs + 1):
        model.train()
        for spikes, labels in train_loader:
            spikes = spikes.to(device)
            labels = labels.to(device)
            optimizer.zero_grad(set_to_none=True)
            logits = model(spikes)
            loss = criterion(logits, labels)
            loss.backward()
            optimizer.step()

        model.eval()
        validation_truth: list[int] = []
        validation_predicted: list[int] = []
        with torch.no_grad():
            for spikes, labels in validation_loader:
                logits = model(spikes.to(device))
                validation_truth.extend(int(value) for value in labels.tolist())
                validation_predicted.extend(int(value) for value in logits.argmax(dim=1).cpu().tolist())
        metrics = compute_metrics(validation_truth, validation_predicted, list(LABEL_ORDER))
        print(f"epoch={epoch:02d} val_acc={metrics.accuracy:.3f} val_f1={metrics.macro_f1:.3f}")

    return HostDiscoveryArtifact(
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


def evaluate_artifact(rows: list[HostDiscoverySample], artifact: HostDiscoveryArtifact) -> tuple[int, float, float, str]:
    truth: list[int] = []
    predicted: list[int] = []
    for row in rows:
        predicted_index, _ = infer_from_features(artifact, encode_features(row, artifact.feature_ranges))
        truth.append(LABEL_ORDER.index(row.label))
        predicted.append(predicted_index)
    metrics = compute_metrics(truth, predicted, artifact.class_names)
    return metrics.samples, metrics.accuracy, metrics.macro_f1, format_confusion_matrix(metrics.confusion_matrix, metrics.labels)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive hostname discovery tooling for Betta-Morpho.")
    sub = parser.add_subparsers(dest="command", required=True)

    generate = sub.add_parser("generate-synthetic", help="Generate synthetic passive-host-discovery training data")
    generate.add_argument("--output", default=DEFAULT_DATASET)
    generate.add_argument("--samples-per-class", type=int, default=250)
    generate.add_argument("--seed", type=int, default=7)

    train = sub.add_parser("train", help="Train a passive hostname-discovery SNN artifact")
    train.add_argument("--data", default=DEFAULT_DATASET)
    train.add_argument("--artifact", default=DEFAULT_ARTIFACT)
    train.add_argument("--trainer", choices=["auto", "prototype", "torch"], default="auto")
    train.add_argument("--epochs", type=int, default=20)
    train.add_argument("--steps", type=int, default=12)
    train.add_argument("--hidden-dim", type=int, default=12)
    train.add_argument("--batch-size", type=int, default=64)
    train.add_argument("--learning-rate", type=float, default=0.01)
    train.add_argument("--beta", type=float, default=0.82)
    train.add_argument("--threshold", type=float, default=1.0)
    train.add_argument("--seed", type=int, default=7)

    evaluate = sub.add_parser("evaluate", help="Evaluate a passive hostname-discovery artifact")
    evaluate.add_argument("--data", default=DEFAULT_DATASET)
    evaluate.add_argument("--artifact", default=DEFAULT_ARTIFACT)
    evaluate.add_argument("--preview", type=int, default=5)

    discover = sub.add_parser("discover", help="Extract hostnames from Betta-Morpho result CSV files or directories")
    discover.add_argument("inputs", nargs="+", help="One or more result CSV files or directories")
    discover.add_argument("--artifact", default=None, help="Optional passive hostname-discovery artifact")
    discover.add_argument("--output", required=True, help="Output CSV path")
    discover.add_argument("--html", default=None, help="Optional HTML report path")

    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "generate-synthetic":
        output = _resolve_project_path(args.output)
        count = generate_synthetic_dataset(output, args.samples_per_class, args.seed)
        print(f"generated_rows={count} output={output}")
        return 0

    if args.command == "train":
        data = _resolve_project_path(args.data)
        artifact_path = _resolve_project_path(args.artifact)
        rows = load_rows(data)
        _validate_training_rows(rows)
        artifact: HostDiscoveryArtifact | None = None
        if args.trainer in {"auto", "torch"}:
            artifact = train_with_torch(rows, args)
            if args.trainer == "torch" and artifact is None:
                raise RuntimeError("torch trainer requested explicitly but is unavailable")
        if artifact is None:
            artifact = build_prototype_artifact(rows, args.steps, args.beta, args.threshold)
        samples, accuracy, macro_f1, confusion = evaluate_artifact(rows, artifact)
        save_artifact(artifact_path, artifact)
        print(f"samples={samples} accuracy={accuracy:.3f} macro_f1={macro_f1:.3f}")
        print(confusion)
        print(f"artifact={artifact_path}")
        return 0

    if args.command == "evaluate":
        data = _resolve_project_path(args.data)
        artifact = load_artifact(_resolve_project_path(args.artifact))
        rows = load_rows(data)
        preview = rows[: max(0, args.preview)]
        for index, row in enumerate(preview):
            predicted_index, logits = predict_sample(artifact, row)
            print(
                f"row={index} candidate={row.candidate_name} truth={row.label or '-'} "
                f"pred={artifact.class_names[predicted_index]} logits={json.dumps(logits)}"
            )
        labeled_rows = [row for row in rows if row.label in LABEL_ORDER]
        if labeled_rows:
            samples, accuracy, macro_f1, confusion = evaluate_artifact(labeled_rows, artifact)
            print(f"samples={samples} accuracy={accuracy:.3f} macro_f1={macro_f1:.3f}")
            print(confusion)
        return 0

    if args.command == "discover":
        artifact = None
        if args.artifact:
            artifact_path = _resolve_project_path(args.artifact)
            if artifact_path.exists():
                artifact = load_artifact(artifact_path)
        rows = _iter_scan_rows(args.inputs)
        discovered = discover_from_scan_rows(rows, artifact=artifact)
        output = _resolve_project_path(args.output)
        export_discovery_csv(discovered, output)
        if args.html:
            export_discovery_html(discovered, _resolve_project_path(args.html))
        counts = Counter(row["predicted_label"] for row in discovered)
        print(
            f"candidates={len(discovered)} high_value={counts.get('high_value', 0)} "
            f"supporting={counts.get('supporting', 0)} noise={counts.get('noise', 0)} output={output}"
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
