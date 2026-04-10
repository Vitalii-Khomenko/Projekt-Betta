"""
Service Fingerprint Trainer - tools/service_fingerprint.py
===========================================================
Trains and evaluates the Naive Bayes service fingerprint model (the third
neural-network family in Betta-Morpho).  Reads banner CSV data, builds a TF-IDF-style
token frequency model per service class, and writes the model artifact JSON.

Key commands:
  # Train fingerprint model from banner CSV:
  python tools/service_fingerprint.py \
      --train data/banners_train.csv \
      --output artifacts/service_model.json

  # Evaluate on a held-out CSV:
  python tools/service_fingerprint.py \
      --eval data/banners_eval.csv \
      --model artifacts/service_model.json

Used by training/tools/scanner.py --report pipeline for service classification.

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path

try:
    from tools.path_naming import is_result_csv_name, is_service_training_csv_name
except ImportError:
    from path_naming import is_result_csv_name, is_service_training_csv_name

try:
    from service_sigs import detect_service
except ImportError:
    from tools.service_sigs import detect_service

try:
    from tools.nmap_service_catalog import SERVICE_CATALOG_ENV
except ImportError:
    from nmap_service_catalog import SERVICE_CATALOG_ENV

try:
    from tools.artifact_schema import FAMILY_SERVICE, attach_artifact_metadata, normalize_artifact_payload, validate_artifact_payload
except ImportError:
    from artifact_schema import FAMILY_SERVICE, attach_artifact_metadata, normalize_artifact_payload, validate_artifact_payload


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._/+:-]{1,}", re.IGNORECASE)
_LABEL_CANONICAL: dict[str, str] = {
    "dovecot imapd": "Dovecot IMAP",
    "dovecot pop3d": "Dovecot POP3",
    "https": "HTTPS",
    "http": "HTTP",
    "betta-morpho-ctrl ready": "Betta-Morpho Control",
    "microsoft httpapi": "Microsoft HTTPAPI",
}
_PLACEHOLDER_VALUES = {"binary-banner", "unknown-service"}
_GENERIC_LABELS = {
    "ftp",
    "smtp",
    "http",
    "https",
    "pop3",
    "imap",
    "smb",
    "ssh",
    "dns",
    "telnet",
    "rdp",
}


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _is_low_quality_label(value: str) -> bool:
    cleaned = value.strip()
    if not cleaned:
        return True
    lowered = cleaned.lower()
    if lowered in _PLACEHOLDER_VALUES or lowered.startswith("hex:"):
        return True
    if len(cleaned) > 90:
        return True
    word_count = len(re.findall(r"[a-z0-9]+", lowered))
    if word_count > 5 and not any(token in lowered for token in ("microsoft", "windows", "vmware", "betta-morpho")):
        return True
    return False


def _canonicalize_label(label: str) -> str:
    cleaned = label.strip()
    if not cleaned:
        return ""
    return _LABEL_CANONICAL.get(cleaned.lower(), cleaned)


def _strip_model_annotations(value: str) -> str:
    parts = [part.strip() for part in value.split("|") if part.strip()]
    filtered = [part for part in parts if not part.lower().startswith("model=")]
    return " | ".join(filtered)


def _port_bucket_tokens(port: int) -> list[str]:
    if port <= 0:
        return []
    tokens = [f"port:{port}"]
    bucket_start = (port // 1000) * 1000
    bucket_end = bucket_start + 999
    tokens.append(f"port-bucket:{bucket_start:05d}-{bucket_end:05d}")
    if port < 1024:
        tokens.append("port-class:well-known")
    elif port < 49152:
        tokens.append("port-class:registered")
    else:
        tokens.append("port-class:dynamic")
    return tokens


def _heuristic_label_from_text(row: dict[str, str]) -> str:
    banner = row.get("banner", "") or ""
    service_version = row.get("service_version", "") or ""
    technology = _strip_model_annotations(row.get("technology", "") or "")
    service = row.get("service", "") or ""
    text = " ".join(part for part in (service, service_version, technology, banner) if part).lower()
    if not text:
        return ""
    if "proftpd" in text:
        return "ProFTPD"
    if banner.startswith("SSH-") or "openssh" in text:
        return "OpenSSH"
    if banner.startswith("+OK") and "pop3" in text:
        return "POP3"
    if banner.startswith("* OK") and "imap" in text:
        return "Dovecot IMAP" if "dovecot" in text else "IMAP"
    if banner.startswith("220 ") and ("esmtp" in text or "postfix" in text):
        return "Postfix smtpd"
    if banner.startswith("HTTP/") and "apache/" in text:
        return "Apache httpd"
    if banner.startswith("HTTP/") and "server: nginx" in text:
        return "nginx"
    if banner.startswith("HTTP/") and "microsoft-httpapi" in text:
        return "Microsoft HTTPAPI"
    if "serverdaemonprotocol:soap" in text or "vmware authentication daemon" in text:
        return "VMware Authentication Daemon"
    if "cluster_name" in text:
        return "Elasticsearch"
    if "ismaster" in text or "hello" in text:
        return "MongoDB"
    if banner.startswith("STAT ") or "stat pid" in text or "stat ssl" in text:
        return "Memcached"
    if banner.startswith("RFB "):
        return "VNC"
    if text.startswith("amqp"):
        return "AMQP"
    if text.startswith("sip/2.0"):
        return "SIP"
    if "miniserv" in text:
        return "Webmin"
    if "consul/" in text:
        return "Consul"
    if "tornadoserver" in text:
        return "Tornado"
    if "cowboy" in text:
        return "RabbitMQ"
    if "password authentication required" in text:
        return "PostgreSQL"
    if "mysql" in text or banner.startswith("J\x00\x00\x00\n"):
        return "MySQL"
    if "betta-morpho-ctrl ready" in text:
        return "Betta-Morpho Control"
    if "activemq" in text:
        return "ActiveMQ"
    if lowered := banner.lower():
        if lowered.startswith("hex:160303"):
            return "HTTPS"
        if lowered.startswith("hex:0f002f"):
            return "Minecraft"
        if lowered.startswith("hex:4163746976654d51"):
            return "ActiveMQ"
    return ""


def _banner_shape_tokens(row: dict[str, str]) -> list[str]:
    banner = row.get("banner", "") or ""
    technology = _strip_model_annotations(row.get("technology", "") or "")
    service_version = row.get("service_version", "") or ""
    combined = " ".join(part for part in (banner, technology, service_version) if part).lower()
    tokens: list[str] = []
    if not combined:
        return tokens

    banner_length = len(banner)
    if banner_length:
        if banner_length <= 16:
            tokens.append("banner-len:tiny")
        elif banner_length <= 64:
            tokens.append("banner-len:short")
        elif banner_length <= 160:
            tokens.append("banner-len:medium")
        else:
            tokens.append("banner-len:long")

    if banner.startswith("HTTP/"):
        tokens.append("proto:http-response")
        status_match = re.search(r"HTTP/\d(?:\.\d)?\s+(\d{3})", banner)
        if status_match:
            tokens.append(f"http-status:{status_match.group(1)}")
    if "server:" in combined:
        tokens.append("http-header:server")
    if banner.startswith("SSH-"):
        tokens.append("proto:ssh-banner")
    if banner.startswith("+OK"):
        tokens.append("proto:pop3-banner")
    if banner.startswith("* OK"):
        tokens.append("proto:imap-banner")
    if banner.startswith("220 "):
        tokens.append("proto:greeting-220")
    if combined.lstrip().startswith("{") or "\"cluster_name\"" in combined:
        tokens.append("shape:json")
    if "cluster_name" in combined:
        tokens.append("sig:elasticsearch-json")
    if "ismaster" in combined or "hello" in combined:
        tokens.append("sig:mongodb-wire")
    if "stat pid" in combined or "stat ssl" in combined:
        tokens.append("sig:memcached-stat")
    if "microsoft-httpapi" in combined:
        tokens.append("sig:microsoft-httpapi")
    if "vmware authentication daemon" in combined:
        tokens.append("sig:vmware-authd")
    if "tornadoserver" in combined:
        tokens.append("sig:tornado")
    if "cowboy" in combined:
        tokens.append("sig:rabbitmq-cowboy")
    if "consul" in combined:
        tokens.append("sig:consul")
    if "betta-morpho-ctrl ready" in combined:
        tokens.append("sig:betta-control")
    if "activemq" in combined or banner.lower().startswith("hex:4163746976654d51"):
        tokens.append("sig:activemq")
    if banner.startswith("RFB "):
        tokens.append("sig:vnc-rfb")
    if combined.startswith("amqp"):
        tokens.append("sig:amqp")
    if combined.startswith("sip/2.0"):
        tokens.append("sig:sip")
    if "miniserv" in combined:
        tokens.append("sig:webmin")
    if "serverdaemonprotocol:soap" in combined:
        tokens.append("sig:vmware-soap")
    return tokens


def _normalize_label(row: dict[str, str]) -> str:
    service = row.get("service", "").strip()
    heuristic = _heuristic_label_from_text(row)
    if heuristic:
        return _canonicalize_label(heuristic)
    if service and service.lower() not in _PLACEHOLDER_VALUES and not _is_low_quality_label(service):
        fallback = _canonicalize_label(service)
    else:
        fallback = ""
    version_fallback = _canonicalize_label(row.get("service_version", "").strip())
    if version_fallback and not _is_low_quality_label(version_fallback):
        fallback = version_fallback or fallback
    port = int(row.get("target_port", "0") or 0)
    text = " ".join(
        part for part in (
            "" if _is_low_quality_label(row.get("service", "")) else row.get("service", ""),
            row.get("service_version", ""),
            _strip_model_annotations(row.get("technology", "")),
            row.get("cpe", ""),
            row.get("banner", ""),
        )
        if part and part.strip().lower() not in _PLACEHOLDER_VALUES
    )
    detected = detect_service(port, banner=text)
    detected_name = _canonicalize_label(detected.get("name", "").strip())
    if detected_name and not _is_low_quality_label(detected_name):
        return detected_name
    return fallback


def _tokenize_row(row: dict[str, str]) -> list[str]:
    port = int(row.get("target_port", "0") or 0)
    text = " ".join(
        part for part in (
            "" if _is_low_quality_label(row.get("service", "")) else row.get("service", ""),
            row.get("service_version", ""),
            _strip_model_annotations(row.get("technology", "")),
            row.get("cpe", ""),
            row.get("banner", ""),
        )
        if part
    ).lower()
    tokens = TOKEN_RE.findall(text)
    tokens.extend(_port_bucket_tokens(port))
    tokens.extend(_banner_shape_tokens(row))
    detected = detect_service(port, banner=text)
    detected_name = _canonicalize_label(detected.get("name", ""))
    if detected_name:
        tokens.append(f"sig:{_slugify(detected_name)}")
        if _slugify(detected_name) not in _GENERIC_LABELS:
            tokens.append("sig:specific")
    normalized = _canonicalize_label(row.get("service", ""))
    if normalized:
        tokens.append(f"label:{normalized.lower().replace(' ', '_')}")
        if _slugify(normalized) not in _GENERIC_LABELS:
            tokens.append("label:specific")
    return [token for token in tokens if token]


def _collect_csv_paths(items: list[str]) -> list[Path]:
    paths: list[Path] = []
    for item in items:
        path = Path(item)
        if path.is_dir():
            for candidate in sorted(path.rglob("*.csv")):
                if is_result_csv_name(candidate.name) or is_service_training_csv_name(candidate.name):
                    paths.append(candidate)
            continue
        if path.is_file():
            paths.append(path)
    unique = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _load_rows(paths: list[Path]) -> list[dict[str, str]]:
    best_rows: dict[tuple[str, str, str], tuple[int, dict[str, str]]] = {}
    for path in paths:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                protocol_flag = row.get("protocol_flag", "").upper()
                is_verified = is_service_training_csv_name(path.name) or row.get("label_source", "").strip().lower() == "nmap_verified"
                label = _normalize_label(row)
                if not is_verified and protocol_flag != "SYN_ACK":
                    continue
                if not label:
                    continue
                row = dict(row)
                row["service"] = label
                row["_verified_source"] = "1" if is_verified else "0"
                key = (
                    row.get("asset_ip", ""),
                    row.get("target_port", ""),
                    row.get("banner", ""),
                )
                priority = 2 if is_verified else 1
                existing = best_rows.get(key)
                if existing is None or priority > existing[0]:
                    best_rows[key] = (priority, row)
    rows = [value[1] for value in best_rows.values()]
    if not rows:
        raise ValueError("no service-labelled rows found in the provided CSV inputs")
    return rows


def _promote_verified_rows(rows: list[dict[str, str]], verified_weight: int) -> tuple[list[dict[str, str]], dict[str, int]]:
    weight = max(1, int(verified_weight))
    promoted: list[dict[str, str]] = []
    verified_rows = 0
    scanner_rows = 0
    for row in rows:
        is_verified = row.get("_verified_source") == "1"
        if is_verified:
            verified_rows += 1
        else:
            scanner_rows += 1
        copies = weight if is_verified else 1
        for _ in range(copies):
            promoted.append(dict(row))
    return promoted, {
        "unique_rows": len(rows),
        "verified_rows": verified_rows,
        "scanner_rows": scanner_rows,
        "verified_weight": weight,
        "training_rows": len(promoted),
    }


def train_service_model(rows: list[dict[str, str]], training_counts: dict[str, int] | None = None, service_catalog: str = "") -> dict:
    label_counts: Counter[str] = Counter()
    token_counts: dict[str, Counter[str]] = defaultdict(Counter)
    token_totals: Counter[str] = Counter()
    vocabulary: set[str] = set()

    for row in rows:
        label = row["service"]
        tokens = _tokenize_row(row)
        if not tokens:
            continue
        label_counts[label] += 1
        token_counts[label].update(tokens)
        token_totals[label] += len(tokens)
        vocabulary.update(tokens)

    labels = sorted(label_counts)
    vocab_size = max(len(vocabulary), 1)
    priors = {label: label_counts[label] / sum(label_counts.values()) for label in labels}
    token_log_probs: dict[str, dict[str, float]] = {}
    unknown_log_prob: dict[str, float] = {}
    for label in labels:
        denominator = token_totals[label] + vocab_size
        token_log_probs[label] = {
            token: math.log((count + 1) / denominator)
            for token, count in token_counts[label].items()
        }
        unknown_log_prob[label] = math.log(1 / denominator)

    return attach_artifact_metadata({
        "model_type": "service-fingerprint-naive-bayes",
        "version": 3,
        "labels": labels,
        "priors": priors,
        "token_log_probs": token_log_probs,
        "unknown_log_prob": unknown_log_prob,
        "samples": sum(label_counts.values()),
        "training_counts": training_counts or {},
        "service_catalog": service_catalog,
    }, FAMILY_SERVICE, model_type="service-fingerprint-naive-bayes", producer="tools.service_fingerprint")


def load_service_artifact(path: str | Path) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    validate_artifact_payload(payload, expected_family=FAMILY_SERVICE)
    payload = normalize_artifact_payload(
        payload,
        expected_family=FAMILY_SERVICE,
        default_model_type="service-fingerprint-naive-bayes",
        producer="tools.service_fingerprint",
    )
    if not isinstance(payload, dict) or payload.get("model_type") != "service-fingerprint-naive-bayes":
        raise ValueError("invalid service fingerprint artifact")
    return payload


def predict_service_row(artifact: dict, row: dict[str, str]) -> tuple[str, float]:
    labels = artifact.get("labels", [])
    if not labels:
        return "", 0.0
    tokens = _tokenize_row(row)
    if not tokens:
        return "", 0.0

    scores: dict[str, float] = {}
    for label in labels:
        score = math.log(float(artifact["priors"].get(label, 1e-9)))
        token_log_probs = artifact["token_log_probs"].get(label, {})
        unknown = float(artifact["unknown_log_prob"].get(label, math.log(1e-9)))
        for token in tokens:
            score += float(token_log_probs.get(token, unknown))
        scores[label] = score

    best_label = max(scores.items(), key=lambda item: item[1])[0]
    max_score = max(scores.values())
    exp_scores = {label: math.exp(score - max_score) for label, score in scores.items()}
    total = sum(exp_scores.values()) or 1.0
    confidence = exp_scores[best_label] / total
    return str(best_label), float(confidence)


def classify_csv(input_path: Path, artifact_path: Path, output_path: Path) -> int:
    artifact = load_service_artifact(artifact_path)
    with input_path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = list(reader.fieldnames or [])
    for name in ("service_prediction", "service_confidence"):
        if name not in fieldnames:
            fieldnames.append(name)
    for row in rows:
        prediction, confidence = predict_service_row(artifact, row)
        row["service_prediction"] = prediction
        row["service_confidence"] = f"{confidence:.3f}"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def evaluate_model(rows: list[dict[str, str]], artifact: dict) -> tuple[int, float]:
    correct = 0
    for row in rows:
        prediction, _ = predict_service_row(artifact, row)
        if prediction == row["service"]:
            correct += 1
    total = len(rows)
    return total, (correct / total if total else 0.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train and use a separate service-fingerprint artifact on enriched Betta-Morpho scan CSVs.")
    sub = parser.add_subparsers(dest="command", required=True)

    train = sub.add_parser("train", help="Train a service-fingerprint artifact from Betta-Morpho result CSV files or directories")
    train.add_argument("inputs", nargs="+", help="One or more Betta-Morpho result/service-training CSV files or directories")
    train.add_argument("--artifact", default="artifacts/service_model.json", help="Output artifact path")
    train.add_argument("--service-catalog", default="artifacts/service_catalog.json", help="Internal service catalog artifact used for label normalization")
    train.add_argument("--verified-weight", type=int, default=3, help="Replication weight for Nmap-verified training rows")

    evaluate = sub.add_parser("evaluate", help="Evaluate a service-fingerprint artifact against Betta-Morpho CSV inputs")
    evaluate.add_argument("inputs", nargs="+", help="One or more Betta-Morpho result/service-training CSV files or directories")
    evaluate.add_argument("--artifact", required=True, help="Service artifact JSON path")
    evaluate.add_argument("--service-catalog", default="artifacts/service_catalog.json", help="Internal service catalog artifact used for label normalization")

    classify = sub.add_parser("classify", help="Add service predictions to one Betta-Morpho result CSV")
    classify.add_argument("--input", required=True, help="Input Betta-Morpho result CSV")
    classify.add_argument("--artifact", required=True, help="Service artifact JSON path")
    classify.add_argument("--output", required=True, help="Output CSV with predictions")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "train":
        os.environ[SERVICE_CATALOG_ENV] = str(Path(args.service_catalog))
        paths = _collect_csv_paths(args.inputs)
        rows = _load_rows(paths)
        training_rows, training_counts = _promote_verified_rows(rows, args.verified_weight)
        artifact = train_service_model(training_rows, training_counts=training_counts, service_catalog=str(Path(args.service_catalog)))
        output = Path(args.artifact)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
        print(
            f"trained_samples={artifact['samples']} unique_rows={training_counts['unique_rows']} "
            f"verified_rows={training_counts['verified_rows']} labels={len(artifact['labels'])} artifact={output}"
        )
        return 0

    if args.command == "evaluate":
        os.environ[SERVICE_CATALOG_ENV] = str(Path(args.service_catalog))
        paths = _collect_csv_paths(args.inputs)
        rows = _load_rows(paths)
        artifact = load_service_artifact(args.artifact)
        total, accuracy = evaluate_model(rows, artifact)
        print(f"samples={total} accuracy={accuracy:.3f}")
        return 0

    if args.command == "classify":
        count = classify_csv(Path(args.input), Path(args.artifact), Path(args.output))
        print(f"rows={count} output={args.output}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
