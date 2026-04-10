"""
Synthetic Dataset Generator - training/generate_synthetic_data.py
==================================================================
Generates a balanced, labeled CSV dataset for training the Betta-Morpho port-state
classifier.  RTT distributions are calibrated to real HTB VPN measurements:
  normal   - SYN_ACK,  40-450 ms   (real p50 approx. 226 ms)
  delayed  - SYN_ACK,  500 ms-2.5 s (tarpit / IDS throttle)
  filtered - RST/TIMEOUT, 40-600 ms / 1.5-5 s

Key commands:
  # Standard 3 000-row dataset (recommended)
  python training/generate_synthetic_data.py \
      --output data/synthetic_dataset.csv --samples-per-class 1000 --seed 42

  # Small pilot / hold-out fold
  python training/generate_synthetic_data.py \
      --output data/synthetic_holdout.csv --samples-per-class 300 --seed 137

  # Large augmentation set
  python training/generate_synthetic_data.py \
      --output data/synthetic_large.csv --samples-per-class 3000 --seed 42

Parameters:
  --output             Output CSV path (required)
  --samples-per-class  Rows per class (default 300)
  --seed               Random seed for reproducibility (default 7)

Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
License : Apache-2.0 - see LICENSE
Version : 2.3.3
Created : 01.04.2026
"""
from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _resolve_project_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def build_asset_pool(rng: random.Random, asset_count: int) -> list[str]:
    seen: set[str] = set()
    while len(seen) < asset_count:
        seen.add(f"10.42.{rng.randint(0, 3)}.{rng.randint(10, 250)}")
    return sorted(seen)


def build_row(timestamp_us: int, label: str, rng: random.Random, asset_pool: list[str]) -> dict[str, str]:
    asset_ip = rng.choice(asset_pool)
    target_port = rng.choice([22, 25, 53, 80, 110, 123, 443, 445, 993, 3306, 3389, 5432, 8080])

    if label == "normal":
        # SYN-ACK from real HTB VPN targets: observed p5=83ms p50=226ms p95=440ms
        protocol_flag = rng.choices(["SYN_ACK", "UDP_RESPONSE", "ICMP_REPLY"], weights=[0.65, 0.2, 0.15], k=1)[0]
        inter_packet = clamp(rng.gauss(900.0, 140.0), 250.0, 1600.0)
        payload_size = clamp(rng.gauss(64.0, 12.0), 40.0, 110.0)
        rtt = clamp(rng.gauss(200_000.0, 80_000.0), 40_000.0, 450_000.0)
    elif label == "delayed":
        # Tarpit / IDS throttle: SYN-ACK arrives clearly later than normal VPN baseline
        protocol_flag = rng.choices(["SYN_ACK", "UDP_RESPONSE", "ICMP_REPLY"], weights=[0.55, 0.25, 0.2], k=1)[0]
        inter_packet = clamp(rng.gauss(4200.0, 900.0), 1800.0, 9000.0)
        payload_size = clamp(rng.gauss(58.0, 10.0), 30.0, 96.0)
        rtt = clamp(rng.gauss(1_000_000.0, 300_000.0), 500_000.0, 2_500_000.0)
    else:
        # RST: similar RTT to SYN_ACK (same round-trip); TIMEOUT: scanner cutoff ~2-5s
        # Observed RST on HTB: p5=99ms p50=213ms p95=364ms; TIMEOUT p50=3004ms
        protocol_flag = rng.choices(["RST", "TIMEOUT", "ICMP_UNREACHABLE"], weights=[0.35, 0.35, 0.3], k=1)[0]
        inter_packet = clamp(rng.gauss(9200.0, 2200.0), 3500.0, 18000.0)
        payload_size = 0.0 if protocol_flag in {"TIMEOUT", "ICMP_UNREACHABLE"} else clamp(rng.gauss(40.0, 8.0), 20.0, 72.0)
        rtt = clamp(rng.gauss(3_000_000.0, 600_000.0), 1_500_000.0, 5_000_000.0) if protocol_flag == "TIMEOUT" else clamp(rng.gauss(200_000.0, 80_000.0), 40_000.0, 600_000.0)

    return {
        "timestamp_us": str(timestamp_us),
        "asset_ip": asset_ip,
        "target_port": str(target_port),
        "protocol_flag": protocol_flag,
        "inter_packet_time_us": f"{inter_packet:.2f}",
        "payload_size": f"{payload_size:.2f}",
        "rtt_us": f"{rtt:.2f}",
        "label": label,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic defensive network telemetry for SNN training.")
    parser.add_argument("--output", required=True, help="Output CSV path")
    parser.add_argument("--samples-per-class", type=int, default=300, help="Rows to create for each class")
    parser.add_argument("--seed", type=int, default=7, help="Random seed")
    parser.add_argument("--assets", type=int, default=8, help="Reserved for future topology balancing")
    args = parser.parse_args()

    if args.samples_per_class <= 0:
        raise ValueError("--samples-per-class must be greater than 0")
    if args.assets <= 0:
        raise ValueError("--assets must be greater than 0")

    output_path = _resolve_project_path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random(args.seed)
    labels = ["normal", "delayed", "filtered"]
    asset_pool = build_asset_pool(rng, args.assets)

    rows = []
    timestamp_us = 0
    for label in labels:
        for _ in range(args.samples_per_class):
            timestamp_us += rng.randint(150, 600)
            rows.append(build_row(timestamp_us, label, rng, asset_pool))

    rng.shuffle(rows)

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["timestamp_us", "asset_ip", "target_port", "protocol_flag", "inter_packet_time_us", "payload_size", "rtt_us", "label"],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} rows to {output_path} assets={len(asset_pool)}")


if __name__ == "__main__":
    main()

