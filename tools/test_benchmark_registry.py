"""Unit tests for benchmark manifests, experiment registry, and domain summaries."""
from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.benchmark_scans import build_benchmark_manifest, register_manifest
from tools.domain_metrics import build_domain_summary
from tools.experiment_registry import ExperimentRegistry


def _write_result_csv(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = [
        "timestamp_us",
        "asset_ip",
        "target_port",
        "protocol_flag",
        "service",
        "service_prediction",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


class BenchmarkRegistryTests(unittest.TestCase):
    def test_benchmark_manifest_tracks_overlap_and_speed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            baseline_csv = tmp_path / "baseline.csv"
            candidate_csv = tmp_path / "candidate.csv"
            baseline_log = tmp_path / "baseline.log"
            candidate_log = tmp_path / "candidate.log"

            _write_result_csv(
                baseline_csv,
                [
                    {"timestamp_us": "1", "asset_ip": "10.0.0.1", "target_port": "22", "protocol_flag": "SYN_ACK", "service": "OpenSSH", "service_prediction": ""},
                    {"timestamp_us": "2", "asset_ip": "10.0.0.1", "target_port": "80", "protocol_flag": "SYN_ACK", "service": "HTTP", "service_prediction": ""},
                ],
            )
            _write_result_csv(
                candidate_csv,
                [
                    {"timestamp_us": "1", "asset_ip": "10.0.0.1", "target_port": "22", "protocol_flag": "SYN_ACK", "service": "OpenSSH", "service_prediction": "OpenSSH"},
                    {"timestamp_us": "2", "asset_ip": "10.0.0.1", "target_port": "443", "protocol_flag": "SYN_ACK", "service": "HTTPS", "service_prediction": "HTTPS"},
                ],
            )
            baseline_log.write_text("2026-04-04 [SCAN_FINISH] elapsed_seconds=10.0\n", encoding="utf-8")
            candidate_log.write_text("2026-04-04 [SCAN_FINISH] elapsed_seconds=5.0\n", encoding="utf-8")

            manifest = build_benchmark_manifest(
                baseline_csv=baseline_csv,
                candidate_csv=candidate_csv,
                baseline_label="connect",
                candidate_label="raw",
                domain="verified_real",
                baseline_progress_log=baseline_log,
                candidate_progress_log=candidate_log,
            )

            self.assertEqual(manifest["artifact_family"], "benchmark-report")
            self.assertEqual(manifest["metrics"]["matched_open_count"], 1.0)
            self.assertEqual(manifest["metrics"]["recall_vs_baseline"], 0.5)
            self.assertEqual(manifest["metrics"]["precision_vs_baseline"], 0.5)
            self.assertEqual(manifest["metrics"]["service_precision_on_overlap"], 1.0)
            self.assertEqual(manifest["metrics"]["candidate_speedup_vs_baseline"], 2.0)

    def test_registry_and_domain_summary_capture_benchmarks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            registry_path = tmp_path / "experiments.db"
            baseline_csv = tmp_path / "baseline.csv"
            candidate_csv = tmp_path / "candidate.csv"
            _write_result_csv(
                baseline_csv,
                [{"timestamp_us": "1", "asset_ip": "10.0.0.1", "target_port": "22", "protocol_flag": "SYN_ACK", "service": "OpenSSH", "service_prediction": ""}],
            )
            _write_result_csv(
                candidate_csv,
                [{"timestamp_us": "1", "asset_ip": "10.0.0.1", "target_port": "22", "protocol_flag": "SYN_ACK", "service": "OpenSSH", "service_prediction": "OpenSSH"}],
            )

            verified_manifest = build_benchmark_manifest(
                baseline_csv=baseline_csv,
                candidate_csv=candidate_csv,
                baseline_label="nmap",
                candidate_label="betta",
                domain="verified_real",
            )
            synthetic_manifest = build_benchmark_manifest(
                baseline_csv=baseline_csv,
                candidate_csv=candidate_csv,
                baseline_label="synthetic-baseline",
                candidate_label="synthetic-candidate",
                domain="synthetic",
            )

            first_id = register_manifest(verified_manifest, registry_path=registry_path, name="verified-real benchmark")
            second_id = register_manifest(synthetic_manifest, registry_path=registry_path, name="synthetic benchmark")

            registry = ExperimentRegistry(registry_path)
            experiments = registry.list_experiments(limit=10)
            summary = build_domain_summary(registry_path)

            self.assertEqual(len(experiments), 2)
            self.assertGreater(second_id, first_id)
            self.assertEqual(experiments[0]["domain"], "synthetic")
            self.assertEqual(registry.get_experiment(first_id)["kind"], "benchmark")
            self.assertEqual(summary["domains"]["verified_real"]["experiments"], 1)
            self.assertEqual(summary["domains"]["synthetic"]["experiments"], 1)


if __name__ == "__main__":
    unittest.main()
