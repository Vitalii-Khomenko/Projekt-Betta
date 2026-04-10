"""Unit tests for unified Betta-Morpho artifact metadata helpers."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.artifact_schema import (
    FAMILY_BENCHMARK,
    FAMILY_CLASSIFIER,
    attach_artifact_metadata,
    normalize_artifact_payload,
    validate_artifact_payload,
)


class ArtifactSchemaTests(unittest.TestCase):
    def test_attach_metadata_enriches_payload(self) -> None:
        payload = attach_artifact_metadata(
            {"trainer": "prototype"},
            FAMILY_CLASSIFIER,
            model_type="telemetry-snn-classifier",
            producer="training.train",
            extra_metadata={"backend": "prototype"},
        )

        self.assertEqual(payload["artifact_family"], FAMILY_CLASSIFIER)
        self.assertEqual(payload["artifact_schema_version"], 1)
        self.assertEqual(payload["model_type"], "telemetry-snn-classifier")
        self.assertEqual(payload["artifact_metadata"]["backend"], "prototype")

    def test_normalize_legacy_payload_backfills_family(self) -> None:
        legacy_payload = {
            "W1": [[0.1]],
            "W2": [[0.2]],
            "actions": ["PROBE_SYN"],
            "scanner_version": 1,
        }

        normalized = normalize_artifact_payload(
            legacy_payload,
            expected_family="scanner-snn",
            default_model_type="scan-strategy-snn",
            producer="training.tools.scanner",
        )
        info = validate_artifact_payload(normalized, expected_family="scanner-snn")

        self.assertEqual(normalized["artifact_family"], "scanner-snn")
        self.assertEqual(normalized["model_type"], "scan-strategy-snn")
        self.assertEqual(info["artifact_schema_version"], 1)

    def test_benchmark_manifest_family_is_supported(self) -> None:
        payload = attach_artifact_metadata(
            {"benchmark_kind": "scan-comparison"},
            FAMILY_BENCHMARK,
            model_type="scan-comparison",
            producer="tools.benchmark_scans",
        )
        info = validate_artifact_payload(payload, expected_family=FAMILY_BENCHMARK)
        self.assertEqual(info["artifact_family"], FAMILY_BENCHMARK)


if __name__ == "__main__":
    unittest.main()
