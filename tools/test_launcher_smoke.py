"""
Launcher smoke tests for parser wiring and default paths.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import launcher


class LauncherSmokeTests(unittest.TestCase):
    def test_verify_betta_morpho_parser_uses_scan_csv(self) -> None:
        args = launcher.build_parser().parse_args(["verify-betta-morpho", "--scan-csv", "result.csv"])
        self.assertEqual(args.scan_csv, "result.csv")

    def test_train_and_replay_defaults_point_to_existing_project_layout(self) -> None:
        parser = launcher.build_parser()
        train_args = parser.parse_args(["train"])
        replay_args = parser.parse_args(["replay-dir"])
        evaluate_args = parser.parse_args(["evaluate"])

        self.assertEqual(train_args.data, launcher.DEFAULT_DATASET)
        self.assertEqual(replay_args.data_dir, launcher.DEFAULT_REPLAY_DIR)
        self.assertEqual(evaluate_args.data, launcher.DEFAULT_DATASET)

    def test_launcher_resource_targets_exist(self) -> None:
        self.assertTrue((launcher.ROOT / launcher.LAB_SERVICES_SCRIPT).exists())
        self.assertTrue((launcher.ROOT / launcher.LAB_EXERCISE_SCRIPT).exists())
        self.assertTrue(launcher.SPEC_PATH.exists())

    def test_discover_hostnames_parser_and_scan_flags_exist(self) -> None:
        parser = launcher.build_parser()
        discover_args = parser.parse_args(
            ["discover-hostnames", "data/scans/example_result.csv", "--output", "data/scans/example_hostnames.csv"]
        )
        scan_args = parser.parse_args(["scan", "--target", "127.0.0.1", "--discover-hostnames"])

        self.assertEqual(discover_args.inputs, ["data/scans/example_result.csv"])
        self.assertEqual(discover_args.output, "data/scans/example_hostnames.csv")
        self.assertTrue(scan_args.discover_hostnames)


if __name__ == "__main__":
    unittest.main()
