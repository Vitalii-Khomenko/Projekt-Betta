"""Regression tests for scan/report path naming helpers."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.path_naming import build_report_bundle_paths, infer_session_prefix, select_scan_output_base_dir


class PathNamingTests(unittest.TestCase):
    def test_select_scan_output_base_dir_prefers_parent_of_file_path(self) -> None:
        base_dir = select_scan_output_base_dir(Path("data/scans"), Path("custom/output/result.csv"))
        self.assertEqual(base_dir, Path("custom/output"))

    def test_build_report_bundle_paths_keeps_session_directory_layout(self) -> None:
        bundle = build_report_bundle_paths(
            Path("data/scans"),
            "127.0.0.1",
            Path("data/scans/windows_local_test.csv"),
            timestamp="20260410_121554",
        )
        expected_dir = Path("data/scans") / "20260410_121554_127.0.0.1"
        self.assertEqual(bundle["dir"], expected_dir)
        self.assertEqual(bundle["result_csv"], expected_dir / "20260410_121554_127.0.0.1_result.csv")
        self.assertEqual(bundle["classified_csv"], expected_dir / "20260410_121554_127.0.0.1_classified.csv")
        self.assertEqual(bundle["hostnames_csv"], expected_dir / "20260410_121554_127.0.0.1_hostnames.csv")
        self.assertEqual(bundle["hostnames_html"], expected_dir / "20260410_121554_127.0.0.1_hostnames_report.html")

    def test_infer_session_prefix_handles_session_file_names(self) -> None:
        prefix = infer_session_prefix(Path("data/scans/20260410_121554_127.0.0.1/20260410_121554_127.0.0.1_result.csv"))
        self.assertEqual(prefix, "20260410_121554_127.0.0.1")

    def test_infer_session_prefix_handles_hostname_reports(self) -> None:
        prefix = infer_session_prefix(
            Path("data/scans/20260410_121554_127.0.0.1/20260410_121554_127.0.0.1_hostnames_report.html")
        )
        self.assertEqual(prefix, "20260410_121554_127.0.0.1")


if __name__ == "__main__":
    unittest.main()
