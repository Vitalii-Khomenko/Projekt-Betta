#!/usr/bin/env python3
# =============================================================================
# test_launcher_interrupt.py  -  Regression tests for launcher interrupt handling
# =============================================================================
# Usage:
#   python -m unittest tools.test_launcher_interrupt
#   python tools/test_launcher_interrupt.py
#
# Key options:
#   None
#
# Author  : Vitalii Khomenko <khomenko.vitalii@pm.me>
# License : Apache-2.0 - see LICENSE
# Version : 0.1.0
# =============================================================================
from __future__ import annotations

import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import launcher


class LauncherInterruptTests(unittest.TestCase):
    def test_run_script_returns_130_quietly_on_keyboard_interrupt(self) -> None:
        stdout = StringIO()
        with patch("launcher.subprocess.call", side_effect=KeyboardInterrupt), patch("sys.stdout", stdout):
            code = launcher.run_script("training/tools/scanner.py", [])

        self.assertEqual(code, 130)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
