"""Tests for package enumeration + exact-match install check (interactive picker support)."""

from __future__ import annotations

import os
import sys
import types
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.adb import ADB


def _cp(stdout="", rc=0):
    return types.SimpleNamespace(stdout=stdout, stderr="", returncode=rc)


class TestListInstalledPackages(unittest.TestCase):
    def test_parses_and_sorts_dedup(self):
        adb = ADB("dev")
        adb.shell = MagicMock(return_value=_cp("package:com.b.app\npackage:com.a.app\npackage:com.a.app\n"))
        self.assertEqual(adb.list_installed_packages(), ["com.a.app", "com.b.app"])

    def test_ignores_non_package_lines(self):
        adb = ADB("dev")
        adb.shell = MagicMock(return_value=_cp("garbage line\npackage:com.x.app\n\n"))
        self.assertEqual(adb.list_installed_packages(), ["com.x.app"])


class TestIsPackageInstalledExact(unittest.TestCase):
    def test_exact_line_matches(self):
        adb = ADB("dev")
        adb.shell = MagicMock(return_value=_cp("package:com.example\npackage:com.example.app\n"))
        self.assertTrue(adb.is_package_installed("com.example.app"))

    def test_prefix_is_not_falsely_installed(self):
        # The substring filter returns the longer package; querying the prefix must be False.
        adb = ADB("dev")
        adb.shell = MagicMock(return_value=_cp("package:com.example.app\n"))
        self.assertFalse(adb.is_package_installed("com.example"))


if __name__ == "__main__":
    unittest.main()
