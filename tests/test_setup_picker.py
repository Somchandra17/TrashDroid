"""Tests for the interactive target-package picker in phases/setup.py."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phases.setup import _select_installed_package


def _adb(pkgs, installed=True):
    adb = MagicMock()
    adb.list_installed_packages.return_value = pkgs
    adb.is_package_installed.return_value = installed
    return adb


class TestSelectInstalledPackage(unittest.TestCase):
    @patch("phases.setup.Prompt.ask", return_value="2")
    def test_number_selection(self, _ask):
        adb = _adb(["com.a.app", "com.b.app", "com.c.app"])
        self.assertEqual(_select_installed_package(adb), "com.b.app")

    @patch("phases.setup.Prompt.ask", return_value="com.typed.app")
    def test_typed_id_installed(self, _ask):
        adb = _adb(["com.a.app"], installed=True)
        self.assertEqual(_select_installed_package(adb), "com.typed.app")

    @patch("phases.setup.Confirm.ask", return_value=True)
    @patch("phases.setup.Prompt.ask", return_value="com.typed.app")
    def test_typed_id_not_installed_but_overridden(self, _ask, _confirm):
        adb = _adb(["com.a.app"], installed=False)
        self.assertEqual(_select_installed_package(adb), "com.typed.app")

    @patch("phases.setup.Prompt.ask", side_effect=["not a package", "com.valid.app"])
    def test_invalid_then_valid(self, _ask):
        adb = _adb(["com.a.app"], installed=True)
        self.assertEqual(_select_installed_package(adb), "com.valid.app")


if __name__ == "__main__":
    unittest.main()
