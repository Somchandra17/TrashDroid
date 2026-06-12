"""
Unit tests for core/drozer.py — output parsing helpers and run_module input
guards. No device required; subprocess is mocked.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.drozer import (
    Drozer,
    _is_valid_component_name,
    _parse_component_list,
    _strip_drozer_noise,
)


def _completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(args=["drozer"], returncode=rc, stdout=stdout, stderr=stderr)


class TestDrozerParsing(unittest.TestCase):
    def test_strip_noise_removes_console_chatter(self):
        raw = "Selecting f7a8\nattempting to run\ncom.example.MyActivity\ndz> "
        cleaned = _strip_drozer_noise(raw)
        self.assertIn("com.example.MyActivity", cleaned)
        self.assertNotIn("dz>", cleaned)

    def test_parse_component_list_keeps_valid_only(self):
        raw = "Package: com.example\ncom.example.Foo\nnot a class\ncom.example.Bar"
        comps = _parse_component_list(raw)
        self.assertIn("com.example.Foo", comps)
        self.assertIn("com.example.Bar", comps)
        self.assertNotIn("not a class", comps)

    def test_is_valid_component_name(self):
        self.assertTrue(_is_valid_component_name("com.example.MyService"))
        self.assertFalse(_is_valid_component_name("has space"))
        self.assertFalse(_is_valid_component_name("nodots"))


class TestRunModuleGuards(unittest.TestCase):
    def test_rejects_newline_injection(self):
        r = Drozer().run_module("scanner.provider.injection\nrun shell", "")
        self.assertFalse(r.success)
        self.assertIn("rejected", r.stderr)

    def test_rejects_bad_module_name(self):
        r = Drozer().run_module("bad;module", "")
        self.assertFalse(r.success)
        self.assertIn("rejected", r.stderr)

    @patch("core.drozer.subprocess.run")
    def test_valid_module_runs(self, mock_run):
        mock_run.return_value = _completed(stdout="com.example.Foo")
        r = Drozer().run_module("app.package.attacksurface", "-a com.example")
        self.assertTrue(r.success)
        self.assertIn("com.example.Foo", r.stdout)

    @patch("core.drozer.subprocess.run")
    def test_module_error_in_output_is_failure(self, mock_run):
        mock_run.return_value = _completed(stdout="Permission Denied")
        r = Drozer().run_module("app.provider.query", "content://x")
        self.assertFalse(r.success)


if __name__ == "__main__":
    unittest.main()
