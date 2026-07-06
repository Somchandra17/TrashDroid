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

from core.config import Config
from core.drozer import (
    Drozer,
    DrozerResult,
    _is_valid_component_name,
    _parse_component_list,
    _strip_drozer_noise,
)
from phases.drozer_testing import _test_intents

# The exact banner pysolar's ConnectionError print()s to stdout when the agent
# server is unreachable — the "yayerroryay" text lands in captured output.
_PYSOLAR_CONN_ERROR = (
    "<class 'RuntimeError'>\n"
    "yayerroryay you probably didn't specify a valid drozer server "
    "and that's why you're seeing this error message"
)


def _completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(args=["drozer"], returncode=rc, stdout=stdout, stderr=stderr)


def _finding_titles(config):
    return [f["title"] for lst in config.findings.values() for f in lst]


class _FakeScreenshotter:
    def capture(self, *args, **kwargs):
        return None


class _FakeDrozerForIntents:
    """Serves a canned browsable-activities result; launchintent is a no-op."""

    def __init__(self, browsable_result):
        self._browsable = browsable_result

    def get_browsable_activities(self, package):
        return self._browsable

    def run_module(self, module, args="", timeout=30):
        return DrozerResult(module, args, "", "", True)


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


class TestConnectionFailureHandling(unittest.TestCase):
    @patch("core.drozer.subprocess.run")
    def test_connection_error_output_is_blanked(self, mock_run):
        """pysolar's connection banner must never be treated as module output."""
        mock_run.return_value = _completed(
            stdout=_PYSOLAR_CONN_ERROR,
            stderr="'ConnectionError' object has no attribute 'message'",
            rc=255,
        )
        r = Drozer()._run_module_once("scanner.activity.browsable", "-a com.example")
        self.assertFalse(r.success)
        self.assertEqual(r.stdout, "")
        self.assertTrue(Drozer.is_connection_failure(r))

    def test_is_connection_failure_detects_timeout(self):
        r = DrozerResult("m", "", "", "Timed out after 30s", False)
        self.assertTrue(Drozer.is_connection_failure(r))

    def test_is_connection_failure_false_for_normal_result(self):
        r = DrozerResult("m", "", "com.example.Foo", "", True, raw_stdout="com.example.Foo")
        self.assertFalse(Drozer.is_connection_failure(r))

    @patch("core.drozer.Drozer.restart_agent_server", return_value=True)
    @patch("core.drozer.subprocess.run")
    def test_run_module_auto_reconnects_then_succeeds(self, mock_run, mock_restart):
        """A wedged agent triggers exactly one restart, then the retry succeeds."""
        mock_run.side_effect = [
            _completed(stdout=_PYSOLAR_CONN_ERROR, rc=255),
            _completed(stdout="com.example.Foo", rc=0),
        ]
        d = Drozer(rooted=True)
        r = d.run_module("app.package.attacksurface", "-a com.example")
        mock_restart.assert_called_once()
        self.assertTrue(r.success)
        self.assertIn("com.example.Foo", r.stdout)

    @patch("core.drozer.Drozer.restart_agent_server", return_value=False)
    @patch("core.drozer.subprocess.run")
    def test_run_module_reconnect_capped(self, mock_run, mock_restart):
        """When restart never recovers, run_module still returns a clean failure."""
        mock_run.return_value = _completed(stdout=_PYSOLAR_CONN_ERROR, rc=255)
        d = Drozer(rooted=True)
        r = d.run_module("app.package.attacksurface", "-a com.example")
        self.assertFalse(r.success)
        self.assertEqual(r.stdout, "")
        # One failed recovery attempt is made per call (restart returned False).
        mock_restart.assert_called_once()


class TestIntentSniffingReporting(unittest.TestCase):
    def _run(self, browsable_result):
        config = Config()
        config.package_name = "com.example.app"
        _test_intents(config, _FakeDrozerForIntents(browsable_result), _FakeScreenshotter(), "com.example.app")
        return config

    def test_no_finding_on_connection_error(self):
        conn_err = DrozerResult(
            "scanner.activity.browsable", "-a com.example.app",
            stdout="", stderr="drozer connection error", success=False,
            raw_stdout=_PYSOLAR_CONN_ERROR,
        )
        config = self._run(conn_err)
        self.assertNotIn("Browsable activities found", _finding_titles(config))

    def test_no_finding_on_empty_success(self):
        empty = DrozerResult("scanner.activity.browsable", "-a com.example.app", "", "", True)
        config = self._run(empty)
        self.assertNotIn("Browsable activities found", _finding_titles(config))

    def test_finding_on_real_browsable_data(self):
        data = DrozerResult(
            "scanner.activity.browsable", "-a com.example.app",
            stdout="com.example.app.DeepLinkActivity", stderr="", success=True,
            raw_stdout="com.example.app.DeepLinkActivity",
        )
        config = self._run(data)
        self.assertIn("Browsable activities found", _finding_titles(config))


if __name__ == "__main__":
    unittest.main()
