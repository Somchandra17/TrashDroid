"""
Unit tests for core/adb.py — command building, retry/error handling, and the
shell-input validation guards. No device required; subprocess is mocked.
"""

from __future__ import annotations

import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.adb import ADB, ADBError


def _completed(stdout="", stderr="", rc=0):
    return subprocess.CompletedProcess(args=["adb"], returncode=rc, stdout=stdout, stderr=stderr)


class TestADBRun(unittest.TestCase):
    @patch("core.adb.subprocess.run")
    def test_run_returns_completed_process(self, mock_run):
        mock_run.return_value = _completed(stdout="ok")
        result = ADB("dev").run(["shell", "echo hi"])
        self.assertEqual(result.stdout, "ok")
        # device id is threaded into the command
        self.assertEqual(mock_run.call_args[0][0][:3], ["adb", "-s", "dev"])

    @patch("core.adb.subprocess.run")
    def test_check_nonzero_raises_after_retries(self, mock_run):
        mock_run.return_value = _completed(stderr="boom", rc=1)
        with self.assertRaises(ADBError):
            ADB().run(["shell", "x"], check=True, retries=0)

    @patch("core.adb.time.sleep", lambda *_: None)
    @patch("core.adb.subprocess.run")
    def test_timeout_becomes_adberror(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="adb", timeout=1)
        with self.assertRaises(ADBError):
            ADB().run(["shell", "x"], retries=1)

    @patch("core.adb.subprocess.run")
    def test_missing_adb_becomes_adberror(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        with self.assertRaises(ADBError) as ctx:
            ADB().run(["devices"])
        self.assertIn("adb executable not found", str(ctx.exception))

    @patch("core.adb.subprocess.run")
    def test_get_devices_parses_only_online(self, mock_run):
        mock_run.return_value = _completed(
            stdout="List of devices attached\nemulator-5554\tdevice\nabc123\toffline\n"
        )
        self.assertEqual(ADB.get_devices(), ["emulator-5554"])


class TestADBInputGuards(unittest.TestCase):
    def test_package_guard_rejects_bad_names(self):
        a = ADB()
        for bad in ["bad pkg", "com.x; rm -rf /", "", "x"]:
            with self.assertRaises(ADBError):
                a.get_app_data_path(bad)

    def test_package_guard_accepts_valid(self):
        self.assertEqual(ADB().get_app_data_path("com.example.app"), "/data/data/com.example.app")

    def test_device_path_guard_rejects_injection(self):
        with self.assertRaises(ADBError):
            ADB().list_dir("/data/data/com.x; rm -rf /")
        with self.assertRaises(ADBError):
            ADB().pull_as_root("/sdcard/../etc/passwd", "/tmp/x")

    def test_start_activity_rejects_bad_component(self):
        with self.assertRaises(ADBError):
            ADB().start_activity("com.example.app", "Foo;reboot")

    @patch("core.adb.subprocess.run")
    def test_start_activity_accepts_valid(self, mock_run):
        mock_run.return_value = _completed(stdout="Starting")
        out = ADB().start_activity("com.example.app", ".MainActivity")
        self.assertEqual(out, "Starting")

    def test_start_activity_rejects_unsafe_extras(self):
        a = ADB()
        for bad in ["--es u $(reboot)", "--es u a; rm -rf /", "--ez x true && id", "x `id`", "a | nc h 1"]:
            with self.assertRaises(ADBError):
                a.start_activity("com.example.app", ".MainActivity", bad)

    @patch("core.adb.subprocess.run")
    def test_start_activity_accepts_safe_extras(self, mock_run):
        mock_run.return_value = _completed(stdout="Starting")
        # URL/path punctuation in extras is legitimate and must be allowed through.
        out = ADB().start_activity(
            "com.example.app", ".MainActivity", "--es redirect_uri https://evil.com --ez is_admin true"
        )
        self.assertEqual(out, "Starting")


if __name__ == "__main__":
    unittest.main()
