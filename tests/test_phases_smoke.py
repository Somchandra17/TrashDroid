"""
Smoke tests for representative phases: they must follow the error contract
(record on config, never raise past the orchestrator) and the W1 package guards
must short-circuit cleanly on a bad package name. No device required.
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config
from phases.backup import run_backup_analysis
from phases.filesystem import run_filesystem_analysis
from phases.manifest import run_manifest_analysis
from phases.memory import run_memory_analysis
from phases.post_logout import run_post_logout_testing
from phases.setup import _sha256_file, install_and_prepare, select_device


def _ns(stdout="", stderr="", rc=0):
    return types.SimpleNamespace(stdout=stdout, stderr=stderr, returncode=rc)


class _FakeADB:
    """Minimal ADB stand-in returning empty, well-typed results."""

    def __init__(self):
        self.device_id = "dev"

    def is_rooted(self):
        return False

    def pull(self, remote, local):
        return ""

    def shell(self, cmd, root=False, timeout=60):
        return _ns(stdout="")

    def get_app_data_path(self, package):
        return f"/data/data/{package}"


def _config(tmp: Path, package="com.example.app") -> Config:
    c = Config()
    c.package_name = package
    c.output_dir = tmp
    c.screenshot_dir = tmp / "screenshots"
    return c


class TestPackageGuards(unittest.TestCase):
    """A bad package must skip the phase without raising or touching the device."""

    def test_filesystem_bad_package_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d), package="bad pkg; rm -rf /")
            adb = MagicMock()
            run_filesystem_analysis(c, adb)  # must not raise
            adb.get_app_data_path.assert_not_called()
            self.assertTrue(any(e["rc"] == 1 for e in c.commands_log))

    def test_memory_bad_package_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d), package="bad pkg")
            adb = MagicMock()
            run_memory_analysis(c, adb)  # must not raise (guard precedes any prompt)
            adb.get_pid.assert_not_called()

    def test_manifest_bad_package_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d), package="bad pkg")
            c.apk_path = None
            adb = MagicMock()
            run_manifest_analysis(c, adb)  # must not raise
            adb.shell.assert_not_called()


class TestFilesystemHappyPath(unittest.TestCase):
    def test_runs_clean_on_empty_device(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d))
            # Should complete without raising and produce a grep results artifact.
            run_filesystem_analysis(c, _FakeADB())
            self.assertTrue((Path(d) / "grep_results.txt").exists())


class TestSetup(unittest.TestCase):
    @patch("phases.setup.ADB.get_devices", return_value=[])
    def test_select_device_none(self, _):
        self.assertEqual(select_device(), "")

    @patch("phases.setup.ADB.get_devices", return_value=["only-dev"])
    def test_select_device_autoselects_single(self, _):
        self.assertEqual(select_device(), "only-dev")

    def test_sha256_file_streams_correct_digest(self):
        import hashlib
        payload = b"trashdroid" * 1000
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "a.bin"
            p.write_bytes(payload)
            self.assertEqual(_sha256_file(p), hashlib.sha256(payload).hexdigest())

    def test_install_and_prepare_auto_no_apk(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d))
            c.auto_mode = True
            c.apk_path = None
            adb = MagicMock()
            install_and_prepare(adb, c)  # auto mode: no prompts, must not raise
            adb.install_apk.assert_not_called()
            self.assertFalse(c.logged_in)


class TestBackupSmoke(unittest.TestCase):
    def test_empty_backup_records_finding_without_raising(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d))
            c.auto_mode = True
            adb = MagicMock()
            adb.backup.return_value = _ns(rc=0)  # command returns but writes no backup file
            run_backup_analysis(c, adb)  # must not raise
            titles = [f.get("title", "") for lst in c.findings.values() for f in lst]
            self.assertTrue(any("backup" in t.lower() for t in titles))


class TestPostLogoutSmoke(unittest.TestCase):
    def test_bad_package_short_circuits(self):
        with tempfile.TemporaryDirectory() as d:
            c = _config(Path(d), package="bad pkg; rm -rf /")
            run_post_logout_testing(c, MagicMock(), MagicMock(), MagicMock())  # must not raise
            self.assertTrue(any(e["rc"] == 1 for e in c.commands_log))


if __name__ == "__main__":
    unittest.main()
