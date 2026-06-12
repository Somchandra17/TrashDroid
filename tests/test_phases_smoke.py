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
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config
from phases.filesystem import run_filesystem_analysis
from phases.manifest import run_manifest_analysis
from phases.memory import run_memory_analysis


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


if __name__ == "__main__":
    unittest.main()
