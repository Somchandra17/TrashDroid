"""
Unit tests for phases/backup.py — the safe tar-extraction path-traversal defence.
No device required.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from phases.backup import _safe_extract_tar


def _make_tar(tar_path: str, entries: list[tuple[str, bytes]]) -> None:
    with tarfile.open(tar_path, "w") as tar:
        for name, data in entries:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


class TestSafeExtractTar(unittest.TestCase):
    def test_extracts_normal_members(self):
        with tempfile.TemporaryDirectory() as d:
            tar_path = os.path.join(d, "b.tar")
            out = os.path.join(d, "out")
            _make_tar(tar_path, [("apps/x/f.txt", b"hello")])
            self.assertTrue(_safe_extract_tar(tar_path, out))
            self.assertEqual((Path(out) / "apps" / "x" / "f.txt").read_bytes(), b"hello")

    def test_skips_parent_traversal_member(self):
        with tempfile.TemporaryDirectory() as d:
            tar_path = os.path.join(d, "b.tar")
            out = os.path.join(d, "out")
            _make_tar(tar_path, [("../escape.txt", b"pwned"), ("ok.txt", b"ok")])
            self.assertTrue(_safe_extract_tar(tar_path, out))
            self.assertFalse((Path(d) / "escape.txt").exists())   # traversal blocked
            self.assertTrue((Path(out) / "ok.txt").exists())      # safe member kept

    def test_skips_absolute_path_member(self):
        with tempfile.TemporaryDirectory() as d:
            tar_path = os.path.join(d, "b.tar")
            out = os.path.join(d, "out")
            escape = os.path.join(d, "sibling_escape.txt")  # absolute, outside `out`
            _make_tar(tar_path, [(escape, b"pwned")])
            self.assertTrue(_safe_extract_tar(tar_path, out))
            self.assertFalse(Path(escape).exists())


if __name__ == "__main__":
    unittest.main()
