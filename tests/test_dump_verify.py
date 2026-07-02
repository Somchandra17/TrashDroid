"""
Regression tests for phases/dump_verify.py — the Phase IV BLOB-decode crash and the
SQLite WAL-sidecar false positive (fixed in commit d0dd4b8/ddfcf63 lineage).
No device required; the hermetic test mocks sqlite3, the end-to-end test is skipped
when the sqlite3 CLI is unavailable.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config
from phases.dump_verify import _deep_sqlite_analysis


def _cfg(tmp: Path) -> Config:
    c = Config()
    c.output_dir = tmp
    return c


class TestDumpVerifyHermetic(unittest.TestCase):
    @patch("phases.dump_verify.subprocess.run")
    def test_skips_sqlite_sidecars_and_uses_errors_replace(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=["sqlite3"], returncode=0, stdout="", stderr=""
        )
        with tempfile.TemporaryDirectory() as d:
            db_dir = Path(d) / "databases"
            db_dir.mkdir()
            for name in ["mis_db", "mis_db-wal", "mis_db-shm", "mis_db-journal"]:
                (db_dir / name).write_bytes(b"")
            _deep_sqlite_analysis(_cfg(Path(d)), db_dir)

        queried = [call.args[0][1] for call in mock_run.call_args_list]
        # The real DB is queried; the -wal/-shm/-journal sidecars are skipped entirely.
        self.assertTrue(any(p.endswith("mis_db") for p in queried))
        self.assertFalse(any(p.endswith(("-wal", "-shm", "-journal")) for p in queried))
        # The decode-crash fix: every sqlite3 invocation tolerates non-UTF-8 output.
        for call in mock_run.call_args_list:
            self.assertEqual(call.kwargs.get("errors"), "replace")


class TestDumpVerifyEndToEnd(unittest.TestCase):
    @unittest.skipUnless(shutil.which("sqlite3"), "sqlite3 CLI not available")
    def test_binary_blob_and_sidecar_no_crash_no_false_positive(self):
        with tempfile.TemporaryDirectory() as d:
            db_dir = Path(d) / "databases"
            db_dir.mkdir()
            db_path = db_dir / "real.db"
            con = sqlite3.connect(str(db_path))
            con.execute("CREATE TABLE t (id INTEGER, data BLOB)")
            con.execute("INSERT INTO t VALUES (1, ?)", (bytes([0xB8, 0xFF, 0x00, 0x01, 0xFE]),))
            con.commit()
            con.close()
            (db_dir / "real.db-shm").write_bytes(b"\x00\x01\x02")  # non-DB sidecar

            c = _cfg(Path(d))
            # Pre-fix this raised UnicodeDecodeError on the BLOB and mis-flagged the sidecar.
            _deep_sqlite_analysis(c, db_dir)

            titles = [f.get("title", "") for lst in c.findings.values() for f in lst]
            self.assertFalse(
                any("Encrypted" in t for t in titles),
                f"unexpected encrypted-DB finding(s): {titles}",
            )


if __name__ == "__main__":
    unittest.main()
