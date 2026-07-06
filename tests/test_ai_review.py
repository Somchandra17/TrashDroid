"""Unit tests for the AI-review package assembler (core/ai_review.py). No `claude` needed."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rich.console import Console

from core.ai_review import assemble_review_package, run_claude_review
from core.config import Config

DEVICE = {"model": "Pixel", "android_version": "14", "sdk": "34"}


def _make_config(tmp: Path) -> Config:
    c = Config()
    c.package_name = "com.example.app"
    c.output_dir = tmp
    c.screenshot_dir = tmp / "screenshots"
    c.logged_in = True

    (tmp / "screenshots").mkdir(parents=True, exist_ok=True)
    (tmp / "screenshots" / "shot1.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
    c.add_screenshot("screenshots/shot1.png", "Splash", "Phase I — Drozer Component Testing")

    (tmp / "grep_results.txt").write_text("password=hunter2\n", encoding="utf-8")

    c.add_finding("Phase I — Drozer Component Testing", "Exported activity accessible", "Medium", "detail A")
    c.add_finding("Phase III — Local File System Analysis", "Sensitive data in storage", "High", "detail B")
    # duplicate of the first → must be merged by _dedupe_findings
    c.add_finding("Phase I — Drozer Component Testing", "Exported activity accessible", "Medium", "detail A")
    c.log_command("Phase I — Drozer Component Testing", "run app.activity.info", "out", "")
    return c


def _report(tmp: Path) -> Path:
    p = tmp / "DAST_Report.md"
    p.write_text("PREAMBLE TO STRIP\n# Android DAST Report — `com.example.app`\nbody\n", encoding="utf-8")
    return p


class TestAssemblePackage(unittest.TestCase):
    def test_package_layout(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = assemble_review_package(_make_config(tmp), DEVICE, _report(tmp))
            for f in ["PROMPT.md", "CLAUDE.md", "findings.json", "report.md", "run_review.sh", "gen_html.py"]:
                self.assertTrue((pkg / f).exists(), f"missing {f}")
            self.assertTrue((pkg / "screenshots" / "shot1.png").exists())
            self.assertTrue((pkg / "screenshots" / "index.json").exists())
            self.assertTrue((pkg / "logs" / "commands.log").exists())
            self.assertTrue((pkg / "logs" / "grep_results.txt").exists())
            # report.md has the embedded prompt/preamble stripped down to the marker
            self.assertTrue((pkg / "report.md").read_text(encoding="utf-8").startswith("# Android DAST Report"))
            # PROMPT.md embeds the Android triage prompt + VAPT standard
            prompt = (pkg / "PROMPT.md").read_text(encoding="utf-8")
            self.assertIn("Android application penetration tester", prompt)
            self.assertIn("TICKET FORMAT", prompt)

    def test_findings_ids_counts_and_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = assemble_review_package(_make_config(tmp), DEVICE, _report(tmp))
            data = json.loads((pkg / "findings.json").read_text(encoding="utf-8"))

            self.assertEqual(data["tool"], "TrashDroid")
            self.assertEqual(data["package"], "com.example.app")
            self.assertTrue(data["tested_logged_in"])
            # the duplicate Medium finding merged → 2 findings total
            self.assertEqual(data["total_findings"], 2)
            self.assertEqual(data["severity_counts"]["High"], 1)
            self.assertEqual(data["severity_counts"]["Medium"], 1)

            ids = [f["id"] for f in data["findings"]]
            self.assertEqual(ids, ["F-001", "F-002"])
            # sorted by severity → High first
            self.assertEqual(data["findings"][0]["severity"], "High")

            drozer = next(f for f in data["findings"] if f["phase"] == "Phase I — Drozer Component Testing")
            self.assertIn("shot1.png", drozer["evidence"]["screenshots"])
            self.assertIn("commands.log", drozer["evidence"]["logs"])  # general log attaches to all
            self.assertEqual(drozer["occurrences"], 2)

            fs = next(f for f in data["findings"] if f["phase"] == "Phase III — Local File System Analysis")
            self.assertIn("grep_results.txt", fs["evidence"]["logs"])

    def test_screenshot_index_maps_finding_ids(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = assemble_review_package(_make_config(tmp), DEVICE, _report(tmp))
            idx = json.loads((pkg / "screenshots" / "index.json").read_text(encoding="utf-8"))
            shot = next(s for s in idx if s["file"] == "shot1.png")
            self.assertIn("F-002", shot["finding_ids"])  # the Phase I finding


class TestRunClaudeReview(unittest.TestCase):
    def _pkg(self, tmp: Path) -> Path:
        return assemble_review_package(_make_config(tmp), DEVICE, _report(tmp))

    @patch("core.ai_review.shutil.which", return_value=None)
    def test_degrades_without_claude(self, _which):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = self._pkg(tmp)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("TRASHDROID_REVIEW_CMD", None)
                run_claude_review(pkg, Console())  # must not raise
            self.assertFalse((pkg / "final_report.md").exists())

    @patch("core.ai_review.subprocess.run")
    def test_custom_cmd_placeholder_substitution(self, mock_run):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = self._pkg(tmp)
            with patch.dict(os.environ, {"TRASHDROID_REVIEW_CMD": "mytool {prompt_file}"}):
                run_claude_review(pkg, Console())
            cmd = mock_run.call_args.args[0]
            self.assertEqual(cmd[0], "mytool")
            self.assertTrue(cmd[1].endswith("PROMPT.md"))

    @patch("core.ai_review.subprocess.run")
    def test_custom_cmd_appends_prompt_when_no_placeholder(self, mock_run):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            pkg = self._pkg(tmp)
            with patch.dict(os.environ, {"TRASHDROID_REVIEW_CMD": "mytool --yes"}):
                run_claude_review(pkg, Console())
            cmd = mock_run.call_args.args[0]
            self.assertEqual(cmd[:2], ["mytool", "--yes"])
            self.assertTrue(cmd[-1].endswith("PROMPT.md"))


if __name__ == "__main__":
    unittest.main()
