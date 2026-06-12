"""
Correctness tests for core/report.py — CVSS computation, screenshot matching,
and Markdown escaping. Runs without a device.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.config import Config
from core.report import (
    _BASE_METRICS_BY_SEVERITY,
    ReportGenerator,
    _contextual_cvss,
    _cvss31_base_score,
    _cvss31_roundup,
    _fence,
    _md_cell,
    _md_image,
    _screenshots_for_finding,
)


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse a 'CVSS:3.1/AV:N/AC:L/...' string into a metrics dict."""
    metrics = {}
    for part in vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            metrics[k] = v
    return metrics


class TestContextualCVSS(unittest.TestCase):
    def test_score_always_matches_its_vector(self):
        # Neutral text triggers no AV override, so each severity round-trips.
        for sev in _BASE_METRICS_BY_SEVERITY:
            score_str, vector = _contextual_cvss(sev, "Generic finding", "plain detail")
            recomputed = _cvss31_base_score(_parse_vector(vector))
            self.assertEqual(score_str, f"{recomputed:.1f}", f"mismatch for {sev}")

    def test_critical_neutral_is_9_8(self):
        score, vector = _contextual_cvss("Critical", "Generic", "detail")
        self.assertEqual(score, "9.8")
        self.assertIn("AV:N", vector)

    def test_info_is_na(self):
        self.assertEqual(_contextual_cvss("Info", "x", "y"), ("0.0", "N/A"))

    def test_unknown_severity_is_na(self):
        self.assertEqual(_contextual_cvss("Bogus", "x", "y"), ("0.0", "N/A"))

    def test_backup_high_uses_physical_av_and_lowers_score(self):
        neutral_score, _ = _contextual_cvss("High", "Generic finding", "detail")
        score, vector = _contextual_cvss("High", "ADB backup contains secrets", "extracted backup")
        self.assertIn("AV:P", vector)
        # Physical access is harder to reach than network → score must drop.
        self.assertLess(float(score), float(neutral_score))
        # And the score still matches the adjusted vector.
        self.assertEqual(score, f"{_cvss31_base_score(_parse_vector(vector)):.1f}")

    def test_medium_exported_gets_local_av(self):
        # This is the case the old string-replace silently dropped.
        neutral_score, neutral_vec = _contextual_cvss("Medium", "Generic finding", "detail")
        self.assertIn("AV:N", neutral_vec)
        score, vector = _contextual_cvss("Medium", "Exported component is accessible", "detail")
        self.assertIn("AV:L", vector)
        self.assertLess(float(score), float(neutral_score))

    def test_roundup_matches_spec(self):
        self.assertEqual(_cvss31_roundup(4.582), 4.6)
        self.assertEqual(_cvss31_roundup(4.0), 4.0)
        self.assertEqual(_cvss31_roundup(9.762), 9.8)


class TestMarkdownEscaping(unittest.TestCase):
    def test_fence_longer_than_internal_backtick_run(self):
        content = "a ``` b ```` c"  # longest run is 4
        fence = _fence(content)
        self.assertEqual(fence, "`" * 5)
        self.assertTrue(all(ch == "`" for ch in fence))

    def test_fence_minimum_three(self):
        self.assertEqual(_fence("no backticks here"), "```")

    def test_md_cell_escapes_pipe_and_newline(self):
        out = _md_cell("a|b\nc")
        self.assertIn("\\|", out)
        self.assertNotIn("\n", out)

    def test_md_image_handles_special_chars(self):
        out = _md_image("shot]name", "./screenshots/a b(1).png")
        self.assertTrue(out.startswith("!["))
        self.assertIn("\\]", out)               # caption bracket escaped
        self.assertIn("(<./screenshots/a b(1).png>)", out)  # angle-bracket path


class TestScreenshotMatching(unittest.TestCase):
    def test_exact_component_target_matches(self):
        shots = [{"phase": "P", "caption": "Activity: com.example.Foo", "path": "a.png"}]
        finding = {"title": "Exported activity accessible: com.example.Foo", "detail": ""}
        matched = _screenshots_for_finding(shots, "P", finding, set())
        self.assertEqual([s["path"] for s in matched], ["a.png"])

    def test_generic_caption_provider_finding_still_matches(self):
        # Regression: the old strict 'continue' dropped these entirely.
        shots = [{"phase": "P", "caption": "Content Provider Tests", "path": "p.png"}]
        finding = {
            "title": "SQL injection in content provider: content://com.example.provider/secret",
            "detail": "",
        }
        matched = _screenshots_for_finding(shots, "P", finding, set())
        self.assertEqual([s["path"] for s in matched], ["p.png"])

    def test_screenshot_used_at_most_once(self):
        used: set[str] = set()
        shots = [{"phase": "P", "caption": "Activity: com.example.Foo", "path": "a.png"}]
        f1 = {"title": "Exported activity accessible: com.example.Foo", "detail": ""}
        first = _screenshots_for_finding(shots, "P", f1, used)
        self.assertEqual(len(first), 1)
        second = _screenshots_for_finding(shots, "P", f1, used)
        self.assertEqual(second, [])

    def test_other_phase_screenshots_ignored(self):
        shots = [{"phase": "OTHER", "caption": "Activity: com.example.Foo", "path": "a.png"}]
        finding = {"title": "Exported activity accessible: com.example.Foo", "detail": ""}
        self.assertEqual(_screenshots_for_finding(shots, "P", finding, set()), [])


class TestGenerateSmoke(unittest.TestCase):
    def _build_config(self, tmp: Path) -> Config:
        c = Config()
        c.package_name = "com.x.app"
        c.device_id = "emulator-5554"
        c.output_dir = tmp
        c.screenshot_dir = tmp / "screenshots"
        phase = "Phase V — Logcat Monitoring"
        # A finding whose title/detail contain Markdown metacharacters.
        c.add_finding(phase, "Sensitive data leaked | token", "High", "secret = ```inline``` value")
        c.log_command(phase, "adb logcat", "some output")
        c.add_screenshot("./screenshots/shot]1.png", "Activity: com.x.app.Main", phase)
        return c

    def test_generate_writes_valid_report_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            c = self._build_config(tmp)
            device_info = {"model": "Pixel", "android_version": "13", "sdk": "33"}
            path = ReportGenerator(c, device_info).generate()

            self.assertTrue(Path(path).exists())
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("# Android DAST Report", content)
            self.assertIn("## Risk Summary", content)
            # Pipe in the title is escaped in the Risk Summary table.
            self.assertIn("Sensitive data leaked \\| token", content)
            # Inner ``` run forced a longer outer fence somewhere in the doc.
            self.assertIn("````", content)

            # JSON sidecar exists and parses.
            json_files = list(tmp.glob("findings_*.json"))
            self.assertEqual(len(json_files), 1)
            data = json.loads(json_files[0].read_text(encoding="utf-8"))
            self.assertEqual(data["package"], "com.x.app")
            self.assertGreaterEqual(data["total_findings"], 1)


if __name__ == "__main__":
    unittest.main()
