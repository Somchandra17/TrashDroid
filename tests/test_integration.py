"""
Integration tests for Presidio scanning helpers.

Tests the helper functions in utils/helpers.py that provide
the Presidio-aware scanning interface used by all phases.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass, field

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.helpers import (
    grep_sensitive_lines,
    presidio_scan_text,
    presidio_scan_file,
    presidio_findings_to_report,
    is_library_component,
)


class TestGrepSensitiveLines(unittest.TestCase):
    """Test the original regex scanning function (always available)."""

    def test_finds_password(self):
        text = "config: password=hunter2\nnormal line"
        result = grep_sensitive_lines(text)
        self.assertIn("password", result)

    def test_finds_token(self):
        text = "auth_token: abc123\nnormal line"
        result = grep_sensitive_lines(text)
        self.assertIn("auth_token", result)

    def test_empty_text(self):
        result = grep_sensitive_lines("")
        self.assertEqual(result, "")

    def test_no_matches(self):
        result = grep_sensitive_lines("just a normal line\nanother normal line")
        self.assertEqual(result, "")

    def test_max_lines(self):
        text = "\n".join(f"password_{i}" for i in range(300))
        result = grep_sensitive_lines(text, max_lines=10)
        self.assertEqual(len(result.splitlines()), 10)

    def test_case_insensitive(self):
        text = "PASSWORD=secret\nPASSWD=hidden"
        result = grep_sensitive_lines(text)
        self.assertIn("PASSWORD", result)
        self.assertIn("PASSWD", result)

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\ndata here"
        result = grep_sensitive_lines(text)
        self.assertIn("BEGIN RSA PRIVATE KEY", result)


class TestIsLibraryComponent(unittest.TestCase):
    """Test library component detection."""

    def test_android_library(self):
        self.assertTrue(is_library_component("androidx.core.SomeClass"))

    def test_firebase(self):
        self.assertTrue(is_library_component("com.google.firebase.auth.SomeClass"))

    def test_app_component(self):
        self.assertFalse(is_library_component("com.example.myapp.MainActivity"))


class TestPresidioScanTextFallback(unittest.TestCase):
    """Test presidio_scan_text with no Presidio engine (regex fallback)."""

    def setUp(self):
        self.config = MagicMock()
        self.config.presidio_engine = None

    def test_regex_fallback_finds_sensitive(self):
        """Without Presidio, should fall back to regex."""
        result = presidio_scan_text("password=secret123", self.config, source_label="test")
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]["entity_type"], "SENSITIVE_PATTERN")
        self.assertEqual(result[0]["severity"], "High")

    def test_regex_fallback_empty(self):
        """Without Presidio, normal text returns empty."""
        result = presidio_scan_text("just a normal line", self.config)
        self.assertEqual(result, [])

    def test_empty_text(self):
        result = presidio_scan_text("", self.config)
        self.assertEqual(result, [])

    def test_whitespace_text(self):
        result = presidio_scan_text("   \n   ", self.config)
        self.assertEqual(result, [])


class TestPresidioFindingsToReport(unittest.TestCase):
    """Test the finding conversion helper."""

    def setUp(self):
        self.config = MagicMock()
        self.config.add_finding = MagicMock()

    def test_empty_findings(self):
        """No findings should produce no add_finding calls."""
        presidio_findings_to_report([], "Phase Test", self.config)
        self.config.add_finding.assert_not_called()

    def test_regex_fallback_finding(self):
        """SENSITIVE_PATTERN findings should use the fallback title."""
        findings = [{
            "entity_type": "SENSITIVE_PATTERN",
            "text": "password=secret",
            "score": 0.5,
            "severity": "High",
            "source": "test",
        }]
        presidio_findings_to_report(
            findings, "Phase Test", self.config,
            fallback_title="Custom title",
            fallback_detail="Custom detail",
        )
        self.config.add_finding.assert_called_once()
        call_args = self.config.add_finding.call_args
        self.assertEqual(call_args[0][0], "Phase Test")
        self.assertEqual(call_args[0][1], "Custom title")

    def test_pii_finding(self):
        """Presidio entity findings should get proper PII title format."""
        findings = [
            {"entity_type": "CREDIT_CARD", "text": "4111-1111-1111-1111", "score": 0.9, "severity": "Critical", "source": "test", "context": "card: 4111-1111-1111-1111"},
            {"entity_type": "CREDIT_CARD", "text": "5500-0000-0000-0004", "score": 0.85, "severity": "Critical", "source": "test", "context": "card: 5500-0000-0000-0004"},
        ]
        presidio_findings_to_report(findings, "Phase Test", self.config)
        self.config.add_finding.assert_called_once()
        call_args = self.config.add_finding.call_args
        title = call_args[0][1]
        self.assertIn("CREDIT_CARD", title)
        self.assertIn("2 occurrences", title)
        severity = call_args[0][2]
        self.assertEqual(severity, "Critical")

    def test_grouped_by_entity_type(self):
        """Multiple entity types should produce separate add_finding calls."""
        findings = [
            {"entity_type": "EMAIL_ADDRESS", "text": "a@b.com", "score": 0.8, "severity": "High", "source": "test", "context": ""},
            {"entity_type": "CREDIT_CARD", "text": "4111-1111-1111-1111", "score": 0.9, "severity": "Critical", "source": "test", "context": ""},
        ]
        presidio_findings_to_report(findings, "Phase Test", self.config)
        self.assertEqual(self.config.add_finding.call_count, 2)

    def test_highest_severity_wins(self):
        """When grouping, the highest severity in the group should be used."""
        findings = [
            {"entity_type": "EMAIL_ADDRESS", "text": "a@b.com", "score": 0.9, "severity": "High", "source": "test", "context": ""},
            {"entity_type": "EMAIL_ADDRESS", "text": "c@d.com", "score": 0.3, "severity": "Low", "source": "test", "context": ""},
        ]
        presidio_findings_to_report(findings, "Phase Test", self.config)
        call_args = self.config.add_finding.call_args
        severity = call_args[0][2]
        self.assertEqual(severity, "High")


# Only run Presidio-specific tests if the package is available
try:
    import presidio_analyzer
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False


@unittest.skipUnless(PRESIDIO_AVAILABLE, "presidio-analyzer not installed")
class TestPresidioScanTextWithEngine(unittest.TestCase):
    """Tests with actual Presidio engine attached to config."""

    @classmethod
    def setUpClass(cls):
        from core.presidio_engine import PresidioEngine
        cls.engine = PresidioEngine(use_gliner=False)
        cls.config = MagicMock()
        cls.config.presidio_engine = cls.engine

    def test_detects_credit_card(self):
        result = presidio_scan_text(
            "Pay with card 4111-1111-1111-1111",
            self.config,
            source_label="test",
        )
        entity_types = [r["entity_type"] for r in result]
        self.assertIn("CREDIT_CARD", entity_types)

    def test_detects_email(self):
        result = presidio_scan_text(
            "Send to user@example.com",
            self.config,
        )
        entity_types = [r["entity_type"] for r in result]
        self.assertIn("EMAIL_ADDRESS", entity_types)

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = presidio_scan_text(f"token: {jwt}", self.config)
        entity_types = [r["entity_type"] for r in result]
        self.assertIn("JWT", entity_types)

    def test_finding_has_severity(self):
        result = presidio_scan_text(
            "card: 4111-1111-1111-1111",
            self.config,
        )
        self.assertTrue(len(result) > 0)
        self.assertIn("severity", result[0])
        valid = {"Critical", "High", "Medium", "Low", "Info"}
        self.assertIn(result[0]["severity"], valid)

    def test_finding_has_score(self):
        result = presidio_scan_text(
            "card: 4111-1111-1111-1111",
            self.config,
        )
        self.assertTrue(len(result) > 0)
        self.assertIsInstance(result[0]["score"], float)
        self.assertGreater(result[0]["score"], 0.0)


if __name__ == "__main__":
    unittest.main()
