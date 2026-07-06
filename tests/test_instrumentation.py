"""Tests for the objection→frida fallback selection in core/instrumentation.py."""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.instrumentation import InstrumentationResult, disable_ssl_pinning


class TestBypassFallback(unittest.TestCase):
    @patch("core.instrumentation.frida_available")
    @patch("core.instrumentation._objection_command")
    @patch("core.instrumentation.have_objection", return_value=True)
    def test_objection_success_short_circuits(self, _have, mock_obj, mock_fa):
        mock_obj.return_value = InstrumentationResult(
            tool="objection", hooks_installed=True, evidence="Found okhttp3.CertificatePinner"
        )
        r = disable_ssl_pinning(adb=None, pkg="com.x")
        self.assertEqual(r.tool, "objection")
        self.assertTrue(r.hooks_installed)
        mock_fa.assert_not_called()  # frida never consulted when objection worked

    @patch("core.instrumentation._frida_run")
    @patch("core.instrumentation.ensure_frida_server", return_value=True)
    @patch("core.instrumentation.frida_available", return_value=True)
    @patch("core.instrumentation._objection_command")
    @patch("core.instrumentation.have_objection", return_value=True)
    def test_falls_back_to_frida_when_objection_finds_nothing(self, _have, mock_obj, _fa, _efs, mock_frida):
        mock_obj.return_value = InstrumentationResult(tool="objection", hooks_installed=False)
        mock_frida.return_value = InstrumentationResult(
            tool="frida", hooks_installed=True, bypass_observed=True, evidence="HOOK SSLContext.init"
        )
        r = disable_ssl_pinning(adb=None, pkg="com.x")
        self.assertEqual(r.tool, "frida")
        self.assertTrue(r.bypass_observed)
        mock_frida.assert_called_once()

    @patch("core.instrumentation.frida_available", return_value=True)
    @patch("core.instrumentation.ensure_frida_server", return_value=True)
    @patch("core.instrumentation._frida_run")
    @patch("core.instrumentation.have_objection", return_value=False)
    def test_uses_frida_when_objection_absent(self, _have, mock_frida, _efs, _fa):
        mock_frida.return_value = InstrumentationResult(tool="frida", hooks_installed=True)
        r = disable_ssl_pinning(adb=None, pkg="com.x")
        self.assertEqual(r.tool, "frida")
        mock_frida.assert_called_once()

    @patch("core.instrumentation.frida_available", return_value=False)
    @patch("core.instrumentation.have_objection", return_value=False)
    def test_no_tooling_returns_none(self, _have, _fa):
        r = disable_ssl_pinning(adb=None, pkg="com.x")
        self.assertEqual(r.tool, "none")


if __name__ == "__main__":
    unittest.main()
