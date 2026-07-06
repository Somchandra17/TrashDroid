"""Unit tests for the shared host-tool runner in utils/proc.py."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from utils.proc import have_tool, run_tool


class TestRunTool(unittest.TestCase):
    def test_success(self):
        r = run_tool(["python3", "-c", "print('hi')"])
        self.assertTrue(r.ok)
        self.assertTrue(r.found)
        self.assertFalse(r.timed_out)
        self.assertIn("hi", r.stdout)

    def test_missing_binary(self):
        r = run_tool(["trashdroid-not-a-real-binary-xyz"])
        self.assertFalse(r.found)
        self.assertFalse(r.ok)
        self.assertEqual(r.rc, 127)

    def test_timeout(self):
        r = run_tool(["python3", "-c", "import time; time.sleep(5)"], timeout=1)
        self.assertTrue(r.timed_out)
        self.assertFalse(r.ok)
        self.assertEqual(r.rc, 124)

    def test_nonzero_exit(self):
        r = run_tool(["python3", "-c", "import sys; sys.exit(3)"])
        self.assertTrue(r.found)
        self.assertFalse(r.ok)
        self.assertEqual(r.rc, 3)

    def test_input_text_is_passed(self):
        r = run_tool(["python3", "-c", "import sys; sys.stdout.write(sys.stdin.read())"], input_text="echo\n")
        self.assertIn("echo", r.stdout)


class TestHaveTool(unittest.TestCase):
    def test_present(self):
        self.assertTrue(have_tool("python3"))

    def test_absent(self):
        self.assertFalse(have_tool("trashdroid-not-a-real-binary-xyz"))


if __name__ == "__main__":
    unittest.main()
