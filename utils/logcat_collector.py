"""
Background logcat collector — captures app-specific logs during entire test run.

Start at the beginning of testing, stop at the end. Captured logs are
saved to the output directory and scanned for sensitive data.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from pathlib import Path

from core.config import SENSITIVE_PATTERNS


class BackgroundLogcatCollector:
    """Lightweight background logcat collector thread."""

    def __init__(self, device_id: str, package_name: str, output_dir: Path):
        self.device_id = device_id
        self.package_name = package_name
        self.output_dir = output_dir
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lines: list[str] = []

    def start(self) -> None:
        """Start background logcat capture in a daemon thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background capture and save results."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _capture_loop(self) -> None:
        cmd = ["adb"]
        if self.device_id:
            cmd += ["-s", self.device_id]
        cmd += ["logcat", "-v", "threadtime"]

        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while not self._stop_event.is_set():
                if proc.stdout is None:
                    break
                line = proc.stdout.readline()
                if line:
                    # Only capture app-related lines to keep memory bounded
                    if self.package_name in line:
                        self._lines.append(line)
                    # Cap at 50k lines to prevent memory issues
                    if len(self._lines) >= 50000:
                        break
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            pass

    def save_and_scan(self) -> list[dict]:
        """Save collected logs and return findings for sensitive data."""
        if not self._lines:
            return []

        # Save full background log
        log_path = self.output_dir / "background_logcat.txt"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("".join(self._lines), encoding="utf-8")

        # Scan for sensitive data
        findings = []
        sensitive_lines = []
        for line in self._lines:
            if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE):
                sensitive_lines.append(line.strip())

        if sensitive_lines:
            findings.append({
                "title": f"Sensitive data in background logcat ({len(sensitive_lines)} lines)",
                "severity": "High",
                "detail": (
                    "Background logcat monitoring during the entire test run captured "
                    f"{len(sensitive_lines)} lines containing potentially sensitive data:\n\n"
                    + "\n".join(sensitive_lines[:200])
                ),
            })

        return findings
