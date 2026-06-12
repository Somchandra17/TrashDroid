"""
Background logcat collector — captures app-specific logs during entire test run.

Start at the beginning of testing, stop at the end. Captured logs are
saved to the output directory and scanned for sensitive data.
"""

from __future__ import annotations

import re
import subprocess
import threading
from pathlib import Path

from core.config import LIMITS, SENSITIVE_PATTERNS
from utils.proc import start_logcat_process, terminate_process


class BackgroundLogcatCollector:
    """Lightweight background logcat collector thread."""

    def __init__(self, device_id: str, package_name: str, output_dir: Path):
        self.device_id = device_id
        self.package_name = package_name
        self.output_dir = output_dir
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._proc: subprocess.Popen | None = None
        self._proc_lock = threading.Lock()
        self._lines: list[str] = []

    def start(self) -> None:
        """Start background logcat capture in a daemon thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the background capture and save results."""
        self._stop_event.set()
        self._terminate_process(force_kill=True)

        thread = self._thread
        if thread:
            thread.join(timeout=5)
            if thread.is_alive():
                self._terminate_process(force_kill=True)
                thread.join(timeout=2)
        self._thread = None

    def _get_process(self) -> subprocess.Popen | None:
        with self._proc_lock:
            return self._proc

    def _set_process(self, proc: subprocess.Popen | None) -> None:
        with self._proc_lock:
            self._proc = proc

    def _terminate_process(self, force_kill: bool) -> None:
        terminate_process(self._get_process(), force_kill=force_kill)
        self._set_process(None)

    def _capture_loop(self) -> None:
        try:
            proc = start_logcat_process(self.device_id)
            self._set_process(proc)
            while not self._stop_event.is_set():
                if proc.stdout is None:
                    break
                line = proc.stdout.readline()
                if line:
                    # Only capture app-related lines to keep memory bounded
                    if self.package_name in line:
                        self._lines.append(line)
                    # Cap line count to keep memory bounded.
                    if len(self._lines) >= LIMITS.max_logcat_lines:
                        break
        except (OSError, subprocess.SubprocessError):
            pass  # Capture stream closed/failed — saved lines are still usable.
        finally:
            self._terminate_process(force_kill=True)

    def save_and_scan(self) -> list[dict]:
        """Save collected logs and return findings for sensitive data."""
        if not self._lines:
            return []

        # Save full background log
        log_path = self.output_dir / "background_logcat.txt"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("".join(self._lines), encoding="utf-8")

        findings = []
        full_text = "".join(self._lines)

        # Try Presidio post-scan for entity-level detection
        try:
            from core.presidio_engine import get_engine
            engine = get_engine()
            if engine is not None:
                pii_results = engine.analyze_text_for_findings(
                    full_text, source_label="background_logcat"
                )
                if pii_results:
                    # Group by entity type for cleaner reporting
                    entity_groups: dict[str, list[dict]] = {}
                    for r in pii_results:
                        entity_groups.setdefault(r["entity_type"], []).append(r)

                    for entity_type, group in entity_groups.items():
                        avg_score = sum(g["score"] for g in group) / len(group)
                        samples = [g["text"] for g in group[:5]]
                        findings.append({
                            "title": f"PII detected in background logcat: {entity_type} ({len(group)} occurrence{'s' if len(group) > 1 else ''})",
                            "severity": group[0].get("severity", "High"),
                            "detail": (
                                f"Background logcat monitoring detected {len(group)} "
                                f"{entity_type} entity(ies) (avg confidence: {avg_score:.2f}).\n\n"
                                f"Sample matches:\n" + "\n".join(f"  - {s}" for s in samples)
                            ),
                        })
                    return findings
        except Exception:
            pass  # Fall through to regex

        # Regex fallback scan
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
