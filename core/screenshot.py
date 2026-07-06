"""
Screenshot management: captures device screen via adb screencap.
Optionally runs scrcpy in the background for live viewing.
"""

from __future__ import annotations

import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console

from core.config import TIMING

console = Console()


class ScreenshotManager:
    def __init__(self, adb, screenshot_dir: Path, config=None):
        self.adb = adb
        self.screenshot_dir = screenshot_dir
        self.config = config
        self._scrcpy_proc: Optional[subprocess.Popen] = None
        self._counter = 0

    def start_scrcpy(self) -> None:
        """Launch scrcpy in the background for live device mirroring."""
        try:
            cmd = ["scrcpy"]
            if self.adb.device_id:
                cmd += ["-s", self.adb.device_id]
            cmd += ["--window-title", "DAST Live View", "--stay-awake"]
            self._scrcpy_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            # Give scrcpy a moment to fail fast (e.g. device offline) before assuming it is live.
            time.sleep(1.0)
            if self._scrcpy_proc.poll() is not None:
                console.print(
                    f"[yellow]  scrcpy exited immediately (code "
                    f"{self._scrcpy_proc.returncode}) — live mirroring unavailable[/yellow]"
                )
                self._scrcpy_proc = None
                return
            console.print("[green]  scrcpy launched for live device mirroring[/green]")
        except FileNotFoundError:
            console.print("[yellow]  scrcpy not found — live mirroring unavailable[/yellow]")

    def stop_scrcpy(self) -> None:
        if self._scrcpy_proc:
            self._scrcpy_proc.terminate()
            try:
                self._scrcpy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._scrcpy_proc.kill()
            self._scrcpy_proc = None

    def capture(self, phase: str, label: str, delay: Optional[float] = None) -> Optional[str]:
        """
        Capture a screenshot with an optional delay (to let the UI settle).
        Returns the local file path or None on failure.
        """
        if delay is None:
            delay = self.config.screenshot_delay if self.config else TIMING.screenshot_settle_delay
        time.sleep(delay)
        self._counter += 1
        ts = datetime.now().strftime("%H%M%S")
        safe_label = label.replace(" ", "_").replace("/", "_").replace(".", "_")[:60]
        filename = f"{phase}_{safe_label}_{ts}_{self._counter}.png"
        output_path = self.screenshot_dir / filename
        # Defence in depth: the label is already sanitised, but confirm the resolved
        # path can never escape the screenshot directory before writing to it.
        if not output_path.resolve().is_relative_to(self.screenshot_dir.resolve()):
            console.print(f"[yellow]  Refusing screenshot path outside output dir: {filename}[/yellow]")
            return None
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path = str(output_path)

        success = self.adb.screencap(output_path)
        if success:
            rel_path = f"./screenshots/{filename}"
            return rel_path
        console.print(f"[yellow]  Screenshot capture failed for {label}[/yellow]")
        return None
