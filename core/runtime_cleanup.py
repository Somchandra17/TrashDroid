"""
Runtime cleanup manager for long-running assessment sessions.
"""

from __future__ import annotations

from rich.console import Console

from core.report import ReportGenerator

console = Console()


class RuntimeCleanupManager:
    """Coordinates one-time teardown and optional partial-report generation."""

    def __init__(self, screenshotter, config, device_info: dict):
        self.screenshotter = screenshotter
        self.config = config
        self.device_info = device_info
        self.bg_logcat = None
        self._cleaned = False
        self._final_report_generated = False

    def set_background_collector(self, collector) -> None:
        self.bg_logcat = collector

    def mark_final_report_generated(self) -> None:
        self._final_report_generated = True

    def cleanup(self, generate_partial_report: bool = True) -> None:
        if self._cleaned:
            return
        self._cleaned = True

        if self.bg_logcat is not None:
            try:
                self.bg_logcat.stop()
            except (OSError, RuntimeError) as e:
                console.print(f"[yellow][Cleanup] Failed to stop background logcat: {e}[/yellow]")

        if self.screenshotter is not None:
            try:
                self.screenshotter.stop_scrcpy()
            except (OSError, RuntimeError) as e:
                console.print(f"[yellow][Cleanup] Failed to stop scrcpy: {e}[/yellow]")

        if not generate_partial_report or self._final_report_generated:
            return

        if self.config and self.device_info and any(self.config.findings.values()):
            try:
                reporter = ReportGenerator(self.config, self.device_info)
                path = reporter.generate()
                console.print(f"\n[green][Cleanup] Partial report saved to: {path}[/green]")
            except (OSError, ValueError) as e:
                console.print(f"[red][Cleanup] Failed to write partial report: {e}[/red]")
