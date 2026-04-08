#!/usr/bin/env python3
"""
TrashDroid — Automated Android DAST Framework
Main entry point and phase orchestrator.

Usage:
    python main.py
    python main.py --skip-preflight
    python main.py --phases 1,3,5,8
"""

from __future__ import annotations

import argparse
import atexit
import signal
import sys
import time
import traceback
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.align import Align


from core.config import Config, BANNER
from core.adb import ADB
from core.drozer import Drozer
from core.screenshot import ScreenshotManager
from core.report import ReportGenerator

from phases.preflight import run_preflight
from phases.setup import select_device, get_apk_input, install_and_prepare
from phases.drozer_testing import run_drozer_testing
from phases.filesystem import run_filesystem_analysis
from phases.dump_verify import run_dump_verification
from phases.logcat import run_logcat_monitoring
from phases.memory import run_memory_analysis
from phases.backup import run_backup_analysis
from phases.manifest import run_manifest_analysis
from phases.post_logout import run_post_logout_testing

console = Console()

ALL_PHASES = {
    1: ("Phase I   — Drozer Component Testing", "drozer"),
    3: ("Phase III — Local File System Analysis", "filesystem"),
    4: ("Phase IV  — Dump File Verification", "dump_verify"),
    5: ("Phase V   — Logcat Monitoring", "logcat"),
    6: ("Phase VI  — Memory Analysis", "memory"),
    7: ("Phase VII — ADB Backup Analysis", "backup"),
    8: ("Phase VIII— Manifest Analysis", "manifest"),
    9: ("Phase IX  — Post-Logout Access Control", "post_logout"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Android DAST — Automated VAPT Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="Skip tool availability checks",
    )
    parser.add_argument(
        "--phases",
        type=str,
        default="",
        help="Comma-separated list of phase numbers to run (e.g. 1,3,5,8). Default: all",
    )
    parser.add_argument(
        "--package",
        type=str,
        default="",
        help="Package name (skip interactive prompt)",
    )
    parser.add_argument(
        "--apk",
        type=str,
        default="",
        help="Path to APK file (skip interactive prompt)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default="",
        help="Device serial (skip interactive prompt)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Non-interactive mode — uses sensible defaults for all prompts",
    )
    parser.add_argument(
        "--report",
        choices=["client", "internal"],
        default="client",
        help="Report detail level (internal includes prompts)",
    )
    parser.add_argument(
        "--screenshot-delay",
        type=float,
        default=4.5,
        help="Delay in seconds before capturing a screenshot (default: 4.5)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    console.print(Align.left(Panel(BANNER, style="bright_white", expand=True, subtitle="Author: 0xs0m")))

    # ── Pre-flight ──
    if not args.skip_preflight:
        if not run_preflight():
            return 1
    else:
        console.print("[yellow]Pre-flight checks skipped (--skip-preflight).[/yellow]")

    # ── Device selection ──
    if args.device:
        available_devices = ADB.get_devices()
        if args.device not in available_devices:
            console.print(
                f"[red]Device '{args.device}' not found via adb. "
                f"Available: {available_devices or 'none'}[/red]"
            )
            return 1
        device_id = args.device
        console.print(f"[green]Using device: {device_id}[/green]")
    else:
        device_id = select_device()
        if not device_id:
            return 1

    adb = ADB(device_id)
    config = Config(device_id=device_id)

    try:
        device_info = adb.get_device_info()
    except Exception as e:
        console.print(f"[red]Failed to read device information: {e}[/red]")
        return 1
    console.print(
        f"[green]Device: {device_info['model']} | "
        f"Android {device_info['android_version']} | "
        f"SDK {device_info['sdk']}[/green]"
    )

    root_status = adb.is_rooted()
    if root_status:
        console.print("[green]✓ Device is rooted.[/green]")
    else:
        console.print("[yellow]⚠ Device does not appear to be rooted. Some tests may fail.[/yellow]")

    # Check on-device prerequisites
    from phases.preflight import verify_device_prerequisites
    if not verify_device_prerequisites(adb):
        return 1

    # ── APK input ──
    if args.package:
        config.package_name = args.package
        config.apk_path = args.apk or None
        config.is_preinstalled = not bool(args.apk)
        if config.apk_path and not Path(config.apk_path).exists():
            console.print(f"[red]APK file not found: {config.apk_path}[/red]")
            return 1
    else:
        apk_path, pkg, is_pre = get_apk_input(adb)
        config.apk_path = apk_path
        config.package_name = pkg
        config.is_preinstalled = is_pre

    if not config.package_name.strip():
        console.print("[red]Package name cannot be empty.[/red]")
        return 1

    config.auto_mode = args.auto
    config.report_mode = args.report
    config.screenshot_delay = args.screenshot_delay
    config.init_output()

    # ── Install & prepare ──
    install_and_prepare(adb, config)

    # ── Init helpers ──
    drozer = Drozer(device_id)
    screenshotter = ScreenshotManager(adb, config.screenshot_dir, config)

    # ── Register cleanup handler (prevents orphan scrcpy + saves partial report) ──
    _cleanup_state = {"screenshotter": screenshotter, "config": config, "device_info": device_info}

    def _cleanup():
        ss = _cleanup_state.get("screenshotter")
        if ss:
            ss.stop_scrcpy()
        cfg = _cleanup_state.get("config")
        dinfo = _cleanup_state.get("device_info")
        if cfg and dinfo and any(cfg.findings.values()):
            try:
                from core.report import ReportGenerator
                reporter = ReportGenerator(cfg, dinfo)
                path = reporter.generate()
                print(f"\n[Cleanup] Partial report saved to: {path}")
            except Exception:
                pass

    atexit.register(_cleanup)

    def _signal_handler(signum, frame):
        console.print(f"\n[yellow]Received signal {signum} — cleaning up...[/yellow]")
        _cleanup()
        sys.exit(128 + signum)

    signal.signal(signal.SIGTERM, _signal_handler)
    signal.signal(signal.SIGINT, _signal_handler)

    # Determine which phases to run
    if args.phases:
        selected = set()
        invalid_phases: list[str] = []
        for p in args.phases.split(","):
            try:
                phase_num = int(p.strip())
                if phase_num in ALL_PHASES:
                    selected.add(phase_num)
                else:
                    invalid_phases.append(str(phase_num))
            except ValueError:
                invalid_phases.append(p.strip())
        if invalid_phases:
            console.print(f"[yellow]Ignoring invalid phase(s): {', '.join(invalid_phases)}[/yellow]")
    else:
        selected = set(ALL_PHASES.keys())

    console.print(f"\n[bold]Phases to run:[/bold] {sorted(selected)}\n")

    # ── Optionally start scrcpy for live viewing ──
    if any(p in selected for p in [1, 9]):
        if args.auto:
            console.print("[yellow]Auto-mode: skipping scrcpy live view (screenshots still captured via adb).[/yellow]")
        else:
            console.print(
                "[bold]scrcpy provides a live mirror of the device screen but can be GPU-heavy.[/bold]\n"
                "[dim]Screenshots are always captured in the background via adb regardless of this choice.[/dim]"
            )
            want_scrcpy = Confirm.ask("Launch scrcpy for live screen mirroring?", default=True)
            if want_scrcpy:
                screenshotter.start_scrcpy()

    # ── Start background logcat collector ──
    from utils.logcat_collector import BackgroundLogcatCollector
    bg_logcat = BackgroundLogcatCollector(device_id, config.package_name, config.output_dir)
    bg_logcat.start()
    console.print("[dim]Background logcat collector started.[/dim]")
    _cleanup_state["bg_logcat"] = bg_logcat

    # ── Execute phases ──
    phase_runners = {
        1: lambda: run_drozer_testing(config, adb, drozer, screenshotter),
        3: lambda: run_filesystem_analysis(config, adb), #include trufflehog
        4: lambda: run_dump_verification(config, adb),
        5: lambda: run_logcat_monitoring(config, adb),
        6: lambda: run_memory_analysis(config, adb),
        7: lambda: run_backup_analysis(config, adb),
        8: lambda: run_manifest_analysis(config, adb),
        9: lambda: run_post_logout_testing(config, adb, drozer, screenshotter),
    }

    for phase_num in sorted(selected):
        if phase_num not in phase_runners:
            console.print(f"[yellow]Unknown phase {phase_num}, skipping.[/yellow]")
            continue

        phase_name = ALL_PHASES[phase_num][0]
        try:
            phase_runners[phase_num]()
        except KeyboardInterrupt:
            console.print(f"\n[yellow]Phase {phase_num} interrupted by user.[/yellow]")
            if not args.auto and not Confirm.ask("Continue to next phase?", default=True):
                break
        except Exception as e:
            console.print(f"\n[red]Error in {phase_name}: {e}[/red]")
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
            config.add_finding(
                phase_name,
                f"Phase execution error",
                "Info",
                f"Phase {phase_num} encountered an error:\n{traceback.format_exc()}",
            )
            if not args.auto and not Confirm.ask("Continue to next phase?", default=True):
                break

    # ── Stop background logcat collector and integrate findings ──
    bg_logcat.stop()
    bg_findings = bg_logcat.save_and_scan()
    for bf in bg_findings:
        config.add_finding("Background Logcat", bf["title"], bf["severity"], bf["detail"])
    if bg_findings:
        console.print(f"[yellow]Background logcat found {len(bg_findings)} finding(s).[/yellow]")

    # ── Stop scrcpy ──
    screenshotter.stop_scrcpy()

    # ── Generate report ──
    console.print("\n[bold cyan]═══ Generating Report ═══[/bold cyan]\n")
    reporter = ReportGenerator(config, device_info)
    report_path = reporter.generate()

    total_findings = sum(len(v) for v in config.findings.values())
    total_screenshots = len(config.screenshots)
    total_commands = len(config.commands_log)

    console.print(Panel(
        f"[bold green]DAST Assessment Complete[/bold green]\n\n"
        f"  Report:      {report_path}\n"
        f"  Findings:    {total_findings}\n"
        f"  Screenshots: {total_screenshots}\n"
        f"  Commands:    {total_commands}\n"
        f"  Output dir:  {config.output_dir}",
        title="Summary",
        style="green",
        expand=False,
    ))

    console.print("\n[dim]Tip: Feed the generated .md report into an AI model for "
                  "risk rating, executive summary, and Jira ticket generation.[/dim]\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
