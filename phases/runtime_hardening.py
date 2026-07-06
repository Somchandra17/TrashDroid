"""
Phase X — Runtime Hardening (SSL pinning + root/debugger detection).

Attempts to defeat the app's runtime self-defence controls with dynamic
instrumentation, trying objection first and falling back to a self-contained
Frida agent (objection is optional). The point is not the bypass itself — on a
rooted/instrumented device these controls are always defeatable — but to
*document* which controls the app implements and confirm they can be neutralised,
so a tester knows what to expect before MitM / runtime work.
"""

from __future__ import annotations

import time

from rich.console import Console

from core.adb import ADB
from core.config import Config
from core.instrumentation import (
    InstrumentationResult,
    disable_root_detection,
    disable_ssl_pinning,
    ensure_frida_server,
    frida_available,
    have_objection,
)
from core.screenshot import ScreenshotManager
from utils.helpers import is_valid_package_name

console = Console()
PHASE = "Phase X — Runtime Hardening"


def run_runtime_hardening(config: Config, adb: ADB, screenshotter: ScreenshotManager) -> None:
    """Phase X — probe & bypass SSL pinning and root/debug detection.

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    if not is_valid_package_name(pkg):
        console.print(f"[red]Invalid package name '{pkg}'. Skipping runtime hardening.[/red]")
        config.log_command(PHASE, "validate package", "", f"invalid package name: {pkg}", rc=1)
        return

    has_objection = have_objection()
    has_frida = frida_available()
    if not (has_objection or has_frida):
        console.print("[yellow]  Neither objection nor Frida is installed — skipping.[/yellow]")
        config.add_finding(
            PHASE,
            "Runtime hardening checks skipped — no instrumentation tooling",
            "Info",
            "Neither objection nor the Frida Python bindings are installed on the host.\n"
            "Install one to test SSL pinning / root-detection bypass:\n"
            "  pip install frida frida-tools objection",
        )
        return

    console.print(
        f"[dim]  Instrumentation: objection={'yes' if has_objection else 'no'}, "
        f"frida={'yes' if has_frida else 'no'}[/dim]"
    )

    # Both objection and the Frida fallback need frida-server on the device.
    if has_frida:
        ensure_frida_server(adb)

    # objection attaches to a running process; make sure the app is up.
    if adb.get_pid(pkg) is None:
        console.print(f"[cyan]  Launching {pkg}...[/cyan]")
        adb.launch_app(pkg)
        time.sleep(3)

    # ── SSL certificate pinning ──
    console.print("\n[bold magenta]── SSL Certificate Pinning ──[/bold magenta]")
    ssl = disable_ssl_pinning(adb, pkg)
    _record(config, "SSL certificate pinning", ssl,
            remediation="Certificate pinning limits MitM interception. If absent, add pinning; "
                        "if present, note it is bypassable on rooted/instrumented devices.")

    # ── Root / debugger detection ──
    console.print("\n[bold magenta]── Root / Debugger Detection ──[/bold magenta]")
    root = disable_root_detection(adb, pkg)
    _record(config, "Root/debugger detection", root,
            remediation="Root/debug detection is a defence-in-depth control; confirm it exists and "
                        "understand it can be neutralised via Frida/objection.")

    screenshot_path = screenshotter.capture("runtime_hardening", "post_bypass")
    if screenshot_path:
        config.add_screenshot(screenshot_path, "Runtime Hardening (post-bypass)", PHASE)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _record(config: Config, control: str, result: InstrumentationResult, remediation: str) -> None:
    """Turn an InstrumentationResult into console output + a finding."""
    config.log_command(
        PHASE,
        f"{control} bypass via {result.tool}",
        result.evidence,
        result.error,
    )

    if result.tool == "none" or (not result.hooks_installed and result.error):
        console.print(f"  [yellow]{control}: could not instrument ({result.error or 'no tooling'}).[/yellow]")
        config.add_finding(
            PHASE,
            f"{control}: instrumentation failed",
            "Info",
            f"Could not instrument {control.lower()}.\nReason: {result.error or 'unknown'}\n\n"
            f"{remediation}",
        )
        return

    if result.hooks_installed and result.bypass_observed:
        console.print(f"  [red]{control}: present and bypassed[/red] (via {result.tool}).")
        config.add_finding(
            PHASE,
            f"{control} is present and bypassable",
            "Low",
            f"{control} was exercised at runtime and defeated via {result.tool}.\n"
            f"On a rooted/instrumented device this is expected; documented for MitM/runtime planning.\n\n"
            f"{remediation}\n\nEvidence:\n{result.evidence}",
        )
    elif result.hooks_installed:
        console.print(f"  [green]{control}: hooks installed[/green] (via {result.tool}); "
                      f"no {control.lower()} calls observed in the window.")
        config.add_finding(
            PHASE,
            f"{control}: instrumentation loaded, control not observed",
            "Info",
            f"Bypass hooks for {control.lower()} were installed via {result.tool}, but no "
            f"{control.lower()} calls fired during the observation window — the app may not "
            f"enforce this control, or performed no relevant activity while instrumented.\n\n"
            f"{remediation}\n\nEvidence:\n{result.evidence}",
        )
    else:
        console.print(f"  [yellow]{control}: instrumentation produced no hooks.[/yellow]")
        config.add_finding(
            PHASE,
            f"{control}: no hooks placed",
            "Info",
            f"Instrumentation via {result.tool} ran but installed no {control.lower()} hooks.\n"
            f"{remediation}\n\nEvidence:\n{result.evidence or result.error}",
        )
