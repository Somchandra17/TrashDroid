"""
Phase IX -- Post-Logout Access Control Testing.

After the user logs out (or app data is cleared), re-tests exported activities
and attempts direct access to sensitive screens to detect broken access control.
Applies the same library-component filtering as Phase I.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from core.adb import ADB, ADBError
from core.config import Config
from core.drozer import Drozer
from core.screenshot import ScreenshotManager
from phases.drozer_common import ensure_drozer_connected
from utils.helpers import is_library_component, is_valid_package_name

console = Console()
PHASE = "Phase IX — Post-Logout Access Control"


def run_post_logout_testing(config: Config, adb: ADB, drozer: Drozer, screenshotter: ScreenshotManager) -> None:
    """Phase IX — re-test exported activities after logout to detect broken access control.

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    if not is_valid_package_name(pkg):
        console.print(f"[red]Invalid package name '{pkg}'. Skipping post-logout testing.[/red]")
        config.log_command(PHASE, "validate package", "", f"invalid package name: {pkg}", rc=1)
        return

    if config.auto_mode:
        console.print("[yellow]Auto-mode: clearing app data for post-logout testing...[/yellow]")
        result = adb.clear_app_data(pkg)
        config.log_command(PHASE, f"adb shell pm clear {pkg}", result)
        console.print(f"  {result}")
    else:
        console.print(Panel(
            "Please LOG OUT of the application.\nPress Enter when you have logged out.",
            style="bold yellow",
        ))

        clear_data = Confirm.ask("Do you want to force-clear all app data instead?", default=False)
        if clear_data:
            console.print(f"[cyan]Clearing app data for {pkg}...[/cyan]")
            result = adb.clear_app_data(pkg)
            config.log_command(PHASE, f"adb shell pm clear {pkg}", result)
            console.print(f"  {result}")
        else:
            input("Press Enter after logging out...")

    time.sleep(2)

    # ── Prompt user to grant permissions but NOT log in ──
    if not config.auto_mode:
        console.print(Panel(
            "Now open the app and GRANT ALL PERMISSIONS if prompted.\n\n"
            ">>> DO NOT LOG IN <<<\n\n"
            "Press Enter once permissions are granted.",
            style="bold yellow",
        ))
        input()
    else:
        console.print("[yellow]Auto-mode: launching app briefly to trigger permission state...[/yellow]")
        adb.launch_app(pkg)
        time.sleep(3)
        adb.force_stop(pkg)

    # ── Verify drozer connection for post-logout tests ──
    drozer_ok = ensure_drozer_connected(config, adb, drozer, PHASE)
    if drozer_ok:
        console.print("\n[cyan]Re-testing exported activities post-logout...[/cyan]")
        _retest_activities_drozer(config, adb, drozer, screenshotter, pkg)
    else:
        console.print("[yellow]Drozer unavailable — proceeding with ADB intents only.[/yellow]")

    console.print("\n[cyan]Testing direct activity access via ADB intents...[/cyan]")
    _test_direct_activity_access(config, adb, screenshotter, pkg)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _retest_activities_drozer(
    config: Config, adb: ADB, drozer: Drozer, ss: ScreenshotManager, pkg: str
) -> None:
    all_activities = drozer.get_exported_activities(pkg)

    if not all_activities:
        info = drozer.get_activities(pkg)
        config.log_command(PHASE, f"run app.activity.info -a {pkg}", info.stdout, info.stderr)
        console.print("[yellow]  No exported activities to re-test.[/yellow]")
        return

    # Filter out library components (same as Phase I)
    activities = [a for a in all_activities if not is_library_component(a)]
    skipped = [a for a in all_activities if is_library_component(a)]

    if skipped:
        console.print(f"  [dim]Skipping {len(skipped)} library component(s): {', '.join(skipped)}[/dim]")

    if not activities:
        console.print("[yellow]  All exported activities are library components — nothing to re-test.[/yellow]")
        return

    table = Table(title="Post-Logout Activity Re-test")
    table.add_column("Activity")
    table.add_column("Result")

    for act in activities:
        adb.force_stop(pkg)
        result = drozer.start_activity(pkg, act)
        config.log_command(
            PHASE,
            f"run app.activity.start --component {pkg} {act}",
            result.stdout,
            result.stderr,
        )

        screenshot_path = ss.capture("post_logout_activity", act)
        if screenshot_path:
            config.add_screenshot(screenshot_path, f"Post-logout: {act}", PHASE)

        status = "[red]Accessible[/red]" if result.success else "[green]Blocked[/green]"
        table.add_row(act, status)

        if result.success:
            config.add_finding(
                PHASE,
                f"Activity accessible after logout: {act}",
                "High",
                f"Activity {act} was accessible after logout/data clear.\n"
                f"This indicates broken access control.\n\nOutput:\n{result.stdout}",
            )

        adb.force_stop(pkg)

    console.print(table)


def _test_direct_activity_access(config: Config, adb: ADB, ss: ScreenshotManager, pkg: str) -> None:
    """Launch potentially sensitive activities directly via am start."""
    dumpsys_result = adb.shell(f"dumpsys package {pkg}")
    config.log_command(PHASE, f"dumpsys package {pkg} (activity list)", "(parsed)")

    all_activities = _extract_activities_from_dumpsys(dumpsys_result.stdout, pkg)

    # Filter out library components
    all_activities = [a for a in all_activities if not is_library_component(a)]

    sensitive_keywords = [
        "profile", "account", "setting", "admin", "payment", "wallet",
        "dashboard", "home", "main", "detail", "order", "history",
        "transaction", "transfer", "otp", "verify", "config",
    ]

    sensitive_activities = []
    for act in all_activities:
        act_lower = act.lower()
        if any(kw in act_lower for kw in sensitive_keywords):
            sensitive_activities.append(act)

    if not sensitive_activities:
        sensitive_activities = all_activities[:10]

    if not sensitive_activities:
        console.print("  [yellow]No app-specific activities found to test.[/yellow]")
        return

    console.print(f"  Testing {len(sensitive_activities)} potentially sensitive activit(ies)...\n")

    table = Table(title="Direct Activity Access (Post-Logout)")
    table.add_column("Activity")
    table.add_column("Extras")
    table.add_column("Accessible?")

    test_cases = []
    for act in sensitive_activities:
        test_cases.append((act, ""))
        test_cases.append((act, "--ez is_admin true"))
        test_cases.append((act, "--ez bypass_auth true"))
        test_cases.append((act, "--ez logged_in true"))
        test_cases.append((act, "--es user_id 1"))
        test_cases.append((act, "--es role admin"))
        test_cases.append((act, "--es token test_token"))
        test_cases.append((act, "--es redirect_uri https://evil.com"))

    for act, extras in test_cases:
        adb.force_stop(pkg)
        try:
            result = adb.start_activity(pkg, act, extras)
        except ADBError as e:
            # Activity name came from dumpsys parsing; skip anything that fails validation.
            console.print(f"  [yellow]Skipping unsafe activity {act!r}: {e}[/yellow]")
            continue
        config.log_command(
            PHASE,
            f"adb shell am start -n {pkg}/{act} {extras}".strip(),
            result,
        )

        # Determine if the activity was actually accessible
        result_lower = result.lower() if isinstance(result, str) else ""
        blocked = (
            "permission denial" in result_lower
            or "securityexception" in result_lower
            or "does not exist" in result_lower
            or "unable to find" in result_lower
            or "error type 3" in result_lower  # Activity class does not exist
            or ("error" in result_lower and "starting" in result_lower)
        )
        accessible = not blocked and result.strip() != ""
        status = "[red]YES[/red]" if accessible else "[green]Blocked[/green]"
        table.add_row(act.split(".")[-1], extras or "(none)", status)

        if accessible and extras:
            time.sleep(1)
            screenshot_path = ss.capture("post_logout_direct", f"{act}_{extras.replace(' ', '_')}", delay=1.5)
            if screenshot_path:
                config.add_screenshot(screenshot_path, f"Direct access: {act} {extras}", PHASE)

            config.add_finding(
                PHASE,
                f"Direct activity access post-logout: {act}",
                "High",
                f"Activity {act} was accessible after logout using:\n"
                f"  am start -n {pkg}/{act} {extras}\n\nOutput:\n{result}",
            )

        adb.force_stop(pkg)

    console.print(table)


def _extract_activities_from_dumpsys(dumpsys_output: str, pkg: str) -> list[str]:
    activities = []
    in_activity_section = False
    for line in dumpsys_output.splitlines():
        stripped = line.strip()
        if "Activity Resolver Table:" in stripped or "Non-Data Actions:" in stripped:
            in_activity_section = True
            continue
        if in_activity_section:
            if stripped.startswith("Receiver Resolver") or stripped.startswith("Service Resolver"):
                break
            if pkg in stripped:
                parts = stripped.split()
                for part in parts:
                    if pkg in part and "/" in part:
                        act = part.split("/")[-1]
                        if act.startswith("."):
                            act = pkg + act
                        if act not in activities:
                            activities.append(act)
                    elif part.startswith(pkg + "."):
                        if part not in activities:
                            activities.append(part)
    return activities
