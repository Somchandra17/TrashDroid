"""
Phase I -- Drozer Component Testing + Phase II Screenshot Capture.

Tests all exported activities, services, broadcast receivers, content providers,
and intent sniffing. Screenshots are captured after each test.
Supports filtering out false-positive library components (androidx.*, google.gms.*, etc.).
"""

from __future__ import annotations

from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from core.adb import ADB
from core.config import Config
from core.drozer import Drozer
from core.screenshot import ScreenshotManager
from phases.drozer_common import ensure_drozer_connected
from utils.helpers import is_library_component, is_valid_package_name

console = Console()
PHASE = "Phase I — Drozer Component Testing"


def _filter_components(components: list[str], include_library: bool) -> tuple[list[str], list[str]]:
    """Split components into (to_test, skipped). If include_library=True, test all."""
    if include_library:
        return components, []
    to_test = [c for c in components if not is_library_component(c)]
    skipped = [c for c in components if is_library_component(c)]
    return to_test, skipped


def _print_filtered_table(title: str, to_test: list[str], skipped: list[str], col_name: str) -> None:
    table = Table(title=f"{title} ({len(to_test)} to test, {len(skipped)} skipped)")
    table.add_column("#", style="dim")
    table.add_column(col_name)
    table.add_column("Status")
    for i, item in enumerate(to_test, 1):
        table.add_row(str(i), item, "[green]Testing[/green]")
    for item in skipped:
        table.add_row("-", item, "[dim]Skipped (library)[/dim]")
    console.print(table)


def run_drozer_testing(config: Config, adb: ADB, drozer: Drozer, screenshotter: ScreenshotManager) -> None:
    """Phase I — test exported components via drozer and capture screenshots.

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    if not is_valid_package_name(pkg):
        console.print(f"[red]Invalid package name '{pkg}'. Skipping drozer testing.[/red]")
        config.log_command(PHASE, "validate package", "", f"invalid package name: {pkg}", rc=1)
        return

    # ── Verify drozer connection (with auto-launch + retry) ──
    if not ensure_drozer_connected(config, adb, drozer, PHASE):
        return

    # ── Attack surface overview ──
    console.print("[cyan]Gathering attack surface...[/cyan]")
    surface = drozer.get_attack_surface(pkg)
    console.print(f"[dim]{surface.stdout}[/dim]")
    config.log_command(PHASE, f"run app.package.attacksurface {pkg}", surface.stdout, surface.stderr)

    # ── Ask what to test ──
    if config.auto_mode:
        console.print("[yellow]Auto-mode: testing all component types, filtering library components.[/yellow]")
        test_activities = test_services = test_receivers = test_providers = test_intents = True
        include_library = False
    else:
        console.print("\n[bold]Select component types to test:[/bold]")
        test_activities = Confirm.ask("  Test exported Activities?", default=True)
        test_services = Confirm.ask("  Test exported Services?", default=True)
        test_receivers = Confirm.ask("  Test exported Broadcast Receivers?", default=True)
        test_providers = Confirm.ask("  Test Content Providers?", default=True)
        test_intents = Confirm.ask("  Test Intent Sniffing / Browsable Activities?", default=True)

        console.print(
            "\n[bold]Some components belong to libraries (androidx.*, com.google.android.gms.*, "
            "com.google.firebase.*) and are typically false positives.[/bold]"
        )
        include_library = Confirm.ask("  Include library/framework components in testing?", default=False)

    if test_activities:
        _test_activities(config, adb, drozer, screenshotter, pkg, include_library)

    if test_services:
        _test_services(config, adb, drozer, screenshotter, pkg, include_library)

    if test_receivers:
        _test_receivers(config, adb, drozer, screenshotter, pkg, include_library)

    if test_providers:
        _test_providers(config, drozer, screenshotter, pkg)

    if test_intents:
        _test_intents(config, drozer, screenshotter, pkg)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _test_activities(
    config: Config, adb: ADB, drozer: Drozer, ss: ScreenshotManager, pkg: str, include_library: bool
) -> None:
    console.print("\n[bold magenta]── Exported Activities ──[/bold magenta]")
    all_activities = drozer.get_exported_activities(pkg)

    if not all_activities:
        console.print("[yellow]  No exported activities found.[/yellow]")
        info_result = drozer.get_activities(pkg)
        config.log_command(PHASE, f"run app.activity.info -a {pkg}", info_result.stdout, info_result.stderr)
        return

    activities, skipped = _filter_components(all_activities, include_library)
    _print_filtered_table("Exported Activities", activities, skipped, "Activity")

    if not activities:
        console.print("[yellow]  All exported activities are library components — nothing to test.[/yellow]")
        return

    for act in activities:
        adb.force_stop(pkg)
        console.print(f"  [cyan]Starting:[/cyan] {act}")
        result = drozer.start_activity(pkg, act)
        config.log_command(PHASE, f"run app.activity.start --component {pkg} {act}", result.stdout, result.stderr)

        screenshot_path = ss.capture("drozer_activity", act)
        if screenshot_path:
            config.add_screenshot(screenshot_path, f"Activity: {act}", PHASE)

        if result.stderr and "exception" in result.stderr.lower():
            config.add_finding(
                PHASE,
                f"Activity launch error: {act}",
                "Info",
                f"Launching {act} produced an error:\n{result.stderr}",
            )
        elif result.success:
            config.add_finding(
                PHASE,
                f"Exported activity accessible: {act}",
                "Medium",
                f"Activity {act} can be started externally without explicit permissions.\n"
                f"Output:\n{result.stdout}",
            )

    # Test with extra intent flags
    for act in activities:
        for extra_label, extras in [
            ("is_admin=true", '--extra boolean is_admin "true"'),
            ("bypass_auth=true", '--extra boolean bypass_auth "true"'),
            ("logged_in=true", '--extra boolean logged_in "true"'),
            ("is_root=true", '--extra boolean is_root "true"'),
            ("role=admin", '--extra string role "admin"'),
            ("user_id=1", '--extra integer user_id 1'),
            ("token=test", '--extra string token "test_token"'),
            ("redirect_uri=evil", '--extra string redirect_uri "https://evil.com"'),
        ]:
            adb.force_stop(pkg)
            result = drozer.start_activity(pkg, act, extras)
            config.log_command(
                PHASE,
                f"run app.activity.start --component {pkg} {act} {extras}",
                result.stdout,
                result.stderr,
            )
            screenshot_path = ss.capture("drozer_activity_extras", f"{act}_{extra_label}")
            if screenshot_path:
                config.add_screenshot(screenshot_path, f"Activity {act} with {extra_label}", PHASE)


def _verify_service_running(adb: ADB, pkg: str, svc: str) -> tuple[bool, str]:
    import time

    from core.config import TIMING

    svc_short = svc.split(".")[-1]
    running = False
    matched_block: list[str] = []

    def finalize_block(block: list[str]) -> tuple[bool, list[str]]:
        if not block:
            return False, []
        block_text = "\n".join(block)
        if svc not in block_text and svc_short not in block_text:
            return False, []
        is_running = "app=ProcessRecord{" in block_text and "app=null" not in block_text
        return is_running, block

    for _ in range(TIMING.polling_retries):
        time.sleep(1.0)
        result = adb.shell(f"dumpsys activity services {pkg}")

        current_block: list[str] = []
        running = False
        matched_block = []

        for line in result.stdout.splitlines():
            if "* ServiceRecord{" in line:
                block_running, block_lines = finalize_block(current_block)
                if block_running:
                    running = True
                    matched_block = block_lines
                current_block = [line]
                continue
            if current_block:
                current_block.append(line)

        block_running, block_lines = finalize_block(current_block)
        if block_running:
            running = True
            matched_block = block_lines

        if running:
            break

    evidence = "\n".join(matched_block[:40]) if matched_block else result.stdout[:2000]
    return running, evidence


def _test_services(
    config: Config, adb: ADB, drozer: Drozer, ss: ScreenshotManager, pkg: str, include_library: bool
) -> None:
    console.print("\n[bold magenta]── Exported Services ──[/bold magenta]")
    all_services = drozer.get_exported_services(pkg)

    if not all_services:
        console.print("[yellow]  No exported services found.[/yellow]")
        info_result = drozer.get_services(pkg)
        config.log_command(PHASE, f"run app.service.info -a {pkg}", info_result.stdout, info_result.stderr)
        return

    services, skipped = _filter_components(all_services, include_library)
    _print_filtered_table("Exported Services", services, skipped, "Service")

    if not services:
        console.print("[yellow]  All exported services are library components — nothing to test.[/yellow]")
        return

    results_table = Table(title="Service Verification Results")
    results_table.add_column("Service")
    results_table.add_column("Drozer Start")
    results_table.add_column("Actually Running?")
    results_table.add_column("Message Send")

    for svc in services:
        adb.force_stop(pkg)
        console.print(f"  [cyan]Starting service:[/cyan] {svc}")
        result = drozer.start_service(pkg, svc)
        config.log_command(PHASE, f"run app.service.start --component {pkg} {svc}", result.stdout, result.stderr)

        screenshot_path = ss.capture("drozer_service", svc)
        if screenshot_path:
            config.add_screenshot(screenshot_path, f"Service: {svc}", PHASE)

        # Verify the service is actually running
        running, dumpsys_out = _verify_service_running(adb, pkg, svc)
        verify_cmd = f"dumpsys activity services {pkg}"
        config.log_command(PHASE, verify_cmd, dumpsys_out[:3000])

        drozer_status = "[green]OK[/green]" if result.success else "[red]Failed[/red]"
        running_status = "[red]YES — running[/red]" if running else "[green]Not running[/green]"

        # Send message to service
        msg_result = drozer.send_to_service(pkg, svc)
        config.log_command(PHASE, f"run app.service.send {pkg} {svc} --msg 1 2 3", msg_result.stdout, msg_result.stderr)
        msg_status = "[green]Sent[/green]" if msg_result.success else "[dim]Failed[/dim]"

        results_table.add_row(svc.split(".")[-1], drozer_status, running_status, msg_status)

        if running:
            config.add_finding(
                PHASE,
                f"Exported service confirmed running: {svc}",
                "Medium",
                f"Service {svc} was started externally and confirmed running via dumpsys.\n\n"
                f"Drozer output:\n{result.stdout}\n\n"
                f"dumpsys verification:\n{dumpsys_out[:2000]}",
            )
        elif result.success:
            config.add_finding(
                PHASE,
                f"Exported service startable but not confirmed running: {svc}",
                "Low",
                f"Drozer reported success starting {svc}, but dumpsys did not confirm it running.\n"
                f"The service may have started and stopped immediately.\n\n"
                f"Drozer output:\n{result.stdout}",
            )

    console.print(results_table)


def _verify_receiver_processed(adb: ADB, pkg: str, rcv: str) -> tuple[bool, str]:
    """
    Check logcat for evidence that the receiver actually processed the broadcast.
    Logcat should have been cleared before sending the broadcast (caller responsibility).
    Uses host-side `adb logcat -d` for reliability.
    """
    import time
    time.sleep(2)
    result = adb.run(["logcat", "-d", "-v", "brief"], timeout=15)
    output = result.stdout
    rcv_short = rcv.split(".")[-1]

    evidence_lines = []
    for line in output.splitlines():
        lower = line.lower()
        # Match lines that reference the package or receiver class
        if pkg.lower() in lower or rcv_short.lower() in lower:
            if any(kw in lower for kw in [
                "receiver", "broadcast", "onreceive", "delivered",
                "process", "handling", "brq", "delivering",
                rcv_short.lower(),
            ]):
                evidence_lines.append(line.strip())
        # Also catch system BroadcastQueue logs about this receiver
        elif "broadcastqueue" in lower or "brq" in lower:
            if rcv_short.lower() in lower or pkg.lower() in lower:
                evidence_lines.append(line.strip())

    return bool(evidence_lines), "\n".join(evidence_lines[:30])


def _test_receivers(
    config: Config, adb: ADB, drozer: Drozer, ss: ScreenshotManager, pkg: str, include_library: bool
) -> None:
    console.print("\n[bold magenta]── Exported Broadcast Receivers ──[/bold magenta]")
    all_receivers = drozer.get_exported_receivers(pkg)

    if not all_receivers:
        console.print("[yellow]  No exported broadcast receivers found.[/yellow]")
        info_result = drozer.get_receivers(pkg)
        config.log_command(PHASE, f"run app.broadcast.info -a {pkg}", info_result.stdout, info_result.stderr)
        return

    receivers, skipped = _filter_components(all_receivers, include_library)
    _print_filtered_table("Exported Receivers", receivers, skipped, "Receiver")

    if not receivers:
        console.print("[yellow]  All exported receivers are library components — nothing to test.[/yellow]")
        return

    results_table = Table(title="Broadcast Receiver Verification Results")
    results_table.add_column("Receiver")
    results_table.add_column("Drozer Send")
    results_table.add_column("Processed? (logcat)")

    for rcv in receivers:
        adb.force_stop(pkg)

        # Clear logcat before sending the broadcast so we get a clean signal
        adb.logcat_clear()

        console.print(f"  [cyan]Sending broadcast to:[/cyan] {rcv}")
        result = drozer.send_broadcast(pkg, rcv)
        config.log_command(
            PHASE,
            f"run app.broadcast.send --component {pkg} {rcv}",
            result.stdout,
            result.stderr,
        )

        screenshot_path = ss.capture("drozer_receiver", rcv)
        if screenshot_path:
            config.add_screenshot(screenshot_path, f"Broadcast Receiver: {rcv}", PHASE)

        # Verify the receiver actually processed the broadcast
        processed, logcat_evidence = _verify_receiver_processed(adb, pkg, rcv)
        config.log_command(PHASE, f"logcat check for {rcv}", logcat_evidence or "(no evidence found)")

        drozer_status = "[green]OK[/green]" if result.success else "[red]Failed[/red]"
        processed_status = "[red]YES — processed[/red]" if processed else "[yellow]No evidence[/yellow]"
        results_table.add_row(rcv.split(".")[-1], drozer_status, processed_status)

        if processed:
            config.add_finding(
                PHASE,
                f"Broadcast receiver confirmed processing: {rcv}",
                "Medium",
                f"Receiver {rcv} accepted and processed the broadcast (verified via logcat).\n\n"
                f"Drozer output:\n{result.stdout}\n\n"
                f"Logcat evidence:\n{logcat_evidence}",
            )
        elif result.success:
            config.add_finding(
                PHASE,
                f"Broadcast sent to receiver (not confirmed via logcat): {rcv}",
                "Low",
                f"Drozer successfully sent a broadcast to {rcv}, but no processing evidence "
                f"was found in logcat. The receiver may silently accept it, or it may have "
                f"ignored the broadcast.\n\nDrozer output:\n{result.stdout}",
            )

    console.print(results_table)

    for action in [f"{pkg}.LOGOUT", f"{pkg}.RESET", "android.intent.action.BOOT_COMPLETED"]:
        result = drozer.run_module("app.broadcast.send", f"--action {action}")
        config.log_command(PHASE, f"run app.broadcast.send --action {action}", result.stdout, result.stderr)


def _test_providers(config: Config, drozer: Drozer, ss: ScreenshotManager, pkg: str) -> None:
    console.print("\n[bold magenta]── Content Providers ──[/bold magenta]")
    providers = drozer.get_exported_providers(pkg)

    info_result = drozer.get_providers(pkg)
    config.log_command(PHASE, f"run app.provider.info -a {pkg}", info_result.stdout, info_result.stderr)

    uris: list[str] = []
    for line in info_result.stdout.splitlines():
        line = line.strip()
        if "content://" in line:
            start = line.index("content://")
            uri = line[start:].split()[0].rstrip("/")
            uris.append(uri)

    if not uris and not providers:
        console.print("[yellow]  No exported content providers found.[/yellow]")
        return

    for uri in uris:
        console.print(f"  [cyan]Querying:[/cyan] {uri}")
        result = drozer.query_provider(uri)
        config.log_command(PHASE, f"run app.provider.query {uri}", result.stdout, result.stderr)

        if result.success and result.stdout and "No results" not in result.stdout:
            config.add_finding(
                PHASE,
                f"Content provider data accessible: {uri}",
                "High",
                f"Content provider at {uri} returned data:\n{result.stdout[:2000]}",
            )

        sqli_result = drozer.query_provider_injection(uri, "* FROM sqlite_master--")
        config.log_command(
            PHASE,
            f'run app.provider.query {uri} --projection "* FROM sqlite_master--"',
            sqli_result.stdout,
            sqli_result.stderr,
        )
        if sqli_result.success and sqli_result.stdout and "error" not in sqli_result.stdout.lower():
            config.add_finding(
                PHASE,
                f"SQL Injection in content provider: {uri}",
                "Critical",
                f"SQL injection via projection on {uri}:\n{sqli_result.stdout[:2000]}",
            )

        # Additional SQL injection payloads
        for payload_label, payload in [
            ("selection-or-1=1", "1 OR 1=1--"),
            ("projection-quote", "' OR ''='"),
        ]:
            sqli2 = drozer.query_provider_injection(uri, payload)
            config.log_command(PHASE, f'sqli test ({payload_label}) on {uri}', sqli2.stdout, sqli2.stderr)
            if sqli2.success and sqli2.stdout and "error" not in sqli2.stdout.lower():
                config.add_finding(
                    PHASE,
                    f"SQL Injection ({payload_label}) in content provider: {uri}",
                    "Critical",
                    f"SQL injection via '{payload_label}' on {uri}:\n{sqli2.stdout[:2000]}",
                )

        # Path traversal tests — multiple targets
        traversal_targets = [
            ("../../../etc/passwd", "root:"),
            ("/../proc/self/environ", "PATH="),
            (f"/../../../data/data/{pkg}/shared_prefs/", "xml"),
        ]
        for traversal_path, indicator in traversal_targets:
            traversal_uri = f"{uri}/{traversal_path}"
            traversal_result = drozer.read_provider(traversal_uri)
            config.log_command(
                PHASE,
                f"run app.provider.read {traversal_uri}",
                traversal_result.stdout,
                traversal_result.stderr,
            )
            if traversal_result.success and indicator in traversal_result.stdout:
                config.add_finding(
                    PHASE,
                    f"Path traversal in content provider: {uri}",
                    "Critical",
                    f"Path traversal via {traversal_path} allowed reading sensitive data:\n{traversal_result.stdout[:2000]}",
                )

    console.print("  [cyan]Running injection scanner...[/cyan]")
    inj_result = drozer.scan_provider_injection(pkg)
    config.log_command(PHASE, f"run scanner.provider.injection -a {pkg}", inj_result.stdout, inj_result.stderr)
    if inj_result.stdout and "injection" in inj_result.stdout.lower():
        config.add_finding(
            PHASE,
            "Automated injection scan found vulnerabilities",
            "High",
            inj_result.stdout[:2000],
        )

    console.print("  [cyan]Running traversal scanner...[/cyan]")
    trav_result = drozer.scan_provider_traversal(pkg)
    config.log_command(PHASE, f"run scanner.provider.traversal -a {pkg}", trav_result.stdout, trav_result.stderr)
    if trav_result.stdout and "traversal" in trav_result.stdout.lower():
        config.add_finding(
            PHASE,
            "Automated traversal scan found vulnerabilities",
            "High",
            trav_result.stdout[:2000],
        )

    # URI discovery scan
    console.print("  [cyan]Running URI discovery scanner...[/cyan]")
    finduri_result = drozer.run_module("scanner.provider.finduri", f"-a {pkg}")
    config.log_command(PHASE, f"run scanner.provider.finduri -a {pkg}", finduri_result.stdout, finduri_result.stderr)
    if finduri_result.stdout:
        config.log_command(PHASE, "Discovered URIs", finduri_result.stdout[:3000])

    screenshot_path = ss.capture("drozer_providers", "content_provider_tests")
    if screenshot_path:
        config.add_screenshot(screenshot_path, "Content Provider Tests", PHASE)


def _test_intents(config: Config, drozer: Drozer, ss: ScreenshotManager, pkg: str) -> None:
    console.print("\n[bold magenta]── Intent Sniffing & Browsable Activities ──[/bold magenta]")

    result = drozer.get_browsable_activities(pkg)
    config.log_command(PHASE, f"run scanner.activity.browsable -a {pkg}", result.stdout, result.stderr)

    # Only treat output as a finding when the module actually ran and returned
    # real data. A failed/unreachable module yields blanked stdout (see
    # Drozer._run_module_once), and an empty success just means the app has no
    # browsable activities — neither is a finding.
    if not result.success:
        console.print("[yellow]  scanner.activity.browsable did not complete "
                      "(agent error or timeout) — skipping.[/yellow]")
    elif result.stdout.strip():
        console.print(f"[dim]{result.stdout}[/dim]")
        config.add_finding(
            PHASE,
            "Browsable activities found",
            "Medium",
            f"The following browsable activities/intents were discovered:\n{result.stdout[:2000]}",
        )
    else:
        console.print("[green]  No browsable activities exposed.[/green]")

    launch_result = drozer.run_module("app.package.launchintent", pkg)
    config.log_command(PHASE, f"run app.package.launchintent {pkg}", launch_result.stdout, launch_result.stderr)

    screenshot_path = ss.capture("drozer_intents", "intent_sniffing")
    if screenshot_path:
        config.add_screenshot(screenshot_path, "Intent Sniffing", PHASE)
