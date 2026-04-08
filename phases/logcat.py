"""
Phase V — Logcat Monitoring.

Captures logcat output while the user interacts with the app,
then scans for sensitive data leakage in logs.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time

from rich.console import Console
from rich.panel import Panel

from core.config import Config, SENSITIVE_PATTERNS
from core.adb import ADB

console = Console()
PHASE = "Phase V — Logcat Monitoring"

MAX_CAPTURE_SECONDS = 120
NOISE_TAGS = (
    "WindowManagerShell",
    "WindowManager:",
    "ActivityTaskManager",
    "SurfaceFlinger",
    "Launcher3",
)


def run_logcat_monitoring(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name

    # Launch the app
    console.print("[cyan]Launching the application...[/cyan]")
    adb.launch_app(pkg)
    config.log_command(PHASE, f"adb shell monkey -p {pkg} 1", "App launched")

    # Clear old logs
    adb.logcat_clear()

    from core.config import TIMING
    auto_timeout = TIMING.logcat_auto_timeout if config.auto_mode else MAX_CAPTURE_SECONDS
    if not config.auto_mode:
        console.print(Panel(
            "Please use the app — enter sensitive data (login, PII).\nPress ENTER when done (auto-stops after 2 min).",
            style="bold yellow",
        ))
    else:
        console.print(f"[yellow]Auto-mode: capturing logcat for {auto_timeout}s...[/yellow]")

    # Start logcat capture in background
    stop_event = threading.Event()
    log_lines: list[str] = []

    def _capture_logcat():
        cmd = ["adb"]
        if adb.device_id:
            cmd += ["-s", adb.device_id]
        cmd += ["logcat", "-v", "threadtime"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            start = time.time()
            while not stop_event.is_set():
                if proc.stdout is None:
                    break
                line = proc.stdout.readline()
                if line:
                    log_lines.append(line)
                if time.time() - start > auto_timeout:
                    break
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception as e:
            log_lines.append(f"[ERROR] Logcat capture failed: {e}\n")

    capture_thread = threading.Thread(target=_capture_logcat, daemon=True)
    capture_thread.start()

    if config.auto_mode:
        time.sleep(auto_timeout)
    else:
        input_event = threading.Event()

        def _wait_for_input():
            input()
            input_event.set()

        input_thread = threading.Thread(target=_wait_for_input, daemon=True)
        input_thread.start()
        input_event.wait(timeout=auto_timeout)

    stop_event.set()
    capture_thread.join(timeout=5)

    # Also dump any buffered logs
    dump_output = adb.logcat_dump()
    all_logs = "".join(log_lines) + "\n" + dump_output

    # Save full logcat
    logcat_path = config.output_dir / "logcat_dump.txt"
    logcat_path.parent.mkdir(parents=True, exist_ok=True)
    logcat_path.write_text(all_logs, encoding="utf-8")
    console.print(f"  [green]Captured {len(log_lines)} log lines → logcat_dump.txt[/green]")

    # ── Filter for app-specific logs ──
    pid = adb.get_pid(pkg)
    app_logs = []
    for line in all_logs.splitlines():
        if pkg in line or (pid and pid in line):
            app_logs.append(line)

    app_logcat_path = config.output_dir / "logcat_app_filtered.txt"
    app_logcat_path.parent.mkdir(parents=True, exist_ok=True)
    app_logcat_path.write_text("\n".join(app_logs), encoding="utf-8")

    app_logs_text = "\n".join(app_logs)

    # ── Scan for sensitive data ──
    console.print("[cyan]Scanning logs for sensitive data...[/cyan]")
    sensitive_lines = []
    for line in app_logs_text.splitlines():
        if any(tag in line for tag in NOISE_TAGS):
            continue
        if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE):
            sensitive_lines.append(line.strip())

    sensitive_output = "\n".join(sensitive_lines)
    config.log_command(PHASE, "grep -iE '<patterns>' logcat_app_filtered.txt", sensitive_output[:5000])

    if sensitive_lines:
        config.add_finding(
            PHASE,
            f"Sensitive data leaked in logcat ({len(sensitive_lines)} lines)",
            "High",
            f"The following log lines contain potentially sensitive data:\n\n{sensitive_output[:5000]}",
        )
        console.print(f"  [red]Found {len(sensitive_lines)} sensitive line(s) in logcat![/red]")
    else:
        console.print("  [green]No obvious sensitive data in logcat.[/green]")

    # ── Additional pattern scans (app-focused to reduce false positives) ──
    _scan_for_http(config, app_logs_text)
    _scan_for_sql(config, app_logs_text)
    _scan_for_exceptions(config, app_logs_text, pkg)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _scan_for_http(config: Config, logs: str) -> None:
    http_lines = [l for l in logs.splitlines() if re.search(r"https?://", l, re.IGNORECASE)]
    if http_lines:
        http_text = "\n".join(http_lines[:100])
        cleartext_http = [l for l in http_lines if "http://" in l.lower()]
        if cleartext_http:
            config.add_finding(
                PHASE,
                f"Cleartext HTTP URLs in logcat ({len(cleartext_http)} occurrences)",
                "Medium",
                "\n".join(cleartext_http[:50]),
            )

        # Flag sensitive API endpoints
        sensitive_endpoint_patterns = re.compile(
            r"/(api|auth|login|logout|token|oauth|v[0-9]+/users|graphql|signup|register|password|session)", re.IGNORECASE
        )
        sensitive_lines = [l for l in http_lines if sensitive_endpoint_patterns.search(l)]
        if sensitive_lines:
            config.add_finding(
                PHASE,
                f"Sensitive API endpoints in logcat ({len(sensitive_lines)} URLs)",
                "Medium",
                "HTTP URLs referencing authentication/API endpoints were found in logs:\n\n"
                + "\n".join(sensitive_lines[:50]),
            )


def _scan_for_sql(config: Config, logs: str) -> None:
    # Match realistic SQL statements instead of generic words like "update task".
    sql_regex = re.compile(
        r"\b(SELECT\s+.+\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|"
        r"CREATE\s+(TABLE|INDEX)|DROP\s+(TABLE|INDEX))\b",
        re.IGNORECASE,
    )
    sql_lines = [
        l for l in logs.splitlines()
        if sql_regex.search(l)
    ]
    if sql_lines:
        config.add_finding(
            PHASE,
            f"SQL queries visible in logcat ({len(sql_lines)} occurrences)",
            "Medium",
            "\n".join(sql_lines[:50]),
        )


def _scan_for_exceptions(config: Config, logs: str, pkg: str) -> None:
    exception_blocks: list[str] = []
    lines = logs.splitlines()
    i = 0
    while i < len(lines):
        if re.search(r"Exception|Error|FATAL", lines[i]) and pkg in lines[i]:
            block = [lines[i]]
            j = i + 1
            while j < len(lines) and j < i + 20:
                if lines[j].strip().startswith("at "):
                    block.append(lines[j])
                    j += 1
                else:
                    break
            exception_blocks.append("\n".join(block))
            i = j
        else:
            i += 1

    if exception_blocks:
        config.add_finding(
            PHASE,
            f"Application exceptions in logcat ({len(exception_blocks)} stack traces)",
            "Info",
            "\n\n---\n\n".join(exception_blocks[:10]),
        )
