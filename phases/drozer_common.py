"""
Shared drozer connection/recovery used by Phase I (drozer_testing) and Phase IX
(post_logout). Previously each phase carried its own near-identical copy that had
drifted (different agent-launch commands, different retry behaviour); this is the
single source of truth.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.panel import Panel

from core.adb import ADB
from core.config import DROZER_AGENT_PKG, DROZER_PORT, Config
from core.drozer import Drozer

console = Console()

MAX_DROZER_RETRIES = 3


def ensure_drozer_connected(config: Config, adb: ADB, drozer: Drozer, phase_name: str) -> bool:
    """
    Set up port forwarding and verify the drozer connection. If it fails:
      - On rooted devices, restart the on-device agent's embedded server
        automatically (no UI interaction — works in --auto).
      - On non-rooted devices, launch the agent and ask the user to flip the
        Embedded Server toggle, since the server can't be started otherwise.
    Retries up to MAX_DROZER_RETRIES times. Returns True if connected.
    """
    console.print("[cyan]Setting up Drozer port forwarding...[/cyan]")
    drozer.setup_port_forward()
    config.log_command(phase_name, f"adb forward tcp:{DROZER_PORT} tcp:{DROZER_PORT}", "Port forwarded")

    console.print("[cyan]Verifying Drozer connection...[/cyan]")
    if drozer.verify_connection():
        console.print("[green]Drozer connected successfully.[/green]")
        return True

    if drozer.rooted:
        for attempt in range(1, MAX_DROZER_RETRIES + 1):
            console.print(
                f"\n[yellow]Drozer not reachable (attempt {attempt}/{MAX_DROZER_RETRIES}) — "
                f"restarting the on-device agent server...[/yellow]"
            )
            if drozer.restart_agent_server():
                console.print("[green]Drozer connected successfully.[/green]")
                config.log_command(phase_name, "restart drozer agent server", "connected")
                return True
    else:
        for attempt in range(1, MAX_DROZER_RETRIES + 1):
            console.print(f"\n[red bold]Drozer connection failed (attempt {attempt}/{MAX_DROZER_RETRIES}).[/red bold]")
            console.print("[cyan]Launching Drozer Agent on the device...[/cyan]")
            adb.shell(f"monkey -p {DROZER_AGENT_PKG} -c android.intent.category.LAUNCHER 1")
            time.sleep(2)

            console.print(Panel(
                "The Drozer Agent app has been opened on your device.\n\n"
                "Tap the toggle/button to ENABLE the Embedded Server.\n\n"
                "Press Enter here once the server is ON.",
                style="bold yellow",
            ))

            if config.auto_mode:
                console.print("[yellow]Auto-mode: waiting 5 seconds for agent to start...[/yellow]")
                time.sleep(5)
            else:
                input()

            drozer.setup_port_forward()
            if drozer.verify_connection():
                console.print("[green]Drozer connected successfully.[/green]")
                return True

    console.print("\n[red bold]Could not connect to Drozer after all retries. Skipping.[/red bold]")
    config.add_finding(
        phase_name,
        "Drozer connection failed after retries",
        "Info",
        "Could not connect to the Drozer agent after multiple attempts. "
        "Ensure the agent APK (com.withsecure.dz) is installed and the embedded server is enabled.",
    )
    return False
