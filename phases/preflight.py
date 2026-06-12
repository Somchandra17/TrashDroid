"""
Pre-flight checks — verifies all required tools, device connectivity, and root status.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from core.config import DROZER_AGENT_PKG, REQUIRED_TOOLS

if TYPE_CHECKING:
    from core.adb import ADB

console = Console()


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def check_tool_version(name: str) -> str:
    for flag in ["--version", "version", "-v"]:
        try:
            result = subprocess.run(
                [name, flag], capture_output=True, text=True, timeout=10,
            )
            output = (result.stdout or result.stderr).strip()
            if output and "unknown command" not in output.lower():
                return output.splitlines()[0][:80]
        except (subprocess.SubprocessError, OSError):
            continue
    return "installed"


def verify_device_prerequisites(adb: ADB) -> bool:
    """Check if necessary components like Drozer are installed on the device itself."""
    drozer_pkg = DROZER_AGENT_PKG
    console.print("\n[cyan]Checking on-device prerequisites...[/cyan]")

    while not adb.is_package_installed(drozer_pkg):
        console.print(f"\n[red]✗ Drozer Agent ({drozer_pkg}) is not installed on the device.[/red]")
        console.print("Please install the Drozer Agent APK on the device using:")
        console.print("[white]adb install path/to/drozer-agent.apk[/white]")

        from rich.prompt import Prompt
        ans = Prompt.ask("Have you installed it now? (y/n/skip)", choices=["y", "n", "skip"], default="y")
        if ans == "skip":
            console.print("[yellow]Skipping Drozer agent check. Phase I tests will likely fail.[/yellow]")
            return True
        elif ans == "n":
            console.print("[red]Aborting due to missing on-device prerequisites.[/red]")
            return False

    console.print("[green]✓ Drozer Agent is installed on the device.[/green]")
    return True


def run_preflight() -> bool:
    """
    Verify all prerequisites. Returns True if all critical checks pass.
    """
    console.print("\n[bold cyan]═══ Pre-flight Checks ═══[/bold cyan]\n")

    table = Table(title="Tool Availability")
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Version")

    all_ok = True
    for tool in REQUIRED_TOOLS:
        found = check_tool(tool)
        version = check_tool_version(tool) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[red]✗ Missing[/red]"
        table.add_row(tool, status, version)
        if not found:
            all_ok = False

    for extra in ["sqlite3", "strings", "aapt2"]:
        found = check_tool(extra)
        version = check_tool_version(extra) if found else "—"
        status = "[green]✓ Found[/green]" if found else "[yellow]~ Optional[/yellow]"
        table.add_row(extra, status, version)

    # Check Python package availability for Presidio/GLiNER
    try:
        import presidio_analyzer
        presidio_ver = getattr(presidio_analyzer, "__version__", "installed")
        table.add_row("presidio-analyzer", "[green]✓ Found[/green]", str(presidio_ver))
    except ImportError:
        table.add_row("presidio-analyzer", "[yellow]~ Optional[/yellow]", "pip install presidio-analyzer")

    try:
        try:
            # Presidio >= 2.2.360
            from presidio_analyzer.predefined_recognizers.ner.gliner_recognizer import GLiNERRecognizer  # noqa: F401
        except ImportError:
            # Older Presidio versions
            from presidio_analyzer.predefined_recognizers.gliner_recognizer import GLiNERRecognizer  # noqa: F401
        table.add_row("GLiNER (NER)", "[green]✓ Found[/green]", "urchade/gliner_multi_pii-v1")
    except ImportError:
        table.add_row("GLiNER (NER)", "[yellow]~ Optional[/yellow]", 'pip install "presidio-analyzer[gliner]"')

    console.print(table)

    if not all_ok:
        console.print("\n[red bold]✗ Critical tools are missing. Install them before proceeding.[/red bold]")
        return False

    from core.adb import ADB
    devices = ADB.get_devices()

    # Check for unauthorized/offline devices that wouldn't show in get_devices()
    try:
        raw = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
        for line in raw.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                if parts[1] == "unauthorized":
                    console.print(
                        f"\n[red bold]⚠ Device '{parts[0]}' found but USB debugging not authorized.[/red bold]"
                    )
                    console.print("  Tap [bold]'Allow USB debugging'[/bold] on the device and re-run.")
                elif parts[1] == "offline":
                    console.print(
                        f"\n[yellow]⚠ Device '{parts[0]}' is offline. Reconnect the USB cable.[/yellow]"
                    )
    except (subprocess.SubprocessError, OSError):
        pass  # Diagnostic-only listing; ignore if `adb devices` can't be run.

    if not devices:
        console.print("\n[red bold]✗ No authorized Android device detected via ADB.[/red bold]")
        console.print("  Ensure USB debugging is enabled and the device is connected.")
        return False

    console.print(f"\n[green]✓ {len(devices)} device(s) connected via ADB.[/green]")
    return True
