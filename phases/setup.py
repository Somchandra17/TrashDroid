"""
Setup phase — device selection, APK input, installation, permission grant, login state.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from core.adb import ADB, ADBError
from core.config import Config
from utils.helpers import is_valid_package_name as _validate_package_name

console = Console()


def select_device() -> str:
    devices = ADB.get_devices()
    if not devices:
        console.print("[red]No connected devices found via adb.[/red]")
        return ""
    if len(devices) == 1:
        console.print(f"[green]Auto-selected device:[/green] {devices[0]}")
        return devices[0]

    console.print("\n[bold cyan]Connected devices:[/bold cyan]")
    for i, dev in enumerate(devices, 1):
        console.print(f"  [{i}] {dev}")

    while True:
        choice = Prompt.ask("Select device number", default="1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                return devices[idx]
        except ValueError:
            pass
        console.print("[red]Invalid selection, try again.[/red]")


def _select_installed_package(adb: ADB) -> str:
    """Interactive target-package picker.

    Lists installed third-party packages as a numbered menu (mirroring
    `select_device`) and lets the user pick a number or type/paste any package id
    (e.g. a system package not in the list). Verifies the chosen package is
    actually installed so a typo can't run the whole assessment against nothing.
    """
    try:
        packages = adb.list_installed_packages(third_party_only=True)
    except ADBError:
        packages = []

    if packages:
        console.print("\n[bold cyan]Installed third-party packages:[/bold cyan]")
        for i, pkg in enumerate(packages, 1):
            console.print(f"  [{i}] {pkg}")
        console.print("[dim]Pick a number, or type/paste a package name "
                      "(e.g. a system package not shown above).[/dim]")
    else:
        console.print("[yellow]Could not list installed packages — enter the package name manually.[/yellow]")

    while True:
        choice = Prompt.ask("Select target package (number or name)").strip()

        if choice.isdigit() and packages:
            idx = int(choice) - 1
            if 0 <= idx < len(packages):
                return packages[idx]
            console.print("[red]Number out of range, try again.[/red]")
            continue

        if not _validate_package_name(choice):
            console.print("[red]Invalid package name format. Expected: com.example.app[/red]")
            continue

        try:
            installed = adb.is_package_installed(choice)
        except ADBError:
            installed = True  # device query failed — don't block on it
        if not installed and not Confirm.ask(
            f"'{choice}' does not appear to be installed. Use it anyway?", default=False
        ):
            continue
        return choice


def get_apk_input(adb: ADB) -> tuple[str | None, str, bool]:
    """
    Returns (apk_path or None, package_name, is_preinstalled).
    """
    console.print("\n[bold cyan]═══ Target Application ═══[/bold cyan]\n")
    preinstalled = Confirm.ask("Is the app already installed on the device?", default=False)

    if preinstalled:
        return None, _select_installed_package(adb), True

    apk_path = Prompt.ask("Enter the full path to the APK file")
    apk_path = apk_path.strip().strip("'\"")

    pkg = adb.get_package_name_from_apk(apk_path)
    if not pkg:
        pkg = Prompt.ask("Could not auto-detect package name. Enter it manually")
        pkg = pkg.strip()
    while not _validate_package_name(pkg):
        console.print("[red]Invalid package name format. Expected: com.example.app[/red]")
        pkg = Prompt.ask("Enter a valid package name").strip()

    return apk_path, pkg, False


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Compute a file's SHA-256 by streaming it in chunks (avoids loading large APKs into memory)."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_and_prepare(adb: ADB, config: Config) -> None:
    """Install APK, compute hash, prompt for permissions and login."""
    # Compute APK SHA-256 hash for evidence chain-of-custody
    if config.apk_path and Path(config.apk_path).exists():
        apk_hash = _sha256_file(Path(config.apk_path))
        config.apk_hash = apk_hash
        console.print(f"  [dim]APK SHA-256: {apk_hash}[/dim]")

    if not config.is_preinstalled and config.apk_path:
        console.print(f"\n[cyan]Installing APK: {config.apk_path}[/cyan]")
        try:
            result = adb.install_apk(config.apk_path)
        except ADBError as e:
            console.print(f"  [red]✗ APK installation failed: {e}[/red]")
            console.print("  [yellow]Continuing setup, but device-side phases may not work "
                          "until the app is installed manually.[/yellow]")
            config.log_command("Setup", f"adb install -r -d {config.apk_path}", "", str(e), rc=1)
        else:
            console.print(f"  {result}")
            config.log_command("Setup", f"adb install -r -d {config.apk_path}", result)

    if config.auto_mode:
        console.print("[yellow]Auto-mode: skipping permission/login prompts.[/yellow]")
        config.logged_in = False
    else:
        console.print(Panel(
            "Please open the app, grant ALL permissions,\nthen press Enter to continue.",
            style="bold yellow",
        ))
        input()

        want_login = Confirm.ask("Do you want to run tests in a logged-in state?", default=True)
        if want_login:
            console.print("\n[yellow]Please log in to the application now. Press Enter when ready.[/yellow]")
            input()
            config.logged_in = True
        else:
            config.logged_in = False

    console.print(f"\n[green]✓ Setup complete — testing '{config.package_name}' "
                  f"({'logged in' if config.logged_in else 'logged out'})[/green]")
