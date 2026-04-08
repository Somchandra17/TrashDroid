"""
Phase IV — Dump File Verification (Optional).

Re-examines dumped files from Phase III with deeper analysis:
SQLite queries, shared prefs parsing, and binary string extraction.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.prompt import Confirm

from core.config import Config, SENSITIVE_PATTERNS, TIMING, LIMITS
from core.adb import ADB
from utils.helpers import grep_sensitive_lines

console = Console()
PHASE = "Phase IV — Dump File Verification"


def run_dump_verification(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    if not config.auto_mode:
        if not Confirm.ask("Do you want the script to attempt deeper verification of the dumped files?", default=True):
            console.print("[yellow]Skipping dump file verification.[/yellow]")
            return

    local_base = config.output_dir / "filesystem"

    # ── Deep SQLite analysis ──
    _deep_sqlite_analysis(config, local_base / "databases")

    # ── Deep shared prefs analysis ──
    _deep_shared_prefs_analysis(config, local_base / "shared_prefs")

    # ── Binary / cache file string extraction ──
    _binary_string_extraction(config, local_base)

    # ── WebView storage analysis ──
    _webview_analysis(config, local_base / "app_webview")

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _deep_sqlite_analysis(config: Config, db_dir: Path) -> None:
    console.print("\n[cyan]Deep SQLite analysis...[/cyan]")
    if not db_dir.exists():
        return

    db_files = list(db_dir.rglob("*"))
    db_files = [f for f in db_files if f.is_file() and f.suffix not in [".journal", ".wal", ".shm"]]

    for db_file in db_files:
        try:
            # Get all table names
            result = subprocess.run(
                ["sqlite3", str(db_file), ".tables"],
                capture_output=True, text=True, timeout=10,
            )
            tables_out = result.stdout.strip()
            stderr_out = result.stderr.strip().lower()

            if "file is encrypted or is not a database" in stderr_out or "file is not a database" in stderr_out:
                config.add_finding(
                    PHASE,
                    f"Encrypted Database Detected: {db_file.name}",
                    "Info",
                    f"Database '{db_file.name}' could not be read using standard sqlite3, which strongly implies it is encrypted (e.g., SQLCipher).\n\nError: {result.stderr.strip()}"
                )
                console.print(f"  [green]Encrypted DB detected:[/green] {db_file.name}")
                continue

            if not tables_out:
                continue

            table_names = tables_out.split()
            for table in table_names:
                # Get row count
                count_out = subprocess.run(
                    ["sqlite3", str(db_file), f"SELECT COUNT(*) FROM [{table}];"],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()

                # Get column info
                pragma_out = subprocess.run(
                    ["sqlite3", str(db_file), f"PRAGMA table_info([{table}]);"],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()

                config.log_command(
                    PHASE,
                    f"sqlite3 {db_file.name} 'PRAGMA table_info([{table}])'",
                    f"Rows: {count_out}\nColumns:\n{pragma_out}",
                )

                # Select first 5 rows to check data
                select_out = subprocess.run(
                    ["sqlite3", str(db_file), f"SELECT * FROM [{table}] LIMIT 5;"],
                    capture_output=True, text=True, timeout=10,
                ).stdout.strip()

                if select_out:
                    if re.search(SENSITIVE_PATTERNS, select_out, re.IGNORECASE):
                        config.add_finding(
                            PHASE,
                            f"Sensitive data in table {table} ({db_file.name})",
                            "High",
                            f"Database: {db_file.name}\nTable: {table}\nRows: {count_out}\n"
                            f"Sample data:\n{select_out[:2000]}",
                        )

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            console.print(f"  [yellow]Error on {db_file.name}: {e}[/yellow]")


def _deep_shared_prefs_analysis(config: Config, prefs_dir: Path) -> None:
    console.print("[cyan]Deep shared preferences analysis...[/cyan]")
    if not prefs_dir.exists():
        return

    import xml.etree.ElementTree as ET

    for xml_file in prefs_dir.rglob("*.xml"):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            interesting_entries = []

            for elem in root.iter():
                name = elem.get("name", "")
                value = elem.text or elem.get("value", "")
                if re.search(SENSITIVE_PATTERNS, name, re.IGNORECASE):
                    interesting_entries.append(f"  Key: {name} = {value}")
                if value and re.search(SENSITIVE_PATTERNS, value, re.IGNORECASE):
                    interesting_entries.append(f"  Key: {name} = {value}")

                # Check for boolean flags that might control features
                if elem.tag == "boolean" and name:
                    interesting_entries.append(f"  [bool] {name} = {value}")

            if interesting_entries:
                config.add_finding(
                    PHASE,
                    f"Interesting entries in {xml_file.name}",
                    "Medium",
                    f"File: {xml_file.name}\n" + "\n".join(interesting_entries[:100]),
                )
                config.log_command(
                    PHASE,
                    f"parse {xml_file.name}",
                    "\n".join(interesting_entries[:100]),
                )
        except ET.ParseError:
            console.print(f"  [yellow]Could not parse {xml_file.name}[/yellow]")


def _binary_string_extraction(config: Config, base_dir: Path) -> None:
    console.print("[cyan]Extracting strings from binary/cache files...[/cyan]")

    binary_extensions = {".bin", ".dat", ".so", ".dex", ".realm", ".db", ""}
    budget_start = time.monotonic()
    max_time_secs = TIMING.db_query_timeout
    max_files = LIMITS.max_binary_files
    files_processed = 0

    for f in base_dir.rglob("*"):
        # Budget checks
        if files_processed >= max_files:
            console.print(f"  [yellow]File count budget reached ({max_files} files). Stopping binary scan.[/yellow]")
            break
        if time.monotonic() - budget_start > max_time_secs:
            console.print(f"  [yellow]Time budget reached ({max_time_secs}s). Stopping binary scan.[/yellow]")
            break

        if not f.is_file() or f.stat().st_size > 50 * 1024 * 1024:  # skip >50MB
            continue
        if f.suffix in binary_extensions or f.suffix == "":
            files_processed += 1
            try:
                result = subprocess.run(
                    ["strings", str(f)],
                    capture_output=True, text=True, timeout=30,
                )
                matches = [
                    line for line in result.stdout.splitlines()
                    if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
                ]
                if matches:
                    config.add_finding(
                        PHASE,
                        f"Sensitive strings in binary: {f.name}",
                        "Medium",
                        f"File: {f}\n\n" + "\n".join(matches[:100]),
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass


def _webview_analysis(config: Config, webview_dir: Path) -> None:
    console.print("[cyan]Analyzing WebView storage...[/cyan]")
    if not webview_dir.exists():
        console.print("  [yellow]No WebView directory found.[/yellow]")
        return

    for f in webview_dir.rglob("*"):
        if not f.is_file():
            continue
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
            if re.search(SENSITIVE_PATTERNS, content, re.IGNORECASE):
                matches = [
                    line for line in content.splitlines()
                    if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
                ]
                if matches:
                    config.add_finding(
                        PHASE,
                        f"Sensitive data in WebView storage: {f.name}",
                        "High",
                        f"File: {f}\n\n" + "\n".join(matches[:50]),
                    )
        except Exception:
            pass
