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

from core.adb import ADB
from core.config import LIMITS, SENSITIVE_PATTERNS, TIMING, Config
from utils.helpers import presidio_findings_to_report, presidio_scan_text

console = Console()
PHASE = "Phase IV — Dump File Verification"


def run_dump_verification(config: Config, adb: ADB) -> None:
    """Phase IV — deep-analyze dumped files (SQLite, shared prefs, binaries, WebView).

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
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
    # SQLite sidecar files use a DASH (mis_db-shm/-wal/-journal), so a .suffix check misses
    # them — they then get read as standalone DBs and mis-reported as "Encrypted DB". Match
    # both dash- and dot-separated forms on the full name.
    _sidecar = (".journal", ".wal", ".shm", "-journal", "-wal", "-shm")
    db_files = [f for f in db_files if f.is_file() and not f.name.endswith(_sidecar)]

    for db_file in db_files:
        try:
            # Get all table names
            result = subprocess.run(
                ["sqlite3", str(db_file), ".tables"],
                capture_output=True, text=True, errors="replace", timeout=10,
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
                    capture_output=True, text=True, errors="replace", timeout=10,
                ).stdout.strip()

                # Get column info
                pragma_out = subprocess.run(
                    ["sqlite3", str(db_file), f"PRAGMA table_info([{table}]);"],
                    capture_output=True, text=True, errors="replace", timeout=10,
                ).stdout.strip()

                config.log_command(
                    PHASE,
                    f"sqlite3 {db_file.name} 'PRAGMA table_info([{table}])'",
                    f"Rows: {count_out}\nColumns:\n{pragma_out}",
                )

                # Select first 5 rows to check data
                select_out = subprocess.run(
                    ["sqlite3", str(db_file), f"SELECT * FROM [{table}] LIMIT 5;"],
                    capture_output=True, text=True, errors="replace", timeout=10,
                ).stdout.strip()

                if select_out:
                    pii = presidio_scan_text(select_out, config, source_label=f"db_table:{db_file.name}/{table}")
                    if pii:
                        presidio_findings_to_report(
                            pii, PHASE, config,
                            fallback_title=f"Sensitive data in table {table} ({db_file.name})",
                            fallback_detail=(
                                f"Database: {db_file.name}\nTable: {table}\nRows: {count_out}\n"
                                f"Sample data:\n{select_out[:2000]}"
                            ),
                        )

        except (subprocess.SubprocessError, OSError, ValueError) as e:
            # ValueError covers UnicodeDecodeError from binary BLOB columns — a single
            # malformed DB must not abort the whole phase.
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
            seen_keys: set[str] = set()  # Prevent duplicate entries

            # Collect all key=value pairs for batch analysis
            all_pairs: list[tuple[str, str]] = []
            for elem in root.iter():
                name = elem.get("name", "")
                value = elem.text or elem.get("value", "")
                if name:
                    all_pairs.append((name, value))

                # Check for boolean flags that might control features
                if elem.tag == "boolean" and name and name not in seen_keys:
                    interesting_entries.append(f"  [bool] {name} = {value}")
                    seen_keys.add(name)

            # Batch scan all key=value text at once for efficiency
            batch_text = "\n".join(f"{n}={v}" for n, v in all_pairs if n)
            pii_findings = presidio_scan_text(batch_text, config, source_label=f"prefs:{xml_file.name}")

            # If Presidio found entity-level results, map matched text back to keys
            pii_matched_texts = set()
            if pii_findings and pii_findings[0].get("entity_type") != "SENSITIVE_PATTERN":
                for pf in pii_findings:
                    pii_matched_texts.add(pf.get("text", ""))

            for name, value in all_pairs:
                if name in seen_keys:
                    continue
                # Check via regex OR if Presidio matched something in this entry
                entry_text = f"{name}={value}"
                is_sensitive = (
                    re.search(SENSITIVE_PATTERNS, name, re.IGNORECASE) or
                    (value and re.search(SENSITIVE_PATTERNS, value, re.IGNORECASE)) or
                    any(mt in entry_text for mt in pii_matched_texts if mt)
                )
                if is_sensitive:
                    interesting_entries.append(f"  Key: {name} = {value}")
                    seen_keys.add(name)

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
                    capture_output=True, text=True, errors="replace", timeout=30,
                )
                pii = presidio_scan_text(result.stdout, config, source_label=f"binary:{f.name}")
                if pii:
                    presidio_findings_to_report(
                        pii, PHASE, config,
                        fallback_title=f"Sensitive strings in binary: {f.name}",
                        fallback_detail=f"File: {f}\n\n" + "\n".join(
                            line for line in result.stdout.splitlines()
                            if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
                        )[:3000],
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
            pii = presidio_scan_text(content, config, source_label=f"webview:{f.name}")
            if pii:
                presidio_findings_to_report(
                    pii, PHASE, config,
                    fallback_title=f"Sensitive data in WebView storage: {f.name}",
                    fallback_detail=f"File: {f}\n\n" + "\n".join(
                        line for line in content.splitlines()
                        if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
                    )[:3000],
                )
        except (OSError, ValueError):
            continue  # Unreadable/binary WebView file — skip and continue.
