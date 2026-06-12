"""
Phase III — Local File System Analysis.

Pulls the app's data directory from the device and scans for sensitive data
in shared preferences, databases, internal files, cache, and external storage.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from rich.console import Console

from core.adb import ADB, ADBError
from core.config import LIMITS, SENSITIVE_PATTERNS, Config
from utils.helpers import (
    grep_sensitive_lines,
    is_safe_device_path,
    is_valid_package_name,
    presidio_findings_to_report,
    presidio_scan_text,
)

console = Console()
PHASE = "Phase III — Local File System Analysis"


def run_filesystem_analysis(config: Config, adb: ADB) -> None:
    """Phase III — pull the app's data directory and scan it for sensitive data.

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    if not is_valid_package_name(pkg):
        console.print(f"  [red]Refusing to run: '{pkg}' is not a valid package name.[/red]")
        config.log_command(PHASE, "validate package", "", f"invalid package name: {pkg}", rc=1)
        return
    device_base = adb.get_app_data_path(pkg)
    local_base = config.output_dir / "filesystem"
    local_base.mkdir(parents=True, exist_ok=True)

    rooted = adb.is_rooted()
    if rooted:
        console.print("  [green]Device is rooted — using root shell to pull app data.[/green]")
    else:
        console.print("  [yellow]Device is not rooted — pull may fail for /data/data/ paths.[/yellow]")

    # Paths under /data/data require root; /sdcard paths do not.
    root_targets = [
        (f"{device_base}/shared_prefs/", str(local_base / "shared_prefs")),
        (f"{device_base}/databases/", str(local_base / "databases")),
        (f"{device_base}/files/", str(local_base / "files")),
        (f"{device_base}/cache/", str(local_base / "cache")),
        (f"{device_base}/app_webview/", str(local_base / "app_webview")),
    ]
    non_root_targets = [
        (f"/sdcard/Android/data/{pkg}/", str(local_base / "external")),
    ]

    for remote, local in root_targets:
        console.print(f"  [cyan]Pulling (root):[/cyan] {remote}")
        Path(local).mkdir(parents=True, exist_ok=True)
        try:
            if rooted:
                result = adb.pull_as_root(remote, local)
            else:
                result = adb.pull(remote, local)
            config.log_command(PHASE, f"adb pull {remote} {local}", result)
            file_count = sum(1 for _ in Path(local).rglob("*") if _.is_file())
            if file_count > 0:
                console.print(f"    [green]Pulled {file_count} file(s)[/green]")
            else:
                console.print("    [yellow]Directory empty or inaccessible[/yellow]")
                # On-device grep fallback for inaccessible directories
                if rooted:
                    _on_device_grep_fallback(config, adb, remote)
        except (ADBError, OSError) as e:
            console.print(f"    [yellow]Could not pull {remote}: {e}[/yellow]")
            config.log_command(PHASE, f"adb pull {remote} {local}", "", str(e))
            # On-device grep fallback when pull fails entirely
            if rooted:
                _on_device_grep_fallback(config, adb, remote)

    for remote, local in non_root_targets:
        console.print(f"  [cyan]Pulling:[/cyan] {remote}")
        Path(local).mkdir(parents=True, exist_ok=True)
        try:
            result = adb.pull(remote, local)
            config.log_command(PHASE, f"adb pull {remote} {local}", result)
        except (ADBError, OSError) as e:
            console.print(f"    [yellow]Could not pull {remote}: {e}[/yellow]")
            config.log_command(PHASE, f"adb pull {remote} {local}", "", str(e))

    # NOTE: Full data dir pull removed (was redundant with individual subdirectory pulls above).

    # ── Scan for sensitive data (Presidio or grep fallback) ──
    console.print("\n[cyan]Scanning pulled files for sensitive data...[/cyan]")
    grep_results = _grep_sensitive(str(local_base))

    # Cap the number of matched lines so a pathological target cannot flood the
    # report / Presidio pass; the full grep output is still written to disk below.
    _grep_lines = grep_results.splitlines()
    if len(_grep_lines) > LIMITS.max_grep_lines:
        console.print(
            f"  [yellow]grep produced {len(_grep_lines)} lines — capping to "
            f"{LIMITS.max_grep_lines} for analysis.[/yellow]"
        )
        grep_results = "\n".join(_grep_lines[:LIMITS.max_grep_lines])

    grep_output_path = config.output_dir / "grep_results.txt"
    grep_output_path.parent.mkdir(parents=True, exist_ok=True)
    grep_output_path.write_text(grep_results, encoding="utf-8")
    config.log_command(PHASE, f"grep -rniE '<patterns>' {local_base}", grep_results)

    if grep_results.strip():
        lines = grep_results.strip().splitlines()
        # Run Presidio analysis on grep results for richer entity detection
        pii_findings = presidio_scan_text(grep_results, config, source_label="filesystem_grep")
        if pii_findings and pii_findings[0].get("entity_type") != "SENSITIVE_PATTERN":
            presidio_findings_to_report(
                pii_findings, PHASE, config,
                fallback_title=f"Sensitive data found in local storage ({len(lines)} matches)",
                fallback_detail=grep_results[:5000],
            )
        else:
            config.add_finding(
                PHASE,
                f"Sensitive data found in local storage ({len(lines)} matches)",
                "High",
                grep_results[:5000],
            )
        console.print(f"  [red]Found {len(lines)} sensitive data match(es) — saved to grep_results.txt[/red]")
    else:
        console.print("  [green]No obvious sensitive data patterns found in pulled files.[/green]")

    # ── SQLite database analysis ──
    _analyze_databases(config, str(local_base))

    # ── Shared preferences analysis ──
    _analyze_shared_prefs(config, str(local_base / "shared_prefs"))

    # ── NoSQL / Realm analysis ──
    _analyze_nosql(config, adb, pkg, str(local_base))

    # ── File permission analysis ──
    _check_file_permissions(config, adb, pkg)

    # ── Keystore analysis ──
    _analyze_keystores(config, str(local_base))

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _grep_sensitive(directory: str) -> str:
    try:
        result = subprocess.run(
            ["grep", "-rniE", SENSITIVE_PATTERNS, directory],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def _on_device_grep_fallback(config: Config, adb: ADB, remote_path: str) -> None:
    """Run grep directly on the device when local pull is not possible."""
    # remote_path is interpolated into a root shell command; reject anything
    # that isn't a plain device path before it can reach `su -c`.
    if not is_safe_device_path(remote_path):
        console.print(f"    [yellow]Skipping on-device grep — unsafe path: {remote_path}[/yellow]")
        config.log_command(PHASE, "on-device grep", "", f"unsafe path rejected: {remote_path}", rc=1)
        return
    console.print(f"    [cyan]Running on-device grep fallback for {remote_path}...[/cyan]")
    try:
        result = adb.shell(
            f"grep -rniE '{SENSITIVE_PATTERNS}' {remote_path} 2>/dev/null",
            root=True,
            timeout=30,
        )
        output = result.stdout.strip()
        config.log_command(PHASE, f"on-device grep {remote_path}", output[:5000])
        if output:
            lines = output.splitlines()
            # Analyze grep output with Presidio for entity-level detection
            pii = presidio_scan_text(output, config, source_label=f"on-device:{remote_path}")
            if pii and pii[0].get("entity_type") != "SENSITIVE_PATTERN":
                presidio_findings_to_report(
                    pii, PHASE, config,
                    fallback_title=f"Sensitive data found on-device (grep fallback): {remote_path}",
                    fallback_detail=f"Could not pull files locally, but on-device grep found {len(lines)} match(es):\n\n{output[:5000]}",
                )
            else:
                config.add_finding(
                    PHASE,
                    f"Sensitive data found on-device (grep fallback): {remote_path}",
                    "High",
                    f"Could not pull files locally, but on-device grep found {len(lines)} match(es):\n\n{output[:5000]}",
                )
            console.print(f"    [red]On-device grep found {len(lines)} sensitive match(es)[/red]")
        else:
            console.print("    [green]On-device grep: no sensitive data[/green]")
    except (ADBError, OSError, subprocess.SubprocessError) as e:
        console.print(f"    [yellow]On-device grep failed: {e}[/yellow]")


def _analyze_databases(config: Config, base_dir: str) -> None:
    console.print("\n[cyan]Analyzing SQLite databases...[/cyan]")
    db_dir = Path(base_dir) / "databases"
    if not db_dir.exists():
        console.print("  [yellow]No databases directory found.[/yellow]")
        return

    # 4.3 Detect SQLite databases by magic header
    db_files = []
    for f in db_dir.rglob("*"):
        if f.is_file():
            try:
                with open(f, "rb") as fd:
                    if fd.read(16) == b"SQLite format 3\x00":
                        db_files.append(f)
            except OSError:
                pass

    if not db_files:
        console.print("  [yellow]No database files found.[/yellow]")
        return

    for db_file in db_files:
        console.print(f"  [cyan]Analyzing:[/cyan] {db_file.name}")
        try:
            # List tables
            tables_result = subprocess.run(
                ["sqlite3", str(db_file), ".tables"],
                capture_output=True, text=True, timeout=10,
            )
            tables = tables_result.stdout.strip()
            config.log_command(PHASE, f"sqlite3 {db_file.name} '.tables'", tables)

            if not tables:
                continue

            # Dump schema
            schema_result = subprocess.run(
                ["sqlite3", str(db_file), ".schema"],
                capture_output=True, text=True, timeout=10,
            )
            config.log_command(PHASE, f"sqlite3 {db_file.name} '.schema'", schema_result.stdout)

            # Full dump and grep
            dump_result = subprocess.run(
                ["sqlite3", str(db_file), ".dump"],
                capture_output=True, text=True, timeout=30,
            )

            # Save full dump
            dump_path = config.output_dir / f"db_dump_{db_file.name}.sql"
            dump_path.parent.mkdir(parents=True, exist_ok=True)
            dump_path.write_text(dump_result.stdout, encoding="utf-8")

            # Presidio or regex scan on DB dump
            pii = presidio_scan_text(dump_result.stdout, config, source_label=f"db:{db_file.name}")
            if pii:
                presidio_findings_to_report(
                    pii, PHASE, config,
                    fallback_title=f"Sensitive data in database: {db_file.name}",
                    fallback_detail=f"Tables: {tables}\n\nSensitive matches:\n{grep_sensitive_lines(dump_result.stdout)[:3000]}",
                )
                console.print(f"    [red]Sensitive data found in {db_file.name}[/red]")
        except FileNotFoundError:
            console.print("  [yellow]sqlite3 not available — skipping DB analysis.[/yellow]")
            break
        except (subprocess.SubprocessError, OSError) as e:
            console.print(f"  [yellow]Error analyzing {db_file.name}: {e}[/yellow]")


def _analyze_shared_prefs(config: Config, prefs_dir: str) -> None:
    console.print("\n[cyan]Analyzing shared preferences...[/cyan]")
    prefs_path = Path(prefs_dir)
    if not prefs_path.exists():
        console.print("  [yellow]No shared_prefs directory found.[/yellow]")
        return

    xml_files = list(prefs_path.glob("*.xml"))
    if not xml_files:
        console.print("  [yellow]No XML preference files found.[/yellow]")
        return

    for xml_file in xml_files:
        console.print(f"  [cyan]Checking:[/cyan] {xml_file.name}")
        try:
            content = xml_file.read_text(encoding="utf-8", errors="replace")
            config.log_command(PHASE, f"cat shared_prefs/{xml_file.name}", content[:2000])

            pii = presidio_scan_text(content, config, source_label=f"shared_prefs:{xml_file.name}")
            if pii:
                presidio_findings_to_report(
                    pii, PHASE, config,
                    fallback_title=f"Sensitive data in shared_prefs: {xml_file.name}",
                    fallback_detail=f"File: {xml_file.name}\n\nMatches:\n{grep_sensitive_lines(content)[:3000]}",
                )
                console.print(f"    [red]Sensitive data found in {xml_file.name}[/red]")
        except (OSError, ValueError) as e:
            console.print(f"  [yellow]Error reading {xml_file.name}: {e}[/yellow]")


def _analyze_nosql(config: Config, adb: ADB, pkg: str, base_dir: str) -> None:
    console.print("\n[cyan]Checking for NoSQL / Realm databases...[/cyan]")

    extensions = ["*.realm", "*.json", "*.bson", "*.cblite2"]
    found_files: list[Path] = []
    base = Path(base_dir)
    for ext in extensions:
        for match in base.rglob(ext):
            found_files.append(match)
            if len(found_files) >= LIMITS.max_scan_files:
                console.print(
                    f"  [yellow]Reached scan cap ({LIMITS.max_scan_files} files) — "
                    f"stopping NoSQL enumeration.[/yellow]"
                )
                break
        if len(found_files) >= LIMITS.max_scan_files:
            break

    if not found_files:
        if not is_valid_package_name(pkg):
            console.print(f"  [yellow]Skipping on-device NoSQL search — invalid package: {pkg}[/yellow]")
            return
        # Try finding on device
        result = adb.shell(f"find /data/data/{pkg} -name '*.realm' -o -name '*.json' -o -name '*.bson' 2>/dev/null", root=True)
        config.log_command(PHASE, f"find /data/data/{pkg} -name '*.realm' ...", result.stdout)
        if result.stdout.strip():
            console.print(f"  [yellow]NoSQL files found on device:[/yellow]\n{result.stdout}")
        else:
            console.print("  [green]No NoSQL database files found.[/green]")
        return

    for f in found_files:
        console.print(f"  [cyan]Found:[/cyan] {f}")
        try:
            result = subprocess.run(
                ["strings", str(f)],
                capture_output=True, text=True, timeout=30,
            )
            pii = presidio_scan_text(result.stdout, config, source_label=f"nosql:{f.name}")
            if pii:
                presidio_findings_to_report(
                    pii, PHASE, config,
                    fallback_title=f"Sensitive data in NoSQL file: {f.name}",
                    fallback_detail=f"File: {f}\n\nSensitive strings:\n{grep_sensitive_lines(result.stdout)[:3000]}",
                )
        except FileNotFoundError:
            pass


def _check_file_permissions(config: Config, adb: ADB, pkg: str) -> None:
    console.print("\n[cyan]Checking file permissions...[/cyan]")

    if not is_valid_package_name(pkg):
        console.print(f"  [yellow]Skipping permission check — invalid package: {pkg}[/yellow]")
        return

    # World-readable files
    result = adb.shell(
        f"find /data/data/{pkg} -type f -perm -o=r 2>/dev/null", root=True
    )
    if result.stdout.strip():
        config.add_finding(
            PHASE,
            "World-readable files in app data directory",
            "Medium",
            f"The following files are world-readable:\n{result.stdout[:3000]}",
        )
        config.log_command(PHASE, f"find /data/data/{pkg} -type f -perm -o=r", result.stdout)

    # World-writable files
    result = adb.shell(
        f"find /data/data/{pkg} -type f -perm -o=w 2>/dev/null", root=True
    )
    if result.stdout.strip():
        config.add_finding(
            PHASE,
            "World-writable files in app data directory",
            "High",
            f"The following files are world-writable:\n{result.stdout[:3000]}",
        )
        config.log_command(PHASE, f"find /data/data/{pkg} -type f -perm -o=w", result.stdout)


def _analyze_keystores(config: Config, base_dir: str) -> None:
    console.print("\n[cyan]Checking for Keystore files...[/cyan]")
    base = Path(base_dir)
    keystores = []
    for ext in ["*.jks", "*.bks", "*.keystore"]:
        keystores.extend(base.rglob(ext))

    if keystores:
        paths = "\n".join(str(k) for k in keystores)
        config.add_finding(
            PHASE,
            "Android Keystore files found in app data",
            "High",
            f"The following keystore files were found in local storage:\n{paths}",
        )
        console.print(f"  [red]Found {len(keystores)} Keystore file(s)[/red]")
    else:
        console.print("  [green]No Keystore files found.[/green]")


# _grep_string removed — use utils.helpers.grep_sensitive_lines instead
