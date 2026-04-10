"""
Phase VI — Memory Analysis.

Dumps application memory and searches for sensitive data
(passwords, tokens, keys, PII) in the memory contents.

Memory dump strategy (fallback chain):
  1. Frida  — fastest, works on non-debuggable release APKs (needs frida-server)
  2. am dumpheap — only works if android:debuggable=true
  3. dd /proc/mem — direct read via root (slow, limited to small regions)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from core.config import Config, SENSITIVE_PATTERNS, LIMITS
from core.adb import ADB
from utils.helpers import presidio_scan_text, presidio_findings_to_report

console = Console()
PHASE = "Phase VI — Memory Analysis"

FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
MAX_DUMP_MB = LIMITS.max_dump_mb


def run_memory_analysis(config: Config, adb: ADB) -> None:
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name

    if not config.auto_mode:
        console.print(Panel(
            "Is the app currently logged in?\nIf not, please log in now. Press Enter to continue.",
            style="bold yellow",
        ))
        input()
    else:
        console.print("[yellow]Auto-mode: proceeding with memory analysis...[/yellow]")

    pid = adb.get_pid(pkg)
    if not pid:
        console.print(f"[yellow]App '{pkg}' is not running. Launching...[/yellow]")
        adb.launch_app(pkg)
        time.sleep(3)
        pid = adb.get_pid(pkg)

    if not pid:
        console.print("[red]Could not get PID for the app. Skipping memory analysis.[/red]")
        config.add_finding(PHASE, "Memory analysis skipped — PID not found", "Info", "App was not running.")
        return

    console.print(f"  [green]App PID: {pid}[/green]")

    _heap_dump(config, adb, pkg, pid)
    _proc_maps(config, adb, pid)
    _memory_strings(config, adb, pid)
    _open_fds(config, adb, pid)
    _network_connections(config, adb, pid)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


# ────────────────────────────────────────────────────────────────
#  Heap / memory dump  (Frida → am dumpheap → dd /proc/mem)
# ────────────────────────────────────────────────────────────────

def _heap_dump(config: Config, adb: ADB, pkg: str, pid: str) -> None:
    console.print("\n[cyan]Capturing process memory dump...[/cyan]")
    local_dump = str(config.output_dir / "memory_dump.bin")
    Path(local_dump).parent.mkdir(parents=True, exist_ok=True)

    dump_ok = False

    # ── Strategy 1: Frida ──
    dump_ok = _frida_dump(config, adb, pkg, pid, local_dump)

    # ── Strategy 2: am dumpheap (debuggable apps only) ──
    if not dump_ok:
        dump_ok = _am_dumpheap(config, adb, pkg, local_dump)

    # ── Strategy 3: dd /proc/mem (root, slow, last resort) ──
    if not dump_ok:
        dump_ok = _dd_proc_mem(config, adb, pid, local_dump)

    # ── Scan results ──
    if dump_ok and Path(local_dump).exists() and Path(local_dump).stat().st_size > 0:
        _scan_dump_for_sensitive(config, local_dump)
    else:
        console.print("  [yellow]All memory dump methods failed.[/yellow]")
        config.add_finding(
            PHASE,
            "Memory dump could not be captured",
            "Info",
            "Tried Frida, am dumpheap, and /proc/mem dd — all failed.\n"
            "Ensure frida + frida-server are set up, or the app is debuggable.\n"
            "Manual analysis with fridump / Objection may be needed.",
        )


# ── Frida-based dump ──────────────────────────────────────────

_FRIDA_AGENT_JS = """\
'use strict';
rpc.exports = {
    getRanges: function(prot) {
        var ranges = Process.enumerateRanges({protection: prot, coalesce: true});
        var result = [];
        for (var i = 0; i < ranges.length; i++) {
            result.push({base: ranges[i].base.toString(), size: ranges[i].size});
        }
        return result;
    },
    readChunk: function(baseStr, size) {
        try {
            return ptr(baseStr).readByteArray(size);
        } catch (e) {
            return null;
        }
    }
};
"""


def _frida_available() -> bool:
    try:
        import frida  # noqa: F401
        return True
    except ImportError:
        return False


def _ensure_frida_server(adb: ADB) -> bool:
    """Make sure frida-server is running on the device. Returns True if ready."""
    ps_out = adb.shell("ps -A", root=True).stdout
    if "frida-server" in ps_out:
        return True

    console.print("  [cyan]frida-server not running. Attempting to start...[/cyan]")
    exists = adb.shell(f"ls {FRIDA_SERVER_PATH}", root=True)
    if "No such file" in exists.stdout or exists.returncode != 0:
        console.print(f"  [yellow]frida-server binary not found at {FRIDA_SERVER_PATH}.[/yellow]")
        console.print("  [yellow]To install: download the matching frida-server from[/yellow]")
        console.print("  [yellow]  https://github.com/frida/frida/releases[/yellow]")
        console.print(f"  [yellow]  then: adb push frida-server {FRIDA_SERVER_PATH}[/yellow]")
        return False

    adb.shell(f"chmod 755 {FRIDA_SERVER_PATH}", root=True)
    adb.shell(f"{FRIDA_SERVER_PATH} -D &", root=True)
    time.sleep(2)

    ps_out = adb.shell("ps -A", root=True).stdout
    if "frida-server" in ps_out:
        console.print("  [green]frida-server started.[/green]")
        return True

    console.print("  [yellow]frida-server failed to start.[/yellow]")
    return False


def _frida_dump(config: Config, adb: ADB, pkg: str, pid: str, local_path: str) -> bool:
    if not _frida_available():
        console.print("  [dim]Frida not installed (pip install frida frida-tools). Skipping.[/dim]")
        return False

    if not _ensure_frida_server(adb):
        return False

    console.print("  [cyan]Dumping memory via Frida...[/cyan]")

    try:
        import frida

        # Version compatibility check
        pip_version = frida.__version__
        server_ver_out = adb.shell(f"{FRIDA_SERVER_PATH} --version", root=True, timeout=5)
        server_version = server_ver_out.stdout.strip()
        if server_version and pip_version and server_version.split(".")[0] != pip_version.split(".")[0]:
            console.print(
                f"  [yellow]⚠ Frida version mismatch: pip={pip_version}, server={server_version}[/yellow]"
            )
            console.print("  [yellow]  This may cause attachment failures. Consider matching versions.[/yellow]")

        device = frida.get_usb_device(timeout=5)
        session = device.attach(int(pid))
        script = session.create_script(_FRIDA_AGENT_JS)
        script.load()

        ranges = script.exports_sync.get_ranges("rw-")
        total_avail = sum(r["size"] for r in ranges)
        console.print(f"    [dim]{len(ranges)} rw- regions, {total_avail / 1024 / 1024:.0f} MB total[/dim]")

        cap = MAX_DUMP_MB * 1024 * 1024
        chunk_max = 4 * 1024 * 1024
        dumped = 0
        errors = 0

        with open(local_path, "wb") as f:
            for r in ranges:
                if dumped >= cap:
                    break
                base = r["base"]
                remaining = min(r["size"], cap - dumped)
                offset = 0
                while offset < remaining:
                    read_sz = min(chunk_max, remaining - offset)
                    base_int = int(base, 16) if isinstance(base, str) else base
                    try:
                        data = script.exports_sync.read_chunk(
                            hex(base_int + offset), read_sz
                        )
                        if data:
                            f.write(data)
                            dumped += len(data)
                        else:
                            errors += 1
                    except Exception:
                        errors += 1
                    offset += read_sz

        session.detach()

        size_mb = dumped / 1024 / 1024
        console.print(f"  [green]Frida dump: {size_mb:.1f} MB captured ({errors} unreadable regions skipped).[/green]")
        config.log_command(
            PHASE,
            f"frida memory dump (rw- regions, {len(ranges)} total)",
            f"Dumped {size_mb:.1f} MB to {local_path}",
        )
        return dumped > 0

    except Exception as e:
        console.print(f"  [yellow]Frida dump failed: {e}[/yellow]")
        config.log_command(PHASE, "frida memory dump", "", str(e))
        return False


# ── am dumpheap (debuggable only) ─────────────────────────────

def _am_dumpheap(config: Config, adb: ADB, pkg: str, local_path: str) -> bool:
    console.print("  [cyan]Trying am dumpheap (requires debuggable app)...[/cyan]")
    remote = "/data/local/tmp/dast_heap.hprof"

    result = adb.shell(f"am dumpheap {pkg} {remote}")
    combined = result.stdout + result.stderr
    config.log_command(PHASE, f"am dumpheap {pkg} {remote}", result.stdout, result.stderr)

    if "SecurityException" in combined or "not debuggable" in combined:
        console.print("  [yellow]am dumpheap: app is not debuggable — skipped.[/yellow]")
        return False

    time.sleep(5)

    try:
        adb.shell(f"chmod 644 {remote}", root=True)
        adb.pull(remote, local_path)
        if Path(local_path).exists() and Path(local_path).stat().st_size > 0:
            console.print(f"  [green]am dumpheap: {Path(local_path).stat().st_size / 1024:.0f} KB captured.[/green]")
            return True
        console.print("  [yellow]am dumpheap: file is empty.[/yellow]")
        return False
    except Exception as e:
        console.print(f"  [yellow]am dumpheap pull failed: {e}[/yellow]")
        return False
    finally:
        adb.shell(f"rm -f {remote}", root=True)


# ── dd /proc/mem (root, last resort) ─────────────────────────

def _dd_proc_mem(config: Config, adb: ADB, pid: str, local_path: str) -> bool:
    console.print("  [cyan]Trying direct /proc/mem read via root...[/cyan]")

    if not adb.is_rooted():
        console.print("  [yellow]Device is not rooted — cannot read /proc/mem.[/yellow]")
        return False

    maps_result = adb.shell(f"cat /proc/{pid}/maps", root=True, timeout=15)
    if not maps_result.stdout.strip():
        console.print("  [yellow]Could not read /proc/maps.[/yellow]")
        return False

    # Target dalvik heap, anon rw-p, and [heap] regions
    regions: list[tuple[int, int]] = []
    for line in maps_result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        perms = parts[1]
        if not perms.startswith("rw"):
            continue

        is_target = (
            "[heap]" in line
            or "[anon:dalvik-main" in line
            or "[anon:dalvik-alloc" in line
            or "[anon:dalvik-large" in line
            or (perms == "rw-p" and "00000000 00:00 0" in line)
        )
        if not is_target:
            continue

        try:
            addr = parts[0].split("-")
            start = int(addr[0], 16)
            end = int(addr[1], 16)
            size = end - start
            # Skip regions > 64 MB (likely the full dalvik space, too big for dd)
            if 0 < size <= 64 * 1024 * 1024:
                regions.append((start, size))
        except (ValueError, IndexError):
            continue

    if not regions:
        console.print("  [yellow]No suitable memory regions found for dd.[/yellow]")
        return False

    cap = MAX_DUMP_MB * 1024 * 1024
    total = 0
    selected = []
    for start, size in regions:
        if total + size > cap:
            break
        selected.append((start, size))
        total += size

    console.print(f"  [dim]Reading {len(selected)} region(s), {total / 1024 / 1024:.1f} MB...[/dim]")

    remote_dump = "/data/local/tmp/dast_memdump.bin"
    try:
        dd_cmds = []
        for start, size in selected:
            page_skip = start // 4096
            page_count = size // 4096
            dd_cmds.append(
                f"dd if=/proc/{pid}/mem bs=4096 skip={page_skip} count={page_count} 2>/dev/null"
            )

        combined_cmd = f"({' ; '.join(dd_cmds)}) > {remote_dump}"
        adb.shell(combined_cmd, root=True, timeout=120)
        adb.shell(f"chmod 644 {remote_dump}", root=True)
        adb.pull(remote_dump, local_path)

        if Path(local_path).exists() and Path(local_path).stat().st_size > 0:
            sz = Path(local_path).stat().st_size
            console.print(f"  [green]dd /proc/mem: {sz / 1024:.0f} KB captured.[/green]")
            config.log_command(PHASE, f"dd /proc/{pid}/mem ({len(selected)} regions)", f"{sz} bytes")
            return True
        console.print("  [yellow]dd dump came back empty.[/yellow]")
        return False
    except Exception as e:
        console.print(f"  [yellow]dd /proc/mem failed: {e}[/yellow]")
        return False
    finally:
        adb.shell(f"rm -f {remote_dump}", root=True)


# ── Sensitive data scan ───────────────────────────────────────

def _scan_dump_for_sensitive(config: Config, local_path: str) -> None:
    console.print("  [cyan]Scanning memory dump for sensitive data...[/cyan]")
    try:
        # ASCII strings
        strings_result = subprocess.run(
            ["strings", local_path],
            capture_output=True, text=True, timeout=120,
        )
        # UTF-16LE strings (Java strings are internally UTF-16)
        strings_utf16 = subprocess.run(
            ["strings", "-el", local_path],
            capture_output=True, text=True, timeout=120,
        )
        combined_output = strings_result.stdout + "\n" + strings_utf16.stdout

        # Use Presidio for entity-level detection or fall back to regex
        pii = presidio_scan_text(combined_output, config, source_label="memory_dump")
        if pii and pii[0].get("entity_type") != "SENSITIVE_PATTERN":
            presidio_findings_to_report(
                pii, PHASE, config,
                fallback_title="Sensitive data in process memory",
            )
            console.print(f"  [red]Found {len(pii)} PII entity(ies) in memory dump![/red]")
        elif pii:
            # Regex fallback
            sensitive = [
                line for line in combined_output.splitlines()
                if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE)
            ]
            if sensitive:
                config.add_finding(
                    PHASE,
                    f"Sensitive data in process memory ({len(sensitive)} matches)",
                    "High",
                    "Sensitive strings found in application memory:\n\n" + "\n".join(sensitive[:200]),
                )
                console.print(f"  [red]Found {len(sensitive)} sensitive string(s) in memory![/red]")
        else:
            console.print("  [green]No obvious sensitive strings in memory dump.[/green]")
    except subprocess.TimeoutExpired:
        console.print("  [yellow]String extraction timed out on large dump.[/yellow]")
    except FileNotFoundError:
        console.print("  [yellow]'strings' tool not available — install binutils.[/yellow]")


# ────────────────────────────────────────────────────────────────
#  Other memory checks
# ────────────────────────────────────────────────────────────────

def _proc_maps(config: Config, adb: ADB, pid: str) -> None:
    console.print("[cyan]Reading process memory maps...[/cyan]")
    result = adb.shell(f"cat /proc/{pid}/maps", root=True)
    config.log_command(PHASE, f"cat /proc/{pid}/maps", result.stdout[:5000])

    maps_path = config.output_dir / "proc_maps.txt"
    maps_path.parent.mkdir(parents=True, exist_ok=True)
    maps_path.write_text(result.stdout, encoding="utf-8")

    so_libs = [line for line in result.stdout.splitlines() if ".so" in line]
    if so_libs:
        config.log_command(PHASE, f"grep '.so' /proc/{pid}/maps", "\n".join(so_libs[:50]))


def _memory_strings(config: Config, adb: ADB, pid: str) -> None:
    console.print("[cyan]Extracting strings from process environment...[/cyan]")

    result = adb.shell(f"cat /proc/{pid}/smaps", root=True, timeout=30)
    smaps_path = config.output_dir / "proc_smaps.txt"
    smaps_path.parent.mkdir(parents=True, exist_ok=True)
    smaps_path.write_text(result.stdout, encoding="utf-8")
    config.log_command(PHASE, f"cat /proc/{pid}/smaps", f"({len(result.stdout)} bytes)")

    mem_result = adb.shell(
        f"strings /proc/{pid}/cmdline 2>/dev/null && "
        f"cat /proc/{pid}/environ 2>/dev/null | strings",
        root=True,
        timeout=15,
    )
    if mem_result.stdout.strip():
        pii = presidio_scan_text(mem_result.stdout, config, source_label="process_env")
        if pii:
            presidio_findings_to_report(
                pii, PHASE, config,
                fallback_title="Sensitive data in process environment/cmdline",
            )


def _open_fds(config: Config, adb: ADB, pid: str) -> None:
    console.print("[cyan]Checking open file descriptors...[/cyan]")
    result = adb.shell(f"ls -la /proc/{pid}/fd/ 2>/dev/null", root=True)
    config.log_command(PHASE, f"ls -la /proc/{pid}/fd/", result.stdout[:3000])

    fd_path = config.output_dir / "open_fds.txt"
    fd_path.parent.mkdir(parents=True, exist_ok=True)
    fd_path.write_text(result.stdout, encoding="utf-8")


def _network_connections(config: Config, adb: ADB, pid: str) -> None:
    console.print("[cyan]Checking network connections...[/cyan]")

    all_net = ""
    for proto in ["tcp", "tcp6", "udp", "udp6"]:
        result = adb.shell(f"cat /proc/{pid}/net/{proto} 2>/dev/null", root=True)
        all_net += f"\n=== {proto} ===\n{result.stdout}"
        if result.stdout.strip():
            config.log_command(PHASE, f"cat /proc/{pid}/net/{proto}", result.stdout[:2000])

    net_path = config.output_dir / "network_connections.txt"
    net_path.parent.mkdir(parents=True, exist_ok=True)
    net_path.write_text(all_net, encoding="utf-8")
