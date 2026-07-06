"""
Shared subprocess plumbing.

Historically this held only the logcat capture helpers. It now also exposes a
small generic host-tool runner (`run_tool` / `have_tool`) used by the
fallback ladders in `core/instrumentation.py` and `core/adb.launch_app`, so
those sites get uniform timeout / missing-binary handling instead of
re-implementing `try/except subprocess.run` each time.

Both the foreground Phase V monitor (`phases/logcat.py`) and the background
collector (`utils/logcat_collector.py`) start an `adb logcat` process and tear
it down with the same terminate→wait→kill escalation. That plumbing lives here
so the two capture loops (which legitimately differ) don't duplicate it.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class ToolResult:
    """Outcome of a host-tool invocation with the failure modes callers care about."""
    rc: int
    stdout: str
    stderr: str
    ok: bool          # process ran and returned 0
    found: bool       # the binary existed (False → not installed)
    timed_out: bool   # killed after exceeding the timeout

    @property
    def combined(self) -> str:
        return f"{self.stdout}\n{self.stderr}".strip()


def have_tool(name: str) -> bool:
    """True if `name` resolves on PATH (wraps shutil.which)."""
    return shutil.which(name) is not None


def run_tool(cmd: list[str], timeout: int = 60, input_text: str | None = None) -> ToolResult:
    """Run a host tool, capturing output and normalizing the three failure modes.

    Never raises for the common cases: a missing binary yields found=False (rc 127)
    and a timeout yields timed_out=True (rc 124), so callers can drive fallback
    ladders on the result instead of wrapping each call in try/except.
    """
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, input=input_text
        )
        return ToolResult(r.returncode, r.stdout, r.stderr, r.returncode == 0, True, False)
    except FileNotFoundError:
        return ToolResult(127, "", f"{cmd[0]}: not found", False, False, False)
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return ToolResult(124, out, err or f"timed out after {timeout}s", False, True, True)


def start_logcat_process(device_id: str = "") -> subprocess.Popen:
    """Start `adb [-s device_id] logcat -v threadtime` with piped stdout/stderr."""
    cmd = ["adb"]
    if device_id:
        cmd += ["-s", device_id]
    cmd += ["logcat", "-v", "threadtime"]
    # errors="replace": logcat carries arbitrary app bytes; a non-UTF-8 byte must not
    # raise UnicodeDecodeError in the reader and silently kill the capture thread.
    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace"
    )


def terminate_process(proc: subprocess.Popen | None, force_kill: bool = True) -> None:
    """Best-effort terminate of a capture process: terminate → wait → (optional) kill.

    Safe to call repeatedly and on an already-exited process.
    """
    if proc is None:
        return
    if proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if force_kill:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (OSError, subprocess.SubprocessError):
                    pass  # Process already gone or unkillable.
        except OSError:
            pass  # Process exited between poll() and terminate().
