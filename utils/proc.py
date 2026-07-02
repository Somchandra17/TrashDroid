"""
Shared subprocess plumbing for logcat capture.

Both the foreground Phase V monitor (`phases/logcat.py`) and the background
collector (`utils/logcat_collector.py`) start an `adb logcat` process and tear
it down with the same terminate→wait→kill escalation. That plumbing lives here
so the two capture loops (which legitimately differ) don't duplicate it.
"""

from __future__ import annotations

import subprocess


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
