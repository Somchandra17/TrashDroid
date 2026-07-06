"""
Global configuration and shared state for the Android DAST framework.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

SENSITIVE_PATTERNS = (
    r"password|passwd|pwd"
    r"|token|auth_token|access_token|refresh_token|bearer"
    r"|api[_\-]?key|apikey|api[_\-]?secret"
    r"|secret|client_secret"
    r"|private[_\-]?key|priv[_\-]?key"
    r"|credential|cred"
    r"|email|e-mail"
    r"|ssn|social.security"
    r"|credit.card|card.number|cvv|pan"
    r"|otp|pin"
    r"|jdbc:|connection.string"
    r"|BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY"
)

MANIFEST_SECURITY_FLAGS = {
    'android:debuggable="true"': {
        "risk": "High",
        "desc": "App is debuggable — allows attaching debuggers and extracting runtime data.",
    },
    'android:allowBackup="true"': {
        "risk": "Medium",
        "desc": "Full ADB backup extraction is allowed — may leak sensitive app data.",
    },
    'android:usesCleartextTraffic="true"': {
        "risk": "Medium",
        "desc": "App allows HTTP (cleartext) traffic — susceptible to MitM attacks.",
    },
    'android:fullBackupContent="true"': {
        "risk": "Medium",
        "desc": "Explicitly allows customized full backup extraction.",
    },
    'android:backupAgent': {
        "risk": "Low",
        "desc": "Custom backup agent heavily utilized, verify logic for sensitive data.",
    },
    'android:directBootAware="true"': {
        "risk": "Info",
        "desc": "Component can run before device is unlocked; credentials may be exposed.",
    },
    'android:networkSecurityConfig': {
        "risk": "Info",
        "desc": "Custom network security config is present; review for weak TrustManagers or cleartext.",
    },
}

REQUIRED_TOOLS = ["adb", "drozer", "scrcpy", "apktool"]

FALSE_POSITIVE_PREFIXES = (
    "androidx.",
    "com.google.android.gms.",
    "com.google.android.datatransport.",
    "com.google.firebase.",
    "com.google.android.play.",
    "com.google.mlkit.",
)

def _load_banner() -> str:
    banner_path = Path(__file__).resolve().parent.parent / "banner.txt"
    try:
        return banner_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "  TrashDroid — Automated Android DAST Framework\n  Author: 0xs0m\n"


BANNER = _load_banner()


@dataclass
class Timing:
    adb_run_timeout: int = 60
    logcat_auto_timeout: int = 45
    screenshot_settle_delay: float = 4.5
    db_query_timeout: int = 120
    polling_retries: int = 3
    file_pull_timeout: int = 300
    # Max wall-clock seconds a single phase may run in --auto mode before the
    # orchestrator abandons it and moves on (0 disables the watchdog).
    phase_budget_sec: float = 600.0


@dataclass
class Limits:
    max_dump_mb: int = 32
    binary_file_scan_limit: int = 50 * 1024 * 1024
    max_binary_files: int = 500
    max_logcat_lines: int = 50000
    # Cap directory enumeration so a huge target tree cannot hang/OOM a scan.
    max_scan_files: int = 5000
    # Cap lines kept from a single grep result before truncating.
    max_grep_lines: int = 2000
    # Wall-clock budget (seconds) for source enumeration scans (e.g. smali).
    source_scan_budget_sec: float = 60.0
    # Largest single file (bytes) read whole into memory (e.g. backup.ab, memory dumps).
    max_in_memory_read: int = 512 * 1024 * 1024


TIMING = Timing()
LIMITS = Limits()


# ── On-device agent / tooling locations (shared across phases) ──
# drozer agent package + launchable activity (WithSecure agent app).
# NOTE: the WithSecure agent keeps a capital-W Java namespace (com.WithSecure.dz)
# even though the package id is lowercase (com.withsecure.dz), so the fully
# qualified activity is required — a relative "/.activities.MainActivity" would
# resolve to the wrong (nonexistent) class and `am start` would fail.
DROZER_AGENT_PKG = "com.withsecure.dz"
DROZER_AGENT_ACTIVITY = "com.withsecure.dz/com.WithSecure.dz.activities.MainActivity"
# Broadcast action the agent's StartServiceReceiver listens for to start its
# embedded server without the UI toggle (only takes effect once the server is
# enabled — see localServerEnabled in the agent prefs).
DROZER_AGENT_START_ACTION = "com.withsecure.dz.PWN"
# Agent SharedPreferences file + the boolean that persists "embedded server on".
DROZER_AGENT_PREFS = "/data/data/com.withsecure.dz/shared_prefs/com.withsecure.dz_preferences.xml"
DROZER_AGENT_SERVER_PREF = "localServerEnabled"
# TCP port drozer forwards between host and on-device agent.
DROZER_PORT = 31415
# Default on-device frida-server path.
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"


@dataclass
class Config:
    """Mutable state shared across all phases."""

    device_id: str = ""
    package_name: str = ""
    apk_path: Optional[str] = None
    apk_hash: Optional[str] = None
    is_preinstalled: bool = False
    logged_in: bool = False
    output_dir: Path = Path(".")
    screenshot_dir: Path = Path(".")
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S"))

    auto_mode: bool = False
    report_mode: str = "client"  # client | internal

    screenshot_delay: float = TIMING.screenshot_settle_delay

    # Presidio PII detection engine (None when not enabled)
    presidio_engine: object = None


    # accumulated findings per phase (phase_name -> list of finding dicts)
    findings: dict = field(default_factory=dict)
    # Commands executed (list of {cmd, stdout, stderr, phase})
    commands_log: list = field(default_factory=list)
    # Screenshot paths (list of {path, caption, phase})
    screenshots: list = field(default_factory=list)

    def init_output(self) -> None:
        self.output_dir = Path("output") / self.package_name
        self.screenshot_dir = self.output_dir / "screenshots"
        for d in [
            self.output_dir,
            self.screenshot_dir,
            self.output_dir / "filesystem",
            self.output_dir / "filesystem" / "shared_prefs",
            self.output_dir / "filesystem" / "databases",
            self.output_dir / "filesystem" / "files",
            self.output_dir / "filesystem" / "cache",
            self.output_dir / "filesystem" / "app_webview",
            self.output_dir / "filesystem" / "external",
            self.output_dir / "backup_unpacked",
            self.output_dir / "apktool_out",
        ]:
            d.mkdir(parents=True, exist_ok=True)

    _VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}

    def add_finding(self, phase: str, title: str, severity: str, detail: str, status: str = "Open") -> None:
        severity = severity.strip().title()
        if severity not in self._VALID_SEVERITIES:
            import warnings
            warnings.warn(
                f"Invalid finding severity '{severity}' for '{title}' — defaulting to 'Info'",
                stacklevel=2,
            )
            severity = "Info"
        self.findings.setdefault(phase, []).append(
            {"title": title, "severity": severity, "detail": detail, "status": status}
        )

    def log_command(self, phase: str, cmd: str, stdout: str, stderr: str = "", rc: int = 0) -> None:
        self.commands_log.append(
            {"phase": phase, "cmd": cmd, "stdout": stdout, "stderr": stderr, "rc": rc}
        )

    def add_screenshot(self, path: str, caption: str, phase: str) -> None:
        self.screenshots.append({"path": path, "caption": caption, "phase": phase})
