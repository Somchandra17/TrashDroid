"""
Drozer command wrapper: automates interaction with the drozer console.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from rich.console import Console

from core.config import DROZER_PORT

console = Console()

# Lines from drozer console noise that should be stripped from output
_NOISE_PATTERNS = re.compile(
    r"^(Selecting |Attempting to run|dz>|For Full Help|"
    r"\.\.\.|^\s*$|^Usage:|^See help)",
    re.IGNORECASE,
)

# Valid drozer module name shape, e.g. "scanner.provider.injection".
_DROZER_MODULE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.]*$")

# Drozer module-level error indicators in stdout/stderr
_MODULE_ERROR_PATTERNS = re.compile(
    r"(could not find|exception occurred|error:|"
    r"cannot find|no such|permission denied|"
    r"security exception|not found|failed to)",
    re.IGNORECASE,
)


def _strip_drozer_noise(output: str) -> str:
    """Remove drozer console connection noise from output."""
    clean_lines = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped and not _NOISE_PATTERNS.match(stripped):
            clean_lines.append(stripped)
    return "\n".join(clean_lines)


def _is_valid_component_name(name: str) -> bool:
    """Check if a string looks like a fully-qualified Java class name (e.g. com.example.MyClass)."""
    if not name or " " in name:
        return False
    parts = name.split(".")
    if len(parts) < 2:
        return False
    if not all(p and (p[0].isalpha() or p[0] == "_") for p in parts):
        return False
    return not _NOISE_PATTERNS.match(name)


def _parse_component_list(raw_output: str) -> list[str]:
    """Extract valid component names from drozer info output, filtering noise."""
    components = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("Package:") or line.startswith("Permission:"):
            continue
        if _NOISE_PATTERNS.match(line):
            continue
        candidate = line.split()[0] if " " in line else line
        if _is_valid_component_name(candidate):
            components.append(candidate)
    return components


@dataclass
class DrozerResult:
    module: str
    args: str
    stdout: str
    stderr: str
    success: bool
    raw_stdout: str = ""


class Drozer:
    """Non-interactive drozer wrapper using `drozer console connect -c`."""

    def __init__(self, device_id: str = ""):
        self.device_id = device_id
        self._connected = False

    def setup_port_forward(self) -> bool:
        cmd = ["adb"]
        if self.device_id:
            cmd += ["-s", self.device_id]
        cmd += ["forward", f"tcp:{DROZER_PORT}", f"tcp:{DROZER_PORT}"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0

    def verify_connection(self) -> bool:
        """Test that drozer console can connect to the agent on the device."""
        try:
            result = subprocess.run(
                ["drozer", "console", "connect", "-c", "list"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                self._connected = True
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        self._connected = False
        return False

    def run_module(self, module: str, args: str = "", timeout: int = 30) -> DrozerResult:
        # The command string is parsed by the drozer console; reject control
        # characters (newline/CR/NUL) and malformed module names so a crafted
        # value can't inject additional drozer console commands.
        if not _DROZER_MODULE_RE.match(module or "") or any(c in (module + args) for c in ("\n", "\r", "\x00")):
            return DrozerResult(
                module=module,
                args=args,
                stdout="",
                stderr="rejected: invalid module name or control characters in drozer command",
                success=False,
            )

        full_cmd = f"run {module}"
        if args:
            full_cmd += f" {args}"

        cmd = ["drozer", "console", "connect", "-c", full_cmd]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            raw_stdout = result.stdout.strip()
            raw_stderr = result.stderr.strip()
            clean_stdout = _strip_drozer_noise(raw_stdout)

            # Determine real success: exit code 0 AND no module-level errors in output
            module_ok = result.returncode == 0
            has_error = bool(_MODULE_ERROR_PATTERNS.search(raw_stdout + " " + raw_stderr))
            real_success = module_ok and not has_error

            return DrozerResult(
                module=module,
                args=args,
                stdout=clean_stdout,
                stderr=raw_stderr,
                success=real_success,
                raw_stdout=raw_stdout,
            )
        except subprocess.TimeoutExpired:
            return DrozerResult(
                module=module,
                args=args,
                stdout="",
                stderr=f"Timed out after {timeout}s",
                success=False,
            )
        except FileNotFoundError:
            return DrozerResult(
                module=module,
                args=args,
                stdout="",
                stderr="drozer not found in PATH",
                success=False,
            )

    # ── Component enumeration ──

    def get_package_info(self, package: str) -> DrozerResult:
        return self.run_module("app.package.info", f"-a {package}")

    def get_attack_surface(self, package: str) -> DrozerResult:
        return self.run_module("app.package.attacksurface", package)

    def get_activities(self, package: str) -> DrozerResult:
        return self.run_module("app.activity.info", f"-a {package}")

    def get_exported_activities(self, package: str) -> list[str]:
        result = self.get_activities(package)
        return _parse_component_list(result.raw_stdout)

    def start_activity(self, package: str, activity: str, extras: str = "") -> DrozerResult:
        args = f"--component {package} {activity}"
        if extras:
            args += f" {extras}"
        return self.run_module("app.activity.start", args)

    def get_services(self, package: str) -> DrozerResult:
        return self.run_module("app.service.info", f"-a {package}")

    def get_exported_services(self, package: str) -> list[str]:
        result = self.get_services(package)
        return _parse_component_list(result.raw_stdout)

    def start_service(self, package: str, service: str) -> DrozerResult:
        return self.run_module("app.service.start", f"--component {package} {service}")

    def send_to_service(self, package: str, service: str, msg: str = "1 2 3") -> DrozerResult:
        return self.run_module("app.service.send", f"{package} {service} --msg {msg}")

    def get_receivers(self, package: str) -> DrozerResult:
        return self.run_module("app.broadcast.info", f"-a {package}")

    def get_exported_receivers(self, package: str) -> list[str]:
        result = self.get_receivers(package)
        return _parse_component_list(result.raw_stdout)

    def send_broadcast(self, package: str, receiver: str, extras: str = "") -> DrozerResult:
        args = f"--component {package} {receiver}"
        if extras:
            args += f" {extras}"
        return self.run_module("app.broadcast.send", args)

    def get_providers(self, package: str) -> DrozerResult:
        return self.run_module("app.provider.info", f"-a {package}")

    def get_exported_providers(self, package: str) -> list[str]:
        result = self.get_providers(package)
        return _parse_component_list(result.raw_stdout)

    def query_provider(self, uri: str) -> DrozerResult:
        return self.run_module("app.provider.query", uri)

    def query_provider_injection(self, uri: str, projection: str) -> DrozerResult:
        return self.run_module("app.provider.query", f"{uri} --projection \"{projection}\"")

    def read_provider(self, uri: str) -> DrozerResult:
        return self.run_module("app.provider.read", uri)

    def scan_provider_injection(self, package: str) -> DrozerResult:
        return self.run_module("scanner.provider.injection", f"-a {package}", timeout=60)

    def scan_provider_traversal(self, package: str) -> DrozerResult:
        return self.run_module("scanner.provider.traversal", f"-a {package}", timeout=60)

    def get_browsable_activities(self, package: str) -> DrozerResult:
        return self.run_module("scanner.activity.browsable", f"-a {package}")

    def sniff_broadcasts(self) -> DrozerResult:
        return self.run_module("app.broadcast.sniff", "--action android.intent.action.VIEW", timeout=15)
