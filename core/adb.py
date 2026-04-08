"""
ADB command wrapper: handles all interactions with the Android device via adb.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console()


class ADBError(Exception):
    pass


class ADB:
    def __init__(self, device_id: str = ""):
        self.device_id = device_id

    def _base_cmd(self) -> list[str]:
        if self.device_id:
            return ["adb", "-s", self.device_id]
        return ["adb"]

    def run(self, args: list[str], timeout: int = 60, check: bool = False, retries: int = 2) -> subprocess.CompletedProcess:
        cmd = self._base_cmd() + args
        
        for attempt in range(1 + retries):
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if check and result.returncode != 0:
                    raise ADBError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
                return result
            except (subprocess.TimeoutExpired, ADBError) as e:
                if attempt < retries:
                    time.sleep(attempt + 1)
                    continue
                raise ADBError(f"Command failed after {retries + 1} attempts: {' '.join(cmd)}") from e

    def shell(self, cmd: str, root: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
        if root:
            return self.run(["shell", "su", "-c", cmd], timeout=timeout)
        return self.run(["shell", cmd], timeout=timeout)

    def shell_output(self, cmd: str, root: bool = False, timeout: int = 60) -> str:
        result = self.shell(cmd, root=root, timeout=timeout)
        return result.stdout.strip()

    # ── Device management ──

    @staticmethod
    def get_devices() -> list[str]:
        result = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().splitlines()[1:]
        devices = []
        for line in lines:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                devices.append(parts[0])
        return devices

    def is_rooted(self) -> bool:
        result = self.shell("su -c id", root=False)
        return "uid=0" in result.stdout

    def get_device_info(self) -> dict:
        model = self.shell_output("getprop ro.product.model")
        android_ver = self.shell_output("getprop ro.build.version.release")
        sdk = self.shell_output("getprop ro.build.version.sdk")
        return {"model": model, "android_version": android_ver, "sdk": sdk}

    # ── APK management ──

    def install_apk(self, apk_path: str) -> str:
        apk = Path(apk_path)
        if not apk.exists():
            raise ADBError(f"APK file not found: {apk_path}")
        result = self.run(["install", "-r", "-d", apk_path], timeout=120)
        if result.returncode != 0:
            raise ADBError(f"APK install failed: {result.stderr.strip() or result.stdout.strip()}")
        return result.stdout.strip()

    def get_package_name_from_apk(self, apk_path: str) -> Optional[str]:
        """Extract package name from an APK file using aapt or aapt2."""
        if not Path(apk_path).exists():
            return None
        for tool in ["aapt2", "aapt"]:
            try:
                result = subprocess.run(
                    [tool, "dump", "badging", apk_path],
                    capture_output=True, text=True, timeout=30,
                )
                for line in result.stdout.splitlines():
                    if line.startswith("package:"):
                        for token in line.split():
                            if token.startswith("name="):
                                return token.split("=")[1].strip("'\"")
            except FileNotFoundError:
                continue
        return None

    def is_package_installed(self, package: str) -> bool:
        result = self.shell(f"pm list packages {package}")
        return f"package:{package}" in result.stdout

    def get_pid(self, package: str) -> Optional[str]:
        result = self.shell(f"pidof {package}")
        pid = result.stdout.strip()
        return pid if pid else None

    def forward_port(self, local: int, remote: int) -> None:
        self.run(["forward", f"tcp:{local}", f"tcp:{remote}"])

    def pull(self, remote: str, local: str) -> str:
        result = self.run(["pull", remote, local], timeout=120)
        return result.stdout.strip()

    def pull_as_root(self, remote: str, local: str) -> str:
        """
        Pull files from a root-protected path by staging them in /data/local/tmp
        via su, then using regular adb pull, then cleaning up.
        Falls back to normal pull if su staging fails.
        """
        import uuid
        staging = f"/data/local/tmp/dast_stage_{uuid.uuid4().hex[:8]}"
        try:
            self.shell(f"mkdir -p {staging}", root=True)
            cp_result = self.shell(f"cp -a {remote} {staging}/", root=True)
            self.shell(f"chmod -R 777 {staging}", root=True)

            if cp_result.returncode != 0:
                console.print(f"  [yellow]Root copy failed, trying regular pull...[/yellow]")
                return self.pull(remote, local)

            result = self.run(["pull", f"{staging}/", local], timeout=120)
            return result.stdout.strip()
        finally:
            self.shell(f"rm -rf {staging}", root=True)

    def launch_app(self, package: str) -> str:
        result = self.shell(f"monkey -p {package} -c android.intent.category.LAUNCHER 1")
        return result.stdout.strip()

    def clear_app_data(self, package: str) -> str:
        result = self.shell(f"pm clear {package}")
        return result.stdout.strip()

    def force_stop(self, package: str) -> None:
        self.shell(f"am force-stop {package}")

    def start_activity(self, package: str, activity: str, extras: str = "") -> str:
        cmd = f"am start -n {package}/{activity}"
        if extras:
            cmd += f" {extras}"
        result = self.shell(cmd)
        return result.stdout.strip()

    def screencap(self, output_path: str) -> bool:
        """Capture a screenshot from the device and save it locally.
        Uses 'adb exec-out' for reliable binary transfer (no PTY corruption)."""
        cmd = self._base_cmd() + ["exec-out", "screencap", "-p"]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode == 0 and len(result.stdout) > 100:
                from pathlib import Path
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                Path(output_path).write_bytes(result.stdout)
                return True
        except (subprocess.TimeoutExpired, OSError):
            pass
        # Fallback to old method if exec-out fails
        remote_path = "/sdcard/dast_screenshot_tmp.png"
        self.shell(f"screencap -p {remote_path}")
        result = self.run(["pull", remote_path, output_path], timeout=30)
        self.shell(f"rm {remote_path}")
        return result.returncode == 0

    def backup(self, package: str, output_path: str) -> subprocess.CompletedProcess:
        return self.run(
            ["backup", "-apk", "-f", output_path, package],
            timeout=120,
        )

    def logcat_dump(self) -> str:
        result = self.run(["logcat", "-d"], timeout=30)
        return result.stdout

    def logcat_clear(self) -> None:
        self.run(["logcat", "-c"])

    def get_app_data_path(self, package: str) -> str:
        return f"/data/data/{package}"

    def list_dir(self, path: str, root: bool = True) -> list[str]:
        output = self.shell_output(f"ls -la {path}", root=root)
        return output.splitlines()
