"""
Phase VIII — Manifest Analysis (Runtime).

Decompiles the APK with apktool and inspects AndroidManifest.xml
for security-relevant flags and misconfigurations.
"""

from __future__ import annotations

import re
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.adb import ADB
from core.config import LIMITS, MANIFEST_SECURITY_FLAGS, Config
from utils.helpers import is_valid_package_name

console = Console()
PHASE = "Phase VIII — Manifest Analysis"


def run_manifest_analysis(config: Config, adb: ADB) -> None:
    """Phase VIII — decompile the APK and inspect the manifest/smali for misconfigurations.

    Records findings and command output on `config` and returns None. Failures are
    handled internally so the orchestrator can continue to the next phase.
    """
    console.print(f"\n[bold cyan]═══ {PHASE} ═══[/bold cyan]\n")

    pkg = config.package_name
    apktool_dir = config.output_dir / "apktool_out"
    apk_path = config.apk_path

    # If no local APK, pull from device
    if not apk_path or not Path(apk_path).exists():
        if not is_valid_package_name(pkg):
            console.print(f"[red]Invalid package name '{pkg}'. Skipping manifest analysis.[/red]")
            return
        console.print("[cyan]Pulling APK from device...[/cyan]")
        pm_result = adb.shell(f"pm path {pkg}")
        apk_device_path = pm_result.stdout.strip().replace("package:", "")
        if apk_device_path:
            local_apk = str(config.output_dir / "pulled_app.apk")
            adb.pull(apk_device_path, local_apk)
            apk_path = local_apk
            config.log_command(PHASE, f"adb pull {apk_device_path}", f"Pulled to {local_apk}")
        else:
            console.print("[red]Could not locate APK on device. Skipping manifest analysis.[/red]")
            return

    # ── Decompile with apktool ──
    console.print("[cyan]Decompiling APK with apktool...[/cyan]")
    try:
        result = subprocess.run(
            ["apktool", "d", apk_path, "-o", str(apktool_dir), "-f"],
            capture_output=True, text=True, timeout=120,
        )
        config.log_command(PHASE, f"apktool d {apk_path} -o {apktool_dir}", result.stdout, result.stderr)
    except FileNotFoundError:
        console.print("[red]apktool not found. Skipping manifest analysis.[/red]")
        return
    except subprocess.TimeoutExpired:
        console.print("[red]apktool timed out. Skipping manifest analysis.[/red]")
        return

    manifest_path = apktool_dir / "AndroidManifest.xml"
    if not manifest_path.exists():
        console.print("[red]AndroidManifest.xml not found in decompiled output.[/red]")
        return

    manifest_content = manifest_path.read_text(encoding="utf-8")
    config.log_command(PHASE, "cat AndroidManifest.xml", manifest_content[:5000])

    # ── Check security flags ──
    console.print("\n[cyan]Checking security flags...[/cyan]\n")

    table = Table(title="Manifest Security Flags")
    table.add_column("Flag", style="bold")
    table.add_column("Present?")
    table.add_column("Risk")
    table.add_column("Description")

    for flag, info in MANIFEST_SECURITY_FLAGS.items():
        present = flag in manifest_content
        status = "[red]YES[/red]" if present else "[green]NO[/green]"
        table.add_row(flag, status, info["risk"], info["desc"])

        if present:
            config.add_finding(
                PHASE,
                f"Insecure manifest flag: {flag}",
                info["risk"],
                info["desc"],
            )

    console.print(table)

    # ── Check exported components without permissions (XML parsing) ──
    _check_exported_without_permissions(config, manifest_path)

    # ── Check overly broad intent filters ──
    _check_intent_filters(config, manifest_content)

    # ── Check permissions declared ──
    _check_permissions(config, manifest_content)

    # ── Check network security config reference ──
    _check_network_security_config(config, manifest_content, apktool_dir)

    # ── Check meta-data for leaked keys/secrets ──
    _check_metadata(config, manifest_path)

    # ── Check SDK versions ──
    _check_sdk_versions(config, manifest_path)

    # ── Scan smali for secrets/weak crypto ──
    _scan_smali_sources(config, apktool_dir)

    console.print(f"\n[green]✓ {PHASE} complete.[/green]")


def _check_exported_without_permissions(config: Config, manifest_path: Path) -> None:
    console.print("[cyan]Checking for exported components without permissions...[/cyan]")

    ns = {"android": "http://schemas.android.com/apk/res/android"}
    exported_no_perm = []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        console.print("  [yellow]Manifest XML parse error — falling back to regex.[/yellow]")
        # Regex fallback for malformed XML
        manifest = manifest_path.read_text(encoding="utf-8")
        component_pattern = re.compile(
            r'<(activity|service|receiver|provider)[^>]*'
            r'android:exported="true"[^>]*'
            r'(?!.*android:permission)',
            re.DOTALL,
        )
        for match in component_pattern.finditer(manifest):
            block = match.group(0)
            name_match = re.search(r'android:name="([^"]+)"', block)
            comp_type = match.group(1)
            name = name_match.group(1) if name_match else "unknown"
            exported_no_perm.append(f"  {comp_type}: {name}")
        if exported_no_perm:
            detail = "\n".join(exported_no_perm)
            config.add_finding(
                PHASE,
                f"Exported components without permission ({len(exported_no_perm)})",
                "High",
                f"The following components are exported without explicit permission guards:\n{detail}",
            )
        return

    for comp_type in ("activity", "service", "receiver", "provider"):
        for elem in root.iter(comp_type):
            exported = elem.get(f"{{{ns['android']}}}exported")
            permission = elem.get(f"{{{ns['android']}}}permission")
            name = elem.get(f"{{{ns['android']}}}name", "unknown")

            # In modern Android, components with intent-filters are implicitly exported
            has_intent_filter = elem.find("intent-filter") is not None
            is_exported = exported == "true" or (exported is None and has_intent_filter)

            if is_exported and not permission:
                exported_no_perm.append(f"  {comp_type}: {name}")

    if exported_no_perm:
        detail = "\n".join(exported_no_perm)
        config.add_finding(
            PHASE,
            f"Exported components without permission ({len(exported_no_perm)})",
            "High",
            f"The following components are exported without explicit permission guards:\n{detail}",
        )
        console.print(f"  [red]Found {len(exported_no_perm)} exported component(s) without permissions[/red]")
    else:
        console.print("  [green]All exported components have permission guards.[/green]")


def _check_intent_filters(config: Config, manifest: str) -> None:
    console.print("[cyan]Checking for overly broad intent filters...[/cyan]")

    import xml.etree.ElementTree as ET
    broad_filters = []
    generic_actions = [
        "android.intent.action.VIEW",
        "android.intent.action.SEND",
        "android.intent.action.SENDTO",
    ]

    try:
        # Discard the XML declaration if it has an encoding ET doesn't like dynamically,
        # but fromstring can usually handle it. If issues arise, we have a regex fallback.
        root = ET.fromstring(manifest.encode('utf-8'))
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        for filter_elem in root.iter("intent-filter"):
            has_broad_action = False
            for action in filter_elem.iter("action"):
                if action.get(f"{{{ns['android']}}}name") in generic_actions:
                    has_broad_action = True
                    break

            if has_broad_action:
                for data in filter_elem.iter("data"):
                    scheme = data.get(f"{{{ns['android']}}}scheme")
                    mime = data.get(f"{{{ns['android']}}}mimeType")
                    if scheme in ("http", "https"):
                        broad_filters.append("VIEW/SEND with http/https scheme")
                    if scheme == "*" or mime == "*/*":
                        broad_filters.append("VIEW/SEND with wildcard scheme/mimeType")
    except ET.ParseError:
        # Manifest XML didn't parse — fall back to string matching.
        for action in generic_actions:
            if action in manifest:
                if 'android:scheme="http"' in manifest or 'android:scheme="https"' in manifest:
                    broad_filters.append(f"{action} with http/https scheme")
                if 'android:scheme="*"' in manifest or 'android:mimeType="*/*"' in manifest:
                    broad_filters.append(f"{action} with wildcard scheme/mimeType")

    broad_filters = list(set(broad_filters))

    if broad_filters:
        config.add_finding(
            PHASE,
            "Overly broad intent filters",
            "Medium",
            "The following broad intent filter configurations were found:\n"
            + "\n".join(f"  - {f}" for f in broad_filters),
        )


def _check_permissions(config: Config, manifest: str) -> None:
    console.print("[cyan]Listing declared permissions...[/cyan]")

    dangerous_perms = [
        "READ_CONTACTS", "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG",
        "CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_SMS", "SEND_SMS",
        "READ_PHONE_STATE", "CALL_PHONE", "READ_CALENDAR", "WRITE_CALENDAR",
        "ACCESS_BACKGROUND_LOCATION",
    ]

    found_dangerous = []
    for perm in dangerous_perms:
        if perm in manifest:
            found_dangerous.append(perm)

    if found_dangerous:
        config.add_finding(
            PHASE,
            f"Dangerous permissions declared ({len(found_dangerous)})",
            "Info",
            "The app declares the following dangerous permissions:\n"
            + "\n".join(f"  - android.permission.{p}" for p in found_dangerous),
        )
        config.log_command(PHASE, "Dangerous permissions check", "\n".join(found_dangerous))


def _check_network_security_config(config: Config, manifest: str, apktool_dir: Path) -> None:
    console.print("[cyan]Checking network security configuration...[/cyan]")

    nsc_match = re.search(r'android:networkSecurityConfig="@xml/([^"]+)"', manifest)
    if not nsc_match:
        config.add_finding(
            PHASE,
            "No custom network security config",
            "Info",
            "The app does not define a custom networkSecurityConfig. "
            "Default platform behavior applies.",
        )
        return

    nsc_name = nsc_match.group(1)
    nsc_path = apktool_dir / "res" / "xml" / f"{nsc_name}.xml"
    if not nsc_path.exists():
        return

    nsc_content = nsc_path.read_text(encoding="utf-8")
    config.log_command(PHASE, f"cat res/xml/{nsc_name}.xml", nsc_content[:3000])

    if "cleartextTrafficPermitted" in nsc_content and '"true"' in nsc_content:
        config.add_finding(
            PHASE,
            "Network security config permits cleartext traffic",
            "Medium",
            f"network_security_config.xml:\n{nsc_content[:2000]}",
        )

    if "<trust-anchors>" in nsc_content and "user" in nsc_content:
        config.add_finding(
            PHASE,
            "Network security config trusts user-installed certificates",
            "Medium",
            f"The app trusts user-installed CA certificates:\n{nsc_content[:2000]}",
        )


def _check_metadata(config: Config, manifest_path: Path) -> None:
    """Scan <meta-data> elements for leaked API keys, secrets, and URLs."""
    console.print("[cyan]Checking meta-data for leaked keys/secrets...[/cyan]")
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return

    key_patterns = re.compile(
        r"(api[_-]?key|secret|token|password|client[_-]?id|app[_-]?id|firebase|maps[_-]?key|gcm|aws)",
        re.IGNORECASE,
    )
    suspicious_entries = []

    for meta in root.iter("meta-data"):
        name = meta.get(f"{{{ns['android']}}}name", "")
        value = meta.get(f"{{{ns['android']}}}value", "")
        resource = meta.get(f"{{{ns['android']}}}resource", "")

        if key_patterns.search(name) or key_patterns.search(value):
            suspicious_entries.append(f"  {name} = {value or resource}")
        # Check for base64-encoded data or long hex strings
        if value and (len(value) > 32 and re.match(r'^[A-Za-z0-9+/=]+$', value)):
            suspicious_entries.append(f"  {name} = {value[:60]}... (looks like base64/key)")

    if suspicious_entries:
        config.add_finding(
            PHASE,
            f"Suspicious meta-data entries in manifest ({len(suspicious_entries)})",
            "Medium",
            "The following <meta-data> entries may contain API keys or secrets:\n"
            + "\n".join(suspicious_entries),
        )
        console.print(f"  [red]Found {len(suspicious_entries)} suspicious meta-data entry/entries[/red]")
    else:
        console.print("  [green]No suspicious meta-data entries found.[/green]")


def _check_sdk_versions(config: Config, manifest_path: Path) -> None:
    """Check minSdkVersion and targetSdkVersion for security implications."""
    console.print("[cyan]Checking SDK version targets...[/cyan]")
    ns = {"android": "http://schemas.android.com/apk/res/android"}

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
    except ET.ParseError:
        return

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is None:
        return

    min_sdk = uses_sdk.get(f"{{{ns['android']}}}minSdkVersion", "")
    target_sdk = uses_sdk.get(f"{{{ns['android']}}}targetSdkVersion", "")
    config.log_command(PHASE, "SDK versions", f"minSdk={min_sdk}, targetSdk={target_sdk}")

    issues = []
    if min_sdk and min_sdk.isdigit():
        v = int(min_sdk)
        if v < 21:
            issues.append(f"minSdkVersion={v} (< 21): allows running on Android < 5.0 which lacks modern security features")
        if v < 24:
            issues.append(f"minSdkVersion={v} (< 24): user CA certificates are trusted by default on these versions")

    if target_sdk and target_sdk.isdigit():
        v = int(target_sdk)
        if v < 28:
            issues.append(f"targetSdkVersion={v} (< 28): cleartext traffic is allowed by default")
        if v < 31:
            issues.append(f"targetSdkVersion={v} (< 31): components with intent-filters are implicitly exported")

    if issues:
        config.add_finding(
            PHASE,
            "SDK version security implications",
            "Medium",
            "\n".join(f"  - {i}" for i in issues),
        )
        for issue in issues:
            console.print(f"  [yellow]{issue}[/yellow]")


def _scan_smali_sources(config: Config, apktool_dir: Path) -> None:
    """Scan decompiled smali for hardcoded secrets, weak crypto, and debug logging."""
    console.print("[cyan]Scanning smali sources for secrets and weak crypto...[/cyan]")

    smali_dirs = list(apktool_dir.glob("smali*"))
    if not smali_dirs:
        console.print("  [yellow]No smali directories found.[/yellow]")
        return

    patterns = {
        "Weak crypto algorithm": re.compile(
            r'"(DES|DESede|RC4|RC2|MD5|SHA-1|AES/ECB|Blowfish)"', re.IGNORECASE
        ),
        "Hardcoded secret/key": re.compile(
            r'const-string[^"]*"((?:[A-Za-z0-9+/]{32,}={0,2}|[0-9a-fA-F]{32,}))"'
        ),
        "Insecure TrustManager": re.compile(
            r'checkServerTrusted|AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER'
        ),
        "Debug logging": re.compile(
            r'Landroid/util/Log;->([dvw])\(', re.IGNORECASE
        ),
        "Hardcoded URL": re.compile(
            r'const-string[^"]*"(https?://[^"]{10,})"'
        ),
    }

    findings_by_type: dict[str, list[str]] = {}
    file_count = 0
    # Bound the scan by wall-clock time rather than an arbitrary file count, so
    # large apps get as much coverage as the budget allows. A hard file cap stays
    # as a backstop against pathological trees.
    deadline = time.monotonic() + LIMITS.source_scan_budget_sec
    max_files = LIMITS.max_scan_files
    truncated = False

    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            if time.monotonic() > deadline or file_count >= max_files:
                truncated = True
                break
            file_count += 1
            try:
                content = smali_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            for finding_type, pattern in patterns.items():
                matches = pattern.findall(content)
                if matches:
                    relative_path = smali_file.relative_to(apktool_dir)
                    for m in matches[:5]:  # limit per file
                        match_str = m if isinstance(m, str) else m[0] if m else ""
                        findings_by_type.setdefault(finding_type, []).append(
                            f"  {relative_path}: {match_str[:80]}"
                        )
        if truncated:
            break

    if truncated:
        console.print(
            f"  [yellow]Smali scan truncated after {file_count} files "
            f"(time/scan-count budget reached) — coverage is partial.[/yellow]"
        )

    for finding_type, entries in findings_by_type.items():
        severity = "Medium" if "secret" in finding_type.lower() or "crypto" in finding_type.lower() else "Info"
        config.add_finding(
            PHASE,
            f"{finding_type} ({len(entries)} occurrences)",
            severity,
            "Found in decompiled smali sources:\n" + "\n".join(entries[:50]),
        )
        console.print(f"  [yellow]{finding_type}: {len(entries)} occurrence(s)[/yellow]")

    if not findings_by_type:
        console.print(f"  [green]No suspicious patterns in {file_count} smali files.[/green]")
