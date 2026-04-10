<div>

```
██████ ▄▄▄▄   ▄▄▄   ▄▄▄▄ ▄▄ ▄▄ ████▄  ▄▄▄▄   ▄▄▄  ▄▄ ▄▄▄▄
  ██   ██▄█▄ ██▀██ ███▄▄ ██▄██ ██  ██ ██▄█▄ ██▀██ ██ ██▀██
  ██   ██ ██ ██▀██ ▄▄██▀ ██ ██ ████▀  ██ ██ ▀███▀ ██ ████▀
```

**Automated Android DAST Framework**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Changelog](https://img.shields.io/badge/changelog-CHANGELOG.md-blue?style=flat-square)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black)](https://github.com/Somchandra17/TrashDroid)
---

</div>

## What is TrashDroid?

TrashDroid is a terminal-based automation framework for **Dynamic Application Security Testing (DAST)** of Android applications. It orchestrates `adb`, `drozer`, `scrcpy`, `apktool`, and `sqlite3` to run a full **9-phase security assessment** - capturing screenshots after every test and generating an AI-ready Markdown report at the end.

> **TL;DR** - Point it at an APK, let it rip, feed the report to GPT-4 / Claude for instant risk ratings and Jira tickets.

---

## Features

| Feature | Details |
|---|---|
| **Drozer Component Testing** | Exported activities, services, receivers, content providers, SQL injection & path traversal |
| **File System Analysis** | Shared prefs, SQLite, Realm/NoSQL, cache, WebView storage, regex scans for secrets |
| **Deep Dump Verification** | Per-table SQLite queries, XML parsing, binary string extraction |
| **Logcat Monitoring** | Real-time capture, scans for leaked credentials, cleartext HTTP, SQL, stack traces |
| **Memory Analysis** | Heap dump, `/proc/pid/maps`, string scanning, open FDs, network connections |
| **Backup Analysis** | ADB backup extraction + sensitive data grep |
| **Manifest Analysis** | `debuggable`, `allowBackup`, `usesCleartextTraffic`, exported components, dangerous permissions |
| **Post-Logout Testing** | Re-launches activities after logout, privilege escalation via intent extras |
| **Context-Aware PII Detection** | Advanced NLP matching via Microsoft Presidio and GLiNER ML models, replacing legacy regex checks |
| **Auto Screenshots** | Captured after every test via `adb screencap` with optional `scrcpy` live mirror |
| **AI-Ready Reports** | Markdown report with AI prompt header, findings, screenshots, and full command log |

---

## Quick Start

```bash
# Clone
git clone https://github.com/Somchandra17/TrashDroid.git
cd TrashDroid

# ── Docker (recommended) ──
docker build -t trashdroid .
adb start-server
docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid

# ── Or native install ──
pip install -r requirements.txt
python main.py
```

> See the [Docker Guide](#docker-guide) below for full details, or [Native Install](#native-install) if you prefer running without Docker. For recent changes, see the [Changelog](CHANGELOG.md).

---

## Docker Guide

### Why Docker?

Zero dependency headaches. The image ships with **adb, drozer, apktool, sqlite3, strings, and Java 17** — all pre-configured. You just need Docker and a USB cable.

### How does the container see my phone?

```
Phone ──USB──▶ Host (adb server :5037) ◀──network host── Docker container
```

Your phone stays plugged into the **host machine**. The host runs the ADB server on port `5037`. The container uses `--network host` to share the host's network stack, so it talks to the same ADB server — no USB passthrough needed.

### 1. Build the image

```bash
git clone https://github.com/Somchandra17/TrashDroid.git
cd TrashDroid
docker build -t trashdroid .
```

### 2. Start ADB on the host

Make sure the ADB server is running and your phone is connected:

```bash
adb start-server
adb devices          # verify your phone shows up
```

### 3. Run TrashDroid

**Interactive mode** (prompts for device, package, phases):

```bash
docker run -it --network host \
  -v "$(pwd)/output:/app/output" \
  trashdroid
```

> **Note:** When prompted for scrcpy live screen mirroring, say **"no"**. scrcpy requires a display server (X11/Wayland) which isn't available inside a container. This doesn't affect testing — all screenshots are still captured automatically via `adb screencap`. Alternatively, use `--auto` mode to skip the prompt entirely.

**Full auto mode** (no prompts, scrcpy skipped automatically):

```bash
docker run -it --network host \
  -v "$(pwd)/output:/app/output" \
  trashdroid --auto --device <SERIAL> --package <PACKAGE> --apk /app/target.apk
```

**Run specific phases only:**

```bash
docker run -it --network host \
  -v "$(pwd)/output:/app/output" \
  trashdroid --phases 1,8,9 --auto --device <SERIAL> --package <PACKAGE>
```

### 4. Mount an APK from the host

If the APK lives on your host machine, bind-mount it into the container:

```bash
docker run -it --network host \
  -v "$(pwd)/output:/app/output" \
  -v "/home/user/targets/app.apk:/app/target.apk" \
  trashdroid --apk /app/target.apk --package com.example.app
```

### 5. Get the results

Output is written to `/app/output` inside the container — which maps to `./output` on your host thanks to the `-v` flag. After the run completes:

```bash
ls output/<package_name>/
# DAST_Report_*.md  screenshots/  filesystem/  apktool_out/  ...
```

### Alternative: USB passthrough

If `--network host` doesn't work for you (e.g., Docker Desktop on macOS/Windows), pass USB devices directly:

```bash
docker run -it --privileged \
  -v /dev/bus/usb:/dev/bus/usb \
  -v "$(pwd)/output:/app/output" \
  trashdroid
```

This gives the container direct USB access so it runs its own ADB server. Requires `--privileged`.

### Docker cheat sheet

| What you want | Command |
|---|---|
| Build image | `docker build -t trashdroid .` |
| Interactive run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid` |
| Auto run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid --auto --device SERIAL --package PKG` |
| Mount APK | Add `-v "/path/to/app.apk:/app/target.apk"` and `--apk /app/target.apk` |
| Specific phases | Add `--phases 1,3,8` |
| USB passthrough | Replace `--network host` with `--privileged -v /dev/bus/usb:/dev/bus/usb` |
| Shell into container | `docker run -it --network host --entrypoint bash trashdroid` |
| Rebuild (no cache) | `docker build --no-cache -t trashdroid .` |

---

## Native Install

```bash
git clone https://github.com/Somchandra17/TrashDroid.git
cd TrashDroid

pip install -r requirements.txt

# Optional: PII detection backends
pip install -r requirements-presidio.txt   # regex + checksum validators
pip install -r requirements-ner.txt         # ML-based NER (~560 MB model)

python main.py

# Or full auto
python main.py --auto --device <SERIAL> --package <PKG> --apk /path/to/app.apk
```

---

## Prerequisites

> **Using Docker?** Skip this section — everything is bundled in the image.

### Host Machine

| Tool | Purpose | Required |
|---|---|---|
| `adb` | Device communication | Yes |
| `drozer` | Component exploitation | Yes |
| `scrcpy` | Live device mirroring | Yes |
| `apktool` | APK decompilation | Yes |
| `sqlite3` | Database analysis | Optional |
| `strings` | Binary string extraction | Optional |
| `aapt2` | Package name auto-detection | Optional |
| `presidio-analyzer` | Advanced PII string scanning | Optional |
| Python 3.10+ | Runtime | Yes |

### Target Device

- **Rooted** Android device (Magisk or similar)
- USB debugging enabled
- [Drozer Agent](https://github.com/WithSecureLabs/drozer-agent/releases) installed and embedded server turned ON

---

## Usage

### Interactive Mode

```bash
python main.py
```

Prompts for device, APK path, permissions, login state, and per-phase options.

### Non-Interactive / Auto Mode

```bash
python main.py \
  --auto \
  --device <DEVICE_SERIAL> \
  --package <PACKAGE_NAME> \
  --apk /path/to/app.apk
```

### Selective Phases

```bash
# Drozer + Manifest + Post-logout only
python main.py --phases 1,8,9

# File system + Logcat only
python main.py --phases 3,5 --package com.example.app --device SERIAL --auto
```

### CLI Reference

| Argument | Description |
|---|---|
| `--auto` | Non-interactive mode with default answers |
| `--device SERIAL` | Device serial from `adb devices` |
| `--package PKG` | Target package name |
| `--apk PATH` | Path to APK file (omit if pre-installed) |
| `--phases 1,3,5` | Comma-separated phase numbers to run |
| `--skip-preflight` | Skip tool availability checks |
| `--report-mode` | `client` (default) or `internal` (includes AI prompt) |
| `--presidio` | Enable Presidio PII detection (regex + checksum validators) |
| `--ner` | Enable GLiNER NER backend for ML-based PII detection |

---

## Test Phases

```
 Phase 1 ─── Drozer Component Testing
 Phase 3 ─── Local File System Analysis
 Phase 4 ─── Dump File Verification
 Phase 5 ─── Logcat Monitoring
 Phase 6 ─── Memory Analysis
 Phase 7 ─── ADB Backup Analysis
 Phase 8 ─── Manifest Analysis
 Phase 9 ─── Post-Logout Access Control
```

> Phase 2 (screenshots) is integrated into Phases 1 and 9 automatically.

---

## Output Structure

```
output/<package_name>/
├── DAST_Report_<pkg>_<timestamp>.md     # Final report
├── screenshots/                         # PNGs from every test
├── filesystem/
│   ├── shared_prefs/                    # XML preference files
│   ├── databases/                       # SQLite databases
│   ├── files/                           # Internal files
│   ├── cache/                           # Cache
│   ├── app_webview/                     # WebView storage
│   └── external/                        # External storage
├── logcat_dump.txt                      # Full logcat
├── logcat_app_filtered.txt              # App-specific logs
├── heap_dump.hprof                      # Java heap dump
├── proc_maps.txt                        # /proc/pid/maps
├── backup.ab                            # Raw ADB backup
├── backup_unpacked/                     # Extracted backup
├── apktool_out/                         # Decompiled APK
└── grep_results.txt                     # Sensitive data matches
```

---

## Report

The generated `.md` report includes:

1. **AI Prompt Header** - feed the report directly into GPT-4 / Claude for risk rating, executive summary, and Jira ticket generation
2. **Executive Summary** - package name, device info, date, severity breakdown
3. **Detailed Findings** - per-phase sections with severity, status, and full detail
4. **Screenshots** - inline Markdown image references
5. **Command Log** - collapsible section with every command and its output
6. **Risk Summary Table** - flat table of all findings

---

## Architecture

```
TrashDroid/
├── main.py                 # Entry point & phase orchestrator
├── CHANGELOG.md            # Version history & release notes
├── requirements.txt            # Base Python dependencies
├── requirements-presidio.txt   # Optional: Presidio PII detection
├── requirements-ner.txt        # Optional: GLiNER NER backend
├── core/
│   ├── config.py           # Global state, patterns, flags
│   ├── adb.py              # ADB command wrapper
│   ├── drozer.py           # Drozer wrapper (non-interactive)
│   ├── screenshot.py       # Screenshot capture + scrcpy
│   └── report.py           # Markdown report generator
├── phases/
│   ├── preflight.py        # Tool & device checks
│   ├── setup.py            # Device selection, APK install
│   ├── drozer_testing.py   # Phase 1 - Drozer tests
│   ├── filesystem.py       # Phase 3 - File system analysis
│   ├── dump_verify.py      # Phase 4 - Deep dump verification
│   ├── logcat.py           # Phase 5 - Logcat monitoring
│   ├── memory.py           # Phase 6 - Memory analysis
│   ├── backup.py           # Phase 7 - Backup analysis
│   ├── manifest.py         # Phase 8 - Manifest analysis
│   └── post_logout.py      # Phase 9 - Post-logout tests
└── output/                 # Generated per run (gitignored)
```

---

## Troubleshooting

<details>
<summary><b>No Android device detected via ADB</b></summary>

- Ensure USB debugging is enabled on the device
- Run `adb devices` and confirm the device shows as `device` (not `unauthorized`)
</details>

<details>
<summary><b>Drozer phases return empty results</b></summary>

- Open the Drozer Agent app and enable the embedded server
- Verify: `adb forward tcp:31415 tcp:31415 && drozer console connect -c "list"`
</details>

<details>
<summary><b>ADB backup times out</b></summary>

- Tap "Back up my data" on the device when prompted
- In `--auto` mode this may fail if unattended - logged as Info
</details>

<details>
<summary><b>apktool not found</b></summary>

- Install from [apktool.org](https://ibotpeaches.github.io/Apktool/install/)
- Verify with `apktool --version`
</details>

<details>
<summary><b>File system pull returns empty</b></summary>

- Device must be rooted - verify with `adb shell su -c id`
- Android 13+ per-app SELinux contexts may block even root pulls
</details>

<details>
<summary><b>Heap dump is empty (0 bytes)</b></summary>

- App must be running and in the foreground
- Non-debuggable apps may produce empty dumps on some devices
</details>

<details>
<summary><b>Docker: "no devices/emulators found"</b></summary>

- Make sure the ADB server is running on the **host** before starting the container: `adb start-server`
- Confirm the phone shows up on the host: `adb devices`
- Ensure you're using `--network host` when running the container
- If on macOS/Windows Docker Desktop, `--network host` won't work — use USB passthrough instead: `--privileged -v /dev/bus/usb:/dev/bus/usb`
</details>

<details>
<summary><b>Docker: output folder is empty or permission denied</b></summary>

- Make sure you mount the output volume: `-v "$(pwd)/output:/app/output"`
- If permission denied, the host directory may be owned by a different user — run `sudo chown -R $USER:$USER output/`
</details>

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

> **This tool is intended for authorized security testing only.** Use it exclusively against applications for which you have explicit written permission. Unauthorized testing is illegal and unethical.

---

<div align="center">

**Built by [0xs0m](somm.tf)**

*If TrashDroid helped you find bugs, consider starring the repo.*

</div>
