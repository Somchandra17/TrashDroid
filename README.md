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
| **Context-Aware PII Detection** | Three-tier detection: regex-only (default, zero deps) → Presidio (`--presidio`, 30+ built-in recognizers + 5 custom security recognizers with checksum validation like Luhn/SSN/IBAN) → GLiNER NER (`--ner`, ML-based NLP detecting 50+ entity types). Graceful degradation to regex when backends are unavailable. Integrated across all scan phases. |
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

**Standard build** (includes Presidio by default):

```bash
git clone https://github.com/Somchandra17/TrashDroid.git
cd TrashDroid
docker build -t trashdroid .
```

**NER build** (includes Presidio + GLiNER ML model, ~560 MB additional):

```bash
docker build --build-arg ENABLE_NER=true -t trashdroid:ner .
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
| Build image (Presidio) | `docker build -t trashdroid .` |
| Build with NER | `docker build --build-arg ENABLE_NER=true -t trashdroid:ner .` |
| Interactive run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid` |
| NER interactive run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid:ner --ner` |
| Auto run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid --auto --device SERIAL --package PKG` |
| NER auto run | `docker run -it --network host -v "$(pwd)/output:/app/output" trashdroid:ner --ner --auto --device SERIAL --package PKG` |
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
```

### 1. Base install (regex-only PII detection, zero extra deps)

```bash
pip install -r requirements.txt
python main.py
```

This gives you the full 9-phase assessment with regex-based pattern matching for sensitive data. No additional Python packages beyond `rich` are required.

### 2. Add Presidio (regex + checksum validators)

```bash
pip install -r requirements-presidio.txt
python main.py --presidio --auto --device <SERIAL> --package <PKG>
```

Adds Microsoft Presidio with 30+ built-in recognizers, checksum validators (Luhn for credit cards, SSN format, IBAN), and 5 custom security recognizers (JWT, API_KEY, PRIVATE_KEY, AUTH_TOKEN, PASSWORD). ~50 MB download.

### 3. Add GLiNER NER (ML-based PII detection)

```bash
pip install -r requirements-ner.txt
python main.py --ner --auto --device <SERIAL> --package <PKG>
```

Adds the GLiNER NLP model (`urchade/gliner_multi_pii-v1`, ~560 MB downloaded on first run) that detects 50+ entity types using context-aware ML inference. `--ner` implies `--presidio`, so both engines run together.

### Full auto mode

```bash
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
| `presidio-analyzer` | Advanced PII string scanning (regex + checksum validators) | Optional |
| `presidio-analyzer[gliner]` | ML-based NER PII detection (50+ entity types) | Optional |
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

## Context-Aware PII Detection

TrashDroid supports three tiers of PII (Personally Identifiable Information) detection, each building on the last. Higher tiers reduce false positives and detect more entity types at the cost of additional dependencies.

### Why not regex-only?

Legacy regex matching (`SENSITIVE_PATTERNS`) generates many false positives — a 16-digit number isn't always a credit card. Presidio adds **checksum validators** (Luhn for credit cards, SSN format checks, IBAN validation) and GLiNER adds **NLP-based entity recognition** that understands context (e.g., distinguishing a person's name from a street name).

### Three Detection Tiers

| Tier | Flag | Method | Dependencies | Model Size |
|---|---|---|---|---|
| Regex-only | *(default)* | Pattern matching via `SENSITIVE_PATTERNS` | None | — |
| Presidio | `--presidio` | 30+ built-in recognizers + 5 custom security recognizers (JWT, API_KEY, PRIVATE_KEY, AUTH_TOKEN, PASSWORD) with checksum validation (Luhn, SSN, IBAN) | `presidio-analyzer` | ~50 MB |
| GLiNER NER | `--ner` | ML-based NLP (`urchade/gliner_multi_pii-v1`) detecting 50+ entity types + all Presidio recognizers | `presidio-analyzer[gliner]` | ~560 MB |

> `--ner` implies `--presidio` — the ML model runs alongside Presidio's checksum validators.

### Entity Types Detected by GLiNER

`person`, `email`, `phone number`, `credit card number`, `social security number`, `iban`, `date of birth`, `address`, `passport number`, `driver license number`, `bank account`, `medical record`, `insurance number`, `username`, `password`, `api key`, `token`, `url`, `ip address`

### Severity Mapping

Each PII entity type maps to a base severity, then adjusts based on confidence score:

| Confidence Score | Severity Adjustment |
|---|---|
| ≥ 0.8 | Base severity (no change) |
| 0.5 – 0.79 | Downgraded by 1 level |
| < 0.5 | Downgraded by 2 levels |

**Base severity by category:**

| Category | Entity Types | Base Severity |
|---|---|---|
| Financial | `CREDIT_CARD`, `IBAN_CODE`, `US_BANK_NUMBER` | Critical |
| Security (custom) | `JWT`, `API_KEY`, `PRIVATE_KEY`, `AUTH_TOKEN` | Critical |
| Identity | `US_SSN`, `US_PASSPORT`, `US_ITIN` | Critical |
| Identity | `US_DRIVER_LICENSE`, `MEDICAL_LICENSE`, `PERSON` | High |
| Security (custom) | `PASSWORD` | High |
| Contact | `EMAIL_ADDRESS`, `PHONE_NUMBER` | High |
| Location/Time | `LOCATION`, `IP_ADDRESS`, `NRP` | Medium |
| Other | `DATE_TIME`, `URL` | Low |

### Integration

The `PresidioEngine` singleton is lazily initialized and has **zero impact** when not enabled. When active, it runs across **all scan phases**: Filesystem, Logcat, Memory, Backup, and Dump Verification. Large inputs are chunked (2000 chars, 200 char overlap) for reliable analysis. If Presidio or GLiNER is not installed, the engine gracefully falls back to regex-only detection.

### Example Commands

```bash
# Tier 1: Regex-only (default, no extra deps)
python main.py --auto --device SERIAL --package com.example.app

# Tier 2: Presidio (requires requirements-presidio.txt)
python main.py --presidio --auto --device SERIAL --package com.example.app

# Tier 3: GLiNER NER (requires requirements-ner.txt, ~560 MB model)
python main.py --ner --auto --device SERIAL --package com.example.app
```

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

<details>
<summary><b>Presidio not found / <code>ModuleNotFoundError: No module named 'presidio_analyzer'</code></b></summary>

- Install the Presidio backend: `pip install -r requirements-presidio.txt`
- Or run without `--presidio` to use regex-only detection
- Docker users: Presidio is included by default in the standard image
</details>

<details>
<summary><b>GLiNER model download fails or times out</b></summary>

- The model is ~560 MB and downloads on first run — ensure stable internet
- To pre-download: `python -c "from gliner import GLiNER; GLiNER.from_pretrained('urchade/gliner_multi_pii-v1')"`
- Docker users: use `docker build --build-arg ENABLE_NER=true -t trashdroid:ner .` to cache the model at build time
- Offline: set `GLINER_HOME` or place the model in `~/.cache/huggingface/hub/` manually
</details>

---

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## Disclaimer

> **This tool is intended for authorized security testing only.** Use it exclusively against applications for which you have explicit written permission. Unauthorized testing is illegal and unethical.

---

<div align="center">

**Built by [0xs0m](https://somm.tf)**

*If TrashDroid helped you find bugs, consider starring the repo.*

</div>
