# Testing TrashDroid

## Automated tests (no device required)

The unit/integration suite runs entirely offline and is what CI executes:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Presidio engine tests skip automatically unless `presidio-analyzer` **and** its
spaCy model are installed (they build a real engine). Everything else always
runs. Lint and byte-compile gates:

```bash
ruff check .
python -m py_compile $(git ls-files '*.py')
```

## Manual device verification (requires a connected device/emulator)

The device-side phases (drozer, `adb` pull, frida, screenshots) can't be
exercised in CI. Run this checklist against a real device before a release.

### Prerequisites
- A rooted device or emulator with USB debugging enabled; `adb devices` shows it
  as `device`.
- Optional tools on PATH as needed: `drozer`, `apktool`, `scrcpy`, `frida`,
  plus the on-device drozer agent and `frida-server` for those phases.

### 1. Smoke — no device interaction
Manifest analysis only needs the APK; it's the safest first run:

```bash
python main.py --phases 8 --auto --package <pkg>     # or --apk path/to/app.apk
```
Expect: the phase completes, a report is written under `output/<pkg>/`, and there
are no tracebacks. Open the generated `DAST_Report_*.md` and confirm tables,
fenced code blocks, and any screenshots render cleanly.

### 2. A device-interactive phase
Filesystem analysis exercises `adb pull` / root-shell paths:

```bash
python main.py --phases 3 --auto --package <pkg>
```
Expect: pulls run (or fall back gracefully), `grep_results.txt` is written, and
findings record without the run aborting.

### 3. A drozer phase (if the agent is set up)
```bash
python main.py --phases 1 --auto --package <pkg>
```
Expect: drozer connects (or the phase skips cleanly if it can't), component
findings record, and screenshots attach to the matching findings in the report.

### 4. Watchdog behaviour (auto mode)
In `--auto` mode each phase is bounded by `TIMING.phase_budget_sec` (default
600s). If a device/tool call wedges, the phase is abandoned and a
"Phase timed out" finding is recorded — the run continues to the next phase
instead of hanging. Verify a normal run stays well under budget.

### What to confirm overall
- No new tracebacks in the console.
- `output/<pkg>/DAST_Report_*.md` and `findings_*.json` are produced and parse.
- CVSS score and vector agree on each finding.
- Invalid/odd package names are rejected up front rather than reaching a shell.
