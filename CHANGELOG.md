# Changelog

All notable changes to the TrashDroid framework will be documented in this file.

## [Unreleased]

### Added
- **Context-Aware PII Detection**: Integrated Microsoft Presidio and GLiNER NER for advanced, machine-learning-based PII matching.
  - Added new CLI flags: `--presidio` (regex + checksum validators) and `--ner` (ML-based NLP entity extraction).
  - Implemented a unified centralized `PresidioEngine` singleton pattern with lazy-initialization to ensure zero impact when not used.
  - Implemented graceful degradation (regex fallback) for systems without `presidio-analyzer` or `gliner` installed.
  - Integrated full Context-Aware PII detection into all phases: Filesystem, Logcat, Memory, Backup, and Dump Verification.
  - Detailed findings report JSON exporting the PII `entity_type` and `confidence_score` metadata alongside UI reporting.
- **Enhanced Dump Verification**:
  - Encrypted SQLite database detection (SQLCipher).
  - Deeper XML and Shared Preferences string extraction avoiding duplicate entity entries.
- **Enhanced Logcat Collection**: Background Logcat Collector timeout and lifecycle improvements.
- Dockerfile updated with `ENABLE_NER` build arg and auto-caching.
- **Per-phase watchdog**: in `--auto` mode each phase is bounded by `TIMING.phase_budget_sec`; a wedged `adb`/drozer/frida call is abandoned with a "Phase timed out" finding so the run continues.
- **Test suite & CI**: offline `unittest` coverage for `adb`, `drozer`, `report`, and phase guards/smoke tests (Presidio engine tests skip cleanly when the model is absent); a GitHub Actions workflow running `ruff` + `py_compile` + the test suite on Python 3.10–3.12.
- **Packaging**: `pyproject.toml` makes the project installable (`pip install -e .`, optional `[presidio]`/`[ner]` extras) and exposes a `trashdroid` console entry point; `ruff` lint config included.
- `TESTING.md` documenting the offline test commands and a manual device-run checklist.
- Pinned dependency versions in `requirements*.txt` for reproducible installs.

### Changed
- Configurable screenshot delay now available via new `--screenshot-delay` CLI flag.
- Improved app-sec `NOISE_TAGS` filtering for logcat dumps.
- Manifest Phase logic upgraded with strict XML parsing for intent-filters and exported components.
- PII startup behavior is now explicit and deterministic:
  - `--presidio`: warns and falls back to regex-only on backend init failure.
  - `--ner`: fails fast with non-zero exit on backend init failure (no silent downgrade).
- Report CVSS is now computed from the (context-adjusted) CVSS 3.1 vector, so the score and vector always agree across every severity.
- Consolidated the duplicated logcat capture/terminate plumbing into a shared `utils/proc.py` helper used by both the foreground and background collectors.
- `PresidioEngine` lazy initialization is now thread-safe (double-checked locking).

### Fixed
- **Phase IV/III binary-decode crash**: deep SQLite analysis (`SELECT *`) and binary `strings` extraction now decode subprocess output with `errors="replace"`, and `UnicodeDecodeError` (a `ValueError` subclass) is caught per file — a single BLOB-bearing or non-UTF-8 database can no longer abort the phase (previously `phases/dump_verify.py` crashed out of Phase IV, losing the shared-prefs/binary/WebView steps). SQLite WAL sidecars (`*-shm`/`*-wal`/`*-journal`, dash-separated) are now skipped instead of being mis-reported as "Encrypted DB".
- Fixed false-positive backend status where NER could be shown as enabled before analyzer warmup succeeded.
- Hardened logcat process lifecycle:
  - Background collector now owns and force-terminates `adb logcat` subprocesses deterministically.
  - Phase V foreground collector now force-terminates stuck `adb logcat` subprocesses under low-log conditions.
- Cleanup path now stops background logcat collectors during signal/exit handling and is idempotent to avoid duplicate cleanup/report behavior.
- Added compatibility for new Presidio GLiNER module path and constructor args in recent versions (`predefined_recognizers.ner.gliner_recognizer`, `model_name`/`threshold`).
- **Report rendering & scoring**: CVSS score/vector are now consistent (computed, not string-patched); screenshot-to-finding matching uses token scoring instead of an all-or-nothing substring skip (provider/intent findings keep their evidence); finding titles/details/captions are Markdown-escaped so pipes, backtick runs, and special characters can no longer break tables, code fences, or image links.
- Narrowed broad `except Exception` handlers to specific exception types across `core/` and `phases/`; bounded previously-unbounded file/directory scans; switched large APK hashing to streaming and guarded large in-memory reads.
- `ADB.run()` now raises a clear `ADBError` when `adb` is missing instead of leaking a raw `FileNotFoundError`, and corrected the documented `--report` flag (was `--report-mode`).

### Security
- Shifted away from naive, regex-only `SENSITIVE_PATTERNS` to lower false-positive rates of data detection metrics.
- **Shell-input hardening**: package names, device paths, activity components, and PIDs are validated (allow-list) before being interpolated into `adb`/`su -c` shell commands across `core/adb.py`, `phases/memory.py`, and the drozer/manifest/post-logout phases; malformed values are rejected at the boundary.
- `drozer.run_module` rejects malformed module names and control-character (newline/CR/NUL) injection into the drozer console command.
