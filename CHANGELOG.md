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

### Changed
- Configurable screenshot delay now available via new `--screenshot-delay` CLI flag.
- Improved app-sec `NOISE_TAGS` filtering for logcat dumps.
- Manifest Phase logic upgraded with strict XML parsing for intent-filters and exported components.
- PII startup behavior is now explicit and deterministic:
  - `--presidio`: warns and falls back to regex-only on backend init failure.
  - `--ner`: fails fast with non-zero exit on backend init failure (no silent downgrade).

### Fixed
- Fixed false-positive backend status where NER could be shown as enabled before analyzer warmup succeeded.
- Hardened logcat process lifecycle:
  - Background collector now owns and force-terminates `adb logcat` subprocesses deterministically.
  - Phase V foreground collector now force-terminates stuck `adb logcat` subprocesses under low-log conditions.
- Cleanup path now stops background logcat collectors during signal/exit handling and is idempotent to avoid duplicate cleanup/report behavior.
- Added compatibility for new Presidio GLiNER module path and constructor args in recent versions (`predefined_recognizers.ner.gliner_recognizer`, `model_name`/`threshold`).

### Security
- Shifted away from naive, regex-only `SENSITIVE_PATTERNS` to lower false-positive rates of data detection metrics.
