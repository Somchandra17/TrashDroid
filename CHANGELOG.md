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

### Security
- Shifted away from naive, regex-only `SENSITIVE_PATTERNS` to lower false-positive rates of data detection metrics.
