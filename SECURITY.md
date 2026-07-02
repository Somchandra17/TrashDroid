# Security Policy

TrashDroid is a security-testing tool intended **only** for authorized use against
applications you have explicit written permission to test (see the
[disclaimer](README.md#disclaimer)).

## Reporting a vulnerability in TrashDroid

If you find a security issue in the framework **itself** (for example a command
injection or path traversal in how TrashDroid handles device-derived data), please
report it privately rather than opening a public issue:

- **Preferred:** open a private report via the repository's **Security → Report a
  vulnerability** tab (GitHub private vulnerability reporting).
- **Alternatively:** reach the maintainer via the contact on <https://somm.tf>.

Please include reproduction steps and the affected version (`python main.py --version`).

## Supported versions

TrashDroid is pre-1.0; fixes land on `main`. Please reproduce against the latest `main`
before reporting.

## Scope

**In scope:** bugs in TrashDroid's own code — shell/command handling, backup/tar
extraction, report generation, screenshot/file writes, and cleanup.

**Out of scope:** findings that TrashDroid *reports about a target app* — that is the
tool working as intended, not a vulnerability in TrashDroid.
