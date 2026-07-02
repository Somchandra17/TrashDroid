# Contributing to TrashDroid

Thanks for your interest in improving TrashDroid! It is an **authorized-use** Android
DAST framework — please keep contributions aligned with the
[disclaimer](README.md#disclaimer) (lawful, authorized security testing only).

## Development setup

```bash
git clone https://github.com/Somchandra17/TrashDroid.git
cd TrashDroid
python -m venv .venv && source .venv/bin/activate
pip install -e .                 # base runtime (rich only)
# optional PII backends:
pip install -e ".[presidio]"     # regex + checksum validators
pip install -e ".[ner]"          # + GLiNER ML model (~560 MB)
```

## Before you open a PR

Run the same gate CI runs — all offline, **no device required**:

```bash
python -m unittest discover -s tests -p "test_*.py" -v   # unit tests
ruff check .                                             # lint (config in pyproject.toml)
python -m py_compile $(git ls-files '*.py')              # byte-compile gate
```

- **Add tests** for new behaviour and bug fixes. Device-touching code must be mockable
  and tested offline — see `tests/` for the `_FakeADB` / `unittest.mock` patterns.
- Keep each PR focused on one logical change.
- Match the existing style (ruff, 120-column lines).
- Update `CHANGELOG.md` under `## [Unreleased]`.

## Adding a new scan phase

Phases live in `phases/` as `run_*(config, adb, ...)` functions, registered in the
`ALL_PHASES` map in `main.py`. Record results via `config.add_finding(...)` and
`config.log_command(...)`. **Validate any device-derived value that reaches a shell
command** with the allow-list helpers in `utils/helpers.py` — `is_valid_package_name`,
`is_valid_component_name`, `is_safe_device_path`, `is_safe_intent_extras` — and prefer
fixed command shapes over string interpolation.

## Reporting security issues

Please do **not** open public issues for vulnerabilities in TrashDroid itself — see
[SECURITY.md](SECURITY.md).
