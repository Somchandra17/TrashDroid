## What & why

<!-- What does this change, and why? Link any related issue (#123). -->

## Checklist

- [ ] Tests added/updated and passing: `python -m unittest discover -s tests -p "test_*.py"`
- [ ] Lint clean: `ruff check .`
- [ ] Byte-compile clean: `python -m py_compile $(git ls-files '*.py')`
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`
- [ ] Device-derived values that reach a shell command are validated (see `utils/helpers.py`)
- [ ] No secrets, tokens, or real target-app data committed
