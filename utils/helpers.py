"""
Shared utility functions used across multiple phases.
"""

from __future__ import annotations

import re
from core.config import SENSITIVE_PATTERNS, FALSE_POSITIVE_PREFIXES


def is_library_component(name: str) -> bool:
    """Check if a component name belongs to a known library/framework prefix."""
    return any(name.startswith(prefix) for prefix in FALSE_POSITIVE_PREFIXES)


def grep_sensitive_lines(text: str, max_lines: int = 200) -> str:
    """Run a case-insensitive regex search over a string for sensitive patterns.
    Returns matching lines joined by newline, capped at max_lines."""
    matches = []
    for line in text.splitlines():
        if re.search(SENSITIVE_PATTERNS, line, re.IGNORECASE):
            matches.append(line.strip())
        if len(matches) >= max_lines:
            break
    return "\n".join(matches)
