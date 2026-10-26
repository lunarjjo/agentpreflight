"""Language and ecosystem recognition package."""

from __future__ import annotations

from agentpreflight.languages.registry import (
    ECOSYSTEMS,
    detect_language,
    ecosystem_summary,
    language_display,
)

__all__ = ["ECOSYSTEMS", "detect_language", "ecosystem_summary", "language_display"]
