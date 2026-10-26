"""Detection rules for AgentPreflight."""

from __future__ import annotations

from agentpreflight.rules.artifacts import PATH_RULES, REPO_RULES
from agentpreflight.rules.base import (
    ALLOW_MARKER,
    ContentPattern,
    ContentRule,
    FileContext,
    PathRule,
    RawFinding,
    RepoContext,
    RepoRule,
    Rule,
)
from agentpreflight.rules.defaults import DEFAULT_RULES
from agentpreflight.rules.registry import ALL_RULES, RULES_BY_ID, rules_by_severity
from agentpreflight.rules.secrets import SECRET_RULES
from agentpreflight.rules.supply import SUPPLY_RULES

__all__ = [
    "ALLOW_MARKER",
    "ALL_RULES",
    "DEFAULT_RULES",
    "PATH_RULES",
    "REPO_RULES",
    "RULES_BY_ID",
    "SECRET_RULES",
    "SUPPLY_RULES",
    "ContentPattern",
    "ContentRule",
    "FileContext",
    "PathRule",
    "RawFinding",
    "RepoContext",
    "RepoRule",
    "Rule",
    "rules_by_severity",
]
