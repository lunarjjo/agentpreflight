"""Central rule registry.

All rules are instantiated once and exposed via :data:`ALL_RULES`.
Adding a rule means adding a class to one of the category modules and
appending it to the relevant ``*_RULES`` list — the registry, CLI, docs
generator and SARIF output pick it up automatically.
"""

from __future__ import annotations

from agentpreflight.models import Severity
from agentpreflight.rules.artifacts import PATH_RULES, REPO_RULES
from agentpreflight.rules.base import Rule
from agentpreflight.rules.defaults import DEFAULT_RULES
from agentpreflight.rules.secrets import SECRET_RULES
from agentpreflight.rules.supply import SUPPLY_RULES

ALL_RULES: list[Rule] = [*SECRET_RULES, *PATH_RULES, *DEFAULT_RULES, *SUPPLY_RULES, *REPO_RULES]

RULES_BY_ID: dict[str, Rule] = {}


def _validate_registry() -> None:
    seen_ids: set[str] = set()
    for rule in ALL_RULES:
        if rule.id in seen_ids:
            raise RuntimeError(f"duplicate rule id: {rule.id}")  # pragma: no cover
        seen_ids.add(rule.id)
        RULES_BY_ID[rule.id] = rule
    expected_prefix = {
        "secret": "APF-SEC-",
        "artifact": "APF-ART-",
        "default": "APF-DEF-",
        "supply": "APF-DEP-",
    }
    for rule in ALL_RULES:
        prefix = expected_prefix[rule.category]
        if not rule.id.startswith(prefix):
            raise RuntimeError(  # pragma: no cover
                f"rule {rule.id} has category {rule.category} but wrong id prefix"
            )


_validate_registry()


def rules_by_severity() -> dict[str, list[Rule]]:
    grouped: dict[str, list[Rule]] = {s.value: [] for s in Severity}
    for rule in ALL_RULES:
        grouped[rule.severity.value].append(rule)
    return grouped
