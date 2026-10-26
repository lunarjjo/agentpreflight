"""Rule abstractions for AgentPreflight.

Three rule kinds are supported:

- :class:`ContentRule` — scans decoded file content line by line
  (secret patterns, insecure defaults).
- :class:`PathRule` — fires on file names and paths without needing
  content (sensitive artifacts such as ``.env`` or ``id_rsa``).
- :class:`RepoRule` — inspects the inventory of files as a whole
  (e.g. a committed ``node_modules`` directory, a missing lockfile).

Rules are stateless: all context arrives via :class:`FileContext` and
:class:`RepoContext`. Raw secret values live only inside
:class:`RawFinding` in memory; the engine converts them to redacted
:class:`~agentpreflight.models.Finding` objects.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from re import Pattern
from typing import Any, ClassVar

from agentpreflight.models import Confidence, Severity
from agentpreflight.redact import looks_generated_secret, looks_like_placeholder

# Allow marker placed anywhere on a line to suppress findings on that line.
ALLOW_MARKER = "agentpreflight: allow"


@dataclass
class FileContext:
    """Everything a rule may need to know about one file.

    ``tracked`` is ``None`` when scanning a directory that is not a Git
    repository. ``text``/``lines`` are ``None`` for binary or oversized
    files (path rules still apply to those).
    """

    rel_path: str
    abs_path: str
    size: int
    tracked: bool | None
    language: str | None = None
    text: str | None = None
    lines: list[str] | None = None
    repo_files: set[str] = field(default_factory=set)


@dataclass
class RepoContext:
    """Whole-repository context for :class:`RepoRule` rules."""

    files: list[FileContext]
    root: str
    tracked: set[str] | None  # None when not a Git repository
    pruned_dirs: list[str] = field(default_factory=list)


@dataclass
class RawFinding:
    """Rule output before redaction / fingerprinting."""

    message: str
    line: int | None = None
    column: int | None = None
    secret_value: str | None = None
    span: tuple[int, int] | None = None
    confidence: Confidence | None = None


@dataclass
class ContentPattern:
    """A regex plus the capture group holding the secret value.

    When ``group`` is None (or ``entropy_gate`` is set) the match carries no
    secret value: findings will not get a preview or span masking. Rules
    whose match itself is the problem (insecure defaults, unsafe patterns)
    use ``group=None``.

    When ``entropy_gate`` is set, the captured value must additionally pass
    :func:`looks_generated_secret` and must not look like a placeholder.
    This is what keeps generic patterns quiet on documentation.
    """

    pattern: Pattern[str]
    group: int | None = 1
    entropy_gate: bool = False

    def match_value(self, m: re.Match[str]) -> str | None:
        if self.group is None or self.group > m.re.groups:
            return None
        return m.group(self.group)


class Rule(ABC):
    """Base class: metadata shared by every detection rule."""

    id: ClassVar[str]
    name: ClassVar[str]
    category: ClassVar[str]  # secret | artifact | default | supply
    severity: ClassVar[Severity]
    confidence: ClassVar[Confidence]
    description: ClassVar[str]
    remediation: ClassVar[str]
    references: ClassVar[list[str]] = []
    applies_to: ClassVar[str] = "all text files"

    def metadata(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "applies_to": self.applies_to,
        }


class ContentRule(Rule):
    """Rule that inspects decoded text content, one line at a time."""

    patterns: ClassVar[list[ContentPattern]] = []

    def file_filter(self, ctx: FileContext) -> bool:
        """Restrict the rule to specific files. Override in subclasses."""
        return True

    def applies(self, ctx: FileContext) -> bool:
        return ctx.lines is not None and self.file_filter(ctx)

    @abstractmethod
    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        """Return raw findings for this file."""

    def default_scan(self, ctx: FileContext, message: str) -> list[RawFinding]:
        """Standard line-by-line scan using :attr:`patterns`."""
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        for lineno, line in enumerate(ctx.lines, start=1):
            for cp in self.patterns:
                for m in cp.pattern.finditer(line):
                    value = cp.match_value(m)
                    if cp.entropy_gate:
                        if value is None or looks_like_placeholder(value):
                            continue
                        if not looks_generated_secret(value):
                            continue
                    span = None
                    if value is not None and cp.group is not None:
                        start = m.start(cp.group)
                        end = m.end(cp.group)
                        if 0 <= start < end:
                            span = (start, end)
                    findings.append(
                        RawFinding(
                            message=message,
                            line=lineno,
                            column=(m.start() + 1),
                            secret_value=value,
                            span=span,
                        )
                    )
        return findings


class PathRule(Rule):
    """Rule that fires purely on file names/paths."""

    @abstractmethod
    def matches(self, ctx: FileContext) -> str | None:
        """Return a human-readable reason if the path is suspicious."""

    def check_path(self, ctx: FileContext) -> list[RawFinding]:
        reason = self.matches(ctx)
        if reason is None:
            return []
        return [RawFinding(message=reason)]


class RepoRule(Rule):
    """Rule that inspects the file inventory as a whole."""

    @abstractmethod
    def check_repo(self, ctx: RepoContext) -> list[tuple[str, RawFinding]]:
        """Return ``(relative_path, raw_finding)`` pairs."""


def line_has_allow_marker(line: str) -> bool:
    """True when the line carries an inline suppression marker."""
    return ALLOW_MARKER in line.lower()
