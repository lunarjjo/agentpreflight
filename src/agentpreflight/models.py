"""Core data models shared across the scanner."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SeverityOrder = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Severity(str, enum.Enum):
    """Severity of a finding.

    Criteria (documented in docs/rules.md):

    - ``critical``: immediate, broad compromise if the value leaks
      (e.g. private key material embedded in the repo).
    - ``high``: credential or setting that typically grants direct access
      to a service or disables a core security control.
    - ``medium``: plausible risk that depends on context, or a dangerous
      default that is acceptable in development but not in production.
    - ``low``: hygiene issue or weak signal that deserves a review.
    - ``info``: informational observation, no direct security impact.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SeverityOrder[self.value]

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {valid}") from None

    @classmethod
    def min_of(cls, threshold: Severity) -> list[Severity]:
        """All severities at or above ``threshold`` (by rank)."""
        return [s for s in cls if s.rank >= threshold.rank]


class Confidence(str, enum.Enum):
    """How certain the rule is that a match is a true positive.

    - ``high``: structural pattern of a well-known credential format.
    - ``medium``: format plus contextual evidence (entropy, key names).
    - ``low``: heuristic that requires human review; expect more noise.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def parse(cls, value: str) -> Confidence:
        try:
            return cls(value.strip().lower())
        except ValueError:
            valid = ", ".join(c.value for c in cls)
            raise ValueError(f"unknown confidence {value!r}; expected one of: {valid}") from None


@dataclass
class Finding:
    """A single, fully redacted detection result.

    ``secret_preview`` never contains the full secret value: only the first
    four characters and a short fingerprint. ``raw_line`` is stored only in
    memory for snippet masking and is stripped before serialisation.
    """

    rule_id: str
    rule_name: str
    severity: Severity
    confidence: Confidence
    category: str
    message: str
    path: str
    line: int | None = None
    column: int | None = None
    secret_preview: str | None = None
    fingerprint: str = ""
    commit: str | None = None
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    raw_line: str | None = None
    redaction_span: tuple[int, int] | None = None

    def to_public_dict(self) -> dict[str, Any]:
        """Dictionary safe for JSON/SARIF output: no raw secrets included."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "secret_preview": self.secret_preview,
            "fingerprint": self.fingerprint,
            "commit": self.commit,
            "remediation": self.remediation,
            "references": self.references,
        }


def make_fingerprint(*parts: str) -> str:
    """Stable short fingerprint (used for findings identity and triage)."""
    digest = hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()
    return digest[:16]


@dataclass
class ScanStats:
    """Counters describing what the scan actually did."""

    files_considered: int = 0
    files_scanned: int = 0
    files_skipped_size: int = 0
    files_skipped_symlink: int = 0
    files_skipped_ignored: int = 0
    files_skipped_unreadable: int = 0
    history_blobs_scanned: int = 0
    history_commits_considered: int = 0
    duration_ms: int = 0
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))


@dataclass
class ScanResult:
    """Everything a scan produced, plus operational diagnostics."""

    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    root: str = "."
    history_scanned: bool = False

    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        counts["total"] = len(self.findings)
        return counts

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)
