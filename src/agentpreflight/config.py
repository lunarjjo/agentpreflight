"""Configuration loading and validation.

Configuration lives in ``.agentpreflight.toml`` at the scan root (or a
file passed via ``--config``). On Python 3.11+ the stdlib ``tomllib`` is
used; on 3.10 the vendored :mod:`agentpreflight._toml_lite` parses the
documented subset.

Validation is strict: unknown keys, invalid severities and malformed
ignore entries are hard errors so misconfiguration is never silent.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

from agentpreflight.models import Severity

CONFIG_FILENAME = ".agentpreflight.toml"

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class ConfigError(ValueError):
    """Raised for invalid configuration. The CLI maps this to exit code 3."""


@dataclass
class IgnoreEntry:
    """One documented suppression entry.

    ``reason`` is mandatory: suppressions must be self-explaining so
    future maintainers can audit them. ``expires`` makes temporary
    suppressions fail loudly instead of rotting forever.
    """

    path: str
    rule_id: str = "*"
    reason: str = ""
    expires: date | None = None
    allow_all: bool = False

    def matches(self, rel_path: str, rule_id: str) -> bool:
        path_ok = fnmatch.fnmatch(rel_path.replace("\\", "/"), self.path) or fnmatch.fnmatch(
            rel_path.replace("\\", "/").split("/")[-1], self.path
        )
        rule_ok = fnmatch.fnmatch(rule_id, self.rule_id)
        return path_ok and rule_ok

    def expired(self, today: date | None = None) -> bool:
        return self.expires is not None and (today or date.today()) > self.expires


@dataclass
class Config:
    """Resolved configuration values."""

    severity: Severity = Severity.INFO  # minimum severity reported
    fail_severity: Severity = Severity.HIGH  # exit 1 threshold
    max_file_size: int = 10 * 1024 * 1024  # 10 MiB
    max_files: int = 50_000
    max_commits: int = 5_000
    workers: int = 0  # 0 = auto
    exclude_paths: list[str] = field(default_factory=list)
    include_rules: list[str] = field(default_factory=list)
    exclude_rules: list[str] = field(default_factory=list)
    ignore: list[IgnoreEntry] = field(default_factory=list)
    redact: bool = True
    format: str = "text"

    def allows_rule(self, rule_id: str) -> bool:
        if any(fnmatch.fnmatch(rule_id, pattern) for pattern in self.exclude_rules):
            return False
        if self.include_rules:
            return any(fnmatch.fnmatch(rule_id, pattern) for pattern in self.include_rules)
        return True

    def is_path_excluded(self, rel_path: str) -> bool:
        normalised = rel_path.replace("\\", "/")
        for pattern in self.exclude_paths:
            if fnmatch.fnmatch(normalised, pattern) or any(
                fnmatch.fnmatch(segment, pattern) for segment in normalised.split("/")
            ):
                return True
        return False

    def active_ignores(self, warnings: list[str] | None = None) -> list[IgnoreEntry]:
        active: list[IgnoreEntry] = []
        today = date.today()
        for entry in self.ignore:
            if entry.expires is not None and today > entry.expires:
                if warnings is not None:
                    assert entry.expires is not None
                    warnings.append(
                        f"ignore entry for '{entry.path}' (rule {entry.rule_id}) expired "
                        f"on {entry.expires.isoformat()}; finding will be reported again"
                    )
                continue
            active.append(entry)
        return active


def _get_int(table: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = table.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ConfigError(f"[scan] {key} must be an integer, got {value!r}")
    if not minimum <= value <= maximum:
        raise ConfigError(f"[scan] {key} must be between {minimum} and {maximum}, got {value}")
    return value


def _get_bool(table: dict[str, Any], key: str, default: bool) -> bool:
    value = table.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"[scan] {key} must be true or false, got {value!r}")
    return value


def _get_str_list(table: dict[str, Any], key: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be an array of strings")
    return value


def from_dict(data: dict[str, Any], source: str = "config") -> Config:
    """Validate and convert a parsed TOML mapping into :class:`Config`."""
    cfg = Config()

    known_top = {"scan", "ignore", "output"}
    unknown = set(data) - known_top
    if unknown:
        raise ConfigError(f"{source}: unknown top-level key(s): {', '.join(sorted(unknown))}")

    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise ConfigError(f"{source}: [scan] must be a table")
    known_scan = {
        "severity",
        "fail_severity",
        "max_file_size",
        "max_files",
        "max_commits",
        "workers",
        "exclude_paths",
        "include_rules",
        "exclude_rules",
    }
    unknown = set(scan) - known_scan
    if unknown:
        raise ConfigError(f"{source}: unknown [scan] key(s): {', '.join(sorted(unknown))}")

    try:
        if "severity" in scan:
            cfg.severity = Severity.parse(scan["severity"])
        if "fail_severity" in scan:
            cfg.fail_severity = Severity.parse(scan["fail_severity"])
    except ValueError as exc:
        raise ConfigError(f"{source}: {exc}") from exc

    cfg.max_file_size = _get_int(scan, "max_file_size", cfg.max_file_size, 1024, 2 * 1024**3)
    cfg.max_files = _get_int(scan, "max_files", cfg.max_files, 1, 5_000_000)
    cfg.max_commits = _get_int(scan, "max_commits", cfg.max_commits, 1, 1_000_000)
    cfg.workers = _get_int(scan, "workers", cfg.workers, 0, 64)

    exclude = scan.get("exclude_paths", [])
    if not isinstance(exclude, list) or not all(isinstance(v, str) for v in exclude):
        raise ConfigError(f"{source}: [scan] exclude_paths must be an array of strings")
    cfg.exclude_paths = exclude
    cfg.include_rules = _get_str_list(scan, "include_rules") if "include_rules" in scan else []
    cfg.exclude_rules = _get_str_list(scan, "exclude_rules") if "exclude_rules" in scan else []

    output = data.get("output", {})
    if not isinstance(output, dict):
        raise ConfigError(f"{source}: [output] must be a table")
    unknown = set(output) - {"format", "redact"}
    if unknown:
        raise ConfigError(f"{source}: unknown [output] key(s): {', '.join(sorted(unknown))}")
    cfg.redact = _get_bool(output, "redact", cfg.redact)
    if "format" in output:
        fmt = output["format"]
        if fmt not in {"text", "json", "sarif"}:
            raise ConfigError(f"{source}: [output] format must be text, json or sarif; got {fmt!r}")
        cfg.format = fmt

    ignore_raw = data.get("ignore", [])
    if not isinstance(ignore_raw, list):
        raise ConfigError(f"{source}: ignore must be an array of tables: [[ignore]]")
    for i, entry in enumerate(ignore_raw, start=1):
        if not isinstance(entry, dict):
            raise ConfigError(f"{source}: ignore entry #{i} must be a table")
        unknown = set(entry) - {"path", "rule_id", "reason", "expires", "allow_all"}
        if unknown:
            raise ConfigError(f"{source}: ignore entry #{i} has unknown key(s): {', '.join(sorted(unknown))}")
        path = entry.get("path")
        if not isinstance(path, str) or not path:
            raise ConfigError(f"{source}: ignore entry #{i} requires a 'path' string")
        rule_id = entry.get("rule_id", "*")
        if not isinstance(rule_id, str) or not rule_id:
            raise ConfigError(f"{source}: ignore entry #{i} 'rule_id' must be a non-empty string")
        reason = entry.get("reason", "")
        if not isinstance(reason, str) or not reason.strip():
            raise ConfigError(
                f"{source}: ignore entry #{i} requires a non-empty 'reason' — suppressions must be documented"
            )
        expires_raw = entry.get("expires")
        expires: date | None = None
        if expires_raw is not None:
            if not isinstance(expires_raw, str) or not _DATE_RE.match(expires_raw):
                raise ConfigError(f"{source}: ignore entry #{i} 'expires' must be YYYY-MM-DD")
            try:
                expires = datetime.strptime(expires_raw, "%Y-%m-%d").date()
            except ValueError as exc:
                raise ConfigError(f"{source}: ignore entry #{i} invalid 'expires': {exc}") from exc
        allow_all = entry.get("allow_all", False)
        if not isinstance(allow_all, bool):
            raise ConfigError(f"{source}: ignore entry #{i} 'allow_all' must be true or false")
        if rule_id == "*" and not allow_all:
            raise ConfigError(
                f"{source}: ignore entry #{i} suppresses ALL rules for '{path}' — "
                "set allow_all = true to acknowledge this explicitly"
            )
        cfg.ignore.append(IgnoreEntry(path=path, rule_id=rule_id, reason=reason, expires=expires, allow_all=allow_all))

    return cfg


def find_config(root: str | Path) -> Path | None:
    """Return the configuration file for a scan root, if present."""
    candidate = Path(root) / CONFIG_FILENAME
    return candidate if candidate.is_file() else None


def load_config_file(path: str | Path) -> tuple[Config, str]:
    """Load + validate a config file. Returns (config, raw_text)."""
    text = Path(path).read_text(encoding="utf-8")
    data = parse_toml(text, str(path))
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: TOML root must be a table")
    return from_dict(data, source=str(path)), text


def parse_toml(text: str, source: str = "config") -> dict[str, Any]:
    """Parse TOML via tomllib (3.11+) or the vendored subset parser."""
    try:
        import tomllib  # type: ignore[import-not-found]  # Python 3.11+
    except ImportError:
        from agentpreflight import _toml_lite

        try:
            return _toml_lite.loads(text)
        except _toml_lite.TomlLiteError as exc:
            raise ConfigError(f"{source}: {exc}") from exc
    try:
        parsed: dict[str, Any] = dict(tomllib.loads(text))
        return parsed
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source}: {exc}") from exc


DEFAULT_CONFIG_TEMPLATE = """\
# AgentPreflight configuration
# Docs: https://github.com/lunarjjo/agentpreflight/blob/main/docs/configuration.md

[scan]
# Minimum severity to report: critical | high | medium | low | info
severity = "info"
# Exit code 1 when findings exist at or above this severity
fail_severity = "high"
# Skip content scanning for files larger than this many bytes (10 MiB)
max_file_size = 10485760
# Abort (with a warning) when a scan would consider more files
max_files = 50000
# Maximum commits to inspect with --history
max_commits = 5000
# Worker threads; 0 = auto
workers = 0

# Optional rule selection
# include_rules = ["APF-SEC-*"]
# exclude_rules = ["APF-DEP-002"]

# Optional path exclusions (fnmatch patterns, matched against the whole
# relative path and each path segment)
# exclude_paths = ["vendor", "tests/fixtures/**"]

[output]
format = "text"
# Secret values are always redacted; this also masks weak/default
# credential values in printed snippets.
redact = true

# Documented suppressions. 'reason' is mandatory. An entry matching all
# rules ('rule_id = \"*\"') additionally requires allow_all = true.
[[ignore]]
path = "tests/fixtures/**"
rule_id = "APF-SEC-*"
reason = "Synthetic secrets used as test fixtures; they must match rule patterns."
expires = "2027-12-31"
"""
