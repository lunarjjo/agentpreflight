"""Scan orchestration.

The engine glues together: file enumeration (walker), rule evaluation,
inline/config suppression, redaction, history scanning and result
assembly. It is deliberately free of I/O concerns like terminal output.

Safety properties enforced here:
- findings never keep raw secret values (converted to redacted previews)
- inline ``agentpreflight: allow`` markers suppress per-line findings
- config ``[[ignore]]`` entries suppress per path/rule (with reason)
- resource limits are honoured and surfaced as warnings/errors
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from agentpreflight.config import Config
from agentpreflight.gitscan import (
    attribute_blob_to_commit,
    enumerate_history_blobs,
    read_history_blobs,
)
from agentpreflight.languages import detect_language
from agentpreflight.models import (
    Confidence,
    Finding,
    ScanResult,
    Severity,
    make_fingerprint,
)
from agentpreflight.redact import (
    fingerprint,
    mask_secret_in_line,
    redact_preview,
    sanitize_for_terminal,
)
from agentpreflight.rules.base import (
    ContentRule,
    FileContext,
    PathRule,
    RawFinding,
    RepoContext,
    RepoRule,
    Rule,
    line_has_allow_marker,
)
from agentpreflight.rules.registry import ALL_RULES, RULES_BY_ID
from agentpreflight.walker import (
    FileInventory,
    gather_files,
    read_file_content,
)

ProgressCallback = Callable[[int, int], None]


@dataclass
class ScanOptions:
    """Everything needed to run a scan."""

    path: str
    config: Config = field(default_factory=Config)
    include_history: bool = False
    no_git: bool = False
    quiet: bool = True
    on_progress: ProgressCallback | None = None


def _raw_to_finding(
    rule: Rule,
    raw: RawFinding,
    rel_path: str,
    lines: list[str] | None,
    commit: str | None,
) -> Finding:
    """Convert a RawFinding into a fully redacted Finding."""
    secret_value = raw.secret_value
    preview = redact_preview(secret_value) if secret_value else None
    snippet: str | None = None
    if raw.line is not None and lines and 1 <= raw.line <= len(lines):
        source_line = lines[raw.line - 1]
        if raw.span is not None and secret_value is not None:
            masked = mask_secret_in_line(source_line, raw.span[0], raw.span[1])
        elif rule.category == "secret":
            masked = source_line
        else:
            masked = source_line
        snippet = sanitize_for_terminal(masked.rstrip())

    fp = make_fingerprint(
        rule.id,
        rel_path,
        str(raw.line or 0),
        fingerprint(secret_value) if secret_value else "-",
    )

    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=rule.severity,
        confidence=raw.confidence or rule.confidence,
        category=rule.category,
        message=sanitize_for_terminal(raw.message),
        path=sanitize_for_terminal(rel_path),
        line=raw.line,
        column=raw.column,
        secret_preview=preview,
        fingerprint=fp,
        commit=commit,
        remediation=rule.remediation,
        references=list(rule.references),
        raw_line=snippet,
    )


def _scan_one_file(
    root: str,
    rel_path: str,
    tracked: bool | None,
    repo_files: set[str],
    rules: list[Rule],
    max_file_size: int,
) -> tuple[list[Finding], str | None]:
    """Scan a single file with all applicable rules. Returns (findings, skip_reason)."""
    abs_path = os.path.join(root, rel_path)
    size, text, skip_reason = read_file_content(abs_path, max_file_size=max_file_size)
    language = detect_language(rel_path)
    lines = text.splitlines() if text is not None else None

    ctx = FileContext(
        rel_path=rel_path,
        abs_path=abs_path,
        size=size,
        tracked=tracked,
        language=language,
        text=text,
        lines=lines,
        repo_files=repo_files,
    )

    findings: list[Finding] = []

    # allow-marker line set (computed lazily from the lines themselves)
    allow_lines: set[int] = set()
    if lines:
        for idx, line in enumerate(lines, start=1):
            if line_has_allow_marker(line):
                allow_lines.add(idx)

    for rule in rules:
        if isinstance(rule, ContentRule) and rule.applies(ctx):
            try:
                raws = rule.check_content(ctx)
            except Exception as exc:
                findings.append(_rule_error(rule, rel_path, exc))
                continue
            for raw in raws:
                if raw.line is not None and raw.line in allow_lines:
                    continue
                findings.append(_raw_to_finding(rule, raw, rel_path, lines, None))
        elif isinstance(rule, PathRule):
            try:
                raws = rule.check_path(ctx)
            except Exception as exc:
                findings.append(_rule_error(rule, rel_path, exc))
                continue
            for raw in raws:
                if raw.line is not None and raw.line in allow_lines:
                    continue
                findings.append(_raw_to_finding(rule, raw, rel_path, lines, None))
    return findings, skip_reason


def _rule_error(rule: Rule, rel_path: str, exc: Exception) -> Finding:
    """A rule raised an exception: report it as an informational finding, never crash."""
    return Finding(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        category=rule.category,
        message=f"rule raised {exc.__class__.__name__} while scanning this file — please report a bug",
        path=rel_path,
        remediation="This is an AgentPreflight bug, not a finding in your code: https://github.com/lunarjjo/agentpreflight/issues",
        references=[],
    )


def _apply_ignores(result: ScanResult, config: Config) -> None:
    active = config.active_ignores(result.warnings)
    if not active:
        return
    kept: list[Finding] = []
    suppressed_counts: dict[str, int] = {}
    for finding in result.findings:
        entry = next((e for e in active if e.matches(finding.path, finding.rule_id)), None)
        if entry is not None:
            key = f"{entry.path}|{entry.rule_id}"
            suppressed_counts[key] = suppressed_counts.get(key, 0) + 1
            continue
        kept.append(finding)
    result.findings = kept
    for key, count in sorted(suppressed_counts.items()):
        path, rule_id = key.split("|", 1)
        result.warnings.append(f"suppressed {count} finding(s) under '{path}' (rules '{rule_id}')")


def _filter_severity(result: ScanResult, config: Config) -> None:
    if config.severity == Severity.INFO:
        return
    result.findings = [f for f in result.findings if f.severity.rank >= config.severity.rank]


def run_scan(options: ScanOptions) -> ScanResult:
    """Execute a full scan and return the assembled result."""
    started = time.perf_counter()
    config = options.config
    result = ScanResult(root=options.path)

    root = options.path
    if not os.path.isdir(root) and os.path.isfile(root):
        root = os.path.dirname(os.path.abspath(root)) or "."
        single_file = os.path.abspath(options.path)
    else:
        single_file = None

    active_rules = [r for r in ALL_RULES if config.allows_rule(r.id)]

    inventory: FileInventory = gather_files(
        root,
        max_files=config.max_files,
        no_git=options.no_git,
        exclude_paths=config.is_path_excluded if config.exclude_paths else None,
    )
    result.errors.extend(inventory.errors)

    repo_files: set[str] = set(inventory.files)
    tracked_set = inventory.tracked

    if single_file is not None:
        # Restrict the scan to exactly one file.
        target_rel = os.path.relpath(single_file, root).replace(os.sep, "/")
        inventory.files = [target_rel]
        repo_files = {target_rel}

    stats = result.stats
    stats.files_considered = len(inventory.files)

    content_rules = [r for r in active_rules if isinstance(r, ContentRule)]
    path_rules = [r for r in active_rules if isinstance(r, PathRule)]
    per_file_rules: list[Rule] = [*content_rules, *path_rules]

    all_findings: list[Finding] = []
    scanned = 0

    def work(rel_path: str) -> tuple[str, list[Finding], str | None]:
        tracked = None if tracked_set is None else rel_path in tracked_set
        findings, skip_reason = _scan_one_file(
            root, rel_path, tracked, repo_files, per_file_rules, config.max_file_size
        )
        return rel_path, findings, skip_reason

    workers = config.workers if config.workers > 0 else min(4, (os.cpu_count() or 2) + 1)
    progress = options.on_progress
    done_count = 0
    total = len(inventory.files)
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for _rel_path, findings, skip_reason in pool.map(work, inventory.files):
                done_count += 1
                if progress is not None and (done_count % 50 == 0 or done_count == total):
                    progress(done_count, total)
                if skip_reason == "oversized":
                    stats.files_skipped_size += 1
                elif skip_reason == "":
                    pass  # binary file: path rules still ran
                elif skip_reason is not None:
                    stats.files_skipped_unreadable += 1
                else:
                    scanned += 1
                all_findings.extend(findings)
    except KeyboardInterrupt:  # pragma: no cover — interactive behaviour
        result.warnings.append("scan interrupted; results are partial")
        stats.files_scanned = scanned
        _finish_scan(result, all_findings, active_rules, config, root, inventory, started, options)
        return result
    stats.files_scanned = scanned

    # Repo-level rules
    file_contexts: list[FileContext] = []
    for rel_path in inventory.files:
        file_contexts.append(
            FileContext(
                rel_path=rel_path,
                abs_path=os.path.join(root, rel_path),
                size=0,
                tracked=None if tracked_set is None else rel_path in tracked_set,
                language=detect_language(rel_path),
            )
        )
    repo_ctx = RepoContext(files=file_contexts, root=root, tracked=tracked_set, pruned_dirs=inventory.pruned_dirs)
    for rule in active_rules:
        if isinstance(rule, RepoRule):
            try:
                pairs = rule.check_repo(repo_ctx)
            except Exception as exc:
                all_findings.append(_rule_error(rule, "<repo>", exc))
                continue
            for rel_path, raw in pairs:
                all_findings.append(_raw_to_finding(rule, raw, rel_path, None, None))

    # History scan
    if options.include_history:
        result.history_scanned = True
        history_findings, history_stats = _scan_history(
            root,
            active_rules,
            config,
            root_path=options.path,
        )
        stats.history_blobs_scanned = history_stats.get("blobs", 0)
        stats.history_commits_considered = history_stats.get("commits", 0)
        all_findings.extend(history_findings)

    _finish_scan(result, all_findings, active_rules, config, root, inventory, started, options)
    return result


def _finish_scan(
    result: ScanResult,
    findings: list[Finding],
    active_rules: list[Rule],
    config: Config,
    root: str,
    inventory: FileInventory,
    started: float,
    options: ScanOptions,
) -> None:
    result.findings = findings
    _apply_ignores(result, config)
    _filter_severity(result, config)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.findings.sort(
        key=lambda f: (
            severity_order.get(f.severity.value, 9),
            f.path,
            f.line or 0,
            f.rule_id,
        )
    )
    # Dedupe identical findings (same rule, path, line, fingerprint).
    seen: set[tuple[str, str, int | None, str]] = set()
    deduped: list[Finding] = []
    for f in result.findings:
        key = (f.rule_id, f.path, f.line, f.fingerprint)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    result.findings = deduped
    result.stats.duration_ms = int((time.perf_counter() - started) * 1000)
    _ = active_rules, root, inventory, options


def _scan_history(
    root: str,
    active_rules: list[Rule],
    config: Config,
    *,
    root_path: str,
) -> tuple[list[Finding], dict[str, Any]]:
    """Scan all reachable Git blobs for secrets and dangerous defaults."""
    findings: list[Finding] = []
    stats: dict[str, Any] = {"blobs": 0, "commits": 0}
    try:
        blobs, commit_count = enumerate_history_blobs(root, max_commits=config.max_commits)
    except Exception:
        return findings, stats
    if not blobs:
        return findings, {"blobs": 0, "commits": commit_count}
    stats["commits"] = commit_count

    content_rules = [r for r in active_rules if isinstance(r, ContentRule)]
    path_rules = [r for r in active_rules if isinstance(r, PathRule)]

    try:
        contents, truncated = read_history_blobs(root, blobs, max_blob_size=config.max_file_size)
    except Exception:
        return findings, stats
    if truncated:
        stats["truncated"] = True

    stats["blobs"] = len(contents)

    # Deterministic order for stable results
    for blob_sha in sorted(contents):
        data = contents[blob_sha]
        if b"\x00" in data[:8192]:
            continue  # binary blob
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()

        ctx = FileContext(
            rel_path=f"<history:{blob_sha[:12]}>",
            abs_path=root_path,
            size=len(data),
            tracked=None,
            language=None,
            text=text,
            lines=lines,
            repo_files=set(),
        )

        allow_lines: set[int] = set()
        for idx, line in enumerate(lines, start=1):
            if line_has_allow_marker(line):
                allow_lines.add(idx)

        commit = None
        for rule in content_rules:
            if not rule.applies(ctx):
                continue
            try:
                raws = rule.check_content(ctx)
            except Exception:
                continue
            hit = False
            for raw in raws:
                if raw.line is not None and raw.line in allow_lines:
                    continue
                if commit is None:
                    commit = attribute_blob_to_commit(root, blob_sha)
                findings.append(_raw_to_finding(rule, raw, ctx.rel_path, lines, commit))
                hit = True
            if hit:
                break  # one rule per blob is enough for history triage

    # History path rules are not useful (blob paths vary); skipped on purpose.
    _ = path_rules
    return findings, stats


def rule_count() -> int:
    return len(ALL_RULES)


def get_rule(rule_id: str) -> Rule | None:
    return RULES_BY_ID.get(rule_id)
