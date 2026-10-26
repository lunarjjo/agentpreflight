"""Human-readable terminal output.

Security properties:
- all dynamic text is sanitised against escape-sequence injection
- secret values are already redacted upstream; snippets additionally
  mask the matched span
- colours are disabled automatically when stdout is not a TTY or when
  NO_COLOR/CLICOLOR=0 is set (CI-friendly)
"""

from __future__ import annotations

import os
import sys
from typing import IO

from agentpreflight.models import Finding, ScanResult, Severity
from agentpreflight.redact import sanitize_for_terminal

WIDTH = 72

SEVERITY_STYLES = {
    "critical": ("CRITICAL", "\033[97;41m"),
    "high": ("HIGH", "\033[91m"),
    "medium": ("MEDIUM", "\033[93m"),
    "low": ("LOW", "\033[94m"),
    "info": ("INFO", "\033[92m"),
}

RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"


def _enable_ansi(no_color_flag: bool, stream: IO[str] | None) -> bool:
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("CLICOLOR") == "0":
        return False
    if stream is None or not stream.isatty():
        return False
    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            return os.environ.get("WT_SESSION") is not None
    return True


class Renderer:
    def __init__(self, no_color: bool = False, stream: IO[str] | None = None):
        self.stream = stream or sys.stdout
        self.color = _enable_ansi(no_color, self.stream)

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def header(self, tool_version: str, root: str, history: bool) -> None:
        hist = " (+ full history)" if history else ""
        print(
            f"{self._c(BOLD, f'AgentPreflight {tool_version}')} — scanning {sanitize_for_terminal(root)}{hist}",
            file=self.stream,
        )

    def finding(self, finding: Finding) -> None:
        label, style = SEVERITY_STYLES[finding.severity.value]
        sev = self._c(style, label.ljust(8))
        location = finding.path
        if finding.line:
            location += f":{finding.line}"
        if finding.commit:
            location += f" @ {finding.commit[:10]}"
        loc = self._c(BOLD, sanitize_for_terminal(location))
        print(f"{sev} {finding.rule_id}  {loc}", file=self.stream)
        print(f"{' ' * 9}{finding.message}", file=self.stream)
        if finding.secret_preview:
            print(
                f"{' ' * 9}value: {self._c(DIM, sanitize_for_terminal(finding.secret_preview))} (redacted)",
                file=self.stream,
            )
        if finding.raw_line:
            snippet = finding.raw_line.strip()[:120]
            print(f"{' ' * 11}{self._c(DIM, snippet)}", file=self.stream)

    def summary(self, result: ScanResult) -> None:
        counts = result.summary()
        print(self._c(DIM, "─" * WIDTH), file=self.stream)
        parts = []
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts[sev]:
                _, style = SEVERITY_STYLES[sev]
                parts.append(self._c(style, f"{counts[sev]} {sev}"))
        print(f"  {(' · '.join(parts)) if parts else 'no findings'}", file=self.stream)
        stats = result.stats
        detail = (
            f"{stats.files_scanned} files scanned · "
            f"{stats.files_skipped_size} skipped (size) · "
            f"{stats.duration_ms / 1000:.1f}s"
        )
        if result.history_scanned:
            detail += f" · history: {stats.history_commits_considered} commits, {stats.history_blobs_scanned} blobs"
        print(f"  {self._c(DIM, detail)}", file=self.stream)

    def diagnostics(self, result: ScanResult) -> None:
        for error in result.errors:
            print(
                f"  {self._c(SEVERITY_STYLES['high'][1], 'error:')} {sanitize_for_terminal(error)}",
                file=self.stream,
            )
        for warning in result.warnings:
            print(
                f"  {self._c(SEVERITY_STYLES['medium'][1], 'warn:')}  {sanitize_for_terminal(warning)}",
                file=self.stream,
            )

    def exit_notice(self, fail_severity: Severity, exit_code: int) -> None:
        if exit_code == 1:
            print(
                f"\n  findings at or above {fail_severity.value.upper()} — failing (exit 1)",
                file=self.stream,
            )
            print(
                "  fix the findings, or document suppressions in .agentpreflight.toml",
                file=self.stream,
            )


def render(
    result: ScanResult,
    *,
    tool_version: str,
    fail_severity: Severity,
    exit_code: int,
    no_color: bool = False,
    quiet: bool = False,
    stream: IO[str] | None = None,
) -> None:
    renderer = Renderer(no_color=no_color, stream=stream)
    if not quiet:
        renderer.header(tool_version, result.root, result.history_scanned)
        print(file=renderer.stream)
    if result.findings:
        for finding in result.findings:
            renderer.finding(finding)
            print(file=renderer.stream)
    elif not quiet:
        print("  no findings at the configured severity threshold", file=renderer.stream)
        print(file=renderer.stream)
    if not quiet:
        renderer.summary(result)
    if result.errors or result.warnings:
        renderer.diagnostics(result)
    renderer.exit_notice(fail_severity, exit_code)
