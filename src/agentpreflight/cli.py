"""Command-line interface.

Commands
--------
``scan``      scan a path (working tree and optionally full Git history)
``init``      write a starter ``.agentpreflight.toml``
``doctor``    environment diagnostics
``rules``     list rules or explain one rule in detail
``version``   print version information

Exit codes
----------
0  no findings at or above the failure threshold
1  findings at or above the failure threshold
2  operational error (unreadable path, I/O failure, ...)
3  usage or configuration error
130  interrupted
"""

from __future__ import annotations

import argparse
import json as jsonlib
import os
import platform
import shutil
import sys
from collections.abc import Callable, Sequence
from typing import NoReturn

from agentpreflight import __version__
from agentpreflight.config import (
    CONFIG_FILENAME,
    DEFAULT_CONFIG_TEMPLATE,
    Config,
    ConfigError,
    find_config,
    load_config_file,
)
from agentpreflight.engine import ScanOptions, run_scan
from agentpreflight.models import Severity
from agentpreflight.output import render_json, render_sarif, render_text
from agentpreflight.rules.registry import ALL_RULES, RULES_BY_ID

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_USAGE = 3
EXIT_INTERRUPTED = 130


class Parser(argparse.ArgumentParser):
    """argparse parser that exits with the documented usage code 3."""

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)


def build_parser() -> Parser:
    parser = Parser(
        prog="agentpreflight",
        description="Local-first repository security and pre-release readiness scanner.",
    )
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--quiet", "-q", action="store_true", help="minimal output")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a directory or file")
    scan.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: .)")
    scan.add_argument(
        "--format",
        "-f",
        choices=("text", "json", "sarif"),
        default=None,
        help="output format (default: text, or [output] format from config)",
    )
    scan.add_argument("--output", "-o", default=None, help="write output to a file instead of stdout")
    scan.add_argument("--history", action="store_true", help="also scan full Git history (requires git)")
    scan.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        default=None,
        help="minimum severity to report (default: info)",
    )
    scan.add_argument(
        "--fail-severity",
        choices=[s.value for s in Severity],
        default=None,
        help="exit 1 when findings exist at or above this severity (default: high)",
    )
    scan.add_argument(
        "--include-rule",
        action="append",
        default=None,
        metavar="PATTERN",
        help="include only rules matching (repeatable, fnmatch)",
    )
    scan.add_argument(
        "--exclude-rule",
        action="append",
        default=None,
        metavar="PATTERN",
        help="exclude rules matching (repeatable, fnmatch)",
    )
    scan.add_argument(
        "--config",
        default=None,
        metavar="PATH",
        help="explicit configuration file (default: .agentpreflight.toml in the scan path)",
    )
    scan.add_argument("--no-git", action="store_true", help="ignore Git; walk the filesystem directly")
    scan.add_argument(
        "--max-file-size",
        type=int,
        default=None,
        metavar="BYTES",
        help="skip content of files larger than this (default: 10485760)",
    )
    scan.add_argument("--workers", type=int, default=None, metavar="N", help="worker threads (default: auto)")
    scan.add_argument("--no-progress", action="store_true", help=argparse.SUPPRESS)

    sub.add_parser("init", help=f"write a starter {CONFIG_FILENAME} in the current directory")

    sub.add_parser("doctor", help="environment diagnostics")

    rules = sub.add_parser("rules", help="inspect the rule catalog")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    rules_list = rules_sub.add_parser("list", help="list all rules")
    rules_list.add_argument("--format", choices=("table", "json", "markdown"), default="table")
    rules_explain = rules_sub.add_parser("explain", help="explain one rule in detail")
    rules_explain.add_argument("rule_id", metavar="RULE_ID")

    sub.add_parser("version", help="print version information")
    return parser


def _load_effective_config(args: argparse.Namespace, scan_root: str) -> tuple[Config, str | None]:
    """Merge config file (if any) with CLI overrides."""
    config = Config()
    source = None
    if getattr(args, "config", None):
        source = args.config
        config, _ = load_config_file(source)
    else:
        found = find_config(scan_root)
        if found is not None:
            source = str(found)
            config, _ = load_config_file(found)

    if getattr(args, "severity", None):
        config.severity = Severity.parse(args.severity)
    if getattr(args, "fail_severity", None):
        config.fail_severity = Severity.parse(args.fail_severity)
    if getattr(args, "include_rule", None):
        config.include_rules = list(args.include_rule)
    if getattr(args, "exclude_rule", None):
        config.exclude_rules = list(args.exclude_rule)
    if getattr(args, "max_file_size", None) is not None:
        if args.max_file_size <= 0:
            raise ConfigError("--max-file-size must be positive")
        config.max_file_size = args.max_file_size
    if getattr(args, "workers", None) is not None:
        if args.workers < 0:
            raise ConfigError("--workers must be >= 0")
        config.workers = args.workers
    return config, source


def _progress(no_color: bool) -> tuple[Callable[[int, int], None], dict[str, bool]]:
    """Simple stderr progress counter for long scans."""
    state = {"shown": False}

    def cb(done: int, total: int) -> None:
        if not sys.stderr.isatty():
            return
        sys.stderr.write(f"\r  scanning… {done}/{total}")
        sys.stderr.flush()
        state["shown"] = True

    return cb, state


def cmd_scan(args: argparse.Namespace) -> int:
    path = os.path.abspath(os.path.expanduser(args.path))
    if not os.path.exists(path):
        print(f"error: scan path does not exist: {args.path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        config, _source = _load_effective_config(args, path)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"error: cannot read configuration: {exc}", file=sys.stderr)
        return EXIT_ERROR

    fmt = args.format or config.format
    if fmt not in ("text", "json", "sarif"):
        print(f"error: unknown format {fmt!r}", file=sys.stderr)
        return EXIT_USAGE

    progress_cb, progress_state = _progress(args.no_color)

    options = ScanOptions(
        path=path,
        config=config,
        include_history=args.history,
        no_git=args.no_git,
        quiet=args.quiet or fmt != "text",
        on_progress=None if (args.no_progress or args.quiet or fmt != "text") else progress_cb,
    )

    try:
        result = run_scan(options)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if progress_state["shown"]:
        sys.stderr.write("\r" + " " * 40 + "\r")

    exit_code = EXIT_OK
    if result.has_findings_at_or_above(config.fail_severity):
        exit_code = EXIT_FINDINGS
    elif result.errors:
        exit_code = EXIT_ERROR

    if fmt == "json":
        payload = render_json(result)
    elif fmt == "sarif":
        payload = render_sarif(result)
    else:
        render_text(
            result,
            tool_version=__version__,
            fail_severity=config.fail_severity,
            exit_code=exit_code,
            no_color=args.no_color,
            quiet=args.quiet,
        )
        return exit_code

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.write("\n")
    else:
        print(payload)
    return exit_code


def cmd_init(args: argparse.Namespace) -> int:
    target = os.path.join(os.getcwd(), CONFIG_FILENAME)
    if os.path.exists(target):
        print(f"error: {CONFIG_FILENAME} already exists here (not overwritten)", file=sys.stderr)
        return EXIT_ERROR
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(DEFAULT_CONFIG_TEMPLATE)
    print(f"written {CONFIG_FILENAME} — edit it to match your project")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    from agentpreflight.rules.registry import ALL_RULES as rules

    git_note = f"found: {_git_version()}" if shutil.which("git") else "NOT found — --history will be unavailable"
    checks = [
        (True, f"python {platform.python_version()} ({sys.version.split()[0]})"),
        (True, f"platform {sys.platform} ({platform.system()} {platform.release()})"),
        (shutil.which("git") is not None, f"git binary {git_note}"),
        (rules is not None, f"{len(rules)} detection rules loaded"),
    ]
    cfg = find_config(os.getcwd())
    checks.append((True, f"config file: {cfg if cfg else 'not found (defaults active)'}"))

    exit_code = EXIT_OK
    for ok, message in checks:
        mark = "ok " if ok else "!! "
        print(f"  [{mark}] {message}")
        if not ok:
            exit_code = EXIT_ERROR

    # quick self-test: scan a temp dir with a synthetic secret
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        synthetic = os.path.join(tmp, "synthetic.txt")
        with open(synthetic, "w", encoding="utf-8") as fh:
            fh.write(
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"  # agentpreflight: allow
            )
        result = run_scan(ScanOptions(path=tmp, config=Config(), no_git=True, quiet=True))
        detected = any(f.rule_id == "APF-SEC-001" for f in result.findings)
        checks_ok = detected
        print(f"  [{'ok ' if checks_ok else '!! '}] self-test: synthetic AWS example key detected and redacted")
        if not checks_ok:
            exit_code = EXIT_ERROR
    return exit_code


def _git_version() -> str:
    import subprocess

    try:
        out = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10, check=False)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def cmd_rules(args: argparse.Namespace) -> int:
    if args.rules_command == "list":
        if args.format == "json":
            print(jsonlib.dumps([r.metadata() for r in ALL_RULES], indent=2, ensure_ascii=False))
        elif args.format == "markdown":
            print("# Rule catalog")
            print()
            print(f"Auto-generated from the rule registry ({len(ALL_RULES)} rules).")
            print("Regenerate with `agentpreflight rules list --format markdown > docs/rules.md`.")
            print()
            for rule in ALL_RULES:
                meta = rule.metadata()
                print(f"## {meta['id']} — {meta['name']}")
                print()
                print(f"- **Severity:** {meta['severity']}")
                print(f"- **Confidence:** {meta['confidence']}")
                print(f"- **Category:** {meta['category']}")
                print(f"- **Applies to:** {meta['applies_to']}")
                print()
                print(f"{meta['description']}")
                if meta["remediation"]:
                    print()
                    print(f"**Remediation:** {meta['remediation']}")
                if meta["references"]:
                    print()
                    for ref in meta["references"]:
                        print(f"- <{ref}>")
                print()
        else:
            print(f"  {'RULE ID':<14} {'SEV':<9} {'CONF':<7} CATEGORY   NAME")
            for rule in ALL_RULES:
                print(
                    f"  {rule.id:<14} {rule.severity.value:<9} {rule.confidence.value:<7} "
                    f"{rule.category:<10} {rule.name}"
                )
        return EXIT_OK

    if args.rules_command == "explain":
        matched = RULES_BY_ID.get(args.rule_id)
        if matched is None:
            print(f"error: unknown rule id: {args.rule_id}", file=sys.stderr)
            print(
                f"run `agentpreflight rules list` to see all {len(ALL_RULES)} rules",
                file=sys.stderr,
            )
            return EXIT_USAGE
        meta = matched.metadata()
        print(f"{meta['id']} — {meta['name']}")
        print()
        print(f"severity:   {meta['severity']}")
        print(f"confidence: {meta['confidence']}")
        print(f"category:   {meta['category']}")
        print(f"applies to: {meta['applies_to']}")
        print()
        print(meta["description"])
        print()
        if meta["remediation"]:
            print("remediation:")
            print(f"  {meta['remediation']}")
        if meta["references"]:
            print()
            print("references:")
            for ref in meta["references"]:
                print(f"  - {ref}")
        return EXIT_OK
    return EXIT_USAGE


def cmd_version(args: argparse.Namespace) -> int:
    print(f"agentpreflight {__version__}")
    print(f"python {platform.python_version()} on {platform.system()} {platform.release()}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "init":
            return cmd_init(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "version":
            return cmd_version(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover
        return EXIT_OK
    parser.error(f"unknown command: {args.command}")
    raise SystemExit(EXIT_USAGE)  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
