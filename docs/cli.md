# CLI reference

```
agentpreflight [--no-color] [--quiet] COMMAND [OPTIONS]
```

Global flags: `--no-color` (also honoured: `NO_COLOR`, `CLICOLOR=0`,
non-TTY), `--quiet/-q` (minimal output).

## `scan`

```bash
agentpreflight scan [PATH] [OPTIONS]
```

Scans a directory (default `.`) or a single file.

| Option | Values | Default | Meaning |
|---|---|---|---|
| `--format, -f` | text, json, sarif | text (or `[output] format`) | output format |
| `--output, -o` | PATH | stdout | write formatted output to a file |
| `--history` | flag | off | also scan full Git history |
| `--severity` | critical…info | info | minimum severity reported |
| `--fail-severity` | critical…info | high | exit-1 threshold |
| `--include-rule` | PATTERN (repeatable) | all | run only matching rules |
| `--exclude-rule` | PATTERN (repeatable) | none | skip matching rules |
| `--config` | PATH | discovered | explicit config file |
| `--no-git` | flag | auto | ignore Git; walk the filesystem |
| `--max-file-size` | BYTES | 10485760 | content size cap |
| `--workers` | N | auto | worker threads |
| `--no-progress` | flag | auto | suppress progress line |

Exit codes: `0` clean · `1` findings ≥ fail-severity · `2` operational error
(unreadable path, truncated scan) · `3` usage/config error · `130`
interrupted.

### Examples

```bash
# pre-release gate, fail on high+ findings
agentpreflight scan . --fail-severity high

# full audit including deleted-from-HEAD secrets
agentpreflight scan . --history

# machine output for tooling
agentpreflight scan . --format json --output report.json

# SARIF for GitHub code scanning
agentpreflight scan . --format sarif --output agentpreflight.sarif

# only secret rules, one directory, quiet
agentpreflight scan src --include-rule "APF-SEC-*" -q

# single file
agentpreflight scan config/settings.py
```

## `init`

```bash
agentpreflight init
```

Writes a commented starter `.agentpreflight.toml` in the current directory.
Fails (exit 2) if one already exists — existing configuration is never
overwritten.

## `doctor`

```bash
agentpreflight doctor
```

Environment diagnostics: Python/platform versions, git availability (needed
for `--history`), rule count, config discovery, and a self-test that scans a
synthetic AWS documentation key in a temp directory and verifies it is
detected **and redacted**. Exits 0 when healthy, 2 when a critical component
is missing.

## `rules`

```bash
agentpreflight rules list [--format table|json|markdown]
agentpreflight rules explain RULE_ID
```

`list` prints the catalog (table, JSON, or Markdown — the Markdown output
is how `docs/rules.md` is generated). `explain` shows description, severity,
confidence, remediation and references for one rule; exit 3 for unknown IDs.

## `version`

```bash
agentpreflight version
```

Prints the tool version plus the Python/platform it runs on.

## Behaviour notes

- **Non-interactive/CI safe**: colours and progress disable automatically
  when stdout/stderr are not TTYs; `--quiet` trims further.
- **Interruptions** (Ctrl-C) stop cleanly with a partial-results warning and
  exit 130.
- **Large repositories** hit the documented budgets (`max_files`,
  `max_file_size`, history budgets) and degrade loudly, never hang.
- **No terminal leakage**: file names and snippets are sanitised against
  escape sequences; secrets are always redacted.
