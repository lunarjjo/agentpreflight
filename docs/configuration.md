# Configuration reference

AgentPreflight looks for `.agentpreflight.toml` at the scan root (the
directory you point `scan` at). `--config PATH` overrides discovery. Create
a starter file with `agentpreflight init`.

On Python 3.11+ the file is parsed with the standard library's `tomllib`;
on 3.10 a vendored parser handles the documented subset (tests verify both
agree on every shipped example). Validation is strict — unknown keys and
invalid values fail with exit code 3, never silently.

## Reference

```toml
[scan]
# Minimum severity to REPORT: critical | high | medium | low | info
severity = "info"

# Exit code 1 when findings exist AT OR ABOVE this severity
fail_severity = "high"

# Skip content scanning of files larger than this (bytes). Path rules
# still apply. 10 MiB default.
max_file_size = 10485760

# Hard cap on files considered; exceeding it truncates the scan with an
# error and partial results.
max_files = 50000

# Maximum commits inspected with --history.
max_commits = 5000

# Worker threads for content scanning. 0 = auto.
workers = 0

# Rule selection (fnmatch patterns; --include-rule/--exclude-rule
# override these).
# include_rules = ["APF-SEC-*"]
# exclude_rules = ["APF-DEP-002"]

# Path exclusions (fnmatch; matched against the whole path AND each
# segment, so "vendor" excludes any depth).
# exclude_paths = ["vendor", "tests/fixtures/**"]

[output]
# text | json | sarif (--format overrides)
format = "text"
# Secrets are ALWAYS redacted; this also masks weak/default credential
# values in printed snippets. There is no option to disable redaction.
redact = true

# Documented suppressions. 'reason' is MANDATORY.
[[ignore]]
path = "tests/fixtures/**"        # fnmatch against paths
rule_id = "APF-SEC-*"             # fnmatch against rule IDs
reason = "Synthetic secrets used as test fixtures"   # required
expires = "2027-12-31"            # optional: entry becomes inactive + warns
# allow_all = true                # required ONLY when rule_id = "*"
```

## Semantics

| Area | Behaviour |
|---|---|
| Precedence | CLI flags > config file > defaults |
| Severity filter | findings below `severity` are not reported at all |
| Fail threshold | exit 1 when any finding ≥ `fail_severity` |
| `include_rules` | when non-empty, ONLY matching rules run |
| `exclude_rules` | always wins over include |
| `exclude_paths` | removes files before any rule runs (path and content) |
| `[[ignore]]` | removes findings AFTER detection, with a visible warning line |
| `expires` | date (YYYY-MM-DD) after which the entry is ignored again, loudly |

## Inline suppression

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # agentpreflight: allow
```

Any line containing the (case-insensitive) marker suppresses content-rule
findings on that line only. Works in any comment syntax (`#`, `//`, `<!--`,
`/*`, `--`) because it is matched as plain text. Path rules (file-name
based) are not affected by line markers — use a documented ignore for those.

## Safety rails

- A suppression with `rule_id = "*"` (all rules) is rejected unless
  `allow_all = true` is set — blanket suppression is always a deliberate,
  reviewable choice.
- Every `[[ignore]]` must carry a non-empty `reason`.
- Unknown keys are hard errors, so typos cannot silently disable limits.

## Examples per project type

**Node service with vendored fixtures:**

```toml
[scan]
fail_severity = "high"
exclude_paths = ["coverage", "dist"]

[[ignore]]
path = "test/fixtures/**"
rule_id = "APF-SEC-*"
reason = "synthetic tokens for unit tests"
expires = "2027-06-30"
```

**Python library, strict:**

```toml
[scan]
severity = "low"
fail_severity = "medium"
max_commits = 20000

[[ignore]]
path = "docs/examples/*.md"
rule_id = "APF-SEC-001"
reason = "AWS documentation example key in tutorial"
```

**Monorepo subdirectory (scan a package only):**

```toml
[scan]
exclude_paths = ["generated", "third_party"]
```

```bash
agentpreflight scan services/api --config deploy/agentpreflight.toml
```

## Verifying your config

```bash
agentpreflight doctor     # reports whether a config was found and parses
agentpreflight scan .     # config errors exit 3 with a precise message
```
