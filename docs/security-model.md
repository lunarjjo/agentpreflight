# Security and privacy model

This document describes exactly what AgentPreflight does with your data —
and what it never does. It is part of the release contract: changes here are
release-noteworthy.

## Threat model: repository content is hostile

Everything scanned is treated as untrusted input:

| Threat | Mitigation | Test coverage |
|---|---|---|
| Path traversal via crafted Git index entries (`../evil`, absolute paths, NUL bytes) | every candidate path is validated to be safe and root-relative before any filesystem access | `test_walker.py::TestValidateRelative` |
| Symlink escapes out of the scan root | symlinks are never followed in either enumeration mode | `test_walker.py::test_walk_never_follows_symlinks` |
| Binary/malformed files | NUL-byte + control-ratio detection skips content; decode uses `errors="replace"` | `test_walker.py::TestBinaryDetection` |
| Resource exhaustion | per-file size cap, total file-count cap, per-blob and total history memory budgets, worker bound | `test_engine.py::TestLimits` |
| Terminal escape-sequence injection (file names or content containing ANSI/bidi control chars) | all dynamic output passes through `sanitize_for_terminal` | `test_output.py::test_terminal_injection_sanitised` |
| Secret leakage through any output channel | redaction is unconditional and structurally enforced: `Finding` keeps only a prefix+fingerprint preview, snippet spans are masked | `test_output.py`, `test_engine.py::TestRedactionEndToEnd` |
| Scanner executing scanned code | the scanner never runs, installs or builds repository content; the only subprocess used is `git` itself for history operations | by construction (see `gitscan.py`) |
| Malicious rule crash taking the scan down | rule exceptions are isolated and reported as informational findings | `test_engine.py::TestRuleResilience` |
| Suppression disabling all checks silently | blanket `rule_id = "*"` ignores require explicit `allow_all = true` and a mandatory reason | `test_config.py` |

## Privacy

- **No network access.** v0.1.0 contains no code path that performs a
  network request. No telemetry, crash reporting or update checks exist.
- **No data leaves the machine.** Findings are written to stdout/stderr or
  the file you choose with `--output`. History scanning talks to the local
  `git` binary only.
- **No API keys or accounts** are required for any core functionality.

Planned integrations that would require the network (OSV lookup,
TruffleHog verification hand-off) are explicitly designed as opt-in flags
with network disclosure — see ROADMAP.md. If they ship, this document ships
with them.

## Redaction specification

- Preview: at most the first **4 characters** (fewer for short values) plus
  `…` plus an 8-hex-character SHA-256 fingerprint, e.g. `AKIA…1a5d44a2`.
- Snippets: the matched span is replaced with `****REDACTED****` in all
  rendered formats.
- JSON/SARIF: carry `secret_preview` and `fingerprint` fields only; the
  full value is never serialised.
- History findings attribute a commit SHA but never the secret content.
- There is **no flag** to disable redaction. Triage uses the fingerprint to
  match the value against your secret manager without re-leaking it.

## CI safety of this repository

- Workflows apply least-privilege permissions (`contents: read` by
  default; `security-events: write` only in the SARIF-upload job).
- Third-party Actions are pinned to verified commit SHAs.
- Untrusted pull-request code never runs in a workflow holding secrets:
  the self-scan runs on the merge target, and no `pull_request_target`
  pattern is used anywhere.
- The repository scans itself on every push (`.github/workflows/self-scan.yml`).

## Trust boundaries summary

```
Your repository (untrusted)
   │  read-only, budgeted
   ▼
AgentPreflight process (never executes repo content; only git subprocess)
   │  redacted findings only
   ▼
stdout / stderr / your --output file (never the network)
```
