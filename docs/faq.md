# FAQ

## Does AgentPreflight send my code anywhere?

No. v0.1.0 contains no network code path at all — no telemetry, no update
checks, no uploads. See docs/security-model.md.

## Can it verify whether a leaked key still works?

No, and by design. Verification requires calling the provider (network).
Use TruffleHog for that step; AgentPreflight stays offline.

## How is this different from Gitleaks?

Gitleaks is an excellent dedicated secret scanner — in maintenance mode.
AgentPreflight covers secrets *plus* sensitive artifacts, insecure
defaults, CI-safety and repo hygiene in one offline gate, with an honest
capability matrix and SARIF output. Full comparison with sources:
docs/comparison.md.

## Why zero dependencies?

A supply-chain safety tool that itself drags in a dependency tree is a
liability (and an ironic one). Zero deps = trivial install, fast CI, small
audit surface, and no transitive supply-chain risk.

## A finding points at a documentation example. Bug?

No — a well-formed example token is indistinguishable from a real one by
structure. Add `# agentpreflight: allow` on that line, or an `[[ignore]]`
with a reason. docs/false-positives.md covers the escalation order.

## Why did my scan exit 1 when the output looks fine?

Exit 1 means findings exist at or above `fail-severity` (default `high`).
Check the summary line ("N high · ..."), or lower the threshold with
`--fail-severity medium` if that matches your policy.

## Does `--history` rewrite my Git repository?

Never. It only reads objects (via `git rev-list`/`cat-file`/`log`).
Removing secrets from history is a separate, deliberate action with
`git filter-repo` or BFG.

## Python 3.10 shows a warning about TOML?

It doesn't — 3.10 transparently uses the vendored `_toml_lite` subset
parser, which tests verify against `tomllib` on every shipped config
example. Only if you hand-write TOML outside the documented subset will you
get a precise parse error.

## SARIF import fails on my platform

GitHub code scanning is verified in this repository's own CI
(self-scan.yml). Other platforms read SARIF 2.1.0 natively — if one
rejects the output, file an issue with the validation error text.

## Can I write rules in YAML/regex only, without Python?

Not in v0.1 — rules are typed, tested Python classes (about 50 lines with
metadata; guide in CONTRIBUTING.md). This guarantees rule code goes through
the same lint/type/test gates as the core. A declarative rule-pack format
is a roadmap item.

## How do I suppress one specific line?

```python
password = "hunter2"  # agentpreflight: allow
```

The marker is case-insensitive and works in any comment style.

## Why is `node_modules` only one finding?

Repo-level rules fire once per directory, not per file — a committed
`node_modules` is one decision, one finding, one remediation.

## Indonesian documentation?

README.id.md ships with the project; deep technical docs are
English-canonical for now (localisation expansion is roadmap).
