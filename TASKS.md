# TASKS.md — engineering checklist

Living record of the 0.1.0 build. Status reflects verified work only:
✅ implemented **and** tested; ⚠️ implemented with documented limitations;
⬜ not done (tracked in ROADMAP.md instead of this file).

## 1. Research & scope

- ✅ Competitive research with primary sources → `docs/comparison.md`
- ✅ Defensible scope defined (offline pre-release readiness gate)
- ✅ Out-of-scope areas documented (SAST, advisories, live verification)

## 2. Core engine

- ✅ File inventory via `git ls-files` (tracked + untracked-not-ignored) with
  filesystem fallback
- ✅ Path validation against traversal (`../`, absolute, NUL)
- ✅ Symlinks never followed (walk + git modes)
- ✅ Binary detection (NUL / control-ratio heuristic)
- ✅ Resource limits: max file size, max files, history budgets
- ✅ Rule kinds: content / path / repo-level
- ✅ Rule crash isolation (degrades to informational finding)
- ✅ Threaded content scanning (auto workers, deterministic results)
- ✅ Severity ordering, dedupe by fingerprint
- ✅ Inline allow markers (`# agentpreflight: allow`)

## 3. Detection rules

- ✅ 20 secret rules (structural + generic entropy-gated)
- ✅ 8 artifact rules (path + repo-level)
- ✅ 12 insecure-default rules
- ✅ 7 supply-chain rules
- ✅ Registry with id/prefix/category validation
- ✅ Severity + confidence documented per rule

## 4. Outputs

- ✅ Text renderer (colour-safe, CI-safe, no secrets)
- ✅ JSON (stable schema, redaction verified by tests)
- ✅ SARIF 2.1.0 (rules + results + fingerprints + relative URIs)
- ✅ Terminal escape-sequence sanitisation
- ✅ Stable exit codes (0/1/2/3/130) tested

## 5. Git history

- ✅ Blob enumeration deduped by SHA (`rev-list --objects --no-object-names`)
- ✅ Batch content read with per-blob + total memory budgets, deadlock-safe
- ✅ Commit attribution via `git log --find-object`
- ✅ `max_commits` truncation with reporting

## 6. Configuration

- ✅ `.agentpreflight.toml` (tomllib on 3.11+, vendored subset on 3.10)
- ✅ Strict validation (unknown keys, types, severities)
- ✅ Documented `[[ignore]]` with mandatory reason + optional expiry
- ✅ Blanket suppression requires explicit `allow_all = true`
- ✅ CLI overrides with clear precedence

## 7. Testing

- ✅ 390 tests, all passing on Linux/Python 3.12 (CI adds 3.10/3.11/3.13
  and macOS/Windows)
- ✅ Every rule: positive + negative fixtures
- ✅ False-positive corpus (placeholders, docs examples)
- ✅ Redaction assertions across all output channels
- ✅ Terminal injection, traversal, symlink, large-file tests
- ✅ Exit-code + usage-error tests (subprocess e2e)
- ✅ Config validation failure matrix
- ✅ Ruff (lint + format) clean; mypy strict clean

## 8. Documentation

- ✅ README (EN canonical) + README.id.md (Indonesian)
- ✅ docs/: comparison, rules (auto-generated), supported-languages,
  configuration, cli, ci-cd, security-model, architecture,
  false-positives, troubleshooting, testing, benchmark, releasing, faq
- ✅ CONTRIBUTING (incl. rule-writing guide), SECURITY, CODE_OF_CONDUCT,
  GOVERNANCE, THIRD_PARTY_NOTICES, CHANGELOG, ROADMAP
- ✅ Honest limitations section; no documented-but-missing features

## 9. CI/CD & distribution

- ✅ ci.yml: lint + mypy + test matrix + packaging verification
- ✅ self-scan.yml: repository scans itself via its own composite action
  and uploads SARIF to code scanning
- ✅ release.yml: build + verify + checksums + GitHub release on tags
- ⚠️ PyPI publication prepared but disabled until trusted publishing is
  configured (documented in release.yml + docs/releasing.md)
- ✅ Third-party Actions pinned to verified commit SHAs
- ✅ Least-privilege workflow permissions

## 10. Release readiness checklist (per docs/releasing.md)

- ✅ Clean-env wheel install verified in CI (fresh venv + version/doctor)
- ✅ Core commands exercised end-to-end
- ✅ Redaction verified in all formats
- ✅ Exit codes stable and tested
- ⬜ First tagged release cut (maintainer action after CI proves green
  on the pushed default branch)
- ⬜ PyPI listing (blocked on trusted publishing, see above)
