# AgentPreflight

[![CI](https://github.com/lunarjjo/agentpreflight/actions/workflows/ci.yml/badge.svg)](https://github.com/lunarjjo/agentpreflight/actions/workflows/ci.yml)
[![Self-scan](https://github.com/lunarjjo/agentpreflight/actions/workflows/self-scan.yml/badge.svg)](https://github.com/lunarjjo/agentpreflight/actions/workflows/self-scan.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-success)](pyproject.toml)

**Local-first repository security and pre-release readiness scanner.** AgentPreflight finds exposed secrets, sensitive artifacts, insecure defaults and supply-chain hygiene risks **before** you publish, deploy or release — entirely offline, with redacted output and zero runtime dependencies.

> 🌐 **Languages / Bahasa**: **English** · [Bahasa Indonesia 🇮🇩](README.id.md) · *more translations welcome*

---

## Why another scanner?

AgentPreflight is not another secret-detection engine, and it does not try to replace your SAST. It is the **pre-release readiness gate** that existing tools leave uncovered — one fast, offline, private command that answers: *"is this repository safe to ship right now?"*

- **Gitleaks / TruffleHog** scan for secrets (and verify them in TruffleHog's case, via network calls). They don't assess artifacts, insecure defaults or CI safety, and Gitleaks is now in maintenance-only "feature complete" mode.
- **Semgrep** does deep taint analysis — but its OSS engine is single-file, and writing rules requires expertise.
- **OSV-Scanner / Trivy / Dependabot** answer "are my dependencies vulnerable?" — but only with network access and downloaded databases.
- **Repolinter** (repository hygiene) is archived.

No surveyed tool combines secret scanning + sensitive artifacts + insecure defaults + CI safety + repo hygiene in one **offline** gate. That is AgentPreflight's scope — see the [full comparison](docs/comparison.md) with verified sources.

**Out of scope, by design:** vulnerability-advisory lookup (use OSV-Scanner/Trivy), deep taint analysis (use Semgrep), and "is this secret still live?" verification (use TruffleHog, which makes API calls).

## What it detects (47 rules)

| Category | Examples | Count |
|---|---|---|
| **Secrets** (`APF-SEC-*`) | AWS/GitHub/Slack/Stripe/OpenAI/GitLab/npm/PyPI/SendGrid/Telegram/Shopify/Azure/Square/Meta tokens, private keys, JWTs, URLs with embedded credentials, generic high-entropy assignments | 20 |
| **Artifacts** (`APF-ART-*`) | `.env` files, private keys/keystores, `.netrc`/`.aws/credentials`/`.docker/config.json`, SQL dumps, `.DS_Store`, committed `node_modules`/IDE dirs | 8 |
| **Insecure defaults** (`APF-DEF-*`) | Django `DEBUG=True`, `verify=False`, SSL bypass, CORS `*`, weak/default passwords, Ansible `host_key_checking=False`, Dockerfiles running as root, unsafe Kubernetes settings, MD5/SHA-1, JWT `none` | 12 |
| **Supply chain** (`APF-DEP-*`) | curl-to-shell pipelines, unpinned requirements, `pull_request_target` + PR checkout (critical CI escape), `permissions: write-all`, unpinned Actions, missing lockfile, npm install hooks | 7 |

Severity model: `critical` / `high` / `medium` / `low` / `info` — criteria documented in [docs/rules.md](docs/rules.md). Full catalog: `agentpreflight rules list`.

## Install

**Requirements:** Python 3.10+ (3.11+ uses stdlib TOML; 3.10 uses the built-in fallback parser). No other dependencies.

```bash
# from the repository (recommended until the first tagged release)
python -m pip install "git+https://github.com/lunarjjo/agentpreflight"

# or from a checkout
python -m pip install .
```

Verify:

```bash
agentpreflight version
agentpreflight doctor
```

## Quick start

```bash
agentpreflight scan .                     # scan the working tree
agentpreflight scan . --history           # + full git history (deleted secrets included)
agentpreflight scan . --format json       # machine-readable output
agentpreflight scan . --format sarif      # SARIF 2.1.0 for code scanning
agentpreflight init                       # write .agentpreflight.toml
agentpreflight rules list                # catalog of all rules
agentpreflight rules explain APF-SEC-007  # one rule in detail
agentpreflight doctor                     # environment diagnostics + self-test
```

Example output (secret values always redacted):

```
AgentPreflight 0.1.0 — scanning /project

CRITICAL APF-SEC-007  config/server.pem:1
         Private key material detected
           [REDACTED:ssh_private_key]

HIGH     APF-SEC-009  .env:1
         URL with embedded credentials detected
         value: post…8b0111bc (redacted)
           DB_URL=****REDACTED****

────────────────────────────────────────────────────────────────────────
  1 critical · 1 high
  42 files scanned · 0 skipped (size) · 0.4s

  findings at or above HIGH — failing (exit 1)
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no findings at/above the failure threshold |
| 1 | findings at/above the failure threshold (default: `high`) |
| 2 | operational error (unreadable path, partial scan) |
| 3 | usage or configuration error |
| 130 | interrupted |

### Suppressing false positives

Inline (preferred for documentation examples):

```python
api_key = "AKIAIOSFODNN7EXAMPLE"  # agentpreflight: allow
```

Or documented, expiring suppressions in `.agentpreflight.toml`:

```toml
[[ignore]]
path = "tests/fixtures/**"
rule_id = "APF-SEC-*"
reason = "Synthetic secrets used as test fixtures"
expires = "2027-12-31"
```

Suppressing **all** rules for a path requires an explicit `allow_all = true` — blanket ignores never happen silently. See [docs/configuration.md](docs/configuration.md) and [docs/false-positives.md](docs/false-positives.md).

## Use in CI (GitHub Actions)

```yaml
- name: AgentPreflight
  uses: lunarjjo/agentpreflight@main  # pin to a tag/SHA once v0.1.0 is released
  with:
    fail-severity: high
    sarif: agentpreflight.sarif

- uses: github/codeql-action/upload-sarif@v3.28.15
  if: always()
  with:
    sarif_file: agentpreflight.sarif
```

Inputs: `path`, `fail-severity`, `severity`, `history`, `sarif`, `exclude-rules`. Outputs: `findings-count`, `exit-code`. Full reference in [docs/ci-cd.md](docs/ci-cd.md) — this repository scans itself with this action on every push (see [self-scan.yml](.github/workflows/self-scan.yml)).

## Security & privacy model

- **Local-first.** Ordinary scans never touch the network — no telemetry, no API keys, no uploads. No network-dependent feature exists in v0.1.0.
- **Redaction is unconditional.** Detected values never appear in terminal, JSON or SARIF output — only a short prefix plus a fingerprint (`AKIA…1a5d44a2`) for triage.
- **Untrusted input handling.** Repository content is treated as hostile: symlinks are never followed, index paths are validated against traversal, file/count budgets are enforced, terminal escape sequences are sanitised, and rules that crash degrade to an informational "please report" finding instead of aborting the scan.
- **The scanner never executes scanned code** and never modifies your files.

Full model: [docs/security-model.md](docs/security-model.md) · Report vulnerabilities: [SECURITY.md](SECURITY.md) (private advisory form, please).

## Documentation

| Topic | |
|---|---|
| Comparison with other tools | [docs/comparison.md](docs/comparison.md) |
| Rule catalog (auto-generated) | [docs/rules.md](docs/rules.md) |
| Supported languages & capability matrix | [docs/supported-languages.md](docs/supported-languages.md) |
| Configuration reference | [docs/configuration.md](docs/configuration.md) |
| CLI reference | [docs/cli.md](docs/cli.md) |
| CI/CD integration | [docs/ci-cd.md](docs/ci-cd.md) |
| Security & privacy model | [docs/security-model.md](docs/security-model.md) |
| Architecture overview | [docs/architecture.md](docs/architecture.md) |
| False-positive guide | [docs/false-positives.md](docs/false-positives.md) |
| Troubleshooting | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Testing guide | [docs/testing.md](docs/testing.md) |
| Benchmark methodology | [docs/benchmark.md](docs/benchmark.md) |
| FAQ | [docs/faq.md](docs/faq.md) |
| Roadmap | [ROADMAP.md](ROADMAP.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

## Contributing

Issues and pull requests are welcome — including new rules, which follow a [documented ~50-line pattern](CONTRIBUTING.md#writing-a-new-rule). Read [CONTRIBUTING.md](CONTRIBUTING.md) for the rule-writing guide, development setup and review expectations. All contributions are covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Limitations (honest ones)

- Secret detection is **structural + heuristic**. It cannot verify whether a credential is live (TruffleHog's job) and will not catch every custom format. The generic assignment rule (APF-SEC-020) trades recall for precision.
- Git history scanning requires the `git` binary and is bounded by `max_commits` / memory budgets; very large histories are truncated with a warning.
- Regex-based detection can produce false positives on documentation that resembles real usage — that's what allow markers and documented ignores are for.
- Language *recognition* covers 50+ ecosystems; ecosystem-specific **checks** currently exist for Python, JavaScript/TypeScript, Docker, Kubernetes/Helm, GitHub Actions, GitLab CI and Ansible. The rest rely on language-agnostic rules. The [capability matrix](docs/supported-languages.md) is honest per ecosystem.

## License

[MIT](LICENSE) © 2026 Lunar.JJO · Third-party notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
