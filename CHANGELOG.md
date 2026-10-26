# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-26

Initial public release.

### Added

- **Core scanner**: local-first, offline, zero-runtime-dependency engine that
  scans working trees (and optionally full Git history) with hard resource
  budgets, symlink-safe traversal, escape-sequence sanitisation and
  unconditional secret redaction.
- **47 detection rules** in four categories:
  - 20 secret rules (`APF-SEC-*`) covering AWS, GitHub (classic and
    fine-grained), Slack (tokens and webhooks), Google, Stripe (live keys),
    OpenAI/Anthropic, private key blocks, JWTs, URLs with embedded
    credentials, GitLab, npm, PyPI, SendGrid, Telegram, Shopify, Azure
    Storage, Square, Meta, plus a generic credential-assignment rule gated
    by entropy and placeholder heuristics.
  - 8 artifact rules (`APF-ART-*`): `.env` files, private keys/keystores,
    credential stores (`.netrc`, `.aws/credentials`, `.docker/config.json`,
    `.kube/config`, `.git-credentials`), SQL dumps and backups, OS cruft,
    SQLite files, vendored/generated directories and IDE folders.
  - 12 insecure-default rules (`APF-DEF-*`): Django `DEBUG`, dev-server
    debug mode, `verify=False`, SSL bypasses, CORS wildcards, weak/default
    passwords, Ansible host-key checking, containers running as root,
    insecure Kubernetes settings, weak hashes, JWT verification disabled,
    world-writable permissions.
  - 7 supply-chain rules (`APF-DEP-*`): remote scripts piped to shell,
    unpinned Python requirements, `pull_request_target` with untrusted
    checkout, overly broad workflow permissions, unpinned Actions,
    Node lockfile/install-hook checks, remote CI template review.
- **CLI** (`scan`, `init`, `doctor`, `rules list`, `rules explain`, `version`)
  with stable exit codes, severity thresholds, rule include/exclude,
  progress output and `--history` mode.
- **Output formats**: human-readable terminal output, JSON, and SARIF 2.1.0
  (validated structurally and uploaded to GitHub code scanning in CI).
- **Configuration**: `.agentpreflight.toml` with strict validation,
  documented+expiring `[[ignore]]` suppressions (blanket suppression needs
  explicit `allow_all`), and inline `# agentpreflight: allow` markers.
- **Git history scanning**: blob-deduplicated scan of all reachable objects
  with commit attribution via `--find-object`.
- **Language registry**: 50+ recognisable languages/ecosystems separated
  from rule implementation, feeding an honest capability matrix.
- **GitHub Action**: composite `action.yml` with SARIF output, severity
  gates and machine-readable outputs; used by this repository to scan itself.
- **CI**: lint + strict mypy + cross-platform test matrix (Python 3.10–3.13
  on Linux/macOS/Windows), packaging checks, self-scan with SARIF upload,
  and a release pipeline with checksums (PyPI publication prepared but
  disabled until trusted publishing is configured).
- **Testing**: 390 tests covering every rule (positive and negative),
  redaction, terminal injection, path traversal, symlinks, large files,
  Git history, output formats, exit codes, configuration validation and
  end-to-end CLI behaviour.
- **Documentation**: English (canonical) and Indonesian README, plus docs
  on comparison with other tools, rules, supported languages, configuration,
  CLI, CI/CD, security model, architecture, false positives, troubleshooting,
  testing, benchmarks, releasing and FAQ.

### Known limitations

- Secret detection is structural and heuristic; it cannot verify whether a
  credential is still live, and the generic rule trades recall for precision.
- History scanning is bounded by `max_commits` and a memory budget.
- Ecosystem-specific checks exist for Python, JavaScript/TypeScript, Docker,
  Kubernetes/Helm, GitHub Actions, GitLab CI and Ansible only; other
  recognised ecosystems rely on language-agnostic rules.
- The package is installable from Git; PyPI publication is pending trusted
  publishing configuration (see docs/releasing.md).

[0.1.0]: https://github.com/lunarjjo/agentpreflight/releases/tag/v0.1.0
