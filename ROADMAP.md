# Roadmap

This roadmap reflects genuine, planned work — not promises. Items move up
as maintainers and contributors pick them up; nothing here is guaranteed
by a date.

## v0.1.x (maintenance)

- [ ] First tagged release `v0.1.0` with attached, checksum-verified artifacts.
- [ ] Enable PyPI publication via trusted publishing (maintainer action).
- [ ] Ship the composite Action to the GitHub Marketplace.
- [ ] Collect real-world false-positive reports from early users and tune
      the generic credential rule (APF-SEC-020).

## v0.2 (baseline & DX)

- [ ] **Baseline files**: `--save-baseline` / `--baseline` so CI fails only on
      *new* findings (detect-secrets-inspired UX).
- [ ] **Incremental scanning**: cache file fingerprints (mtime+size+hash) so
      only changed files are rescanned in repeat runs.
- [ ] **`--no-git` worktree diff mode**: scan exactly the staged changes
      (`git diff --cached`), for a pre-commit use case.
- [ ] Structured `--rules-config` validation for project-pinned rule severity
      overrides.
- [ ] Markdown report format for security-review handoffs.

## v0.3 (deeper ecosystem coverage)

- [ ] Terraform/OpenTofu-specific checks (state file exposure, hard-coded
      credentials in providers).
- [ ] Android (Gradle manifests) and iOS (project.pbxproj signing) checks.
- [ ] Helm chart deep checks (securityContext defaults across values.yaml).
- [ ] Language-specific insecure-default rules beyond Python/JS (Java, Go,
      PHP, Ruby frameworks).
- [ ] Archive artifact detection (`.zip`/`.tar.gz` containing `.env` or keys).

## v0.4 (integrations, explicit opt-in only)

- [ ] **Optional** OSV advisory lookup behind an explicit `--osv` flag with
      clear network disclosure (offline remains the default).
- [ ] Optional TruffleHog hand-off (`--verify-with trufflehog`) for live
      secret verification, keeping AgentPreflight itself offline.
- [ ] SARIF upload compatibility testing beyond GitHub (GitLab, Azure DevOps).
- [ ] Pre-commit framework hook packaging.

## Later / exploratory

- [ ] Plugin interface for third-party rule packs (pip-entry-point based).
- [ ] TOML/INI/YAML semantic parsing for low-confidence config rules that
      are regex-based today.
- [ ] Community translations beyond Indonesian (translation guide exists in
      docs/contributing section of CONTRIBUTING.md).

## Explicitly not planned

- Deep taint analysis / SAST (Semgrep's domain).
- Vulnerability advisory databases (OSV/Trivy's domain).
- Live credential verification by default (TruffleHog's domain — any
  integration will be opt-in and disclosed).
- Telemetry of any kind.
