# CI/CD integration guide

## GitHub Actions (recommended)

The repository ships a composite action (`action.yml`) that installs
AgentPreflight from the scanned commit and runs it against your checkout.

```yaml
name: security-preflight
on: [push, pull_request]

permissions:
  contents: read

jobs:
  preflight:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed for SARIF upload
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5

      - name: AgentPreflight
        uses: lunarjjo/agentpreflight@main   # pin to a tag/SHA after v0.1.0 is released
        with:
          path: .
          fail-severity: high
          sarif: agentpreflight.sarif

      - name: Upload to code scanning
        if: always()
        uses: github/codeql-action/upload-sarif@45775bd8235c68ba998cffa5171334d58593da47 # v3.28.15
        with:
          sarif_file: agentpreflight.sarif
```

### Action inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | directory to scan |
| `fail-severity` | `high` | fail the job when findings at/above this severity exist |
| `severity` | `info` | minimum severity to report |
| `history` | `false` | also scan full Git history (slower) |
| `sarif` | `agentpreflight.sarif` | write SARIF to this path (empty string disables) |
| `exclude-rules` | — | comma-separated rule patterns to exclude |

### Action outputs

| Output | Description |
|---|---|
| `findings-count` | number of findings reported |
| `exit-code` | scanner exit code (1 = threshold exceeded) |

The action fails the step when findings meet `fail-severity` — that is the
point of a gate. To run report-only, set `fail-severity: critical` and guard
with `if: always()` where needed.

### Recommended policy

- **PRs**: working-tree scan (`history: false`) — fast, catches new leaks
  before merge.
- **Nightly/release**: `history: true` on the default branch — catches
  secrets deleted from HEAD but still in history.
- Pin `uses:` to a release tag (or full commit SHA) once v0.1.0 ships;
  `@main` is shown for bootstrapping only.

## Direct CLI in any CI

AgentPreflight is a single zero-dependency Python package — any runner with
Python 3.10+ works:

```yaml
- run: python -m pip install "git+https://github.com/lunarjjo/agentpreflight@v0.1.0"
- run: agentpreflight scan . --format sarif --output agentpreflight.sarif
```

GitLab CI:

```yaml
preflight:
  image: python:3.12
  script:
    - pip install "git+https://github.com/lunarjjo/agentpreflight@v0.1.0"
    - agentpreflight scan . --fail-severity high
```

Jenkins (declarative):

```groovy
sh 'pip install "git+https://github.com/lunarjjo/agentpreflight@v0.1.0"'
sh 'agentpreflight scan . --fail-severity high'
```

## Other tools alongside AgentPreflight

The intended stack (see `docs/comparison.md` for rationale):

| Concern | Tool |
|---|---|
| Pre-release readiness gate (secrets + artifacts + defaults + CI safety) | **AgentPreflight** |
| Deep taint analysis / custom rules | Semgrep |
| Dependency advisories | OSV-Scanner or Trivy |
| Live-secret verification | TruffleHog |

Example combined job:

```yaml
      - name: Semgrep
        uses: semgrep/semgrep-action@<pinned>
      - name: OSV scan
        uses: google/osv-scanner-action@<pinned>
      - name: AgentPreflight
        uses: lunarjjo/agentpreflight@main
        with:
          fail-severity: high
```

## Git hooks (local gate)

With [pre-commit](https://pre-commit.com) you can run the scanner directly
(a local hook avoids the framework's virtualenv isolation):

```yaml
repos:
  - repo: local
    hooks:
      - id: agentpreflight
        name: agentpreflight (changed files only in v0.1: scan .)
        language: system
        entry: agentpreflight scan .
        pass_filenames: false
        stages: [pre-push]
```

`stages: [pre-push]` keeps interactive commits fast. A dedicated staged-diff
mode is on the roadmap (v0.2).
