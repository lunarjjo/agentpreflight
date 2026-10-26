# Comparison with other tools

AgentPreflight is a local-first, zero-runtime-dependency CLI that gates a repository *before* it is published or released: exposed secrets, sensitive artifacts (`.env`, private keys), insecure defaults (`DEBUG=True`, `verify=False`), and supply-chain hygiene risks (`curl`-to-shell pipelines, unsafe CI permissions). This document maps the existing landscape so AgentPreflight positions itself as a **pre-release readiness gate**, not another deep SAST engine or cloud service. All facts below were verified against primary sources (official repositories, READMEs, LICENSE files, and vendor documentation) on **2026-10-26**. Where something could not be verified, it is stated explicitly.

### Gitleaks

- **Purpose & audience:** detect secrets (passwords, API keys, tokens) in git repos, directories/files, or stdin; aimed at individual developers and CI pipelines.
- **Scope:** language-agnostic; scans git history (`git log -p` under the hood), directories, and piped input.
- **Detection & limitations:** configurable regex rules plus Shannon-entropy checks, stopwords, allowlists, and baselines. Purely static — it never validates whether a secret is live, so false positives/negatives are possible.
- **Execution:** fully local, single static Go binary.
- **License & distribution:** MIT; Homebrew, Docker (Docker Hub and `ghcr.io/gitleaks/gitleaks`), `go install`, release binaries.
- **CI/CD:** official GitHub Action ([gitleaks-action](https://github.com/gitleaks/gitleaks-action)), pre-commit hook, Docker images; JSON, CSV, JUnit, SARIF and template output.
- **Overlap with AgentPreflight:** this *is* the reference open-source secret scanner — fast, local, SARIF-capable. AgentPreflight should not try to out-rule Gitleaks at regex breadth.
- **Complementary angle:** Gitleaks only finds secrets. Notably, its README now warns that the project is **feature complete** (security patches only) and the maintainer has shifted focus to Betterleaks (see below) — an opening for tools offering broader pre-release checks.
- **Sources (verified 2026-10-26):** https://github.com/gitleaks/gitleaks (README, LICENSE)

### TruffleHog

- **Purpose & audience:** find **and verify** secrets; aimed at security teams. Classifies 800+ secret types and maps them back to the identity they belong to.
- **Scope:** git repos, GitHub/GitLab orgs, S3, GCS, Docker images, Jenkins, Kubernetes, filesystems, stdin.
- **Detection & limitations:** detector rules plus programmatic verification against the issuing service's API (verified / unknown / unverified statuses). Verification requires outbound network calls; unauthenticated GitHub scans hit rate limits.
- **Execution:** local CLI, but verification contacts external services; a commercial TruffleHog Enterprise offering continuously monitors Git, Jira, Slack, Confluence, Teams, and SharePoint.
- **License & distribution:** AGPL-3.0; Homebrew, Docker, `go install`, signed install script (Cosign-verified).
- **CI/CD:** official GitHub Action with SARIF upload to code scanning; GitLab pipeline examples; CircleCI/Travis examples; `--fail` exit code 183 and PR-diff modes (`--since-commit`, `--branch`).
- **Overlap with AgentPreflight:** deepest secret-detection coverage including history and live verification — AgentPreflight must not duplicate this.
- **Complementary angle:** AgentPreflight is the offline, no-account pre-flight gate; users who need to know whether a found secret is *live* should be pointed at TruffleHog.
- **Sources (verified 2026-10-26):** https://github.com/trufflesecurity/trufflehog (README, LICENSE)

### detect-secrets (Yelp)

- **Purpose & audience:** enterprise-minded secret *prevention*: stop new secrets from entering a codebase, audit a baseline of existing ones, and produce a migration checklist.
- **Scope:** any text files in a working tree or git diff.
- **Detection & limitations:** plugin heuristics (keyword detection, entropy) with word lists and an optional ML "gibberish detector". The README is explicit that it is "not a sure-fire solution": multi-line secrets and default passwords that don't trigger the KeywordDetector (e.g. `login = "hunter2"`) are missed.
- **Execution:** fully local Python CLI.
- **License & distribution:** Apache-2.0; PyPI and Homebrew.
- **CI/CD:** designed around git hooks — pre-commit usage via `detect-secrets-hook` against a `.secrets.baseline`; interactive `detect-secrets audit` tool.
- **Overlap with AgentPreflight:** the baseline idea (record accepted findings, fail only on *new* issues) is a UX pattern AgentPreflight should study rather than compete with head-on.
- **Complementary angle:** AgentPreflight adds the non-secret dimensions (artifacts, insecure defaults, CI safety) that detect-secrets deliberately does not cover.
- **Sources (verified 2026-10-26):** https://github.com/Yelp/detect-secrets (README, LICENSE)

### GitHub Secret Scanning + Push Protection

- **Purpose & audience:** platform-native secret detection and push-time blocking for GitHub users.
- **Scope:** entire git history on all branches, plus issue/PR/Discussion titles, descriptions and comments, wikis, and secret gists.
- **Detection & limitations:** partner/provider patterns, generic patterns (private keys, connection strings), user-defined custom regex patterns, validity checks (contacts the issuing service), AI-detected unstructured passwords, and AI-generated regexes. Only works on GitHub.
- **Execution:** cloud service running on GitHub's infrastructure. Secret scanning runs automatically and free on public repos; organization-owned private/internal repos require GitHub Secret Protection on Team or Enterprise Cloud plans. Push protection blocks pushes (CLI, web commits, file uploads, REST API, and the GitHub MCP server for public repos); push protection *for users* is on by default on GitHub.com for pushes to public repos.
- **License & distribution:** proprietary platform feature; no local mode.
- **CI/CD:** built into the GitHub push flow and Security/Code Security tabs.
- **Overlap with AgentPreflight:** an excellent free gate — but only on GitHub, only at push time, and only for secrets.
- **Complementary angle:** AgentPreflight catches problems *before* any push on any forge (GitLab, Gitea, local-only), adds hygiene/defaults/CI checks, and works offline in air-gapped setups.
- **Sources (verified 2026-10-26):** https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning ; https://docs.github.com/en/code-security/concepts/secret-security/push-protection

### Semgrep

- **Purpose & audience:** fast open-source static analysis to find bugs and enforce secure guardrails/coding standards; aimed at security engineers and platform teams.
- **Scope:** Semgrep Code supports 30+ languages; Semgrep Supply Chain covers 12 languages across 15 package managers.
- **Detection & limitations:** semantic pattern rules ("code you already write"). The README is candid that Community Edition misses many true positives because it only analyzes within a single function or file; the proprietary Pro/AppSec platform adds cross-file/cross-function data-flow reachability.
- **Execution:** scans run locally, and the README states code is not uploaded even when using the AppSec Platform; rules are pulled from the registry.
- **License & distribution:** OSS engine is LGPL-2.1; AppSec Platform and Pro rules are proprietary. Registry offers 2,000+ community rules; the platform ships 20,000+ proprietary rules. Install via pip, Docker (`semgrep/semgrep`), or the platform.
- **CI/CD:** documented for IDEs, pre-commit checks, and CI/CD workflows; Docker-based CI usage with `semgrep ci`.
- **Overlap with AgentPreflight:** deep SAST — explicitly out of AgentPreflight's scope.
- **Complementary angle:** AgentPreflight can detect whether a repo has Semgrep wired in (config/CI presence) as a readiness signal, and defer all code-level analysis to it; SARIF keeps results interoperable.
- **Sources (verified 2026-10-26):** https://github.com/semgrep/semgrep (README, LICENSE)

### OSV-Scanner

- **Purpose & audience:** find known vulnerabilities in a project's dependencies; the officially supported frontend to the OSV.dev database. Aimed at developers and OSS maintainers.
- **Scope:** C/C++, Dart, Elixir, Go, Java, JavaScript, PHP, Python, R, Ruby, Rust; container images, SBOMs; 11+ ecosystems and 19+ lockfile formats. (V2 is currently in beta per the README.)
- **Detection & limitations:** matches manifests/lockfiles/SBOMs against the OSV database; optional call analysis to determine whether a vulnerable function is actually used; guided remediation recommendations. Requires database access (an offline mode with pre-downloaded databases exists).
- **Execution:** local CLI; database fetched from OSV.dev.
- **License & distribution:** Apache-2.0; prebuilt binaries, `go install`, Docker.
- **CI/CD:** official GitHub Action ([google/osv-scanner-action](https://github.com/google/osv-scanner-action)); also license scanning per its docs.
- **Overlap with AgentPreflight:** dependency CVE/advisory scanning — AgentPreflight should defer this entirely.
- **Complementary angle:** AgentPreflight's hygiene checks can verify that *some* dependency scanner is wired into CI and recommend OSV-Scanner when it is missing.
- **Sources (verified 2026-10-26):** https://github.com/google/osv-scanner (README, LICENSE); https://google.github.io/osv-scanner/usage/

### Trivy

- **Purpose & audience:** "comprehensive and versatile" scanner for vulnerabilities, IaC misconfigurations, secrets, and licenses, plus SBOM generation; aimed at DevSecOps teams.
- **Scope:** targets include container images, filesystems, git repos, Kubernetes, and VM images; covers most popular languages and OSes.
- **Detection & limitations:** database-driven CVE scanning, misconfig checks, and secret detection in one tool. Vulnerability DBs must be downloaded, and the breadth makes it heavier than single-purpose tools.
- **Execution:** local CLI; databases downloaded at runtime. Commercial editions compared at trivy.dev.
- **License & distribution:** Apache-2.0; Homebrew, Docker, apt/RPM, and more.
- **CI/CD:** official GitHub Action ([aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action)); extensive CI adoption.
- **Overlap with AgentPreflight:** the closest single-binary "everything" competitor — it already does secrets + misconfigs + vulns.
- **Complementary angle:** AgentPreflight is narrower on purpose: no database downloads, sub-second hygiene/defaults/CI checks designed to run before every push and release, not deep container/vuln analysis. Recommend Trivy where depth is needed.
- **Sources (verified 2026-10-26):** https://github.com/aquasecurity/trivy (README, LICENSE)

### Dependabot

- **Purpose & audience:** automated dependency update pull requests (version updates and security updates) for GitHub users.
- **Scope:** Ruby, JavaScript, Python, PHP, Dart, Elixir, Elm, Go, Rust, Java, Julia, .NET, plus git submodules, Docker, OpenTofu/Terraform, and pre-commit hooks.
- **Detection & limitations:** resolves the latest compatible versions and opens PRs with changelogs; it is an update *service*, not a gate — it does not block anything.
- **Execution:** runs as a GitHub-hosted service configured via `dependabot.yml`; self-hosting is possible through the Dependabot CLI.
- **License & distribution:** dependabot-core is MIT; the service itself is a GitHub platform feature.
- **CI/CD:** native to GitHub; standalone CLI for advanced users.
- **Overlap with AgentPreflight:** supply-chain hygiene via dependency freshness.
- **Complementary angle:** AgentPreflight can check for a `dependabot.yml`, pinned GitHub Action refs, and similar hygiene signals as part of release readiness — and recommend enabling Dependabot.
- **Sources (verified 2026-10-26):** https://github.com/dependabot/dependabot-core (README, LICENSE); https://docs.github.com/en/code-security/dependabot

### pre-commit

- **Purpose & audience:** a framework for managing and maintaining multi-language git pre-commit hooks; aimed at all developers.
- **Scope:** runs hooks written in any language against staged files.
- **Detection & limitations:** not a scanner at all — it is an integration surface with no security checks of its own.
- **Execution:** local (Python); a managed cloud service exists at pre-commit.ci.
- **License & distribution:** MIT; pip.
- **CI/CD:** pre-commit.ci, or any CI by running `pre-commit run --all-files`.
- **Overlap with AgentPreflight:** none in detection; it is a distribution channel.
- **Complementary angle:** ship a `.pre-commit-hooks.yaml` so `agentpreflight` can be consumed as a pre-commit hook; do not rebuild hook management.
- **Sources (verified 2026-10-26):** https://github.com/pre-commit/pre-commit (README, LICENSE); https://pre-commit.com

### zizmor

- **Purpose & audience:** static analysis for CI/CD configurations — GitHub Actions, Dependabot, and pre-commit setups; aimed at security-minded maintainers.
- **Scope:** CI workflow/config YAML files.
- **Detection & limitations:** audits for template injection (attacker-controlled code execution), accidental credential persistence and leakage, excessive permission scopes, and impostor commits/confusable git refs. Rules-based and CI-focused; some findings are auto-fixable with `--fix`.
- **Execution:** local Rust CLI.
- **License & distribution:** MIT; crates.io and packaged in many repositories. The project has moved from `woodruffw/zizmor` to the `zizmorcore` organization.
- **CI/CD:** official GitHub Action ([zizmorcore/zizmor-action](https://github.com/zizmorcore/zizmor-action)); JSON, SARIF, and GitHub Annotations output.
- **Overlap with AgentPreflight:** the most direct overlap on the "unsafe CI permissions" pillar — zizmor already audits GitHub Actions security in depth.
- **Complementary angle:** keep AgentPreflight's built-in CI checks to a handful of high-signal defaults (e.g. obviously dangerous permissions patterns), defer or integrate for deeper audits, and treat "zizmor not wired in" as a readiness finding.
- **Sources (verified 2026-10-26):** https://github.com/zizmorcore/zizmor (README, LICENSE); https://docs.zizmor.sh/usage/

### ggshield (GitGuardian)

- **Purpose & audience:** GitGuardian's CLI for detecting 500+ secret types locally or in CI; the README also documents scanning of **AI coding assistant interactions** (Cursor, Claude Code, Copilot Chat, Codex, Mistral Vibe), blocking prompts/actions that contain secrets in real time via `ggshield install`.
- **Scope:** files, text content, Docker images, git hooks, and AI-assistant traffic.
- **Detection & limitations:** detection runs through the GitGuardian public API (py-gitguardian), so it requires an account/API access and network; the README states files and secrets are not stored (only metadata such as call time and request size).
- **Execution:** local CLI with cloud-backed detection; GitGuardian is a commercial SaaS (the CLI itself is MIT).
- **License & distribution:** MIT CLI over a proprietary API; install script, Homebrew, packages, pipx.
- **CI/CD:** pre-commit/pre-push/pre-receive hooks, Docker scanning, honeytoken support.
- **Overlap with AgentPreflight:** cloud-based secret scanning and the closest existing "AI coding-agent security" feature.
- **Complementary angle:** AgentPreflight stays offline and account-free; the "agent prompt contains a secret" interception use-case is well served by ggshield and does not need duplicating.
- **Sources (verified 2026-10-26):** https://github.com/GitGuardian/ggshield (README, LICENSE)

### Other notable tools

- **pip-audit** (PyPA): audits Python environments/requirements for known vulnerabilities using the Python Packaging Advisory Database via the PyPI JSON API and OSV; Apache-2.0; GitHub Action and pre-commit support. Defer Python advisory scanning to it. Sources: https://github.com/pypa/pip-audit (verified 2026-10-26).
- **OpenSSF Scorecard**: automated heuristics ("checks") assessing the security posture of open source projects, with a public web viewer/API at scorecard.dev; Apache-2.0. Repo hygiene, but at project-posture level and oriented to GitHub/GitLab APIs — complementary to AgentPreflight's file-level checks. Sources: https://github.com/ossf/scorecard (verified 2026-10-26).
- **Betterleaks**: a new secrets scanner by the original Gitleaks author (MIT-licensed, development supported by Aikido Security), featuring secrets validation via Expr, BPE-tokenization filtering, and sources including GitHub, GitLab, Hugging Face, and S3. Emerging — worth watching as the de-facto Gitleaks successor. Sources: https://github.com/betterleaks/betterleaks (README, LICENSE; verified 2026-10-26).
- **Repolinter** (TODO Group): linted open source repositories for community-health files (LICENSE, README, CONTRIBUTING, etc.); the repository is **archived**, which leaves the file-level repo-hygiene niche open. Sources: https://github.com/todogroup/repolinter (verified 2026-10-26).

### Summary table

| Tool | Focus | Local/cloud | License | Overlap with AgentPreflight |
| --- | --- | --- | --- | --- |
| Gitleaks | Secret detection (git/files) | Local | MIT | High — core secret scanning |
| TruffleHog | Secret detection + live verification | Local CLI, calls external APIs | AGPL-3.0 | High (secrets) — verification out of scope for AP |
| detect-secrets | New-secret prevention + baselines | Local | Apache-2.0 | Medium — baseline UX pattern |
| GitHub Secret Scanning / Push Protection | Platform secret scanning + push blocking | Cloud (GitHub) | Proprietary | Medium — GitHub-only, push-time, secrets only |
| ggshield | Secret detection via API; AI-assistant scanning | Local CLI, cloud API | MIT CLI + SaaS | Medium — secrets + AI-agent angle |
| Semgrep | Deep SAST / SCA | Local scans, registry/platform | LGPL-2.1 OSS + proprietary | Low — AP defers code analysis |
| OSV-Scanner | Dependency vulnerabilities (OSV.dev) | Local CLI, DB download | Apache-2.0 | Low — AP defers advisories |
| Trivy | Vulns + misconfig + secrets + licenses (broad) | Local, DB download | Apache-2.0 | Medium — broadest overlap; AP is lighter/faster |
| Dependabot | Automated dependency update PRs | Cloud (GitHub service) | MIT (core) | Low — updates, not gating |
| zizmor | CI/CD config security (Actions, Dependabot) | Local | MIT | Medium-high on CI-safety pillar |
| pre-commit | Multi-language git hook framework | Local (+ pre-commit.ci) | MIT | None — distribution channel |
| Betterleaks | Next-gen secret scanning (Gitleaks successor) | Local (validation calls out) | MIT | High (secrets), emerging |

### Where AgentPreflight fits

**Build ourselves.** The defensible core is the *combination*: one fast, offline, dependency-free command that gates a release with (a) secret-pattern scanning and sensitive-artifact detection (`.env`, private keys, credential files), (b) insecure-defaults detection (`DEBUG=True`, `verify=False`, permissive CORS, etc.), (c) high-signal supply-chain hygiene checks (pinned action refs, remote-script piping in docs/scripts, obviously unsafe CI permissions), and (d) repo-hygiene/file checks such as missing LICENSE or leaked build artifacts — all reported as CLI text, JSON, and SARIF with a GitHub Action, plus bilingual (English/Indonesian) docs. Each pillar has strong competitors, but no verified current tool combines them into a single local pre-release gate, and the two closest broad tools (Trivy, and Gitleaks for secrets) either require database downloads or cover only secrets; Gitleaks is now in maintenance mode and its successor Betterleaks is still establishing itself.

**Defer to integrations.** Deep data-flow SAST belongs to Semgrep; dependency CVE/advisory scanning belongs to OSV-Scanner, Trivy, pip-audit, and Dependabot; secret *verification* (is the credential live?) belongs to TruffleHog/Betterleaks/ggshield; and deep CI workflow auditing belongs to zizmor. AgentPreflight's SARIF output and GitHub Action make it composable: it can detect that these scanners are absent and recommend them, rather than reimplement them. Keeping the built-in CI-permission checks small and high-signal avoids a head-on collision with zizmor.

**What is genuinely under-served.** A combined, offline, no-account pre-*publish* readiness gate that runs in seconds anywhere (including air-gapped machines and non-GitHub forges — GitHub's push protection is free but GitHub-only and push-time only); insecure-defaults detection as a first-class category (none of the surveyed scanners ship a curated cross-framework defaults ruleset); and multilingual documentation, which none of the surveyed tools offer. The AI coding-agent angle is partially claimed by ggshield's assistant hooks (verified feature), but a *repository-level* readiness gate for agent-heavy workflows — catching the `.env` files, debug flags, and unsafe scripts agents tend to commit before a human publishes — remains open territory and matches AgentPreflight's original positioning.
