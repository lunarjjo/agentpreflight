# Security Policy

## Supported versions

AgentPreflight is pre-1.0. Only the latest release line receives security
fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | latest patch only |

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Please use GitHub's private advisory form:

> https://github.com/lunarjjo/agentpreflight/security/advisories/new

Include, where possible:

1. A minimal reproduction (file content or repository layout).
2. The affected component (scanner engine, rule, output renderer, Action,
   CI workflow).
3. Impact assessment — e.g. secret leakage via logs, crash on crafted input,
   escape-sequence injection.
4. Any suggested mitigation.

You should receive an acknowledgement within 7 days. Security fixes are
released as patch versions with a corresponding advisory. Reporters are
credited in the advisory unless they prefer otherwise.

## What counts as a security issue

- AgentPreflight leaking a **full secret value** through any output channel
  (terminal, JSON, SARIF, warnings, errors).
- Terminal escape-sequence injection through file names or file content
  reaching unsanitised output.
- Path traversal or symlink escape out of the scanned root.
- The scanner executing repository content or modifying/deleting files.
- Unexpected network access during a local scan.
- Crafted repository content causing unhandled crashes or unbounded
  resource consumption beyond the documented budgets.
- Vulnerabilities in CI workflows of this repository (e.g. pwn-request
  exposure).

## What does NOT count

- A secret you committed to *your own* repository being reported — that is
  the tool working as intended.
- False positives/negatives in detection quality — those are regular
  issues, not security reports.
- Vulnerabilities in your own project that AgentPreflight does not detect.

## Hardening notes

- The scanner never executes, installs or builds the code it scans.
- Git history scanning shells out only to `git` itself.
- CI in this repository pins third-party Actions to verified commit SHAs
  and applies least-privilege permissions; untrusted PR code never runs in
  workflows with write permissions.
