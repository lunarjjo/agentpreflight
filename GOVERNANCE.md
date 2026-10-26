# Governance

## Project status

AgentPreflight is an independent open-source project created and maintained
by **Lunar.JJO** ([@lunarjjo](https://github.com/lunarjjo)). It is in the
pre-1.0 / single-maintainer phase.

## Decision making

| Decision | Who decides |
|---|---|
| Bug fixes, rule tuning, docs | Maintainer, after review |
| New rules and features | Maintainer, based on issues/discussions and roadmap fit |
| Severity model or CLI breaking changes | Maintainer, with a CHANGELOG entry and prior discussion |
| Security fixes | Maintainer, via the private advisory process (see SECURITY.md) |

Principles that guide all decisions:

1. **Offline by default** — any feature requiring network access must be
   explicit, documented and opt-in.
2. **Redaction is non-negotiable** — no output channel may print full
   secret values, including debug modes that might be added later.
3. **Honest signals** — severity/confidence must be calibrated, and the
   docs must never describe features that do not exist.
4. **Zero runtime dependencies** — new runtime deps require a compelling
   justification and a maintainer decision; dev/test deps are fine.

## Maintainer responsibilities

- Triage issues and security reports within a week (security: see
  SECURITY.md timelines).
- Keep CI green on the default branch; revert over broken.
- Review and merge community PRs transparently.
- Maintain CHANGELOG, ROADMAP and release process (docs/releasing.md).
- Ensure the project's own repository passes its own scanner.

## Path to broader governance

If the project attracts regular contributors, governance will evolve to a
multi-maintainer model: 2–3 maintainers with documented merge rules (1
approval + CI green, 2 for rules touching redaction or exit codes). Until
then, contributions are reviewed by the sole maintainer, and all decisions
are documented in issues and PRs so the history stays auditable.
