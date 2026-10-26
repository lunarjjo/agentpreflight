# False-positive guide

Detection quality is a trade-off. AgentPreflight biases toward **precision
on documentation and recall on structural secrets**: known token formats
(AWS, GitHub, Stripe, ...) always fire with high confidence; the generic
credential rule fires only when entropy/class heuristics indicate a
generated value, and placeholders are recognised as noise.

This guide lists the known false-positive patterns, why they occur, and the
*right* way to silence them — escalation order matters.

## Escalation order (use the least powerful tool first)

1. **Nothing** — if the finding is a real leaked value, fix the value:
   rotate and remove it (and purge history with e.g. `git filter-repo`).
2. **Inline marker** — for documentation examples:
   `# agentpreflight: allow` on the exact line.
3. **Documented ignore** — `[[ignore]]` in `.agentpreflight.toml` with a
   mandatory `reason` and (recommended) an `expires` date.
4. **Rule exclusion** — `exclude_rules = ["APF-XXX-YYY"]` when the rule is
   genuinely wrong for your project. File an issue so the rule improves.

Never work around findings by disabling redaction (impossible by design) or
by weakening global limits.

## Documented false-positive patterns

### Documentation examples of real token formats

```markdown
Add `GITHUB_TOKEN=<ghp_ + 36 characters>` ...   # fires: real format
```

Structural rules intentionally cannot distinguish "example" from "real"
for well-known formats — a leaked token and a pasted token look identical.
Fix: inline marker, or keep example values in files under an
`[[ignore]]` with reason `"documentation examples"`.

### Generic rule (APF-SEC-020)

Recognised as noise (no finding):

- `${API_KEY}`, `{{ vault.secret }}`, `<your-api-key>`, `%VAR%`
- `changeme`, `password`, `admin`, `xxx`, `hunter2`
- masked values like `sk-XXXXXXXXXXXXXXXX`
- short values (<12 chars), monotone runs, entropy < 4.0 without
  3+ character classes

Still fires on:

- long mixed-class values assigned to credential-ish keys, even in docs.
  Fix: marker, or reword docs to use placeholders.

### URL credentials (APF-SEC-009)

`postgres://user:pass@host/db` <!-- agentpreflight: allow --> in README quick-start examples fires. The
pattern is intentional — connection strings in docs are frequently *real*
dev credentials. Fix: use `postgres://user:${DB_PASSWORD}@host` style in
docs, or a marker.

### `DEBUG = True` (APF-DEF-001)

Only fires in files whose name contains `settings` — the Django settings
convention. If your `settings.py` legitimately enables debug in a
dev-only import guarded by environment, the finding is still fair: gate it
on `os.environ` instead of suppressing.

### Weak hash (APF-DEF-011)

Deliberately low confidence: MD5/SHA-1 have legitimate non-security uses
(cache keys, etags). Review the hit; if it protects nothing sensitive, add
a marker with a comment explaining the use.

### Unpinned dependencies (APF-DEP-002)

Informational by design — not a vulnerability claim, a reproducibility
observation. If you pin in a lockfile the rule does not apply; if you
intentionally float versions, `exclude_rules` it.

### Vendor directories (APF-ART-006)

Detected once per directory, not per file, with tracked status. Vendored
code you maintain deliberately (rare, but exists) → documented ignore.

## Tuning the generic rule for noisy codebases

If APF-SEC-020 produces recurring noise in generated files:

```toml
[scan]
exclude_paths = ["generated/**"]

[[ignore]]
path = "generated/**"
rule_id = "APF-SEC-020"
reason = "machine-generated client SDKs contain assigned token fields"
```

## Reporting a false positive

Open an issue with:

1. the rule ID,
2. the finding line (secret masked),
3. why the value is safe in your context.

See the bug-report template for the exact format. Rule-calibration PRs are
welcome — negative fixtures are mandatory (CONTRIBUTING.md).
