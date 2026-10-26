# Contributing to AgentPreflight

Terima kasih atas minatnya! Dokumen ini mencakup setup pengembangan, panduan
menulis rule, standar kualitas, dan ekspektasi review. (Bahasa Indonesia:
lihat [README.id.md](README.id.md) untuk pengenalan produk; dokumen teknis
kanonisnya bahasa Inggris.)

## Development setup

```bash
git clone https://github.com/lunarjjo/agentpreflight
cd agentpreflight
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

Verify your environment:

```bash
agentpreflight doctor
python -m pytest tests/ -q
```

## Quality gates (must pass before review)

```bash
ruff check src tests          # lint
ruff format --check src tests # formatting
mypy                          # strict type checking (src/)
python -m pytest tests/       # 390+ tests
```

CI runs exactly these commands on Linux/macOS/Windows across Python
3.10–3.13, so anything green locally should be green upstream.

## Writing a new rule

Rules live in `src/agentpreflight/rules/` as plain classes. A content rule
is ~50 lines including metadata. The registry, CLI, SARIF output and docs
pick it up automatically once added to the category list.

1. **Pick the category and ID** (`APF-SEC-` / `APF-ART-` / `APF-DEF-` /
   `APF-DEP-` + next number; the registry enforces prefix consistency).

2. **Subclass `ContentRule` (line-based), `PathRule` (file-name based) or
   `RepoRule` (whole-inventory)** from `rules/base.py`.

3. **Fill in the metadata** — every field is user-visible via
   `agentpreflight rules explain`:

```python
class TerribleThingRule(ContentRule):
    id = "APF-DEF-099"
    name = "Terrible thing"
    category = "default"
    severity = Severity.HIGH          # criteria: docs/rules.md
    confidence = Confidence.HIGH       # how sure are we locally?
    description = "What the pattern is and why it is dangerous."
    remediation = "Concrete fix the developer can apply now."
    references = ["https://owasp.org/..."]     # primary sources only
    applies_to = "which files this rule targets"

    patterns: ClassVar[list[ContentPattern]] = [
        # group=1 marks the secret capture (gets redacted);
        # group=None for non-secret matches (no redaction)
        ContentPattern(re.compile(r"\bterrible_thing\s*=\s*true\b"), group=None),
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.endswith((".py", ".js"))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Terrible thing enabled")
```

4. **Add the instance** to the category list at the bottom of the module
   (e.g. `DEFAULT_RULES`).

5. **Write tests — positive AND negative** in `tests/test_rules_*.py`.
   Use synthetic values only (e.g. AWS's documented `AKIAIOSFODNN7EXAMPLE` <!-- agentpreflight: allow -->,
   or `ghp_` + 36 characters of `a`). Add false-positive cases to
   `tests/test_rules_defaults.py::TestContextualFalsePositives` style
   classes.

6. **Regenerate the rule catalog**:

```bash
agentpreflight rules list --format markdown > docs/rules.md
```

7. **Commit** with a descriptive message referencing the issue.

### Severity and confidence expectations

- `critical` — immediate broad compromise (e.g. private key material).
- `high` — direct service access or disabled core control.
- `medium` — context-dependent risk or dev-only acceptable default.
- `low` / `info` — hygiene and weak signals.

Confidence must reflect what the rule can *locally verify*, not how bad the
issue would be if real. When in doubt, lower the confidence — the severity
and confidence model is documented in `docs/rules.md`.

### What gets a rule rejected

- Detecting bare words ("password appears in the file") without context.
- Anything requiring network access (project principle).
- Duplicating a mature tool's core competency without added value.
- No negative test cases.

## Documentation changes

- English is canonical; keep `README.id.md` and any localized page in sync
  for user-facing changes (note: only README + this policy require
  translation; deep docs are English-only for now — see the roadmap).
- Never document a feature that does not exist. Mark planned features as
  planned (see `ROADMAP.md`).
- Verify every command you add actually runs.

## Commit style

Small, coherent commits with descriptive messages:

```
Add Terraform state artifact rule (APF-ART-009)

Detects committed .tfstate files, which frequently embed cloud
credentials. Path rule + tests + docs regeneration.

Fixes #123
```

## Review expectations

Reviews focus on: detection quality (false positives/negatives), test
coverage, redaction safety, and honest metadata. Expect at least one
round of comments on rule PRs — severity calibration is a discussion.
Maintainers review within a week; ping after 10 days of silence.

## Good first issues

Look for the `good first issue` label — these are genuine, verified tasks
(often a single rule with a clear spec), not busywork.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — private advisory form, never a public
issue.

## Code of conduct

All interactions fall under the [Code of Conduct](CODE_OF_CONDUCT.md).
