# Testing guide

## Layout

```
tests/
├── conftest.py             # helpers: make_file, init_repo, run_cli (subprocess e2e)
├── test_redact.py          # entropy, redaction, sanitisation, placeholder heuristics
├── test_toml_lite.py       # vendored parser parity with tomllib (3.11+)
├── test_config.py          # config loading/validation/suppression semantics
├── test_walker.py          # enumeration, traversal guards, symlinks, limits, binary detection
├── test_rules_secrets.py   # every secret rule: positive + negative + placeholders
├── test_rules_artifacts.py # path rules + repo-level rules
├── test_rules_defaults.py  # insecure defaults incl. contextual false positives
├── test_rules_supply.py    # supply-chain rules (CI YAML, requirements, package.json)
├── test_engine.py          # integration: suppression, filtering, ordering, limits, resilience
├── test_output.py          # text/JSON/SARIF structure + redaction + injection
├── test_gitscan.py         # history scanning incl. deleted-secret recovery
├── test_languages.py       # ecosystem registry + detection matrix
└── test_cli.py             # end-to-end CLI via subprocess: exit codes, formats, flags
```

## Running

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q            # everything
python -m pytest tests/test_rules_secrets.py -q   # one file
python -m pytest tests/ -k "redact" -q            # by keyword
```

CI runs the same suite on Python 3.10–3.13 across Linux, macOS and Windows.

## Conventions

**Synthetic credentials only.** Structural rules are tested with
documentation-example values (AWS's `AKIAIOSFODNN7EXAMPLE` <!-- agentpreflight: allow -->) or clearly
fake generated strings (`ghp_` + 36 characters). Never add a real-looking
credential that could be confused for one that works.

**Every rule needs positive AND negative fixtures** — a case that fires and
a near-miss that must not (e.g. `sk_test_` vs `sk_live_`). False-positive
regressions matter as much as detection.

**Redaction is asserted, not assumed.** Output tests check that the full
secret string never appears in any rendered format.

**CLI behaviour is tested end-to-end** via `run_cli()` (subprocess with the
installed package): exit codes, formats, config handling, usage errors.

**Git tests** build real temporary repositories (`init_repo` +
`commit_all`), including the canonical "secret deleted from HEAD but alive
in history" case.

## What is deliberately NOT tested

- Live network behaviour (the tool performs none; mocking would imply a
  feature that does not exist).
- Real-world precision/recall — no valid public dataset is bundled. Any
  quality claims in the docs are limited to the synthetic corpus in
  `tests/`, which is documented here rather than oversold.

## Adding tests

- New rule → new cases in the matching `test_rules_*.py` (positive,
  negative, and one contextual false-positive where applicable).
- New behaviour in the engine → integration case in `test_engine.py`.
- New CLI flag → usage + happy-path + error-path in `test_cli.py`.
- Bug fix → regression test first, then the fix.

## Quality gates

```bash
ruff check src tests && ruff format --check src tests
mypy
python -m pytest tests/ -q
```

All four must pass locally and in CI before review (see CONTRIBUTING.md).
