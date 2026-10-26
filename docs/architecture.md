# Architecture overview

```
┌────────────────────────────────────────────────────────────┐
│ CLI (cli.py)                                               │
│ scan · init · doctor · rules list/explain · version         │
└───────────────┬────────────────────────────────────────────┘
                │ ScanOptions + Config
┌───────────────▼────────────────────────────────────────────┐
│ Engine (engine.py)                                         │
│  • gathers file inventory      • evaluates rules            │
│  • applies suppression         • redacts & dedupes          │
│  • history scan orchestration                                │
└──┬──────────────┬───────────────┬──────────────────────────┘
   │              │               │
┌──▼─────────┐ ┌──▼───────────┐ ┌─▼──────────────────────────┐
│ Walker     │ │ Rules        │ │ Gitscan                   │
│ (walker.py)│ │ (rules/)     │ │ (gitscan.py)              │
│ git ls-    │ │ secrets.py   │ │ rev-list --objects        │
│ files / fs │ │ artifacts.py │ │ cat-file --batch          │
│ walk,      │ │ defaults.py  │ │ log --find-object         │
│ limits,    │ │ supply.py    │ │ (subprocess, budgeted)    │
│ traversal  │ │ registry.py  │ │                           │
│ guards     │ │ base.py      │ │                           │
└────────────┘ └──────┬───────┘ └───────────────────────────┘
                      │ FileContext / RepoContext
               ┌──────▼──────────────────────┐
               │ Languages (languages/)      │
               │ ecosystem registry          │
               │ (recognition only — no rule │
               │ logic coupled here)         │
               └─────────────────────────────┘
               ┌──────▼──────────────────────┐
               │ Output (output/)            │
               │ text · json · sarif 2.1.0   │
               └─────────────────────────────┘
```

## Data flow

1. **CLI** parses arguments, loads `.agentpreflight.toml` (strict
   validation, CLI overrides), and builds `ScanOptions`.
2. **Walker** enumerates candidate files. In a Git repository the set is
   `git ls-files --cached` ∪ `git ls-files --others --exclude-standard`
   — exactly the files that *would* be committed. Outside Git, a guarded
   `os.walk` prunes vendor directories (recording them for artifact rules).
3. **Engine** reads each file within budgets (binary detection, size cap,
   UTF-8 with replacement) and runs applicable rules on a thread pool.
   Repo-level rules run on the assembled inventory. If `--history` is set,
   `gitscan` streams every unique blob through the same content rules with
   commit attribution.
4. Findings are converted to redacted `Finding` objects: preview = first
   ≤4 chars + 8-hex fingerprint; the matched span is masked in snippets.
5. Suppression (inline allow markers → config `[[ignore]]`), severity
   filtering, deterministic ordering and fingerprint deduplication follow.
6. **Output** renders text/JSON/SARIF. Exit code: findings ≥ fail threshold
   → 1; else errors → 2; else 0.

## Key design decisions

| Decision | Rationale |
|---|---|
| Zero runtime dependencies | A supply-chain scanner must not be its own supply-chain risk; also makes the install trivially auditable. |
| Rules as plain classes, not YAML | Type-checked by mypy, testable by pytest, discoverable by IDE — same rigour as the core. |
| Language registry decoupled from rules | New ecosystems are added without touching the engine; capability docs derive from the registry. |
| `git ls-files` over raw walk in repos | Matches "what would be committed": untracked-but-not-ignored `.env` is caught pre-commit; ignored files stay out of the noise. |
| History scan via `cat-file --batch` | One long-lived process, blob dedupe by SHA, per-blob + total memory budgets, deadlock-free stdin feeding. |
| Unconditional redaction | No flag can ever print a full secret; triage works from the prefix + fingerprint. |
| Strict config validation | Misconfiguration fails loudly with exit 3 rather than silently changing behaviour. |
| Regex + entropy, not parsers | v0.1 targets breadth across 50+ ecosystems; semantic parsing of every config dialect is roadmap work where it demonstrably reduces false positives. |

## Extension points

- **New detection rule**: subclass `ContentRule`/`PathRule`/`RepoRule` and
  append to the category list (guide: CONTRIBUTING.md).
- **New ecosystem recognition**: extend the `ECOSYSTEMS` tuple in
  `languages/registry.py` — nothing else changes.
- **New output format**: implement `render_<format>(result)` in `output/`
  and register the CLI choice.

## Performance model

Single-pass, bounded-memory design. Content scanning is O(files × lines ×
applicable rules) with regexes compiled once at import. The thread pool is
I/O oriented; results are assembled deterministically regardless of worker
count. Oversized files are skipped for content (path rules still apply) and
reported in stats. See docs/benchmark.md for measured numbers and the
reproduction script.
