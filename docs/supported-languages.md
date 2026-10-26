# Supported languages and capability matrix

AgentPreflight separates **language recognition** (which ecosystems a file
belongs to) from **rule implementation** (what is actually checked). Secret
and artifact rules are language-agnostic — they apply to all text files.
Ecosystem-specific checks apply where a rule declares a filter.

Status legend: **supported** = recognition + dedicated checks or full
language-agnostic coverage; **partial** = recognition + language-agnostic
rules only, dedicated checks pending; **experimental** = minimal/uncertain
mapping.

## Matrix

| Ecosystem | Recognition | Language-agnostic rules | Ecosystem-specific checks |
|---|---|---|---|
| Python | ✅ | ✅ all secret/artifact rules | ✅ DEF-001/002/003/011/012, DEP-002 |
| JavaScript / TypeScript / JSX | ✅ | ✅ | ✅ DEF-003/004/005/011/012, DEP-006 |
| Node.js packaging | ✅ package.json | ✅ | ✅ DEP-006 (lockfile, install hooks) |
| Java / Kotlin | ✅ | ✅ | ⬜ (weak-hash detection only: DEF-011) |
| C / C++ | ✅ | ✅ | ⬜ |
| C# / F# / VB.NET | ✅ | ✅ | ⬜ (DEF-011 covers `MessageDigest`-style usage) |
| Go | ✅ | ✅ | ⬜ (DEF-011) |
| Rust | ✅ | ✅ | ⬜ |
| Ruby | ✅ | ✅ | ⬜ (DEF-011 covers `Digest::MD5/SHA1`) |
| PHP | ✅ | ✅ | ⬜ (DEF-011) |
| Swift / Objective-C | ✅ | ✅ | ⬜ |
| Shell (Bash/Zsh/Fish) | ✅ | ✅ | ✅ DEP-001, DEF-004, DEF-014 |
| PowerShell | ✅ | ✅ | ⬜ |
| Perl / Lua / R / Julia / Dart | ✅ | ✅ | ⬜ |
| Elixir / Erlang / Scala / Groovy | ✅ | ✅ | ⬜ |
| Clojure / Haskell / OCaml | ✅ | ✅ | ⬜ |
| Fortran / COBOL / Assembly | ✅ | ✅ | ⬜ |
| Solidity / Move | ✅ | ✅ | ⬜ |
| SQL | ✅ | ✅ | ✅ ART-004 (dump detection) |
| HTML / CSS / Vue / Svelte | ✅ | ✅ | ⬜ |
| GraphQL / Protobuf | ✅ | ✅ | ⬜ |
| WebAssembly (wat) | experimental | ✅ | ⬜ |
| JSON / JSONC | partial | ✅ | ✅ DEP-006 (package.json), ART-003 |
| YAML | ✅ | ✅ | ✅ DEF-006/007/010 |
| TOML | ✅ | ✅ | ✅ DEF-006, config parsing |
| XML / INI / properties | partial | ✅ | ✅ DEF-006/007 |
| dotenv files | ✅ | ✅ | ✅ ART-001, DEF-004/006 |
| Docker / Compose | ✅ | ✅ | ✅ DEF-008, DEP-001 |
| Kubernetes / Helm | partial | ✅ | ✅ DEF-010 |
| Terraform / OpenTofu | partial | ✅ | ⬜ (roadmap v0.3) |
| Ansible | partial | ✅ | ✅ DEF-007 |
| Nix | experimental | ✅ | ⬜ |
| GitHub Actions | ✅ (path + action.yml) | ✅ | ✅ DEP-003/004/005 |
| GitLab CI | ✅ | ✅ | ✅ DEP-008 |
| Jenkins | partial | ✅ | ⬜ |
| Android (Gradle/manifest) | partial | ✅ | ⬜ (roadmap v0.3) |
| iOS (pbxproj/plist) | partial | ✅ | ⬜ (roadmap v0.3) |

✅ supported · ⬜ partial/pending — see ROADMAP.md. This table is generated
from the ecosystem registry in `src/agentpreflight/languages/registry.py`
and manually curated for the checks column; a test asserts registry/doc
consistency where machine-checkable.

## What "language support" means here

1. **Recognition** — file extensions and well-known filenames map to an
   ecosystem id (`detect_language`). Recognition powers reporting and rule
   targeting; unrecognized text files are still scanned by all
   language-agnostic rules (you never lose secret scanning because your
   language is exotic).
2. **Language-agnostic rules** — all `APF-SEC-*` (secrets), `APF-ART-*`
   (artifacts) and generic default rules run on any text file.
3. **Ecosystem-specific checks** — rules with explicit file filters
   (Django settings, Dockerfiles, K8s YAML, CI workflows, requirements.txt,
   package.json, ansible.cfg, ...). These are where per-ecosystem depth
   exists today and where the roadmap adds more.

## Blind spots (honest list)

- Files inside archives are not inspected (`.zip` containing `.env` is only
  caught by future APF-ART-009 — roadmap).
- Obfuscated secrets (base64/reversed/split across lines) are not
  reconstructed.
- Binary formats (`.docx`, `.pdf`, images) are skipped for content.
- Nested worktrees/submodules are not descended into.
- `.m`/`.h` are treated as Objective-C (MATLAB collision noted).
- Non-UTF-8 text is decoded with replacement characters; patterns that
  straddle the replacement may be missed (rare, by design trade-off).
