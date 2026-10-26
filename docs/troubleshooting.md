# Troubleshooting

## `agentpreflight: command not found`

Install first (`pip install "git+https://github.com/lunarjjo/agentpreflight"`)
or run the module form: `python -m agentpreflight version`. On Windows, if
the Scripts directory is not on PATH, prefer `python -m agentpreflight`.

## Exit code 3 — "configuration error: ..."

The config file failed strict validation. The message names the exact key
and expected values. Common causes:

- `severity = "warnings"` (not one of: critical, high, medium, low, info)
- an `[[ignore]]` without `reason`
- a `rule_id = "*"` ignore without `allow_all = true`
- an unknown key (typo protection — check the reference in
  docs/configuration.md)

## Exit code 2 — operational errors

- `scan path does not exist` — check the path argument.
- `file limit (N) reached; scan results are partial` — raise
  `[scan] max_files` or narrow the scan path (e.g. `scan src` instead of
  `scan .` in a monorepo).
- `git ls-files failed` — the directory contains a broken `.git`; use
  `--no-git` for a plain filesystem scan.

## Git history scan issues

- **"git binary NOT found"** (doctor) or history scanning silently off —
  `--history` requires the `git` executable on PATH.
- **`max_commits` truncation** — by default only the most recent 5000
  commits' reachable blobs are scanned; raise `[scan] max_commits`.
- **Memory budget** — history scanning caps total blob content (256 MiB by
  default); enormous repositories are truncated with a warning. This is a
  deliberate safety limit, not a bug.
- **Slow on huge repos** — the attribution step (`git log --find-object`)
  runs per finding; reduce noise with `--severity high` first, then
  attribute.

## Secrets found only with `--history`

That means the value was deleted (or moved) from the working tree but
still exists in earlier commits. Rotating the credential is strongly
recommended — history is publishable. Then purge with `git filter-repo` (or
BFG) before making the repository public.

## Colors look wrong in my terminal

Set `NO_COLOR=1` or pass `--no-color`. On Windows, colors require Windows
10+ Terminal or `WT_SESSION`; classic conhost falls back to plain text
automatically.

## The scan seems to ignore files

In a Git repository the default file set is "tracked + untracked but not
ignored". To include ignored files, use `--no-git` (plain filesystem walk)
— but expect vendor-directory noise. Also check:

- `[scan] exclude_paths` in your config
- file size (`max_file_size`, default 10 MiB — content skipped, path rules
  still apply)
- binary detection (NUL byte / control-heavy files are skipped for content)

## Scan is slow

- Large repos: narrow the path (`scan src`), or exclude heavy generated
  directories in config.
- History scans dominate on big histories: run them on schedule rather
  than per-PR.
- Report genuinely pathological cases as issues with repository shape
  (files/bytes), platform and timing from the summary line.

## A rule crashed

You will see an informational finding "rule raised ... please report a
bug". The scan continued; please open an issue with the stack-free details
(rule ID, file shape, command).

## Still stuck?

Open an issue with:

1. `agentpreflight doctor` output
2. `agentpreflight version` output
3. the exact command and (sanitised) output

Never paste real credentials into issues — mask values.
