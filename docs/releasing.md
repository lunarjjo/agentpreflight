# Release process

This is the exact checklist for cutting a release. Nothing ships until
every applicable item is true — items that cannot be completed are
recorded as blockers in the GitHub release notes.

## Pre-release checklist

1. **Working tree clean** on `main`; CI green (lint + mypy + full matrix +
   self-scan + packaging jobs).
2. **Docs in sync**:
   - `agentpreflight rules list --format markdown > docs/rules.md` (if rules changed)
   - CHANGELOG.md entry complete for the new version
   - README badges/links point to real artifacts
3. **Version bumped** in `src/agentpreflight/__init__.py` (`__version__`).
   No other file carries the version (packaging reads it from the package).
4. **Self-scan clean**: `agentpreflight scan .` exits 0 on the repository
   itself (fixture suppressions are documented in `.agentpreflight.toml`).
5. **Redaction spot-check** on a synthetic repo: confirm text, JSON and
   SARIF outputs never contain the full planted value.
6. **Security review** for anything touching redaction, traversal,
   subprocess use or output rendering (see docs/security-model.md matrix).

## Cutting the release

```bash
# locally verify the artifact pipeline end-to-end first
python -m pip install --upgrade build twine
python -m build && python -m twine check dist/*
python -m venv /tmp/fresh && /tmp/fresh/bin/python -m pip install dist/*.whl
/tmp/fresh/bin/agentpreflight version && /tmp/fresh/bin/agentpreflight doctor

# tag and push — release.yml does the rest on GitHub
git tag -s vX.Y.Z -m "AgentPreflight vX.Y.Z"
git push origin vX.Y.Z
```

`release.yml` (on tag push):

1. builds sdist + wheel, verifies with `twine check`
2. installs the wheel into a **fresh venv** and runs `version` + `doctor`
3. generates `SHA256SUMS.txt`
4. creates the GitHub release with all artifacts attached

## Verification (consumers)

```bash
gh release download vX.Y.Z --pattern SHA256SUMS.txt --pattern 'agentpreflight*'
sha256sum -c SHA256SUMS.txt
```

## Status

| Channel | Status |
|---|---|
| Git tag + GitHub release | ✅ automated by release.yml |
| PyPI | ⏸ prepared, disabled — requires maintainer to configure trusted publishing first (steps in release.yml comments) |
| GitHub Marketplace listing | ⏸ after v0.1.0 tag exists |

Until PyPI is enabled, installation is `pip install
git+https://github.com/lunarjjo/agentpreflight@vX.Y.Z`.

## Never do

- Publish with a failing gate "to fix it later".
- Move a tag that anyone may have fetched (release a new patch instead).
- Include real credentials in release notes or artifacts (they are public).
