# Test fixtures

This directory intentionally contains **synthetic** credential-shaped
strings used by the test suite (positive fixtures must match rule
patterns). None of these values are real credentials:

- AWS uses its documented example key `AKIAIOSFODNN7EXAMPLE`.
- Other formats use obviously synthetic strings (`ghp_` + 36 characters
  of sequential letters, `x`-runs, etc.).
- The repository's own `.agentpreflight.toml` suppresses findings under
  `tests/**` with a documented reason and expiry — see that file.

When adding fixtures:

1. Never use a value that could be mistaken for a working credential.
2. Prefer documentation-example values where vendors publish them.
3. Keep positive AND negative fixtures side by side.

The rules are exercised programmatically via `tests/conftest.py::make_file`
in temporary directories; committed files here support future
corpus-quality measurement (see docs/testing.md for what we do and do not
claim about detection quality).
