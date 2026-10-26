# Third-party notices

## Runtime dependencies

**None.** AgentPreflight has zero runtime dependencies — the installable
package contains only its own code (verified in CI by checking that the
built wheel's metadata lists an empty dependency set).

On Python 3.11+ the scanner uses the standard library's `tomllib` for
configuration parsing. On Python 3.10 it falls back to a vendored
minimal parser (`agentpreflight._toml_lite`) that implements only the
documented configuration subset.

## Development dependencies

Used only for development, testing and release verification — never
installed by end users:

| Tool | License | Purpose |
|---|---|---|
| [pytest](https://pytest.org) | MIT | test runner |
| [ruff](https://docs.astral.sh/ruff/) | MIT | linting + formatting |
| [mypy](https://mypy-lang.org) | MIT | static type checking |
| [build](https://pypa-build.readthedocs.io) | MIT | sdist/wheel building |
| [twine](https://twine.readthedocs.io) | Apache-2.0 | artifact verification |

## CI dependencies (GitHub Actions)

Pinned to verified commit SHAs:

| Action | License |
|---|---|
| [actions/checkout](https://github.com/actions/checkout) | MIT |
| [actions/setup-python](https://github.com/actions/setup-python) | MIT |
| [actions/upload-artifact](https://github.com/actions/upload-artifact) | MIT |
| [actions/download-artifact](https://github.com/actions/download-artifact) | MIT |
| [github/codeql-action/upload-sarif](https://github.com/github/codeql-action) | MIT |

## Detection patterns

Rule patterns were written from public documentation of each credential
format (see `docs/rules.md` references). No proprietary scanner rule sets
were copied. Synthetic fixture values include AWS's published example key
(`AKIAIOSFODNN7EXAMPLE` <!-- agentpreflight: allow -->) and clearly synthetic strings.

## License

AgentPreflight itself is MIT-licensed — see [LICENSE](LICENSE).
