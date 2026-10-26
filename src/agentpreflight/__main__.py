"""Allow ``python -m agentpreflight`` as an alternative to the console script."""

from __future__ import annotations

from agentpreflight.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
