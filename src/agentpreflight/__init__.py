"""AgentPreflight — local-first repository security and pre-release readiness scanner.

AgentPreflight scans a working tree (and optionally Git history) for exposed
secrets, sensitive artifacts, insecure defaults and supply-chain hygiene
risks before you publish, deploy or release a repository.

Design goals:
- Local-first: no network access, no telemetry, no API keys for core use.
- Zero runtime dependencies: the scanner itself must not become a
  supply-chain liability.
- Safe: repository content is treated as untrusted input and detected
  secrets are always redacted in output.
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "Lunar.JJO"

TOOL_NAME = "agentpreflight"
USER_AGENT = f"agentpreflight/{__version__} (+https://github.com/lunarjjo/agentpreflight)"

__all__ = ["TOOL_NAME", "USER_AGENT", "__author__", "__version__"]
