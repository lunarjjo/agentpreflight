"""JSON output for automation."""

from __future__ import annotations

import json
from typing import Any

from agentpreflight import __version__
from agentpreflight.models import ScanResult


def to_dict(result: ScanResult) -> dict[str, Any]:
    return {
        "tool": {"name": "agentpreflight", "version": __version__},
        "scan": {
            "path": result.root,
            "started_at": result.stats.started_at,
            "duration_ms": result.stats.duration_ms,
            "files_scanned": result.stats.files_scanned,
            "files_skipped_size": result.stats.files_skipped_size,
            "files_skipped_unreadable": result.stats.files_skipped_unreadable,
            "history_scanned": result.history_scanned,
            "history_commits_considered": result.stats.history_commits_considered,
            "history_blobs_scanned": result.stats.history_blobs_scanned,
        },
        "findings": [f.to_public_dict() for f in result.findings],
        "errors": list(result.errors),
        "warnings": list(result.warnings),
        "summary": result.summary(),
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False)
