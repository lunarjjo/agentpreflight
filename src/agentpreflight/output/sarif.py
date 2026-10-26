"""SARIF 2.1.0 output for code-scanning integrations.

The SARIF document embeds the full rule catalog in
``runs[0].tool.driver.rules`` and maps every result to its rule via
``ruleIndex``. Severity mapping:

- critical, high  -> error
- medium          -> warning
- low, info       -> note

Relative paths are emitted as relative URIs (recommended for
portability); GitHub Code Scanning resolves them against the checkout.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

from agentpreflight import __version__
from agentpreflight.models import ScanResult, Severity
from agentpreflight.rules.registry import ALL_RULES

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _uri(path: str) -> str:
    return quote(path.replace("\\", "/"), safe="/-._~!$&'()*+,;=:@[]")


def _rule_name(rule_id: str, rule_name: str) -> str:
    """SARIF rule.name: PascalCase-ish, unique, derived from the display name."""
    parts = rule_name.replace("/", " ").replace("-", " ").replace(".", " ").split()
    candidate = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return candidate or rule_id.replace("-", "")


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules_payload: list[dict[str, Any]] = []
    index_by_id: dict[str, int] = {}
    for idx, rule in enumerate(ALL_RULES):
        index_by_id[rule.id] = idx
        rules_payload.append(
            {
                "id": rule.id,
                "name": _rule_name(rule.id, rule.name),
                "shortDescription": {"text": rule.name},
                "fullDescription": {"text": rule.description},
                "help": {
                    "text": rule.remediation or rule.description,
                    "markdown": (
                        (rule.remediation or rule.description)
                        + (
                            "\n\nReferences: " + ", ".join(f"<{ref}>" for ref in rule.references)
                            if rule.references
                            else ""
                        )
                    ),
                },
                "defaultConfiguration": {"level": _LEVEL[rule.severity]},
                "properties": {
                    "security-severity": _security_severity(rule.severity),
                    "agentpreflight-category": rule.category,
                    "agentpreflight-confidence": rule.confidence.value,
                },
            }
        )

    results_payload: list[dict[str, Any]] = []
    for finding in result.findings:
        rule_index = index_by_id.get(finding.rule_id)
        message = finding.message
        if finding.secret_preview:
            message += f" (value redacted: {finding.secret_preview})"
        region: dict[str, Any] = {}
        if finding.line:
            region["startLine"] = finding.line
            if finding.column:
                region["startColumn"] = finding.column
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index,
            "level": _LEVEL[finding.severity],
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _uri(finding.path),
                            "uriBaseId": "ROOTPATH",
                        },
                        **({"region": region} if region else {}),
                    }
                }
            ],
            "fingerprints": {"agentpreflight/finding/v1": finding.fingerprint},
            "partialFingerprints": {
                "agentpreflight/rulePathLine/v1": f"{finding.rule_id}:{finding.path}:{finding.line or 0}"
            },
            "properties": {
                "confidence": finding.confidence.value,
                "category": finding.category,
                "commit": finding.commit,
            },
        }
        results_payload.append(entry)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentPreflight",
                        "version": __version__,
                        "informationUri": "https://github.com/lunarjjo/agentpreflight",
                        "rules": rules_payload,
                    }
                },
                "originalUriBaseIds": {"ROOTPATH": {"uri": "file:///,/"}},
                "results": results_payload,
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


def render_sarif(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2, ensure_ascii=False)


def _security_severity(severity: Severity) -> str:
    """GitHub code-scanning numeric severity (10.0 critical → 1.0 info)."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.0",
        Severity.INFO: "1.0",
    }[severity]
