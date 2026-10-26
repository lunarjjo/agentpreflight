"""Output format tests: text, JSON, SARIF — structure and redaction."""

from __future__ import annotations

import json

from tests.conftest import make_file

from agentpreflight.config import Config
from agentpreflight.engine import ScanOptions, run_scan
from agentpreflight.models import Severity
from agentpreflight.output import (
    render_json,
    render_sarif,
    render_text,
    to_dict,
    to_sarif,
)


def scanned(tree, cfg: Config | None = None):
    make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
    make_file(tree, ".env", "X=1\n")
    return run_scan(ScanOptions(path=str(tree), config=cfg or Config(), no_git=True))


class TestTextOutput:
    def test_renders_without_secret(self, tree, capsys):
        result = scanned(tree)
        render_text(
            result,
            tool_version="0.1.0",
            fail_severity=Severity.HIGH,
            exit_code=1,
            no_color=True,
            quiet=False,
        )
        out = capsys.readouterr().out
        assert "APF-SEC-001" in out
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "CRITICAL" not in out or "HIGH" in out

    def test_terminal_injection_sanitised(self, tree, capsys):
        evil = "\x1b]52;c;base64payload\x07key = AKIAIOSFODNN7EXAMPLE"
        make_file(tree, "evil.txt", evil + "\n")
        result = run_scan(ScanOptions(path=str(tree), no_git=True))
        render_text(
            result,
            tool_version="0.1.0",
            fail_severity=Severity.HIGH,
            exit_code=1,
            no_color=True,
            quiet=False,
        )
        out = capsys.readouterr().out
        assert "\x1b" not in out


class TestJsonOutput:
    def test_structure(self, tree):
        result = scanned(tree)
        data = to_dict(result)
        assert data["tool"]["name"] == "agentpreflight"
        assert "findings" in data and isinstance(data["findings"], list)
        assert data["summary"]["total"] == len(data["findings"])
        for finding in data["findings"]:
            for key in (
                "rule_id",
                "severity",
                "confidence",
                "path",
                "message",
                "remediation",
            ):
                assert key in finding
        assert isinstance(data["errors"], list)

    def test_no_secret_in_json(self, tree):
        result = scanned(tree)
        payload = render_json(result)
        assert "AKIAIOSFODNN7EXAMPLE" not in payload

    def test_json_serialisable(self, tree):
        payload = render_json(scanned(tree))
        assert isinstance(json.loads(payload), dict)


class TestSarifOutput:
    def test_structure(self, tree):
        data = to_sarif(scanned(tree))
        assert data["version"] == "2.1.0"
        assert data["$schema"].endswith("sarif-2.1.0.json")
        run = data["runs"][0]
        assert run["tool"]["driver"]["name"] == "AgentPreflight"
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) >= 40
        for rule in rules:
            assert rule["id"] and rule["name"]
            assert rule["defaultConfiguration"]["level"] in ("error", "warning", "note")

    def test_results_reference_rules(self, tree):
        result = scanned(tree)
        data = to_sarif(result)
        run = data["runs"][0]
        rules = [r["id"] for r in run["tool"]["driver"]["rules"]]
        for res_entry in run["results"]:
            assert res_entry["ruleId"] in rules
            assert res_entry["ruleIndex"] == rules.index(res_entry["ruleId"])
            location = res_entry["locations"][0]["physicalLocation"]
            assert location["artifactLocation"]["uri"] == res_entry_path(location)
            assert "level" in res_entry
            assert "fingerprints" in res_entry

    def test_level_mapping(self, tree):
        data = to_sarif(scanned(tree))
        for res_entry in data["runs"][0]["results"]:
            level = res_entry["level"]
            assert level in ("error", "warning", "note")

    def test_uri_encoding(self, tree):
        make_file(tree, "dir with space/a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        result = run_scan(ScanOptions(path=str(tree), no_git=True))
        data = to_sarif(result)
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in data["runs"][0]["results"]]
        assert all(" " not in u for u in uris)
        assert any(u.startswith("dir%20with%20space") for u in uris)

    def test_no_secret_in_sarif(self, tree):
        payload = render_sarif(scanned(tree))
        assert "AKIAIOSFODNN7EXAMPLE" not in payload

    def test_region_present_for_line_findings(self, tree):
        data = to_sarif(scanned(tree))
        with_line = [r for r in data["runs"][0]["results"] if r["locations"][0]["physicalLocation"].get("region")]
        assert with_line and all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in with_line)


def res_entry_path(location: dict) -> str:
    return location["artifactLocation"]["uri"]
