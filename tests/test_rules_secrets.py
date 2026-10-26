"""Positive and negative tests for every secret-detection rule."""

from __future__ import annotations

import pytest
from tests.conftest import make_file

from agentpreflight.engine import _scan_one_file
from agentpreflight.rules.base import ContentRule, PathRule
from agentpreflight.rules.registry import RULES_BY_ID

# Synthetic fixture values. Formats match real ones; none are credentials.
POSITIVE_FIXTURES = {
    "APF-SEC-001": "aws_key = AKIAIOSFOD" + "NN7EXAMPLE",
    "APF-SEC-002": "token = ghp_abcdef" + "ghijklmnopqrstuvwxyz0123456789",
    "APF-SEC-002-fine": "token = github_pat_11ABCd" + "efGHIjklMNOpqrsTUVwxyz01234567890_987",
    "APF-SEC-003": "slack = xoxb-1234" + "56789012-AbCdEfGhIjKlMnOpQrStUvWx",
    "APF-SEC-004": "key = AIzaSyA123" + "4567890abcdefghijklmnopqrstuv",
    "APF-SEC-005": "stripe = sk_live_abcdef" + "ghijklmnopqrstuvwx",
    "APF-SEC-006": "openai = sk-proj-abcdef" + "ghijklmnopqrstuvwxAbCdEfGhIjKlMnOpqrsTUVwxyz0123456789",
    "APF-SEC-007": "-----BEGIN RSA PRIVATE KEY-----",
    "APF-SEC-008": "jwt = eyJhbGciOiJIUz" + "I1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4",
    "APF-SEC-009": "url = postgres://admin:" + "hunter2pass@db.example.com/prod",
    "APF-SEC-010": "gl = glpat-abcdef" + "ghijklmnopqrst",
    "APF-SEC-011": "npm = npm_abcdef" + "ghijklmnopqrstuvwxyz0123456789",
    "APF-SEC-012": "pypi = pypi-AgEIcH"
    + "lwaS5vcmcJYWFzdGVyLXByb2plY3QyMDI2MDExNzAxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcA",
    "APF-SEC-013": "sg = SG.ABCDEF" + "GHIJKLMNOPQRSTUV.Wxyz0123456789AbCdEfGhIjKlMnOpQrStUvW",
    "APF-SEC-014": "tg = 123456789:AAHfiqksKZ8WmoMTs_12345678901234567",
    "APF-SEC-015": "hook = https://hooks.slack.com/services/T12345" + "678/B12345678/AbCdEfGhIjKlMnOpQrStUv",
    "APF-SEC-016": "shopify = shpat_012345" + "6789abcdef0123456789abcdef",
    "APF-SEC-017": "conn = DefaultEndpointsProtocol=https;AccountKey=AbCdEf"
    + "GhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn==",
    "APF-SEC-018": "square = sq0atp-AbCdEf" + "GhIjKlMnOpQrStUvWx",
    "APF-SEC-019": "meta = EAACEdEose0cBA123456" + "7890ZzZzZzZ",
    "APF-SEC-020": 'api_key = "kQ9mV2xLp7RtWn4JzY6cF3Hs8Tb1"',
}

NEGATIVE_FIXTURES = {
    "APF-SEC-001": "id = AKIAnotake" + "y but AKIAIOSFODNN7EXAMPLEXX is too long anyway",
    "APF-SEC-002": "github_pat_short " + "= github_pat_abc",  # too short for the fine-grained pattern
    "APF-SEC-005": "stripe_test = sk_test_abcdef" + "ghijklmnopqrstuvwx",  # test keys are fine
    "APF-SEC-006": "openai_short = sk-abc123def456",
    "APF-SEC-009": "url = https://example.com/docs",
    "APF-SEC-020": 'api_key = "your-api-key-here"',
    "APF-SEC-020-b": "password = 'changeme'",
    "APF-SEC-020-c": "password = 'admin'",
}

PLACEHOLDER_LINES = [
    "api_key = ${API_KEY}",
    "secret: {{ VAULT_SECRET }}",
    'token = "<insert-token>"',
    "password = 'xxxxxxxx'",
    "api_key: your_api_key",
]


def scan_text(tmp_path, filename: str, content: str):
    make_file(tmp_path, filename, content + "\n")
    rules = [r for r in RULES_BY_ID.values() if isinstance(r, (ContentRule, PathRule))]
    findings, _ = _scan_one_file(str(tmp_path), filename, None, {filename}, rules, 10 * 1024 * 1024)
    return findings


class TestStructuralSecretRules:
    @pytest.mark.parametrize(
        ("rule_id", "line"),
        sorted(POSITIVE_FIXTURES.items()),
        ids=lambda v: str(v)[:40],
    )
    def test_positive(self, tmp_path, rule_id, line):
        base_id = rule_id.split("-")[0] + "-" + rule_id.split("-")[1] + "-" + rule_id.split("-")[2]
        findings = scan_text(tmp_path, "fixture.txt", line)
        ids = {f.rule_id for f in findings}
        assert base_id in ids, f"{base_id} did not fire on: {line}"

    @pytest.mark.parametrize(
        ("rule_id", "line"),
        sorted(NEGATIVE_FIXTURES.items()),
        ids=lambda v: str(v)[:40],
    )
    def test_negative(self, tmp_path, rule_id, line):
        base_id = "-".join(rule_id.split("-")[:3])
        findings = scan_text(tmp_path, "fixture.txt", line)
        ids = {f.rule_id for f in findings}
        assert base_id not in ids, f"{base_id} false-positive on: {line}"

    @pytest.mark.parametrize("line", PLACEHOLDER_LINES)
    def test_placeholders_quiet(self, tmp_path, line):
        findings = scan_text(tmp_path, "fixture.txt", line)
        assert not [f for f in findings if f.rule_id == "APF-SEC-020"], f"generic rule noisy on placeholder: {line}"


class TestSecretRedaction:
    def test_finding_holds_no_full_secret(self, tmp_path):
        secret = "ghp_" + "z" * 36
        findings = scan_text(tmp_path, "t.txt", f"token = {secret}")
        match = [f for f in findings if f.rule_id == "APF-SEC-002"]
        assert match
        f = match[0]
        assert secret not in (f.secret_preview or "")
        assert secret not in (f.raw_line or "")
        assert secret not in f.message

    def test_history_context_marker(self, tmp_path):
        secret = "AKIAIOSFODNN7EXAMPLE"
        findings = scan_text(tmp_path, "t.txt", f"key = {secret}  # agentpreflight: allow")
        assert not [f for f in findings if f.rule_id == "APF-SEC-001"], (
            "inline allow marker did not suppress the finding"
        )

    def test_allow_marker_case_insensitive(self, tmp_path):
        secret = "AKIAIOSFODNN7EXAMPLE"
        findings = scan_text(tmp_path, "t.txt", f"key = {secret}  # AgentPreflight: Allow")
        assert not [f for f in findings if f.rule_id == "APF-SEC-001"]


class TestRuleCatalogIntegrity:
    def test_secret_rule_count(self):
        secret_rules = [r for r in RULES_BY_ID.values() if r.id.startswith("APF-SEC-")]
        assert len(secret_rules) == 20

    def test_all_rules_have_metadata(self):
        for rule in RULES_BY_ID.values():
            meta = rule.metadata()
            assert meta["id"] and meta["name"] and meta["description"]
            assert meta["severity"] in ("critical", "high", "medium", "low", "info")
            assert meta["confidence"] in ("high", "medium", "low")

    def test_rule_ids_are_stable(self):
        expected_prefixes = ("APF-SEC-", "APF-ART-", "APF-DEF-", "APF-DEP-")
        for rule_id in RULES_BY_ID:
            assert rule_id.startswith(expected_prefixes)

    def test_remediation_for_high_severity_rules(self):
        for rule in RULES_BY_ID.values():
            if rule.severity.value in ("critical", "high"):
                assert rule.remediation.strip(), f"{rule.id} needs remediation guidance"
