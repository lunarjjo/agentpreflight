"""Engine integration tests: suppression, filtering, ordering, limits."""

from __future__ import annotations

from typing import ClassVar

from tests.conftest import make_file

from agentpreflight.config import Config, IgnoreEntry
from agentpreflight.engine import ScanOptions, run_scan
from agentpreflight.models import Severity


def scan(tree, config: Config | None = None, history: bool = False):
    return run_scan(ScanOptions(path=str(tree), config=config or Config(), include_history=history, no_git=True))


SYNTHETIC_RECIPE = {
    ".env": "DB=postgres://admin:hunter2pass@db.example.com/x\n",
    "config.py": "key = AKIAIOSFODNN7EXAMPLE\n",
    "notes.md": "# docs\nnothing here\n",
}


class TestBaselineScan:
    def test_finds_all(self, tree):
        for name, content in SYNTHETIC_RECIPE.items():
            make_file(tree, name, content)
        result = scan(tree)
        ids = {f.rule_id for f in result.findings}
        assert "APF-SEC-001" in ids
        assert "APF-SEC-009" in ids
        assert "APF-ART-001" in ids

    def test_clean_tree_no_findings(self, tree):
        make_file(tree, "README.md", "clean\n")
        result = scan(tree)
        assert result.findings == []
        assert result.errors == []

    def test_sort_order_severity_first(self, tree):
        make_file(tree, "a.env", "X=1\n")
        make_file(tree, "b.pem", "-----BEGIN OPENSSH PRIVATE KEY-----\n")
        result = scan(tree)
        severities = [f.severity.value for f in result.findings]
        assert severities == sorted(
            severities,
            key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[s],
        )

    def test_summary_counts(self, tree):
        make_file(tree, ".env", "X=1\n")
        result = scan(tree)
        assert result.summary()["total"] == len(result.findings)

    def test_exit_threshold_logic(self, tree):
        make_file(tree, "notes.txt", "xoxb-" + "123456789-SyntheticTokenValue99\n")
        result = scan(tree)
        assert result.has_findings_at_or_above(Severity.HIGH)
        assert not result.has_findings_at_or_above(Severity.CRITICAL)


class TestSuppression:
    def test_ignore_entry_suppresses(self, tree):
        make_file(tree, "config.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        cfg = Config(ignore=[IgnoreEntry(path="config.py", rule_id="APF-SEC-*", reason="test")])
        result = scan(tree, cfg)
        assert not [f for f in result.findings if f.rule_id == "APF-SEC-001"]
        assert any("suppressed" in w for w in result.warnings)

    def test_ignore_other_rule_still_fires(self, tree):
        make_file(tree, "config.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        cfg = Config(ignore=[IgnoreEntry(path="config.py", rule_id="APF-DEF-*", reason="test")])
        result = scan(tree, cfg)
        assert any(f.rule_id == "APF-SEC-001" for f in result.findings)

    def test_inline_allow_marker(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE  # agentpreflight: allow\n")
        result = scan(tree)
        assert not [f for f in result.findings if f.rule_id == "APF-SEC-001"]

    def test_severity_threshold_filters(self, tree):
        make_file(tree, "notes.txt", "xoxb-" + "123456789-SyntheticTokenValue99\n")  # high
        make_file(tree, "os-cruft", "x")  # not matched; use DS_Store instead
        (tree / ".DS_Store").write_text("junk", encoding="utf-8")
        cfg = Config(severity=Severity.HIGH)
        result = scan(tree, cfg)
        assert all(f.severity.rank >= Severity.HIGH.rank for f in result.findings)

    def test_exclude_rules(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        cfg = Config(exclude_rules=["APF-SEC-*"])
        result = scan(tree, cfg)
        assert not [f for f in result.findings if f.rule_id.startswith("APF-SEC")]

    def test_include_rules(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        make_file(tree, ".env", "X=1\n")
        cfg = Config(include_rules=["APF-SEC-001"])
        result = scan(tree, cfg)
        assert {f.rule_id for f in result.findings} == {"APF-SEC-001"}

    def test_path_exclusion(self, tree):
        make_file(tree, "vendor/a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        make_file(tree, "src/a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        cfg = Config(exclude_paths=["vendor"])
        result = scan(tree, cfg)
        assert all(not f.path.startswith("vendor/") for f in result.findings)


class TestRedactionEndToEnd:
    def test_no_secret_in_output_payload(self, tree):
        secret = "AKIAIOSFODNN7EXAMPLE"
        make_file(tree, "a.py", f"key = {secret}\n")
        result = scan(tree)
        for f in result.findings:
            public = str(f.to_public_dict())
            assert secret not in public
            if f.raw_line:
                assert secret not in f.raw_line

    def test_preview_shape(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        result = scan(tree)
        f = next(x for x in result.findings if x.rule_id == "APF-SEC-001")
        assert f.secret_preview is not None
        assert f.secret_preview.startswith("AKIA")
        assert len(f.secret_preview) < 25


class TestLimits:
    def test_oversized_file_skipped(self, tree):
        big = tree / "big.txt"
        big.write_text("AKIAIOSFODNN7EXAMPLE\n" + "x" * 100, encoding="utf-8")
        cfg = Config(max_file_size=50)
        result = scan(tree, cfg)
        assert result.stats.files_skipped_size == 1
        assert not [f for f in result.findings if f.rule_id == "APF-SEC-001"]

    def test_max_files_truncation(self, tree):
        for i in range(6):
            make_file(tree, f"f{i}.txt", "x")
        cfg = Config(max_files=3)
        result = scan(tree, cfg)
        assert any("partial" in e for e in result.errors)


class TestRuleResilience:
    def test_broken_rule_does_not_crash_scan(self, tree, monkeypatch):
        from agentpreflight import engine
        from agentpreflight.models import Confidence
        from agentpreflight.rules.base import ContentRule

        class ExplodingRule(ContentRule):
            id = "APF-TEST-999"
            name = "exploding"
            category = "secret"
            severity = Severity.INFO
            confidence = Confidence.LOW
            references: ClassVar[list[str]] = []

            def applies(self, ctx):
                return ctx.lines is not None

            def check_content(self, ctx):
                raise RuntimeError("boom")

        original = list(engine.ALL_RULES)
        monkeypatch.setattr(engine, "ALL_RULES", [ExplodingRule(), *original])
        make_file(tree, "a.txt", "hello\n")
        result = run_scan(ScanOptions(path=str(tree), no_git=True))
        assert any(f.rule_id == "APF-TEST-999" and "bug" in f.message for f in result.findings)
        assert result.errors == []


class TestSingleFileScan:
    def test_single_file(self, tree):
        make_file(tree, "clean.py", "ok = True\n")
        make_file(tree, "dirty.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        result = run_scan(ScanOptions(path=str(tree / "dirty.py"), no_git=True))
        assert {f.rule_id for f in result.findings} == {"APF-SEC-001"}
        assert all(f.path == "dirty.py" for f in result.findings)
