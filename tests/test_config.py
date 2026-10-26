"""Configuration loading and validation tests."""

from __future__ import annotations

import pytest

from agentpreflight.config import (
    DEFAULT_CONFIG_TEMPLATE,
    Config,
    ConfigError,
    IgnoreEntry,
    find_config,
    from_dict,
    load_config_file,
    parse_toml,
)


class TestDefaults:
    def test_defaults(self):
        cfg = Config()
        assert cfg.max_file_size == 10 * 1024 * 1024
        assert cfg.max_files == 50_000
        assert cfg.redact is True
        assert cfg.format == "text"


class TestValidConfigs:
    def test_full_config(self, tmp_path):
        text = """
[scan]
severity = "medium"
fail_severity = "critical"
max_file_size = 1024
workers = 2
exclude_paths = ["vendor", "big/**"]

[output]
format = "sarif"
redact = false

[[ignore]]
path = "tests/fixtures/**"
rule_id = "APF-SEC-*"
reason = "synthetic fixtures"
expires = "2030-01-01"
"""
        cfg = from_dict(parse_toml(text))
        assert cfg.severity.value == "medium"
        assert cfg.fail_severity.value == "critical"
        assert cfg.max_file_size == 1024
        assert cfg.workers == 2
        assert cfg.exclude_paths == ["vendor", "big/**"]
        assert cfg.format == "sarif"
        assert cfg.redact is False
        assert len(cfg.ignore) == 1

    def test_default_template_parses(self):
        cfg = from_dict(parse_toml(DEFAULT_CONFIG_TEMPLATE))
        assert cfg.severity.value == "info"
        assert cfg.fail_severity.value == "high"

    def test_template_roundtrip(self, tmp_path):
        target = tmp_path / "cfg.toml"
        target.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        cfg, _ = load_config_file(target)
        assert cfg.ignore[0].reason.startswith("Synthetic")


class TestInvalidConfigs:
    def test_unknown_top_level_key(self):
        with pytest.raises(ConfigError, match="unknown top-level"):
            from_dict({"whatever": 1})

    def test_unknown_scan_key(self):
        with pytest.raises(ConfigError, match="unknown \\[scan\\]"):
            from_dict({"scan": {"nope": 1}})

    def test_bad_severity(self):
        with pytest.raises(ConfigError, match="severity"):
            from_dict({"scan": {"severity": "ultra"}})

    def test_bad_max_files_type(self):
        with pytest.raises(ConfigError, match="max_files"):
            from_dict({"scan": {"max_files": "many"}})

    def test_max_files_out_of_range(self):
        with pytest.raises(ConfigError, match="max_files"):
            from_dict({"scan": {"max_files": 0}})

    def test_bad_format(self):
        with pytest.raises(ConfigError, match="format"):
            from_dict({"output": {"format": "xml"}})

    def test_ignore_without_reason(self):
        with pytest.raises(ConfigError, match="reason"):
            from_dict({"ignore": [{"path": "x"}]})

    def test_ignore_wildcard_all_requires_allow_all(self):
        with pytest.raises(ConfigError, match="allow_all"):
            from_dict({"ignore": [{"path": "x", "reason": "r"}]})

    def test_ignore_bad_date(self):
        with pytest.raises(ConfigError, match="expires"):
            from_dict({"ignore": [{"path": "x", "reason": "r", "expires": "not-a-date"}]})

    def test_ignore_unknown_key(self):
        with pytest.raises(ConfigError, match="unknown key"):
            from_dict({"ignore": [{"path": "x", "reason": "r", "nonsense": 1}]})


class TestIgnoreSemantics:
    def test_expires_makes_entry_inactive(self):
        entry = IgnoreEntry(
            path="a",
            rule_id="*",
            reason="r",
            expires=__import__("datetime").date(2000, 1, 1),
            allow_all=True,
        )
        warnings: list[str] = []
        active = Config(ignore=[entry]).active_ignores(warnings)
        assert active == []
        assert warnings and "expired" in warnings[0]

    def test_future_expiry_active(self):
        entry = IgnoreEntry(
            path="a",
            rule_id="APF-SEC-*",
            reason="r",
            expires=__import__("datetime").date(2999, 1, 1),
        )
        assert Config(ignore=[entry]).active_ignores([]) == [entry]

    def test_matches_glob(self):
        entry = IgnoreEntry(path="tests/**", rule_id="APF-SEC-*", reason="r")
        assert entry.matches("tests/fixtures/a.py", "APF-SEC-001")
        assert not entry.matches("src/a.py", "APF-SEC-001")
        assert not entry.matches("tests/fixtures/a.py", "APF-DEF-001")


class TestFindConfig:
    def test_found(self, tmp_path):
        (tmp_path / ".agentpreflight.toml").write_text("[scan]\n", encoding="utf-8")
        assert find_config(tmp_path) is not None

    def test_not_found(self, tmp_path):
        assert find_config(tmp_path) is None


class TestRuleSelection:
    def test_include_filters(self):
        cfg = Config(include_rules=["APF-SEC-*"])
        assert cfg.allows_rule("APF-SEC-001")
        assert not cfg.allows_rule("APF-DEF-001")

    def test_exclude_filters(self):
        cfg = Config(exclude_rules=["APF-DEP-*"])
        assert not cfg.allows_rule("APF-DEP-002")
        assert cfg.allows_rule("APF-SEC-001")

    def test_exclude_wins_over_include(self):
        cfg = Config(include_rules=["APF-*"], exclude_rules=["APF-SEC-020"])
        assert not cfg.allows_rule("APF-SEC-020")


class TestPathExclusion:
    def test_segment_match(self):
        cfg = Config(exclude_paths=["node_modules"])
        assert cfg.is_path_excluded("node_modules/x/y.js")
        assert cfg.is_path_excluded("a/node_modules/x.js")
        assert not cfg.is_path_excluded("src/app.js")
