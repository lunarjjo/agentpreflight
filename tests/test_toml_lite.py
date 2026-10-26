"""Tests for the vendored TOML-subset parser (_toml_lite)."""

from __future__ import annotations

import pytest

from agentpreflight._toml_lite import TomlLiteError, dumps, loads

tomllib = pytest.importorskip("tomllib", reason="stdlib tomllib available on 3.11+")

EXAMPLES = [
    "# comment only\n",
    '[scan]\nseverity = "high"\nfail_severity = "critical"\n',
    "[scan]\nmax_file_size = 10485760\nworkers = 4\n",
    '[scan]\nexclude_paths = ["vendor", "tests/fixtures/**"]\n',
    '[scan]\ninclude_rules = ["APF-SEC-*"]\nexclude_rules = ["APF-DEP-002"]\n',
    '[output]\nformat = "sarif"\nredact = true\n',
    "[output]\nredact = false\n",
    '[[ignore]]\npath = "tests/fixtures/**"\nrule_id = "APF-SEC-*"\nreason = "synthetic fixtures"\n',
    '[[ignore]]\npath = "a"\nrule_id = "*"\nreason = "r"\nallow_all = true\nexpires = "2027-12-31"\n',
    "[scan]\n[output]\n",
    "[a.b.c]\nx = 1\n",
]


class TestParityWithTomllib:
    @pytest.mark.parametrize("text", EXAMPLES, ids=range(len(EXAMPLES)))
    def test_parses_like_tomllib(self, text):
        assert loads(text) == tomllib.loads(text)


class TestStrictness:
    def test_unknown_syntax_rejected(self):
        with pytest.raises(TomlLiteError):
            loads("key = [unquoted]")

    def test_single_quotes_rejected(self):
        with pytest.raises(TomlLiteError):
            loads("[scan]\nseverity = 'high'")

    def test_dangling_escape_rejected(self):
        with pytest.raises(TomlLiteError):
            loads('a = "abc\\')

    def test_bad_header_rejected(self):
        with pytest.raises(TomlLiteError):
            loads("[scan")

    def test_missing_equals_rejected(self):
        with pytest.raises(TomlLiteError):
            loads("[scan]\nseverity")

    def test_empty_array(self):
        assert loads("a = []") == {"a": []}

    def test_string_escapes(self):
        assert loads(r'a = "x\ty"') == {"a": "x\ty"}
        assert loads(r'a = "say \"hi\""') == {"a": 'say "hi"'}


class TestDumps:
    def test_roundtrip(self):
        data = {
            "scan": {"severity": "high", "workers": 4, "exclude_paths": ["vendor", "x/**"]},
            "output": {"format": "text", "redact": True},
            "ignore": [
                {"path": "a/**", "rule_id": "APF-SEC-*", "reason": "fixtures", "allow_all": False},
            ],
        }
        text = dumps(data)
        assert loads(text) == data

    def test_scalars(self):
        text = dumps({"a": 1, "b": "x", "c": True})
        assert loads(text) == {"a": 1, "b": "x", "c": True}
