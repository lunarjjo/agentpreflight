"""Tests for redaction, entropy and terminal-safety helpers."""

from __future__ import annotations

import math

import pytest

from agentpreflight.redact import (
    fingerprint,
    looks_generated_secret,
    looks_like_placeholder,
    mask_secret_in_line,
    redact_preview,
    sanitize_for_terminal,
    shannon_entropy,
)


class TestEntropy:
    def test_empty_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_binary_ramp_is_one(self):
        assert math.isclose(shannon_entropy("01"), 1.0)

    def test_more_variation_more_entropy(self):
        assert shannon_entropy("ab1!9Xzq#Kd2Lp0v") > shannon_entropy("aaaaaaaaaaaaaaaa")

    def test_order_independent(self):
        assert math.isclose(shannon_entropy("abcd"), shannon_entropy("dcba"))


class TestRedactPreview:
    def test_long_value_shows_prefix_and_fingerprint(self):
        preview = redact_preview("AKIAIOSFODNN7EXAMPLE")
        assert preview.startswith("AKIA")
        assert "…" in preview
        assert fingerprint("AKIAIOSFODNN7EXAMPLE") in preview

    def test_full_value_never_appears(self):
        value = "ghp_" + "a" * 36
        preview = redact_preview(value)
        assert value not in preview
        assert value[:5] not in preview.replace(value[:4], "")

    def test_short_value_leaks_almost_nothing(self):
        preview = redact_preview("short")
        assert preview.count("*") >= 0
        assert "short" not in preview

    def test_empty(self):
        assert redact_preview("") == ""


class TestFingerprint:
    def test_stable(self):
        assert fingerprint("value") == fingerprint("value")

    def test_distinct(self):
        assert fingerprint("value") != fingerprint("value2")

    def test_length(self):
        assert len(fingerprint("x")) == 8


class TestMaskSecretInLine:
    def test_masks_span(self):
        line = "password = 'SuperSecret99'"
        masked = mask_secret_in_line(line, 12, 26)
        assert "SuperSecret99" not in masked
        assert "****REDACTED****" in masked
        assert masked.startswith("password = '")

    def test_invalid_span_returns_line(self):
        line = "abc"
        assert mask_secret_in_line(line, 5, 9) == line
        assert mask_secret_in_line(line, 2, 1) == line


class TestSanitizeForTerminal:
    def test_strips_ansi_escape(self):
        malicious = "\x1b]52;c;base64attack\x07 innocent text"
        cleaned = sanitize_for_terminal(malicious)
        assert "\x1b" not in cleaned

    def test_strips_control_chars_keeps_newline(self):
        cleaned = sanitize_for_terminal("a\x00b\x08c\nd\te")
        assert "\x00" not in cleaned and "\x08" not in cleaned
        assert "\n" in cleaned and "\t" in cleaned

    def test_neutralises_bidi_overrides(self):
        cleaned = sanitize_for_terminal("file\u202ecod.exe")
        assert "\u202e" not in cleaned


class TestPlaceholders:
    @pytest.mark.parametrize(
        "value",
        [
            "changeme",
            "xxx",
            "${API_KEY}",
            "{{ API_KEY }}",
            "<your-api-key>",
            "your-api-key",
            "your-token",
            "sk-XXXXXXXXXXXXXXXXXXXX",
        ],
    )
    def test_placeholders_recognised(self, value):
        assert looks_like_placeholder(value)

    @pytest.mark.parametrize(
        "value",
        [
            "kQ9mV2xLp7RtWn4J",
            "correct horse battery staple 42!",
        ],
    )
    def test_real_values_not_placeholders(self, value):
        assert not looks_like_placeholder(value)


class TestGeneratedSecret:
    def test_high_entropy_long_value(self):
        assert looks_generated_secret("qX7#mK2$vL9!pR4&zW8@")

    def test_mixed_classes_long_value(self):
        assert looks_generated_secret("SuperSecret2024!x")

    def test_short_value_rejected(self):
        assert not looks_generated_secret("Ab1!")

    def test_monotone_rejected(self):
        assert not looks_generated_secret("aaaaaaaaaaaaaaaa")

    def test_words_rejected(self):
        assert not looks_generated_secret("this-is-a-long-password")
