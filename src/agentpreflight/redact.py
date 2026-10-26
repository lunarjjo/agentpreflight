"""Redaction and terminal-safety helpers.

Every piece of text that reaches terminal, JSON or SARIF output passes
through :func:`sanitize_for_terminal` to strip escape sequences and control
characters (defence against terminal escape-sequence injection from malicious
repository content).

Detected secret values are never emitted in full. Previews show at most the
first four characters plus a fingerprint, which is enough to recognise a
value during triage without re-leaking it into logs.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections import Counter
from math import log2

_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

# 4-char prefix at most. Short values show even less.
_PREVIEW_PREFIX_LEN = 4

# Placeholders that look like secrets but are documentation noise.
PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "change_me",
    "example",
    "examples",
    "placeholder",
    "dummy",
    "sample",
    "fake",
    "test",
    "testing",
    "todo",
    "fixme",
    "redacted",
    "xxx",
    "xxxx",
    "xxxxx",
    "xxxxxxxx",
    "your-api-key",
    "your_api_key",
    "your-password",
    "your_password",
    "your-secret",
    "your_secret",
    "your-token",
    "your_token",
    "your-key-here",
    "insert-password",
    "replace-me",
    "replace_me",
    "not-a-real-secret",
    "hunter2",  # the internet's favourite example password
}

PLACEHOLDER_RE = re.compile(
    r"""^(?:
        [<(\[{]                                # <value> {value} [value] (value)
        [^>)\]}]{0,64}
        [>)\]}]
        |
        (?:\$\{[^}]{0,64}\})                    # ${VAR}
        |
        (?:\{\{[^}]{0,64}\}\})                  # {{ VAR }} templates
        |
        (?:\{%[^%]{0,64}%\})                    # {% VAR %}
        |
        (?:\$[A-Za-z_][A-Za-z0-9_]{0,64})       # $VAR
        |
        (?:%[A-Za-z_][A-Za-z0-9_]{0,64}%)       # %VAR%
        |
        (?:`[^`]{0,64}`)                        # `value`
        |
        (?:[A-Za-z0-9][A-Za-z0-9_-]{0,7}[-_][xX*]{4,})  # sk-XXXXXXXX / ghp_xxx
        |
        (?:\.\.\.|…|\*)                        # literal ellipsis/star
    )$""",
    re.VERBOSE,
)

# Values consisting solely of these characters are almost always formatting
# noise rather than credentials (e.g. "xxxxx", "----").
_MONOTONE_RE = re.compile(r"^(.)\1*$")

# Common weak/default passwords are handled by APF-DEF-006, not SEC rules.
WEAK_PASSWORDS = {
    "admin",
    "root",
    "password",
    "passwd",
    "secret",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "letmein",
    "welcome",
    "guest",
    "postgres",
    "mysql",
    "sa",
    "toor",
    "test",
    "test123",
    "abc123",
    "changeme",
    "password1",
    "p@ssw0rd",
}


def shannon_entropy(value: str) -> float:
    """Shannon entropy H(X) in bits per character of ``value``."""
    if not value:
        return 0.0
    length = len(value)
    counts = Counter(value)
    return -sum((c / length) * log2(c / length) for c in counts.values())


def fingerprint(value: str) -> str:
    """Short, stable, non-reversible fingerprint of a secret value."""
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def redact_preview(value: str) -> str:
    """Return a short, safe preview such as ``AKIA…1f2a3b4c``.

    Never returns the full value. For short values even fewer characters are
    shown, so nothing under 8 characters leaks more than two of them.
    """
    value = value.strip()
    if not value:
        return ""
    shown = min(_PREVIEW_PREFIX_LEN, max(1, len(value) - 4))
    prefix = value[:shown]
    return f"{prefix}…{fingerprint(value)}"


def sanitize_for_terminal(text: str) -> str:
    """Strip control characters (except newline and tab) and normalise.

    Also neutralises Unicode directionality overrides that have been used to
    hide malicious content in source files.
    """
    cleaned = _CTRL_RE.sub("", text)
    cleaned = "".join(ch for ch in cleaned if unicodedata.category(ch) not in {"Cc", "Cf"} or ch in "\n\t")
    # Neutralise bidi control characters by replacing with the Unicode
    # replacement marker visible in most terminals.
    cleaned = re.sub(r"[\u200e\u200f\u202a-\u202e\u2066-\u2069]", "?", cleaned)
    return cleaned


def mask_secret_in_line(line: str, start: int, end: int) -> str:
    """Replace the character span ``[start, end)`` with a redaction marker."""
    if start < 0 or end > len(line) or start >= end:
        return line
    return line[:start] + "****REDACTED****" + line[end:]


def looks_like_placeholder(value: str) -> bool:
    """Heuristics for values that are documentation, not credentials."""
    if not value:
        return True
    stripped = value.strip().strip("\"'`")
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES or lowered in WEAK_PASSWORDS:
        return True
    if _MONOTONE_RE.match(stripped):
        return True
    return bool(PLACEHOLDER_RE.match(stripped)) or (lowered.startswith(("your", "my", "the")) and len(lowered) <= 24)


def looks_generated_secret(value: str) -> bool:
    """Positive signals that an assigned value is a real secret.

    Used by the generic secret rule (APF-SEC-020): length plus either high
    Shannon entropy or a mix of character classes typical of generated keys.
    """
    stripped = value.strip()
    if len(stripped) < 12:
        return False
    if shannon_entropy(stripped) >= 4.0:
        return True
    has_lower = any(c.islower() for c in stripped)
    has_upper = any(c.isupper() for c in stripped)
    has_digit = any(c.isdigit() for c in stripped)
    has_symbol = any(not c.isalnum() for c in stripped)
    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    return len(stripped) >= 16 and classes >= 3
