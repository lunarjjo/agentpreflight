"""Minimal TOML-subset parser used when ``tomllib`` is unavailable (Python 3.10).

AgentPreflight's own configuration only needs a restricted slice of TOML:

- comments (``#``) and blank lines
- ``[section]`` and ``[a.b]`` headers, ``[[array-of-tables]]``
- keys with string, integer, boolean and flat string/integer/boolean
  array values

This module parses exactly that subset. It is not a general TOML parser.
On Python 3.11+ the stdlib ``tomllib`` is used instead. Tests verify both
implementations agree on every shipped example configuration.

The parser is intentionally strict: any syntax it does not understand is
a :class:`TomlLiteError`, never a silent misparse.
"""

from __future__ import annotations

import re
from typing import Any, TypeAlias

TomlValue: TypeAlias = str | int | bool | list["TomlValue"] | dict[str, Any]


class TomlLiteError(ValueError):
    """Raised for TOML syntax this parser does not accept."""


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f"}
_INT_RE = re.compile(r"^[+-]?[0-9]+$")
_KEY_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _parse_string(src: str, line_no: int) -> str:
    if len(src) < 2 or src[0] != '"' or src[-1] != '"':
        raise TomlLiteError(f"line {line_no}: expected double-quoted string, got: {src!r}")
    body = src[1:-1]
    out: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\":
            if i + 1 >= len(body):
                raise TomlLiteError(f"line {line_no}: dangling escape in string")
            nxt = body[i + 1]
            if nxt == "u":
                hexpart = body[i + 2 : i + 6]
                if len(hexpart) != 4:
                    raise TomlLiteError(f"line {line_no}: bad \\u escape")
                out.append(chr(int(hexpart, 16)))
                i += 6
                continue
            if nxt not in _ESCAPES:
                raise TomlLiteError(f"line {line_no}: unknown escape \\{nxt}")
            out.append(_ESCAPES[nxt])
            i += 2
            continue
        if ch == '"':
            raise TomlLiteError(f"line {line_no}: unescaped quote inside string")
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_scalar(token: str, line_no: int) -> str | int | bool:
    token = token.strip()
    if token == "true":
        return True
    if token == "false":
        return False
    if _INT_RE.match(token):
        return int(token)
    if token.startswith('"'):
        return _parse_string(token, line_no)
    raise TomlLiteError(f"line {line_no}: unsupported value syntax: {token!r}")


def _parse_inline_array(src: str, line_no: int) -> list[TomlValue]:
    src = src.strip()
    if not (src.startswith("[") and src.endswith("]")):
        raise TomlLiteError(f"line {line_no}: expected inline array")
    inner = src[1:-1].strip()
    if not inner:
        return []
    parts: list[str] = []
    current: list[str] = []
    in_string = False
    for ch in inner:
        if ch == '"':
            in_string = not in_string
        if ch == "," and not in_string:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    parts.append("".join(current))
    return [_parse_scalar(p, line_no) for p in parts if p.strip()]


def _split_kv(line: str) -> tuple[str, str]:
    in_string = False
    for idx, ch in enumerate(line):
        if ch == '"':
            in_string = not in_string
        elif ch == "=" and not in_string:
            return line[:idx].strip(), line[idx + 1 :].strip()
    raise ValueError("no '=' found")


def loads(text: str) -> dict[str, Any]:
    """Parse the TOML subset into a nested dictionary."""
    root: dict[str, Any] = {}
    current: dict[str, Any] = root

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[["):
            if not line.endswith("]]"):
                raise TomlLiteError(f"line {line_no}: malformed array-of-tables header")
            name = line[2:-2].strip()
            if not _KEY_RE.match(name):
                raise TomlLiteError(f"line {line_no}: bad key in array-of-tables header")
            node: Any = root
            parts = name.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                if isinstance(node, list):
                    node = node[-1]
            arr = node.setdefault(parts[-1], [])
            if not isinstance(arr, list):
                raise TomlLiteError(f"line {line_no}: '{name}' redefined as array of tables")
            table: dict[str, Any] = {}
            arr.append(table)
            current = table
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise TomlLiteError(f"line {line_no}: malformed table header")
            name = line[1:-1].strip()
            if not _KEY_RE.match(name):
                raise TomlLiteError(f"line {line_no}: bad key in table header")
            node = root
            parts = name.split(".")
            for part in parts[:-1]:
                nxt = node.setdefault(part, {})
                if isinstance(nxt, list):
                    nxt = nxt[-1]
                node = nxt
            table = node.setdefault(parts[-1], {})
            if isinstance(table, list):  # type: ignore[unreachable]
                raise TomlLiteError(f"line {line_no}: '{name}' is an array of tables")
            current = table
            continue
        # key = value
        try:
            key, value = _split_kv(line)
        except ValueError as exc:
            raise TomlLiteError(f"line {line_no}: expected 'key = value', got: {line!r}") from exc
        if not _KEY_RE.match(key):
            raise TomlLiteError(f"line {line_no}: bad key {key!r}")
        if value.startswith("["):
            parsed: TomlValue = _parse_inline_array(value, line_no)
        else:
            # strip trailing comment outside strings
            if not value.startswith('"'):
                value = value.split("#", 1)[0].strip()
            parsed = _parse_scalar(value, line_no)
        current[key] = parsed

    return root


def dumps(data: dict[str, Any]) -> str:
    """Serialise a plain dict to the supported TOML subset (for `init`)."""

    def fmt_scalar(value: Any) -> str:
        if value is True:
            return "true"
        if value is False:
            return "false"
        if isinstance(value, int):
            return str(value)
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            return f'"{escaped}"'
        raise TypeError(f"unsupported type for dumps: {type(value)!r}")

    def fmt_list(values: list[Any]) -> str:
        return "[" + ", ".join(fmt_scalar(v) for v in values) + "]"

    lines: list[str] = []

    def emit_table(prefix: str, table: dict[str, Any]) -> None:
        scalars = {k: v for k, v in table.items() if not isinstance(v, (dict, list))}
        arrays = {k: v for k, v in table.items() if isinstance(v, list) and all(not isinstance(x, dict) for x in v)}
        subtables = {k: v for k, v in table.items() if isinstance(v, dict)}
        arrays_of_tables = {
            k: v for k, v in table.items() if isinstance(v, list) and all(isinstance(x, dict) for x in v)
        }
        if prefix:
            lines.append(f"[{prefix}]")
        for key, value in {**scalars, **arrays}.items():
            if isinstance(value, list):
                lines.append(f"{key} = {fmt_list(value)}")
            else:
                lines.append(f"{key} = {fmt_scalar(value)}")
        if prefix and (scalars or arrays):
            lines.append("")
        for key, table_value in subtables.items():
            emit_table(f"{prefix}.{key}" if prefix else key, table_value)
        for key, entries in arrays_of_tables.items():
            for entry in entries:
                lines.append(f"[[{key}]]" if not prefix else f"[[{prefix}.{key}]]")
                for entry_key, entry_value in entry.items():
                    if isinstance(entry_value, list):
                        lines.append(f"{entry_key} = {fmt_list(entry_value)}")
                    else:
                        lines.append(f"{entry_key} = {fmt_scalar(entry_value)}")
                lines.append("")

    emit_table("", data)
    return "\n".join(lines).rstrip() + "\n"
