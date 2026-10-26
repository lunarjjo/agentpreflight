"""Shared test helpers.

All credentials in fixtures are SYNTHETIC. Structural patterns are
exercised with documentation-example values (e.g. AWS's published
AKIAIOSFODNN7EXAMPLE) or clearly fake generated strings.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def make_file(root: Path, rel: str, content: str) -> Path:
    """Write a file under root; returns the path."""
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def make_binary_file(root: Path, rel: str, size: int = 256) -> Path:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    # deterministic NUL prefix guarantees binary detection
    target.write_bytes(b"\x00\x01\x02\xff" + os.urandom(size))
    return target


def init_repo(path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)


def git(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def commit_all(path: Path, message: str = "wip") -> None:
    git("add", "-A", cwd=path)
    git("commit", "-qm", message, cwd=path)


def run_cli(*args: str, cwd: Path | None = None, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    """Run the installed CLI as a subprocess (true end-to-end)."""
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["PYTHONUTF8"] = "1"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "agentpreflight", *args],
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )


def scan_paths(result: object) -> set:
    """Set of (rule_id, path, line) tuples from a ScanResult."""
    return {(f.rule_id, f.path, f.line) for f in result.findings}  # type: ignore[attr-defined]


def load_json_output(proc: subprocess.CompletedProcess) -> dict:
    return json.loads(proc.stdout)


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    """A plain directory with no Git metadata."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """A fresh Git repository with one commit."""
    init_repo(tmp_path)
    make_file(tmp_path, "README.md", "# fixture\n")
    commit_all(tmp_path, "init")
    return tmp_path
