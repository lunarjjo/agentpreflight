"""Tests for the walker: enumeration, limits, symlinks, path validation."""

from __future__ import annotations

import os

import pytest
from tests.conftest import make_binary_file, make_file

from agentpreflight.walker import (
    _validate_relative,
    gather_files,
    is_binary_head,
    is_git_work_tree,
    read_file_content,
)


class TestValidateRelative:
    @pytest.mark.parametrize(
        "path",
        ["src/app.py", "a/b/c.txt", ".env", "spaced file.txt"],
    )
    def test_ok(self, path):
        assert _validate_relative(path) == path.replace("\\", "/")

    @pytest.mark.parametrize(
        "path",
        ["", "/abs/path", "../escape", "a/../../b", "..", ".", None, "bad\x00path"],
    )
    def test_rejected(self, path):
        assert _validate_relative(path) is None


class TestFilesystemWalk:
    def test_walk_collects_files(self, tree):
        make_file(tree, "a.txt", "x")
        make_file(tree, "sub/b.py", "y")
        inv = gather_files(str(tree), max_files=100, no_git=True)
        assert sorted(inv.files) == ["a.txt", "sub/b.py"]
        assert inv.tracked is None

    def test_walk_skips_git_dir(self, tree):
        make_file(tree, ".git/config", "x")
        make_file(tree, "code.py", "y")
        inv = gather_files(str(tree), max_files=100, no_git=True)
        assert inv.files == ["code.py"]

    def test_walk_prunes_node_modules_but_records(self, tree):
        make_file(tree, "node_modules/pkg/index.js", "x")
        make_file(tree, "app.js", "y")
        inv = gather_files(str(tree), max_files=100, no_git=True)
        assert inv.files == ["app.js"]
        assert "node_modules" in inv.pruned_dirs

    def test_walk_never_follows_symlinks(self, tree, tmp_path_factory):
        outside = tmp_path_factory.mktemp("outside")
        make_file(outside, "secret.txt", "AKIAIOSFODNN7EXAMPLE\n")
        os.symlink(outside / "secret.txt", tree / "link.txt")
        link_dir = tree / "linkdir"
        link_dir.mkdir()
        os.symlink(outside, link_dir / "pointing-out")
        inv = gather_files(str(tree), max_files=100, no_git=True)
        assert "link.txt" not in inv.files
        assert not any(p.startswith("linkdir") for p in inv.files)

    def test_max_files_limit(self, tree):
        for i in range(10):
            make_file(tree, f"f{i}.txt", "x")
        inv = gather_files(str(tree), max_files=3, no_git=True)
        assert len(inv.files) == 3
        assert any("file limit" in e for e in inv.errors)


class TestGitInventory:
    def test_git_mode_tracks_untracked_but_not_ignored(self, repo):
        make_file(repo, "committed.txt", "a")
        from tests.conftest import commit_all

        commit_all(repo, "add")
        make_file(repo, "fresh.txt", "b")  # untracked, not ignored
        make_file(repo, "ignored.log", "c")
        (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
        inv = gather_files(str(repo), max_files=100)
        assert "committed.txt" in inv.files
        assert "fresh.txt" in inv.files
        assert ".gitignore" in inv.files
        assert "ignored.log" not in inv.files
        assert inv.tracked is not None and "committed.txt" in inv.tracked

    def test_non_git_dir_falls_back_to_walk(self, tree):
        make_file(tree, "x.txt", "a")
        assert not is_git_work_tree(str(tree))
        inv = gather_files(str(tree), max_files=10)
        assert inv.files == ["x.txt"]

    def test_single_file_scan_root(self, tree):
        make_file(tree, "only.py", "a")
        from agentpreflight.engine import ScanOptions, run_scan

        result = run_scan(ScanOptions(path=str(tree / "only.py"), no_git=True))
        assert result.stats.files_scanned <= 1
        assert result.errors == []


class TestBinaryDetection:
    def test_nul_is_binary(self):
        assert is_binary_head(b"ab\x00cd")

    def test_plain_text_is_not_binary(self):
        assert not is_binary_head(b"hello world\n")

    def test_high_control_ratio_is_binary(self):
        assert is_binary_head(bytes(range(1, 30)))

    def test_utf8_with_multibyte_not_binary(self):
        assert not is_binary_head("héllo wörld ünïcode\n".encode())


class TestReadFileContent:
    def test_normal_read(self, tree):
        target = make_file(tree, "a.txt", "content")
        size, text, skip = read_file_content(str(target), max_file_size=1000)
        assert size == 7
        assert text == "content"
        assert skip is None

    def test_oversized(self, tree):
        target = make_file(tree, "big.txt", "x" * 100)
        size, text, skip = read_file_content(str(target), max_file_size=10)
        assert size == 100
        assert text is None
        assert skip == "oversized"

    def test_binary(self, tree):
        target = make_binary_file(tree, "bin.dat")
        _, text, skip = read_file_content(str(target), max_file_size=100000)
        assert text is None
        assert skip == ""

    def test_missing_file(self, tree):
        _, text, skip = read_file_content(str(tree / "nope.txt"), max_file_size=10)
        assert text is None
        assert skip and skip.startswith("unreadable")

    def test_invalid_utf8_still_scanned(self, tree):
        target = tree / "latin.txt"
        target.write_bytes(b"caf\xe9\xff\xfe garbage")
        _, text, skip = read_file_content(str(target), max_file_size=1000)
        assert skip is None
        assert text is not None
