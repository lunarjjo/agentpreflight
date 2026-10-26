"""Git history scanning tests."""

from __future__ import annotations

import pytest
from tests.conftest import commit_all, make_file

from agentpreflight.config import Config
from agentpreflight.engine import ScanOptions

pytestmark = pytest.mark.skipif(__import__("shutil").which("git") is None, reason="git binary unavailable")


class TestHistoryScan:
    def test_secret_deleted_from_head_found_in_history(self, repo):
        make_file(repo, "leak.txt", "db = " + "postgres://admin:Sup3rS3cret99" + "@db/x\n")
        commit_all(repo, "add leak")
        (repo / "leak.txt").unlink()
        commit_all(repo, "remove leak")

        worktree = run_scan(repo, history=False)
        assert not worktree.findings

        history = run_scan(repo, history=True)
        assert any(f.rule_id == "APF-SEC-009" for f in history.findings)
        assert all(f.commit for f in history.findings)

    def test_worktree_secret_not_duplicated_by_history(self, repo):
        make_file(repo, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        commit_all(repo, "add")
        result = run_scan(repo, history=True)
        paths = [f.path for f in result.findings if f.rule_id == "APF-SEC-001"]
        # worktree finding + history finding are distinct (different paths)
        assert any(p == "a.py" for p in paths)
        assert any(p.startswith("<history:") for p in paths)

    def test_history_counts(self, repo):
        make_file(repo, "a.txt", "x\n")
        commit_all(repo, "c1")
        make_file(repo, "b.txt", "y\n")
        commit_all(repo, "c2")
        result = run_scan(repo, history=True)
        assert result.stats.history_commits_considered >= 3
        assert result.stats.history_blobs_scanned > 0

    def test_history_respects_max_commits(self, repo):
        for i in range(5):
            make_file(repo, f"f{i}.txt", f"v{i}\n")
            commit_all(repo, f"c{i}")
        cfg = Config(max_commits=2)
        result = run_scan(repo, cfg, history=True)
        assert result.stats.history_commits_considered <= 2

    def test_clean_history_no_findings(self, repo):
        make_file(repo, "ok.py", "value = 1\n")
        commit_all(repo, "clean")
        result = run_scan(repo, history=True)
        assert not [f for f in result.findings if f.path.startswith("<history:")]


def run_scan(repo, cfg: Config | None = None, history: bool = False):
    return _run(ScanOptions(path=str(repo), config=cfg or Config(), include_history=history))


def _run(options: ScanOptions):
    from agentpreflight.engine import run_scan as _rs

    return _rs(options)


class TestIsGitWorkTree:
    def test_git_dir(self, repo):
        from agentpreflight.walker import is_git_work_tree

        assert is_git_work_tree(str(repo))

    def test_plain_dir(self, tree):
        from agentpreflight.walker import is_git_work_tree

        assert not is_git_work_tree(str(tree))
