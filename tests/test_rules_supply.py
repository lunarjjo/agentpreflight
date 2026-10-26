"""Tests for supply-chain hygiene rules."""

from __future__ import annotations

from tests.conftest import make_file

from agentpreflight.engine import _scan_one_file
from agentpreflight.rules.base import ContentRule, PathRule
from agentpreflight.rules.registry import RULES_BY_ID


def scan_file(tmp_path, name: str, content: str, repo_files: set[str] | None = None):
    make_file(tmp_path, name, content)
    rules = [r for r in RULES_BY_ID.values() if isinstance(r, (ContentRule, PathRule))]
    findings, _ = _scan_one_file(str(tmp_path), name, None, repo_files or {name}, rules, 10**7)
    return findings


class TestCurlPipeShell:
    def test_basic(self, tmp_path):
        findings = scan_file(tmp_path, "install.sh", "curl https://get.example.com/install.sh | sh\n")
        assert "APF-DEP-001" in {f.rule_id for f in findings}

    def test_sudo_bash(self, tmp_path):
        findings = scan_file(tmp_path, "Dockerfile", "RUN wget -qO- https://x.example.dev/setup | sudo bash\n")
        assert "APF-DEP-001" in {f.rule_id for f in findings}

    def test_safe_download_not_flagged(self, tmp_path):
        findings = scan_file(
            tmp_path,
            "install.sh",
            "curl -o /tmp/setup.sh https://get.example.com/setup.sh\nsh /tmp/setup.sh\n",
        )
        assert "APF-DEP-001" not in {f.rule_id for f in findings}

    def test_plain_curl_not_flagged(self, tmp_path):
        findings = scan_file(tmp_path, "docs.md", "curl -I https://example.com | head\n")
        assert "APF-DEP-001" not in {f.rule_id for f in findings}


class TestUnpinnedRequirements:
    def test_unpinned(self, tmp_path):
        findings = scan_file(tmp_path, "requirements.txt", "requests\nflask\n")
        ids = [f.rule_id for f in findings]
        assert ids.count("APF-DEP-002") == 2

    def test_pinned(self, tmp_path):
        findings = scan_file(tmp_path, "requirements.txt", "requests==2.32.3\nflask>=3.0.0\n")
        assert "APF-DEP-002" not in [f.rule_id for f in findings]

    def test_comments_and_options_ignored(self, tmp_path):
        findings = scan_file(
            tmp_path,
            "requirements.txt",
            "# comment\n-r base.txt\n--index-url https://pypi.org/simple\n",
        )
        assert "APF-DEP-002" not in [f.rule_id for f in findings]

    def test_git_url_ignored(self, tmp_path):
        findings = scan_file(tmp_path, "requirements.txt", "git+https://github.com/org/repo.git@v1.0\n")
        assert "APF-DEP-002" not in [f.rule_id for f in findings]


class TestPullRequestTarget:
    def test_pr_head_checkout_flagged(self, tmp_path):
        wf = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - run: ./build.sh
"""
        findings = scan_file(tmp_path, ".github/workflows/pr.yml", wf)
        assert "APF-DEP-003" in {f.rule_id for f in findings}

    def test_pull_request_target_alone_is_not_enough(self, tmp_path):
        wf = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: make test
"""
        findings = scan_file(tmp_path, ".github/workflows/pr.yml", wf)
        assert "APF-DEP-003" not in {f.rule_id for f in findings}

    def test_normal_pr_workflow_not_flagged(self, tmp_path):
        wf = """
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - run: make test
"""
        findings = scan_file(tmp_path, ".github/workflows/pr.yml", wf)
        assert "APF-DEP-003" not in {f.rule_id for f in findings}


class TestBroadPermissions:
    def test_write_all(self, tmp_path):
        wf = "on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-004" in {f.rule_id for f in findings}

    def test_contents_write_with_pr(self, tmp_path):
        wf = """
on:
  - pull_request
permissions:
  contents: write
jobs:
  a:
    runs-on: ubuntu-latest
"""
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-004" in {f.rule_id for f in findings}

    def test_read_only_fine(self, tmp_path):
        wf = "on: pull_request\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-004" not in {f.rule_id for f in findings}


class TestUnpinnedActions:
    def test_tag_ref_flagged(self, tmp_path):
        wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-005" in {f.rule_id for f in findings}

    def test_sha_pinned_fine(self, tmp_path):
        wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-005" not in {f.rule_id for f in findings}

    def test_local_action_fine(self, tmp_path):
        wf = "jobs:\n  a:\n    steps:\n      - uses: ./\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-005" not in {f.rule_id for f in findings}

    def test_docker_ref_fine(self, tmp_path):
        wf = "jobs:\n  a:\n    steps:\n      - uses: docker://alpine:3.19\n"
        findings = scan_file(tmp_path, ".github/workflows/x.yml", wf)
        assert "APF-DEP-005" not in {f.rule_id for f in findings}


class TestPackageJson:
    def test_install_hook(self, tmp_path):
        findings = scan_file(tmp_path, "package.json", '{"scripts": {"postinstall": "husky install"}}')
        assert "APF-DEP-006" in {f.rule_id for f in findings}

    def test_missing_lockfile(self, tmp_path):
        findings = scan_file(tmp_path, "package.json", '{"dependencies": {"express": "^4.0.0"}}')
        assert any(f.rule_id == "APF-DEP-006" and "lockfile" in f.message for f in findings)

    def test_lockfile_present(self, tmp_path):
        findings = scan_file(
            tmp_path,
            "package.json",
            '{"dependencies": {"express": "^4.0.0"}}',
            repo_files={"package.json", "package-lock.json"},
        )
        assert not [f for f in findings if f.rule_id == "APF-DEP-006" and "lockfile" in f.message]

    def test_invalid_json_ignored(self, tmp_path):
        findings = scan_file(tmp_path, "package.json", "{broken json")
        assert findings == []


class TestGitlabCI:
    def test_remote_include_with_secrets(self, tmp_path):
        cfg = "include:\n  remote: 'https://gitlab.com/shared/ci.yml'\nvariables:\n  DEPLOY_TOKEN: value\n"
        findings = scan_file(tmp_path, ".gitlab-ci.yml", cfg)
        assert "APF-DEP-008" in {f.rule_id for f in findings}

    def test_plain_config_fine(self, tmp_path):
        findings = scan_file(tmp_path, ".gitlab-ci.yml", "stages: [test]\n")
        assert "APF-DEP-008" not in {f.rule_id for f in findings}
