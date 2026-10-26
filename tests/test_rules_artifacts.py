"""Tests for artifact rules (path rules and repo-level rules)."""

from __future__ import annotations

import pytest

from agentpreflight.engine import _scan_one_file
from agentpreflight.rules.base import FileContext, PathRule, RepoContext
from agentpreflight.rules.registry import PATH_RULES, REPO_RULES, RULES_BY_ID


def make_ctx(rel_path: str, text: str | None = None, tracked: bool | None = None) -> FileContext:
    return FileContext(
        rel_path=rel_path,
        abs_path=f"/repo/{rel_path}",
        size=len(text or ""),
        tracked=tracked,
        text=text,
        lines=(text or "").splitlines(),
        repo_files={rel_path},
    )


def path_rule_finding(rule_id: str, ctx: FileContext) -> str | None:
    rule = RULES_BY_ID[rule_id]
    assert isinstance(rule, PathRule)
    return rule.matches(ctx)


class TestEnvFileRule:
    def test_env_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx(".env", "X=1")) is not None

    def test_env_local_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx(".env.local", "X=1")) is not None

    def test_env_production_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx("config/.env.production", "X=1")) is not None

    def test_env_example_not_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx(".env.example", "X=1")) is None

    def test_env_template_not_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx(".env.template")) is None

    def test_env_sample_not_flagged(self):
        assert path_rule_finding("APF-ART-001", make_ctx(".env.sample")) is None

    def test_tracked_note_in_message(self):
        ctx = make_ctx(".env", "X=1", tracked=True)
        reason = path_rule_finding("APF-ART-001", ctx)
        assert reason is not None and "tracked by Git" in reason


class TestKeyFileRule:
    @pytest.mark.parametrize(
        "name",
        ["id_rsa", "id_ed25519", "certs/server.pem", "tls/server.key", "app.jks", "signing.p12"],
    )
    def test_key_files_flagged(self, name):
        assert path_rule_finding("APF-ART-002", make_ctx(name)) is not None

    def test_public_cert_note(self):
        reason = path_rule_finding("APF-ART-002", make_ctx("ca.pem"))
        assert reason is not None and "verify" in reason

    def test_random_pem_suffix_not_flagged(self):
        assert path_rule_finding("APF-ART-002", make_ctx("notes.txt")) is None


class TestCredentialFileRule:
    @pytest.mark.parametrize(
        "name",
        [".netrc", ".git-credentials", "serviceaccount.json", "backup.kdbx"],
    )
    def test_credential_files_flagged(self, name):
        assert path_rule_finding("APF-ART-003", make_ctx(name)) is not None

    def test_aws_credentials_flagged(self):
        assert path_rule_finding("APF-ART-003", make_ctx(".aws/credentials")) is not None

    def test_docker_config_flagged(self):
        assert path_rule_finding("APF-ART-003", make_ctx(".docker/config.json")) is not None

    def test_kube_config_flagged(self):
        assert path_rule_finding("APF-ART-003", make_ctx(".kube/config")) is not None

    def test_npmrc_with_auth_flagged(self):
        ctx = make_ctx(".npmrc", "//registry.npmjs.org/:_authToken=npm_synthe" + "tic0000000000000000")
        assert path_rule_finding("APF-ART-003", ctx) is not None

    def test_plain_npmrc_not_flagged(self):
        assert path_rule_finding("APF-ART-003", make_ctx(".npmrc", "registry=https://registry.npmjs.org/")) is None

    def test_htpasswd_flagged(self):
        assert path_rule_finding("APF-ART-003", make_ctx("auth/htpasswd")) is not None


class TestDumpFileRule:
    def test_sql_dump_with_data(self):
        ctx = make_ctx("backup/dump.sql", "INSERT INTO users VALUES (1,'admin');")
        assert path_rule_finding("APF-ART-004", ctx) is not None

    def test_plain_schema_sql_not_flagged(self):
        ctx = make_file_schema()
        assert path_rule_finding("APF-ART-004", ctx) is None

    def test_bak_flagged(self):
        assert path_rule_finding("APF-ART-004", make_ctx("app.py.bak")) is not None

    def test_sql_gz_flagged(self):
        assert path_rule_finding("APF-ART-004", make_ctx("db.sql.gz")) is not None


def make_file_schema() -> FileContext:
    return make_ctx(
        "migrations/001_init.sql",
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);\n",
    )


class TestOSCruftRule:
    def test_ds_store(self):
        assert path_rule_finding("APF-ART-005", make_ctx(".DS_Store")) is not None

    def test_thumbs_db(self):
        assert path_rule_finding("APF-ART-005", make_ctx("Thumbs.db")) is not None

    def test_normal_file(self):
        assert path_rule_finding("APF-ART-005", make_ctx("main.py")) is None


class TestDatabaseFileRule:
    @pytest.mark.parametrize("name", ["dev.sqlite3", "app.db"])
    def test_db_files(self, name):
        assert path_rule_finding("APF-ART-007", make_ctx(name)) is not None

    def test_not_db_file(self):
        assert path_rule_finding("APF-ART-007", make_ctx("db.go")) is None


class TestRepoHygieneRule:
    def _repo_ctx(self, paths: list[str], tracked: set[str] | None = None) -> RepoContext:
        ctx = RepoContext(
            files=[make_ctx(p) for p in paths],
            root="/repo",
            tracked=tracked,
        )
        return ctx

    def test_node_modules_one_finding(self):
        rule = RULES_BY_ID["APF-ART-006"]
        ctx = self._repo_ctx([f"node_modules/pkg{i}/index.js" for i in range(200)])
        results = rule.check_repo(ctx)
        assert len(results) == 1
        path, raw = results[0]
        assert path == "node_modules"
        assert "node_modules" in raw.message

    def test_clean_repo_no_finding(self):
        rule = RULES_BY_ID["APF-ART-006"]
        ctx = self._repo_ctx(["src/app.py", "README.md"])
        assert rule.check_repo(ctx) == []

    def test_tracked_note(self):
        rule = RULES_BY_ID["APF-ART-006"]
        ctx = self._repo_ctx(["node_modules/x.js"], tracked={"node_modules/x.js"})
        (_, raw) = rule.check_repo(ctx)[0]
        assert "tracked by Git" in raw.message

    def test_ide_dirs(self):
        rule = RULES_BY_ID["APF-ART-008"]
        ctx = self._repo_ctx([".idea/workspace.xml", ".vscode/settings.json"])
        results = rule.check_repo(ctx)
        assert {path for path, _ in results} == {".idea", ".vscode"}


class TestPathRuleCount:
    def test_registry(self):
        assert len(PATH_RULES) == 6
        assert len(REPO_RULES) == 2


class TestFullFileScan:
    def test_scan_one_file_env(self, tmp_path):
        from tests.conftest import make_file

        make_file(tmp_path, ".env", "A=1\n")
        findings, skip = _scan_one_file(str(tmp_path), ".env", False, {".env"}, list(RULES_BY_ID.values()), 10**7)
        assert skip is None
        assert any(f.rule_id == "APF-ART-001" for f in findings)
