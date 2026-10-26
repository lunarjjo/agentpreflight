"""End-to-end CLI tests via subprocess."""

from __future__ import annotations

import json

from tests.conftest import load_json_output, make_file, run_cli


class TestVersion:
    def test_version(self):
        proc = run_cli("version")
        assert proc.returncode == 0
        assert "agentpreflight 0.1.0" in proc.stdout

    def test_python_reported(self):
        proc = run_cli("version")
        assert "python" in proc.stdout.lower()


class TestScanCommand:
    def test_clean_exit_zero(self, tree):
        make_file(tree, "README.md", "clean\n")
        proc = run_cli("scan", ".", cwd=tree)
        assert proc.returncode == 0, proc.stderr

    def test_findings_exit_one(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", cwd=tree)
        assert proc.returncode == 1
        assert "APF-SEC-001" in proc.stdout

    def test_missing_path_exit_two(self):
        proc = run_cli("scan", "/definitely/not/a/path/xyz")
        assert proc.returncode == 2

    def test_bad_usage_exit_three(self):
        proc = run_cli("scan", "--nonsense")
        assert proc.returncode == 3

    def test_unknown_command_exit_three(self):
        proc = run_cli("frobnicate")
        assert proc.returncode == 3

    def test_severity_threshold(self, tree):
        make_file(tree, ".DS_Store", "junk")
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--severity", "critical", cwd=tree)
        assert proc.returncode == 0  # only high finding filtered out
        proc2 = run_cli("scan", ".", "--severity", "high", cwd=tree)
        assert proc2.returncode == 1

    def test_fail_severity(self, tree):
        make_file(tree, ".DS_Store", "junk")
        proc = run_cli("scan", ".", "--fail-severity", "low", cwd=tree)
        assert proc.returncode == 1

    def test_exclude_rule(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--exclude-rule", "APF-SEC-001", cwd=tree)
        assert proc.returncode == 0

    def test_include_rule(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        make_file(tree, ".env", "X=1\n")
        proc = run_cli("scan", ".", "--include-rule", "APF-SEC-*", cwd=tree)
        assert "APF-ART-001" not in proc.stdout

    def test_json_format(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--format", "json", cwd=tree)
        data = load_json_output(proc)
        assert any(f["rule_id"] == "APF-SEC-001" for f in data["findings"])
        assert "AKIAIOSFODNN7EXAMPLE" not in proc.stdout

    def test_sarif_format(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--format", "sarif", cwd=tree)
        data = json.loads(proc.stdout)
        assert data["version"] == "2.1.0"
        assert data["runs"][0]["results"]

    def test_output_file(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--format", "json", "--output", "out.json", cwd=tree)
        assert proc.returncode == 1
        assert (tree / "out.json").is_file()
        data = json.loads((tree / "out.json").read_text(encoding="utf-8"))
        assert data["findings"]

    def test_no_git_flag(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", "--no-git", cwd=tree)
        assert proc.returncode == 1

    def test_config_file(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        (tree / ".agentpreflight.toml").write_text(
            '[[ignore]]\npath = "a.py"\nrule_id = "APF-SEC-*"\nreason = "fixture"\n',
            encoding="utf-8",
        )
        proc = run_cli("scan", ".", cwd=tree)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "AWS access key" not in proc.stdout
        assert "suppressed 1 finding(s)" in proc.stdout

    def test_invalid_config_exit_three(self, tree):
        (tree / ".agentpreflight.toml").write_text("[scan]\nseverity = " + '"' + "bogus" + '"' + "\n", encoding="utf-8")
        proc = run_cli("scan", ".", cwd=tree)
        assert proc.returncode == 3
        assert "configuration error" in proc.stderr.lower()

    def test_explicit_config_flag(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        (tree / "custom.toml").write_text('[scan]\nexclude_rules = ["APF-SEC-001"]\n', encoding="utf-8")
        proc = run_cli("scan", ".", "--config", "custom.toml", cwd=tree)
        assert proc.returncode == 0


class TestInitCommand:
    def test_init_writes_config(self, tree):
        proc = run_cli("init", cwd=tree)
        assert proc.returncode == 0
        assert (tree / ".agentpreflight.toml").is_file()

    def test_init_twice_fails(self, tree):
        assert run_cli("init", cwd=tree).returncode == 0
        proc = run_cli("init", cwd=tree)
        assert proc.returncode == 2

    def test_written_config_is_valid(self, tree):
        run_cli("init", cwd=tree)
        proc = run_cli("scan", ".", cwd=tree)
        assert proc.returncode == 0  # config parses + empty scan


class TestDoctorCommand:
    def test_doctor_passes(self, tree):
        proc = run_cli("doctor", cwd=tree)
        assert proc.returncode == 0
        assert "self-test" in proc.stdout


class TestRulesCommand:
    def test_list_table(self):
        proc = run_cli("rules", "list")
        assert proc.returncode == 0
        assert "APF-SEC-001" in proc.stdout

    def test_list_json(self):
        proc = run_cli("rules", "list", "--format", "json")
        data = json.loads(proc.stdout)
        assert isinstance(data, list) and len(data) >= 40

    def test_list_markdown(self):
        proc = run_cli("rules", "list", "--format", "markdown")
        assert "## APF-SEC-001" in proc.stdout

    def test_explain_known(self):
        proc = run_cli("rules", "explain", "APF-SEC-007")
        assert proc.returncode == 0
        assert "Private key block" in proc.stdout

    def test_explain_unknown(self):
        proc = run_cli("rules", "explain", "APF-NOPE-999")
        assert proc.returncode == 3


class TestQuietAndColor:
    def test_no_color_env_respected(self, tree):
        make_file(tree, "a.py", "key = AKIAIOSFODNN7EXAMPLE\n")
        proc = run_cli("scan", ".", cwd=tree)
        assert "\x1b[" not in proc.stdout
