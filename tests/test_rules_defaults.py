"""Tests for insecure-default rules."""

from __future__ import annotations

import pytest
from tests.conftest import make_file

from agentpreflight.engine import _scan_one_file
from agentpreflight.rules.base import ContentRule, PathRule
from agentpreflight.rules.registry import RULES_BY_ID


def scan_file(tmp_path, name: str, content: str):
    make_file(tmp_path, name, content)
    rules = [r for r in RULES_BY_ID.values() if isinstance(r, (ContentRule, PathRule))]
    findings, _ = _scan_one_file(str(tmp_path), name, None, {name}, rules, 10**7)
    return findings


CASES = [
    ("APF-DEF-001", "settings.py", "DEBUG = True\n", True),
    ("APF-DEF-001", "settings.py", "DEBUG = False\n", False),
    ("APF-DEF-001", "settings/dev.py", "DEBUG = True  # agentpreflight: allow\n", False),
    ("APF-DEF-002", "app.py", "app.run(host='0.0.0.0', debug=True)\n", True),
    ("APF-DEF-002", "app.py", "app.run(host='127.0.0.1')\n", False),
    ("APF-DEF-003", "client.py", "requests.get(url, verify=False)\n", True),
    ("APF-DEF-003", "client.py", "requests.get(url, verify=True)\n", False),
    ("APF-DEF-004", "client.py", "ctx = ssl._create_unverified_context()\n", True),
    ("APF-DEF-004", "app.env", "NODE_TLS_REJECT_UNAUTHORIZED=0\n", True),
    ("APF-DEF-004", "app.js", "https.Agent({ rejectUnauthorized: false })\n", True),
    ("APF-DEF-005", "app.py", "app.config['CORS_ALLOWED_ORIGINS'] = allow_origins=['*']\n", True),
    ("APF-DEF-005", "nginx.conf", 'add_header Access-Control-Allow-Origin "*";\n', True),
    ("APF-DEF-006", "config.yaml", "database:\n  password: admin\n", True),
    ("APF-DEF-006", "config.yaml", "database:\n  password: Zx91vQ7mKpL2wRt5\n", False),
    ("APF-DEF-006", "app.yml", "password: changeme\n", True),
    ("APF-DEF-006", "app.yml", "password: hunter2secretvalue\n", False),
    ("APF-DEF-007", "ansible.cfg", "host_key_checking = False\n", True),
    ("APF-DEF-007", "ansible.cfg", "host_key_checking = True\n", False),
    ("APF-DEF-008", "Dockerfile", "FROM python:3.12\nRUN pip install -r req.txt\n", True),
    (
        "APF-DEF-008",
        "Dockerfile",
        "FROM python:3.12\nRUN pip install -r req.txt\nUSER app\n",
        False,
    ),
    ("APF-DEF-008", "Dockerfile", "FROM python:3.12\nRUN --privileged apt update\n", True),
    ("APF-DEF-008", "Dockerfile", "RUN chmod 777 /data\n", True),
    ("APF-DEF-010", "k8s/deploy.yaml", "securityContext:\n  privileged: true\n", True),
    ("APF-DEF-010", "k8s/deploy.yaml", "securityContext:\n  privileged: false\n", False),
    ("APF-DEF-010", "k8s/deploy.yaml", "hostNetwork: true\n", True),
    ("APF-DEF-011", "hashing.py", "digest = hashlib.md5(payload).hexdigest()\n", True),
    ("APF-DEF-011", "hashing.js", "const d = crypto.createHash('sha1').update(x).digest()\n", True),
    ("APF-DEF-011", "hashing.py", "digest = hashlib.sha256(payload).hexdigest()\n", False),
    (
        "APF-DEF-012",
        "auth.py",
        "payload = jwt.decode(token, options={'verify_signature': False})\n",
        True,
    ),
    ("APF-DEF-012", "auth.js", "jwt.verify(token, secret, { algorithms: ['none'] })\n", True),
    ("APF-DEF-012", "auth.py", "payload = jwt.decode(token, key, algorithms=['HS256'])\n", False),
    ("APF-DEF-014", "setup.sh", "chmod -R 777 /var/www\n", True),
    ("APF-DEF-014", "setup.sh", "chmod -R 750 /var/www\n", False),
]


class TestDefaultRules:
    @pytest.mark.parametrize(
        ("rule_id", "filename", "content", "fires"),
        CASES,
        ids=[f"{i:02d}-{c[0]}" for i, c in enumerate(CASES)],
    )
    def test_case(self, tmp_path, rule_id, filename, content, fires):
        findings = scan_file(tmp_path, filename, content)
        hit = rule_id in {f.rule_id for f in findings}
        assert hit == fires, f"{rule_id} on {filename} fired={hit}, expected {fires}"


class TestContextualFalsePositives:
    def test_debug_in_normal_py_file_not_fired_for_django_rule(self, tmp_path):
        # DEBUG = True in a non-settings module is still flagged by design;
        # but the rule only applies to files with settings in the name.
        findings = scan_file(tmp_path, "utils.py", "DEBUG = True\n")
        assert "APF-DEF-001" not in {f.rule_id for f in findings}

    def test_word_password_in_prose_not_default_password(self, tmp_path):
        findings = scan_file(
            tmp_path,
            "docs.md",
            "The word password appears here in prose.\n",
        )
        assert "APF-DEF-006" not in {f.rule_id for f in findings}

    def test_api_docs_not_flagged(self, tmp_path):
        findings = scan_file(
            tmp_path,
            "README.md",
            "Set api_key to ${API_KEY} before running.\npassword = 'your-password'\n",
        )
        assert not findings, f"false positives in docs: {[f.rule_id for f in findings]}"

    def test_weak_hash_in_non_code_not_flagged(self, tmp_path):
        findings = scan_file(tmp_path, "notes.txt", "use md5 or sha1 for checksums\n")
        assert "APF-DEF-011" not in {f.rule_id for f in findings}


class TestNonSecretPatternsNoPreview:
    def test_default_finding_has_no_secret_preview(self, tmp_path):
        findings = scan_file(tmp_path, "settings.py", "DEBUG = True\n")
        f = next(x for x in findings if x.rule_id == "APF-DEF-001")
        assert f.secret_preview is None
