"""Insecure default rules (APF-DEF-*).

These rules detect configuration and code that is dangerous *as a default*
— acceptable in development, a problem in production. They deliberately
avoid flagging every occurrence of words like "password": each rule looks
for a specific, well-known unsafe pattern, and confidence reflects how
much context could be verified locally.
"""

from __future__ import annotations

import re
from typing import ClassVar

from agentpreflight.models import Confidence, Severity
from agentpreflight.rules.base import ContentPattern, ContentRule, FileContext, RawFinding


def _py(ctx: FileContext) -> bool:
    return ctx.rel_path.endswith(".py")


def _py_or_js(ctx: FileContext) -> bool:
    return ctx.rel_path.endswith((".py", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"))


def _config_like(ctx: FileContext) -> bool:
    p = ctx.rel_path.replace("\\", "/").lower()
    return (
        p.endswith(
            (
                ".yml",
                ".yaml",
                ".toml",
                ".ini",
                ".cfg",
                ".conf",
                ".env",
                ".json",
                ".xml",
                ".properties",
                ".tf",
                ".tfvars",
                ".envrc",
            )
        )
        or "/.env" in f"/{p}"
        or p.split("/")[-1].startswith(".env")
    )


class DjangoDebugRule(ContentRule):
    id = "APF-DEF-001"
    name = "Django DEBUG enabled"
    category = "default"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "DEBUG = True in Django settings exposes stack traces, settings and secret keys in production."
    remediation = "Set DEBUG from an environment variable and default it to False outside local development."
    references: ClassVar[list[str]] = ["https://docs.djangoproject.com/en/stable/ref/settings/#debug"]
    applies_to = "Python settings modules"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"^\s*DEBUG\s*=\s*True\b"), group=None)]

    def file_filter(self, ctx: FileContext) -> bool:
        name = ctx.rel_path.replace("\\", "/").lower()
        return _py(ctx) and ("settings" in name or (name.endswith("manage.py") is False and "settings" in name))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Django DEBUG mode enabled")


class FlaskDebugRule(ContentRule):
    id = "APF-DEF-002"
    name = "Flask/Django dev server debug"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = (
        "Application started with debug=True (Flask/Werkzeug dev server or similar). The interactive debugger"
        "allows arbitrary code execution on errors."
    )
    remediation = (
        "Enable debug mode only via an environment variable, and never bind the debugger to a publicinterface."
    )
    references: ClassVar[list[str]] = ["https://flask.palletsprojects.com/en/stable/debugging/"]
    applies_to = "Python files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\.run\(\s*[^)]*debug\s*=\s*True"), group=None),
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return _py(ctx)

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Debug mode enabled for application server")


class VerifyDisabledRule(ContentRule):
    id = "APF-DEF-003"
    name = "TLS verification disabled"
    category = "default"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "verify=False in an HTTP client call disables certificate"  # agentpreflight: allow
        " validation, enabling machine-in-the-middle attacks."
    )
    remediation = (
        "Remove verify=False. For self-signed certificates,"  # agentpreflight: allow
        " add the CA to the trust store instead."
    )
    references: ClassVar[list[str]] = ["https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification"]
    applies_to = "Python files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\bverify\s*=\s*False\b"), group=None)]

    def file_filter(self, ctx: FileContext) -> bool:
        return _py(ctx)

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "TLS certificate verification disabled (verify=False)")  # agentpreflight: allow


class SSLBypassRule(ContentRule):
    id = "APF-DEF-004"
    name = "SSL/context verification bypass"
    category = "default"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "Unverified SSL context or hostname check disabled (ssl._create_unverified_context,"  # agentpreflight: allow
        "check_hostname=False, NODE_TLS_REJECT_UNAUTHORIZED=0)."  # agentpreflight: allow
    )
    remediation = "Use a verified context; add your CA to the trust store rather than disabling checks."
    references: ClassVar[list[str]] = ["https://docs.python.org/3/library/ssl.html#ssl.create_default_context"]
    applies_to = "Python/JS/TS files, env files, shell scripts"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"(ssl\._?create_unverified_context|check_hostname\s*=\s*False|"
                r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0[\"']?|rejectUnauthorized\s*:\s*false|"
                r"rejectUnauthorized\s*=\s*false)"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        p = ctx.rel_path.replace("\\", "/").lower()
        name = p.split("/")[-1]
        return p.endswith(
            (
                ".py",
                ".js",
                ".ts",
                ".mjs",
                ".cjs",
                ".sh",
                ".bash",
                ".zsh",
                ".yml",
                ".yaml",
                ".conf",
                ".cfg",
                ".env",
            )
        ) or name.startswith(".env")

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "TLS verification bypass detected")


class CorsWildcardRule(ContentRule):
    id = "APF-DEF-005"
    name = "CORS wildcard origin"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = (
        "CORS configured to allow any origin ('*'), combined with credential support this leaks authenticated"
        "data cross-origin."
    )
    remediation = "List the exact allowed origins; never combine '*' with credentials."
    references: ClassVar[list[str]] = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"]
    applies_to = "Python/JS/TS code and server config"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"(allow(ed)?[_-]?origins?\s*[:=]\s*\[?\s*[\"']\*[\"']|"
                r"Access-Control-Allow-Origin[\"']?\s*[:=\s]\s*[\"']\*[\"'])"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.endswith(
            (
                ".py",
                ".js",
                ".ts",
                ".mjs",
                ".cjs",
                ".java",
                ".go",
                ".rb",
                ".conf",
                ".yml",
                ".yaml",
                ".json",
            )
        )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "CORS allows any origin ('*')")


class DefaultPasswordRule(ContentRule):
    id = "APF-DEF-006"
    name = "Default or weak password in config"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    description = (
        "A password field is set to a well-known default/weak value (admin, root, password, 123456, changeme,...)."
    )
    remediation = (
        "Set real credentials via environment variables or a secret manager; fail fast if a default is"
        "detected at startup."
    )
    applies_to = "configuration files (YAML/TOML/INI/JSON/env/properties)"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"(?i)\b(?:password|passwd|pwd|admin[_-]?pass(?:word)?|root[_-]?pass(?:word)?)\b"
                r"\s*[:=]\s*[\"']?(admin|root|password|passwd|123456|12345678|123456789|qwerty|"
                r"letmein|welcome|guest|postgres|mysql|sa|toor|changeme|admin123|password1|"
                r"p@ssw0rd|abc123|iloveyou|monkey|dragon)[\"']?\s*(?:$|#|,|;|\})"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return _config_like(ctx)

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Default/weak password value in configuration")


class AnsibleHostKeyRule(ContentRule):
    id = "APF-DEF-007"
    name = "Ansible host key checking disabled"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = (
        "host_key_checking = False disables SSH host verification for Ansible, enabling MITM attacks against"
        "deployments."
    )
    remediation = "Populate known_hosts (or use ssh-keyscan once, deliberately) and re-enable host key checking."
    references: ClassVar[list[str]] = ["https://docs.ansible.com/ansible/latest/user_guide/configuration.html"]
    applies_to = "ansible.cfg, Ansible playbooks, CI environment"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"host_key_checking\s*=\s*[\"']?False[\"']?", re.IGNORECASE), group=None)
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.endswith((".cfg", ".ini", ".yml", ".yaml", ".toml"))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Ansible host key checking disabled")


class DockerRootRule(ContentRule):
    id = "APF-DEF-008"
    name = "Container runs as root"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    description = (
        "Dockerfile has no USER instruction (containers run as root), or a run command uses --privileged /"
        "escalates via sudo."
    )
    remediation = "Create an unprivileged user and set USER; avoid --privileged and sudo inside images."
    references: ClassVar[list[str]] = ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"]
    applies_to = "Dockerfiles"

    _PRIV = re.compile(r"(--privileged|\bsudo\s+(?:-E\s+)?(?:apt|yum|apk|sh|bash|python))")
    _CHMOD777 = re.compile(r"\bchmod\s+[-R]+\s*777\b")

    def file_filter(self, ctx: FileContext) -> bool:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1]
        return name.startswith("Dockerfile") or name in (
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        has_user = any(line.strip().upper().startswith("USER ") for line in ctx.lines)
        name = ctx.rel_path.replace("\\", "/").split("/")[-1]
        if (
            name.startswith("Dockerfile")
            and not has_user
            and any(line.strip().upper().startswith(("FROM ", "RUN ")) for line in ctx.lines)
        ):
            findings.append(
                RawFinding(
                    message="Dockerfile contains no USER instruction; the container will run as root",
                )
            )
        for lineno, line in enumerate(ctx.lines, start=1):
            if self._PRIV.search(line):
                findings.append(
                    RawFinding(
                        message="Privileged container execution (or sudo escalation) detected",
                        line=lineno,
                        column=1,
                    )
                )
            if self._CHMOD777.search(line):
                findings.append(
                    RawFinding(
                        message="World-writable permissions (chmod 777) in container definition",
                        line=lineno,
                        column=1,
                    )
                )
        return findings


class KubernetesInsecureRule(ContentRule):
    id = "APF-DEF-010"
    name = "Insecure Kubernetes workload settings"
    category = "default"
    severity = Severity.HIGH
    confidence = Confidence.MEDIUM
    description = (
        "Kubernetes manifest enables privileged containers, privilege escalation, host namespaces or hostports."
    )
    remediation = "Remove privileged/host settings; run with a restricted Pod Security Standard."
    references: ClassVar[list[str]] = ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"]
    applies_to = "Kubernetes/Helm YAML"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"^\s*(privileged\s*:\s*true|allowPrivilegeEscalation\s*:\s*true|"
                r"hostPID\s*:\s*true|hostIPC\s*:\s*true|hostNetwork\s*:\s*true)\s*$"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        p = ctx.rel_path.replace("\\", "/").lower()
        return p.endswith((".yml", ".yaml")) and (
            "k8s" in p
            or "kubernetes" in p
            or "manifests" in p
            or "charts/" in p
            or "helm" in p
            or p.endswith(("chart.yaml", "values.yaml", "values.yml"))
        )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Insecure Kubernetes workload setting")


class WeakHashRule(ContentRule):
    id = "APF-DEF-011"
    name = "Weak hash algorithm"
    category = "default"
    severity = Severity.MEDIUM
    confidence = Confidence.LOW
    description = (
        "Use of MD5 or SHA-1. Fine for cache keys, dangerous for passwords, signatures or integrity of"
        "untrusted data — verify the usage."
    )
    remediation = (
        "Use SHA-256+ or a password hash (argon2, bcrypt, scrypt, PBKDF2). For HMACs, keep MD5/SHA-1 out ofnew code."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html"
    ]
    applies_to = "Python/JS/TS/Java/Ruby/PHP files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"(hashlib\.(?:md5|sha1)\s*\(|createHash\(\s*[\"'](?:md5|sha1)[\"']\s*\)|"
                r"Digest::(?:MD5|SHA1)|MessageDigest\.getInstance\(\s*[\"'](?:MD5|SHA-?1)[\"']\s*\)|"
                r"hashlib\.new\(\s*[\"'](?:md5|sha1)[\"'])"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.endswith((".py", ".js", ".ts", ".mjs", ".cjs", ".java", ".rb", ".php", ".go"))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Weak hash algorithm (MD5/SHA-1) usage")


class JwtVerificationOffRule(ContentRule):
    id = "APF-DEF-012"
    name = "JWT verification disabled"
    category = "default"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "JWT decoded with signature verification disabled or 'none' algorithm allowed — accepts forgedtokens."
    remediation = "Always verify signatures with an explicit algorithm allowlist and a real key."
    references: ClassVar[list[str]] = ["https://datatracker.ietf.org/doc/html/rfc8725#section-3.1"]
    applies_to = "Python/JS/TS files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"(algorithms\s*[:=]\s*\[[^\]]*[\"']none[\"']|"
                r"algorithms\s*[:=]\s*[\"']none[\"']|"
                r"verify_?signature\s*[\"']?\s*[:=]\s*(?:False|false)\b\b|"
                r"verifySignature\s*:\s*false)"
            ),
            group=None,
        )
    ]

    def file_filter(self, ctx: FileContext) -> bool:
        return _py_or_js(ctx)

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "JWT signature verification disabled or 'none' algorithm allowed")


class Chmod777Rule(ContentRule):
    id = "APF-DEF-014"
    name = "World-writable permissions"
    category = "default"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    description = "chmod 777 in scripts or Dockerfiles makes files world-writable."
    remediation = "Grant the minimum permissions required (e.g. chmod 750 / 640)."
    applies_to = "shell scripts, Dockerfiles, Makefiles"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\bchmod\s+[-Rri]+\s*777\b"), group=None)]

    def file_filter(self, ctx: FileContext) -> bool:
        return (
            ctx.rel_path.endswith((".sh", ".bash", ".zsh", ".dockerfile", ".mk"))
            or "Dockerfile" in ctx.rel_path
            or ctx.rel_path.endswith(("Makefile", "/makefile"))
        )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "World-writable permissions (chmod 777)")


DEFAULT_RULES: list[ContentRule] = [
    DjangoDebugRule(),
    FlaskDebugRule(),
    VerifyDisabledRule(),
    SSLBypassRule(),
    CorsWildcardRule(),
    DefaultPasswordRule(),
    AnsibleHostKeyRule(),
    DockerRootRule(),
    KubernetesInsecureRule(),
    WeakHashRule(),
    JwtVerificationOffRule(),
    Chmod777Rule(),
]
