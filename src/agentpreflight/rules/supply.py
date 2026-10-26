"""Supply-chain hygiene rules (APF-DEP-*).

These are *local configuration* checks, not advisory lookups: they flag
risky dependency configuration and unsafe CI pipelines. Known-vulnerability
lookup requires an external advisory service (OSV/Trivy/pip-audit) and is
explicitly out of scope — see docs/comparison.md for the integration
strategy.
"""

from __future__ import annotations

import json
import re
from typing import ClassVar

from agentpreflight.models import Confidence, Severity
from agentpreflight.rules.base import (
    ContentPattern,
    ContentRule,
    FileContext,
    RawFinding,
)


class CurlPipeShellRule(ContentRule):
    id = "APF-DEP-001"
    name = "Remote script piped to shell"
    category = "supply"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "curl/wget output piped directly into a shell. A compromise of the host or CDN executes arbitrary"
        "code with the caller's privileges."
    )
    remediation = "Download the script, review it (or verify a checksum/signature), then execute the pinned version."
    references: ClassVar[list[str]] = ["https://disman.tl/2015/07/02/how-to-safely-execute-remote-scripts.html"]
    applies_to = "Dockerfiles, CI workflows, shell scripts, docs"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(r"\b(?:curl|wget)\b[^|;&>\n]{0,400}?\|\s*(?:sudo\s+)?(?:ba|z|da|fi)?sh\b"),
            group=None,
        )
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Remote content piped directly into a shell")


class UnpinnedRequirementsRule(ContentRule):
    id = "APF-DEP-002"
    name = "Unpinned Python dependency"
    category = "supply"
    severity = Severity.INFO
    confidence = Confidence.HIGH
    description = (
        "requirements-style file lists dependencies without exact pins (no '=='). Builds are not reproducible"
        "and a malicious release could be pulled automatically."
    )
    remediation = "Pin exact versions ('==') or use a lockfile; consider hash-pinning (pip-compile --generate-hashes)."
    applies_to = "requirements*.txt"

    _SPEC = re.compile(r"(?:==|>=|<=|~=|!=|>|<)")
    _COMMENT = re.compile(r"#.*$")

    def file_filter(self, ctx: FileContext) -> bool:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1].lower()
        return name.startswith("requirements") and name.endswith(".txt")

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        for lineno, raw in enumerate(ctx.lines, start=1):
            line = self._COMMENT.sub("", raw).strip()
            if not line or line.startswith(("-r", "--", "#")):
                continue
            if line.startswith(("git+", "http://", "https://", "file:", "/")):
                continue
            if self._SPEC.search(line):
                continue
            findings.append(
                RawFinding(
                    message=f"Dependency '{line}' is not pinned to an exact version",
                    line=lineno,
                    column=1,
                )
            )
        return findings


class PullRequestTargetRule(ContentRule):
    id = "APF-DEP-003"
    name = "pull_request_target with untrusted checkout"
    category = "supply"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    description = (
        "Workflow uses pull_request_target together with a checkout of the pull request head. This executes"
        "untrusted PR code with access to repository secrets — a classic sandbox escape."
    )
    remediation = (
        "Never check out PR code in pull_request_target workflows. Use pull_request for untrusted builds, "
        "or split into a trusted workflow triggered by labels."
    )
    references: ClassVar[list[str]] = [
        "https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/keeping-your-github-actions-and-workflows-secure",
    ]
    applies_to = ".github/workflows/*.yml"

    _HEAD_REFS = re.compile(
        r"(refs/pull/|github\.event\.pull_request\.(head|merge)\.(sha|ref)|event\.pull_request\.(head|merge)\.(sha|ref))"
    )

    def file_filter(self, ctx: FileContext) -> bool:
        p = ctx.rel_path.replace("\\", "/")
        return p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        text = "\n".join(ctx.lines)
        if "pull_request_target" not in text:
            return findings
        for lineno, line in enumerate(ctx.lines, start=1):
            if self._HEAD_REFS.search(line) and ("ref:" in line or "sha:" in line or "${{ " in line):
                findings.append(
                    RawFinding(
                        message=(
                            "pull_request_target workflow references the PR head — "
                            "untrusted code runs with repository secrets"
                        ),
                        line=lineno,
                        column=1,
                    )
                )
        return findings


class BroadWorkflowPermissionsRule(ContentRule):
    id = "APF-DEP-004"
    name = "Overly broad workflow permissions"
    category = "supply"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = (
        "Workflow grants write-all or contents:write permissions, or grants write permissions in workflows"
        "that run against untrusted pull requests."
    )
    remediation = "Apply least-privilege permissions per job and only grant write access in workflows that need it."
    references: ClassVar[list[str]] = [
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication"
    ]
    applies_to = ".github/workflows/*.yml"

    def file_filter(self, ctx: FileContext) -> bool:
        p = ctx.rel_path.replace("\\", "/")
        return p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        for lineno, line in enumerate(ctx.lines, start=1):
            if re.search(r"^\s*permissions\s*:\s*write-all\s*$", line):
                findings.append(
                    RawFinding(
                        message="Workflow uses permissions: write-all",
                        line=lineno,
                        column=1,
                    )
                )
                break
        text = "\n".join(ctx.lines)
        if (
            re.search(r"^\s*contents\s*:\s*write\s*$", text, re.MULTILINE)
            and re.search(r"^\s*(on\s*:|-\s*pull_request\b)", text, re.MULTILINE)
            and "pull_request_target" not in text
        ):
            findings.append(
                RawFinding(
                    message=(
                        "Workflow grants contents: write while reacting to pull_request events; "
                        "prefer read-only for untrusted triggers"
                    ),
                    line=1,
                    column=1,
                )
            )
        return findings


class UnpinnedActionRule(ContentRule):
    id = "APF-DEP-005"
    name = "Third-party Action not pinned to a commit"
    category = "supply"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    description = (
        "GitHub Action referenced by tag or branch instead of an immutable commit SHA. A force-push to the"
        "tag would run different code in your pipeline."
    )
    remediation = "Pin third-party actions to the full 40-character commit SHA of a reviewed release."
    references: ClassVar[list[str]] = [
        "https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-third-party-actions"
    ]
    applies_to = ".github/workflows/*.yml, action.yml"

    _USES = re.compile(r"^\s*(?:-\s+)?uses\s*:\s*([^\s#]+)\s*$")
    _SHA = re.compile(r"^[0-9a-fA-F]{40}$")

    def file_filter(self, ctx: FileContext) -> bool:
        p = ctx.rel_path.replace("\\", "/")
        return (p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))) or p.split("/")[-1] in (
            "action.yml",
            "action.yaml",
        )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        for lineno, line in enumerate(ctx.lines, start=1):
            m = self._USES.match(line)
            if not m:
                continue
            ref = m.group(1)
            if ref.startswith(("./", "docker://")):
                continue
            if "@" not in ref:
                findings.append(
                    RawFinding(
                        message=f"Action '{ref}' referenced without a version",
                        line=lineno,
                        column=1,
                    )
                )
                continue
            _, _, version = ref.rpartition("@")
            if self._SHA.match(version):
                continue
            findings.append(
                RawFinding(
                    message=f"Action '{ref}' pinned to a mutable ref; pin the commit SHA",
                    line=lineno,
                    column=1,
                )
            )
        return findings


class PackageJsonRule(ContentRule):
    """Custom checks on package.json: install hooks and missing lockfile."""

    id = "APF-DEP-006"
    name = "Node project install hooks / missing lockfile"
    category = "supply"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    description = (
        "package.json defines pre/post-install hooks (arbitrary code on npm install) or the project has no"
        "lockfile (non-reproducible installs)."
    )
    remediation = "Remove install hooks unless essential; commit a lockfile (package-lock.json or equivalent)."
    applies_to = "package.json"

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.replace("\\", "/").split("/")[-1] == "package.json"

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        try:
            data = json.loads(ctx.text or "")
        except ValueError:
            return findings
        if not isinstance(data, dict):
            return findings
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for hook in ("preinstall", "postinstall", "prepublish", "prepare"):
                if hook in scripts:
                    findings.append(
                        RawFinding(
                            message=f"package.json defines a '{hook}' script (runs on install)",
                            line=1,
                            column=1,
                        )
                    )
        dir_ = ctx.rel_path.replace("\\", "/").rsplit("/", 1)[0]
        prefix = f"{dir_}/" if dir_ != ctx.rel_path else ""
        lockfiles = (
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "bun.lockb",
        )
        has_lockfile = any(f"{prefix}{lock}" in ctx.repo_files for lock in lockfiles)
        has_deps = bool(data.get("dependencies") or data.get("devDependencies"))
        if has_deps and not has_lockfile:
            findings.append(
                RawFinding(
                    message="package.json has dependencies but no lockfile is present",
                    line=1,
                    column=1,
                )
            )
        return findings


class GitlabUnprotectedSecretsRule(ContentRule):
    id = "APF-DEP-008"
    name = "CI job exposes secrets to untrusted input"
    category = "supply"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    description = (
        "GitLab CI job with secrets/environment exposure runs scripts from the repository without trust"
        "separation (e.g. include of remote templates with variables)."
    )
    remediation = "Split untrusted validation from privileged jobs; never pass secrets to jobs that execute fork code."
    references: ClassVar[list[str]] = ["https://docs.gitlab.com/ee/ci/security/"]
    applies_to = ".gitlab-ci.yml"

    _REMOTE_INCLUDE = re.compile(r"include\s*:.*\n(?:.*\n){0,20}?.*(?:https?://|::url)")

    def file_filter(self, ctx: FileContext) -> bool:
        return ctx.rel_path.replace("\\", "/").split("/")[-1] == ".gitlab-ci.yml"

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        text = "\n".join(ctx.lines)
        if (
            re.search(r"include\s*:\s*(remote|project)\s*:", text)
            and re.search(r"variables\s*:", text)
            and re.search(r"(MASKED|SECRET|_TOKEN|_KEY)\s*:", text)
        ):
            findings.append(
                RawFinding(
                    message=(
                        "CI configuration includes remote templates and defines sensitive variables — "
                        "verify the trust boundary"
                    ),
                    line=1,
                    column=1,
                )
            )
        return findings


SUPPLY_RULES: list[ContentRule] = [
    CurlPipeShellRule(),
    UnpinnedRequirementsRule(),
    PullRequestTargetRule(),
    BroadWorkflowPermissionsRule(),
    UnpinnedActionRule(),
    PackageJsonRule(),
    GitlabUnprotectedSecretsRule(),
]
