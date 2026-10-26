"""Sensitive artifact rules (APF-ART-*).

These rules flag files that should not normally exist in a repository:
environment files, private keys, credential stores, database dumps and
generated/vendor cruft. They distinguish "suspicious artifact" from a
confirmed secret leak — content-level confirmation comes from the
APF-SEC-* rules.
"""

from __future__ import annotations

import fnmatch
import json
import re
from typing import ClassVar

from agentpreflight.models import Confidence, Severity
from agentpreflight.rules.base import FileContext, PathRule, RawFinding, RepoContext, RepoRule

_ENV_NAME = re.compile(r"^\.env(\.[A-Za-z0-9_.-]+)?$")
_ENV_SAFE_SUFFIXES = (".example", ".template", ".sample", ".default", ".dist")


class EnvFileRule(PathRule):
    id = "APF-ART-001"
    name = "Environment file present"
    category = "artifact"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "A .env file (not .env.example) exists in the scan scope. Env files very often contain realcredentials."
    )
    remediation = (
        "Move secrets out of the file, delete it from the working tree and history, "
        "and commit a .env.example with placeholder values instead."
    )
    references: ClassVar[list[str]] = ["https://dotenvx.com/docs"]  # documented .env conventions
    applies_to = "file names matching .env or .env.<name>"

    def matches(self, ctx: FileContext) -> str | None:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1]
        m = _ENV_NAME.match(name)
        if not m:
            return None
        suffix = m.group(1) or ""
        if suffix and any(suffix.startswith(s) for s in _ENV_SAFE_SUFFIXES):
            return None
        tracked_note = ""
        if ctx.tracked is True:
            tracked_note = " The file is tracked by Git and will be published."
        elif ctx.tracked is False:
            tracked_note = " The file is not tracked by Git; verify that .gitignore covers it."
        return f"Environment file '{name}' present.{tracked_note}"

    def check_path(self, ctx: FileContext) -> list[RawFinding]:
        # Suppress when every line carries an allow marker (rare); default flow applies.
        return super().check_path(ctx)


class KeyFileRule(PathRule):
    id = "APF-ART-002"
    name = "Private key or keystore file"
    category = "artifact"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "File name matches a private key, TLS key, or Java/Android keystore convention."
    remediation = (
        "If this is a real key: rotate it, remove it from the repository and history. "
        "If it is a fixture or documentation, add an inline allow marker or an ignore entry."
    )
    references: ClassVar[list[str]] = ["https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"]
    applies_to = "id_rsa and friends, *.pem/*.key/*.p12/*.pfx/*.jks/*.keystore/*.ppk"

    _NAMES: ClassVar[set[str]] = {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_ecdsa_sk",
        "id_ed25519_sk",
    }
    _PATTERNS: ClassVar[tuple[str, ...]] = (
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.jks",
        "*.keystore",
        "*.ppk",
        "*.htpasswd",
    )

    def matches(self, ctx: FileContext) -> str | None:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1]
        lowered = name.lower()
        if lowered in self._NAMES:
            return f"SSH private key file '{name}' present"
        for pattern in self._PATTERNS:
            if fnmatch.fnmatch(lowered, pattern):
                return (
                    f"Key or keystore file '{name}' present. If it is a public certificate, "
                    "verify the content starts with 'BEGIN PUBLIC KEY' or 'BEGIN CERTIFICATE'"
                    " and add an allow marker if appropriate."
                )
        return None


class CredentialFileRule(PathRule):
    id = "APF-ART-003"
    name = "Known credential file"
    category = "artifact"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "File name matches a known credential store (.netrc, .aws/credentials, .docker/config.json,"
        ".kube/config, .git-credentials, ...)."
    )
    remediation = "Remove the file from the repository and history; these formats store plaintext credentials."
    references: ClassVar[list[str]] = ["https://docs.docker.com/engine/reference/commandline/login/"]
    applies_to = (
        ".netrc, .npmrc (with auth), .aws/credentials, .docker/config.json, credentials.json, .kube/config,"
        ".git-credentials, serviceAccount*.json"
    )

    _EXACT: ClassVar[set[str]] = {
        ".netrc",
        "_netrc",
        "credentials",
        "credentials.json",
        "config.json",  # flagged only when under .docker/
        "config",  # flagged only when under .kube/
    }
    _GLOBS = ("*serviceaccount*.json", "*service_account*.json", "*.kdbx", ".git-credentials")

    def matches(self, ctx: FileContext) -> str | None:
        parts = ctx.rel_path.replace("\\", "/").split("/")
        name = parts[-1].lower()
        lowered = ctx.rel_path.replace("\\", "/").lower()
        if name in (".git-credentials",):
            return ".git-credentials file present (plaintext credential store)"
        if any(fnmatch.fnmatch(name, g) for g in self._GLOBS):
            return f"Credential file '{name}' present"
        if len(parts) >= 2:
            parent = parts[-2]
            if parent == ".docker" and name == "config.json":
                return "Docker config with possible registry credentials present"
            if parent == ".kube" and name == "config":
                return "Kubernetes client config present (contains cluster credentials)"
            if parent == ".aws" and name == "credentials":
                return "AWS CLI credentials file present"
        if name == ".npmrc":
            text = ctx.text or ""
            if "_auth" in text or "_ authToken" in text or " authToken" in text:
                return ".npmrc containing a registry auth token"
            return None
        if name == ".netrc" or name == "_netrc":
            return ".netrc file present (plaintext credentials)"
        if name in self._EXACT and name in ("credentials", "credentials.json"):
            # credentials.json outside a known dir is suspicious enough to review
            return f"'{name}' present; verify it is not a credential export"
        if lowered.endswith("htpasswd"):
            return "htpasswd file present (hashed credentials)"
        return None


class DumpFileRule(PathRule):
    id = "APF-ART-004"
    name = "Database dump or backup file"
    category = "artifact"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    description = "File name looks like a database dump or editor/DB backup (.sql, .dump, .bak, .backup, .sql.gz,.rdb)."
    remediation = "Keep dumps out of the repository; restore from backups stored outside Git if needed."
    applies_to = "*.sql, *.dump, *.bak, *.backup, *.sql.gz, *.rdb"

    _GLOBS: ClassVar[tuple[str, ...]] = ("*.dump", "*.bak", "*.backup", "*.sql.gz", "*.rdb")

    def matches(self, ctx: FileContext) -> str | None:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1].lower()
        if name.endswith(".sql"):
            text = (ctx.text or "").lower()
            if "insert into" in text or "copy " in text[:65536]:
                return "SQL dump containing data rows present"
            return None  # plain schema files are normal
        for pattern in self._GLOBS:
            if fnmatch.fnmatch(name, pattern):
                return f"Backup/dump file '{name}' present"
        return None


class OSCruftRule(PathRule):
    id = "APF-ART-005"
    name = "OS cruft file"
    category = "artifact"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    description = "Operating-system metadata file (.DS_Store, Thumbs.db, desktop.ini)."
    remediation = "Delete the file and add it to .gitignore."
    applies_to = ".DS_Store, Thumbs.db, desktop.ini, ehthumbs.db"

    _NAMES: ClassVar[set[str]] = {".ds_store", "thumbs.db", "desktop.ini", "ehthumbs.db"}

    def matches(self, ctx: FileContext) -> str | None:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1].lower()
        if name in self._NAMES:
            return f"OS metadata file '{name}' present"
        return None


class DatabaseFileRule(PathRule):
    id = "APF-ART-007"
    name = "Database file in repository"
    category = "artifact"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    description = "Binary/SQLite database file present (.sqlite, .sqlite3, .db)."
    remediation = "Move runtime data outside the repository; commit a schema or migration instead."
    applies_to = "*.sqlite, *.sqlite3, *.db"

    _GLOBS: ClassVar[tuple[str, ...]] = ("*.sqlite", "*.sqlite3", "*.db")

    def matches(self, ctx: FileContext) -> str | None:
        name = ctx.rel_path.replace("\\", "/").split("/")[-1].lower()
        if any(fnmatch.fnmatch(name, g) for g in self._GLOBS):
            return f"Database file '{name}' present; verify it contains no user data"
        return None


# Directory prefixes that should never be committed. Used by RepoHygieneRule
# and by the walker (to prune these directories when walking non-Git trees).
VENDOR_DIR_NAMES = frozenset(
    {
        "node_modules",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".eggs",
        ".venv",
        "venv",
        "target",
        ".terraform",
        "vendor",
        ".bundle",
        "bower_components",
    }
)

_DIR_MARKERS = (
    "node_modules/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
    ".tox/",
    ".eggs/",
    ".venv/",
    "/venv/",
    "target/debug/",
    "target/release/",
    ".terraform/",
    "vendor/",
    "bower_components/",
    ".bundle/",
)

_IDE_DIRS = (".idea/", ".vscode/")


class RepoHygieneRule(RepoRule):
    """Flags generated/vendor/IDE directories that appear in the scan scope.

    Implemented as a repo-level rule (not per file) so that one committed
    ``node_modules`` produces one finding instead of thousands.
    """

    id = "APF-ART-006"
    name = "Generated or vendored directory in repository"
    category = "artifact"
    severity = Severity.LOW
    confidence = Confidence.HIGH
    description = (
        "A vendored, generated or IDE directory (node_modules, __pycache__, .idea, build output, ...) is"
        "present in the scan scope."
    )
    remediation = (
        "Remove the directory from the repository (git rm -r --cached if tracked), "
        "restore dependencies from the lockfile at build time, and add it to .gitignore."
    )
    applies_to = "repository inventory"

    def check_repo(self, ctx: RepoContext) -> list[tuple[str, RawFinding]]:
        hits: set[str] = set()
        for fctx in ctx.files:
            path = fctx.rel_path.replace("\\", "/") + "/"
            for marker in _DIR_MARKERS:
                idx = path.find(marker)
                if idx != -1:
                    hits.add("/".join(path[: idx + len(marker)].rstrip("/").split("/")))
                    break
        results: list[tuple[str, RawFinding]] = []
        for directory in sorted(hits):
            tracked_note = ""
            if ctx.tracked is not None:
                any_tracked = any(f.replace("\\", "/").startswith(directory + "/") for f in ctx.tracked)
                tracked_note = " (tracked by Git)" if any_tracked else " (not tracked; verify .gitignore)"
            results.append(
                (
                    directory,
                    RawFinding(message=(f"Vendored/generated directory '{directory}' in repository{tracked_note}")),
                )
            )
        return results


class IDEDirRule(RepoRule):
    id = "APF-ART-008"
    name = "IDE configuration directory in repository"
    category = "artifact"
    severity = Severity.LOW
    confidence = Confidence.MEDIUM
    description = ".idea/ or .vscode/ directory present. May contain local paths, tokens in settings, or just noise."
    remediation = "Add .idea/ and .vscode/ to .gitignore; keep shared editorconfig in .editorconfig instead."
    applies_to = "repository inventory"

    def check_repo(self, ctx: RepoContext) -> list[tuple[str, RawFinding]]:
        hits: set[str] = set()
        for fctx in ctx.files:
            path = fctx.rel_path.replace("\\", "/") + "/"
            for marker in _IDE_DIRS:
                idx = path.find(marker)
                if idx != -1:
                    hits.add(marker.rstrip("/"))
                    break
        return [
            (
                d,
                RawFinding(message=f"IDE configuration directory '{d}' present; review for local settings"),
            )
            for d in sorted(hits)
        ]


def check_npmrc_auth(text: str) -> bool:
    """Used by CredentialFileRule for .npmrc content inspection."""
    return bool(re.search(r"^\s*_auth(Token)?\s*=", text or "", re.MULTILINE))


def json_has_service_account(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return False
    return isinstance(data, dict) and "private_key" in data and "client_email" in data


PATH_RULES = [
    EnvFileRule(),
    KeyFileRule(),
    CredentialFileRule(),
    DumpFileRule(),
    OSCruftRule(),
    DatabaseFileRule(),
]

REPO_RULES = [
    RepoHygieneRule(),
    IDEDirRule(),
]
