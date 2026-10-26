"""Secret detection rules (APF-SEC-*).

Each rule targets a well-known credential format. Known-format rules use
structural regexes with high confidence; the generic assignment rule
(APF-SEC-020) combines assignment syntax with entropy/character-class
gating and placeholder filtering to stay quiet on documentation.

All patterns are verified against synthetic fixtures in
``tests/fixtures/`` — never against real credentials.
"""

from __future__ import annotations

import re
from typing import ClassVar

from agentpreflight.models import Confidence, Severity
from agentpreflight.redact import looks_generated_secret, looks_like_placeholder
from agentpreflight.rules.base import ContentPattern, ContentRule, FileContext, RawFinding


class SecretRule(ContentRule):
    category = "secret"


class AWSAccessKeyRule(SecretRule):
    id = "APF-SEC-001"
    name = "AWS access key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "AWS access key ID (AKIA/ASIA/ABIA/ACCA prefix). Allows API calls if the matching secret key was alsoleaked."
    )
    remediation = (
        "Remove the key from the file and from Git history, deactivate it in the IAM console, "
        "and create a replacement. Prefer IAM roles or short-lived credentials."
    )
    references: ClassVar[list[str]] = [
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    ]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b")),
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(
            ctx,
            "AWS access key ID detected (synthetic example keys used in tests are also matched)",
        )


class GitHubTokenRule(SecretRule):
    id = "APF-SEC-002"
    name = "GitHub token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "GitHub personal access, OAuth, app installation, refresh or fine-grained token."
    remediation = (
        "Revoke the token at https://github.com/settings/tokens, remove it from the repository "
        "and its history, and switch to short-lived tokens or a secret manager."
    )
    references: ClassVar[list[str]] = [
        "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    ]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}"
                r"|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,255})\b"
            )
        )
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "GitHub token detected")


class SlackTokenRule(SecretRule):
    id = "APF-SEC-003"
    name = "Slack token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Slack bot/user/workspace/app token (xox[abeprs]- prefix)."
    remediation = "Revoke the token in the Slack app configuration and rotate any stored copies."
    references: ClassVar[list[str]] = ["https://api.slack.com/authentication/token-types"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(xox[abeprs]-[A-Za-z0-9-]{10,})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Slack token detected")


class GoogleAPIKeyRule(SecretRule):
    id = "APF-SEC-004"
    name = "Google API key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Google API key (AIza prefix, used by Maps, reCAPTCHA and many Google services)."
    remediation = (
        "Restrict or delete the key in the Google Cloud console, then rotate. "
        "Apply HTTP referrer / IP restrictions on the replacement."
    )
    references: ClassVar[list[str]] = ["https://cloud.google.com/docs/authentication/api-keys"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Google API key detected")


class StripeKeyRule(SecretRule):
    id = "APF-SEC-005"
    name = "Stripe live secret key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "Stripe live secret key (sk_live_/rk_live_). Grants full account access. Test keys (sk_test_) are"
        "intentionally not flagged."
    )
    remediation = "Roll the key in the Stripe dashboard immediately; live secret keys allow charging customers."
    references: ClassVar[list[str]] = ["https://docs.stripe.com/keys"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Stripe live secret key detected")


class OpenAIKeyRule(SecretRule):
    id = "APF-SEC-006"
    name = "OpenAI / Anthropic API key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "OpenAI (sk-/sk-proj-) or Anthropic (sk-ant-) API key."
    remediation = "Revoke the key in the provider dashboard and rotate. Keep keys out of source control."
    references: ClassVar[list[str]] = ["https://platform.openai.com/docs/api-reference/authentication"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(r"\b(sk-(?:proj-|ant-)[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b")
        )
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "LLM provider API key detected")


class PrivateKeyBlockRule(SecretRule):
    id = "APF-SEC-007"
    name = "Private key block"
    severity = Severity.CRITICAL
    confidence = Confidence.HIGH
    description = "PEM/OPENSSH/PGP private key material embedded in a file. Full key compromise."
    remediation = (
        "Assume the key is compromised: remove it, rotate it everywhere it is trusted, "
        "and audit access logs. Purge it from Git history before publishing."
    )
    references: ClassVar[list[str]] = ["https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
            group=None,
        )
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Private key material detected")


class JWTRule(SecretRule):
    id = "APF-SEC-008"
    name = "Hardcoded JWT"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = (
        "JSON Web Token embedded in source or configuration. JWTs often carry identity claims and can be"
        "valid credentials."
    )
    remediation = "Remove the token, invalidate the session it belongs to, and generate tokens at runtime instead."
    references: ClassVar[list[str]] = ["https://datatracker.ietf.org/doc/html/rfc8725"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b"))
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Hardcoded JSON Web Token detected")


class URLWithCredentialsRule(SecretRule):
    id = "APF-SEC-009"
    name = "URL with embedded credentials"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = (
        "Database or service URL containing a username:password pair (postgres://, mysql://, mongodb://,"
        "redis://, amqp://, https://...)."
    )
    remediation = (
        "Move the credentials to environment variables or a secret manager and use a "
        "credential-free URL in source code."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
    ]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(
            re.compile(
                r"\b((?:https?|ftps?|ssh|postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss"
                r"|amqps?|mssql|jdbc:[a-z0-9]+)://[^\s:@/\"'{\[]+:[^\s@/\"'{\[]+@[^\s\"'>)\]}]+)"
            )
        )
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "URL with embedded credentials detected")


class GitLabTokenRule(SecretRule):
    id = "APF-SEC-010"
    name = "GitLab token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "GitLab personal/project/group access token (glpat- prefix)."
    remediation = "Revoke the token in GitLab (User Settings > Access Tokens) and rotate."
    references: ClassVar[list[str]] = ["https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "GitLab access token detected")


class NpmTokenRule(SecretRule):
    id = "APF-SEC-011"
    name = "npm access token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "npm registry access token (npm_ prefix). Allows publishing packages."
    remediation = "Revoke at https://www.npmjs.com/settings/USERNAME/tokens and rotate; prefer granular tokens."
    references: ClassVar[list[str]] = ["https://docs.npmjs.com/about-access-tokens"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "npm access token detected")


class PyPITokenRule(SecretRule):
    id = "APF-SEC-012"
    name = "PyPI token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "PyPI upload token (pypi- prefix, used by trusted publishing fallback)."
    remediation = "Revoke at https://pypi.org/manage/account/ and prefer Trusted Publishing where possible."
    references: ClassVar[list[str]] = ["https://docs.pypi.org/trusted-publishers/"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b")),
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "PyPI upload token detected")


class SendGridKeyRule(SecretRule):
    id = "APF-SEC-013"
    name = "SendGrid API key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "SendGrid API key (SG. prefix). Allows sending mail as your domain."
    remediation = "Revoke in the SendGrid console and rotate; store in a secret manager."
    references: ClassVar[list[str]] = ["https://www.twilio.com/docs/sendgrid/api-reference"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\b(SG\.[A-Za-z0-9_\-]{16,64}\.[A-Za-z0-9_\-]{16,64})\b"))
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "SendGrid API key detected")


class TelegramBotTokenRule(SecretRule):
    id = "APF-SEC-014"
    name = "Telegram bot token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Telegram bot token (numeric ID:AA prefix). Grants full control of the bot."
    remediation = "Revoke via @BotFather (/revoke) and rotate."
    references: ClassVar[list[str]] = ["https://core.telegram.org/bots/api#authorizing-your-bot"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b([0-9]{8,10}:AA[A-Za-z0-9_\-]{33})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Telegram bot token detected")


class SlackWebhookRule(SecretRule):
    id = "APF-SEC-015"
    name = "Slack webhook URL"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Incoming webhook URL for a Slack workspace (hooks.slack.com/services/...)."
    remediation = "Delete the webhook in the Slack app config; anyone with the URL can post to the channel."
    references: ClassVar[list[str]] = ["https://api.slack.com/messaging/webhooks"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"))
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Slack incoming webhook URL detected")


class ShopifyTokenRule(SecretRule):
    id = "APF-SEC-016"
    name = "Shopify token"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Shopify API/shared/advanced/public app token (shpat_/shpss_/shpca_/shppa_ prefix)."
    remediation = "Revoke the token in the Shopify admin and rotate."
    references: ClassVar[list[str]] = ["https://shopify.dev/docs/apps/auth"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(shp(?:at|ca|ss|pa)_[a-fA-F0-9]{32})\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Shopify token detected")


class AzureStorageKeyRule(SecretRule):
    id = "APF-SEC-017"
    name = "Azure storage connection key"
    severity = Severity.HIGH
    confidence = Confidence.HIGH
    description = "Azure Storage account key embedded in a connection string (AccountKey=...)."
    remediation = "Rotate the storage account key in the Azure portal and prefer SAS or managed identities."
    references: ClassVar[list[str]] = [
        "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"
    ]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"(AccountKey=[A-Za-z0-9+/=]{60,})"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Azure storage account key detected")


class SquareTokenRule(SecretRule):
    id = "APF-SEC-018"
    name = "Square token"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = "Square OAuth/application token (sq0atp-/sq0csp- prefix)."
    remediation = "Revoke the token in the Square developer dashboard and rotate."
    references: ClassVar[list[str]] = ["https://developer.squareup.com/docs/oauth-api/overview"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [
        ContentPattern(re.compile(r"\b(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,43})\b")),
    ]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Square token detected")


class MetaTokenRule(SecretRule):
    id = "APF-SEC-019"
    name = "Meta/Facebook access token"
    severity = Severity.MEDIUM
    confidence = Confidence.HIGH
    description = "Facebook/Meta long-lived user access token (EAACEdEose0cBA prefix)."
    remediation = "Invalidate the token via the Graph API debug endpoints and rotate."
    references: ClassVar[list[str]] = ["https://developers.facebook.com/docs/facebook-login/guides/access-tokens"]
    applies_to = "all text files"
    patterns: ClassVar[list[ContentPattern]] = [ContentPattern(re.compile(r"\b(EAACEdEose0cBA[A-Za-z0-9]+)\b"))]

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        return self.default_scan(ctx, "Meta access token detected")


class GenericSecretRule(SecretRule):
    """Generic credential assignment with entropy/placeholder gating.

    This rule catches ``api_key = "..."`` style assignments for providers we
    do not have a structural pattern for. It stays quiet on:
    - placeholder/documentation values (``your-api-key``, ``${VAR}``, ``xxx``)
    - weak default passwords (handled by APF-DEF-006)
    - short or low-entropy values that fail the generated-secret heuristics
    """

    id = "APF-SEC-020"
    name = "Generic embedded credential"
    severity = Severity.MEDIUM
    confidence = Confidence.MEDIUM
    description = (
        "Assignment of a generated-looking value to a credential-like key (password, secret, token, api key)"
        "in config or code."
    )
    remediation = (
        "Confirm whether the value is real. If it is, move it to environment variables "
        "or a secret manager and rotate it."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    ]
    applies_to = "all text files"

    _QUOTED = re.compile(
        r"""(?ix)\b
        (?:password|passwd|pwd|secret|passphrase|api[_-]?key|apikey|
           auth[_-]?token|access[_-]?token|auth[_-]?secret|client[_-]?secret|
           private[_-]?key|admin[_-]?token|shared[_-]?key|master[_-]?key|
           db[_-]?pass(?:word)?|database[_-]?pass(?:word)?)
        \b\s*[:=]>?\s*
        ["']([^\s"']{8,256})["']
        """
    )
    _ENV_ASSIGN = re.compile(
        r"""(?i)^
        (?:export\s+)?
        [A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|PWD|SECRET|TOKEN|API[_-]?KEY|APIKEY)
        [A-Za-z0-9_]*
        \s*=\s*
        (?:"([^"\s]{8,256})"|'([^'\s]{8,256})'|([^\s#"']{8,256}))
        \s*$
        """
    )
    _YAML_KEY = re.compile(
        r"""(?i)^\s*
        [A-Za-z_][A-Za-z0-9_.-]*(?:password|passwd|secret|token|api_?key)[A-Za-z0-9_.-]*
        \s*:\s*
        (?:"([^"\s]{8,256})"|'([^'\s]{8,256})'|([^\s#]{8,256}))
        \s*$
        """
    )

    def check_content(self, ctx: FileContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        assert ctx.lines is not None
        for lineno, line in enumerate(ctx.lines, start=1):
            candidates: list[tuple[str, int, int]] = []  # (value, start, end)
            for m in self._QUOTED.finditer(line):
                candidates.append((m.group(1), m.start(1), m.end(1)))
            for m in self._ENV_ASSIGN.finditer(line):
                val = next(g for g in m.groups() if g is not None)
                candidates.append((val, 0, len(line)))
            for m in self._YAML_KEY.finditer(line):
                val = next((g for g in m.groups() if g is not None), "")
                candidates.append((val, 0, len(line)))
            for value, start, end in candidates:
                if looks_like_placeholder(value):
                    continue
                if not looks_generated_secret(value):
                    continue
                span = (start, end) if start < end else None
                findings.append(
                    RawFinding(
                        message="Credential-like value assigned to a secret key",
                        line=lineno,
                        column=1,
                        secret_value=value,
                        span=span,
                    )
                )
        return findings


SECRET_RULES: list[SecretRule] = [
    AWSAccessKeyRule(),
    GitHubTokenRule(),
    SlackTokenRule(),
    GoogleAPIKeyRule(),
    StripeKeyRule(),
    OpenAIKeyRule(),
    PrivateKeyBlockRule(),
    JWTRule(),
    URLWithCredentialsRule(),
    GitLabTokenRule(),
    NpmTokenRule(),
    PyPITokenRule(),
    SendGridKeyRule(),
    TelegramBotTokenRule(),
    SlackWebhookRule(),
    ShopifyTokenRule(),
    AzureStorageKeyRule(),
    SquareTokenRule(),
    MetaTokenRule(),
    GenericSecretRule(),
]
