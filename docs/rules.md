# Rule catalog

Auto-generated from the rule registry (47 rules).
Regenerate with `agentpreflight rules list --format markdown > docs/rules.md`.

## APF-SEC-001 — AWS access key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

AWS access key ID (AKIA/ASIA/ABIA/ACCA prefix). Allows API calls if the matching secret key was alsoleaked.

**Remediation:** Remove the key from the file and from Git history, deactivate it in the IAM console, and create a replacement. Prefer IAM roles or short-lived credentials.

- <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html>

## APF-SEC-002 — GitHub token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

GitHub personal access, OAuth, app installation, refresh or fine-grained token.

**Remediation:** Revoke the token at https://github.com/settings/tokens, remove it from the repository and its history, and switch to short-lived tokens or a secret manager.

- <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens>

## APF-SEC-003 — Slack token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Slack bot/user/workspace/app token (xox[abeprs]- prefix).

**Remediation:** Revoke the token in the Slack app configuration and rotate any stored copies.

- <https://api.slack.com/authentication/token-types>

## APF-SEC-004 — Google API key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Google API key (AIza prefix, used by Maps, reCAPTCHA and many Google services).

**Remediation:** Restrict or delete the key in the Google Cloud console, then rotate. Apply HTTP referrer / IP restrictions on the replacement.

- <https://cloud.google.com/docs/authentication/api-keys>

## APF-SEC-005 — Stripe live secret key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Stripe live secret key (sk_live_/rk_live_). Grants full account access. Test keys (sk_test_) areintentionally not flagged.

**Remediation:** Roll the key in the Stripe dashboard immediately; live secret keys allow charging customers.

- <https://docs.stripe.com/keys>

## APF-SEC-006 — OpenAI / Anthropic API key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

OpenAI (sk-/sk-proj-) or Anthropic (sk-ant-) API key.

**Remediation:** Revoke the key in the provider dashboard and rotate. Keep keys out of source control.

- <https://platform.openai.com/docs/api-reference/authentication>

## APF-SEC-007 — Private key block

- **Severity:** critical
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

PEM/OPENSSH/PGP private key material embedded in a file. Full key compromise.

**Remediation:** Assume the key is compromised: remove it, rotate it everywhere it is trusted, and audit access logs. Purge it from Git history before publishing.

- <https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html>

## APF-SEC-008 — Hardcoded JWT

- **Severity:** medium
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

JSON Web Token embedded in source or configuration. JWTs often carry identity claims and can bevalid credentials.

**Remediation:** Remove the token, invalidate the session it belongs to, and generate tokens at runtime instead.

- <https://datatracker.ietf.org/doc/html/rfc8725>

## APF-SEC-009 — URL with embedded credentials

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Database or service URL containing a username:password pair (postgres://, mysql://, mongodb://,redis://, amqp://, https://...).

**Remediation:** Move the credentials to environment variables or a secret manager and use a credential-free URL in source code.

- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>

## APF-SEC-010 — GitLab token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

GitLab personal/project/group access token (glpat- prefix).

**Remediation:** Revoke the token in GitLab (User Settings > Access Tokens) and rotate.

- <https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html>

## APF-SEC-011 — npm access token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

npm registry access token (npm_ prefix). Allows publishing packages.

**Remediation:** Revoke at https://www.npmjs.com/settings/USERNAME/tokens and rotate; prefer granular tokens.

- <https://docs.npmjs.com/about-access-tokens>

## APF-SEC-012 — PyPI token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

PyPI upload token (pypi- prefix, used by trusted publishing fallback).

**Remediation:** Revoke at https://pypi.org/manage/account/ and prefer Trusted Publishing where possible.

- <https://docs.pypi.org/trusted-publishers/>

## APF-SEC-013 — SendGrid API key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

SendGrid API key (SG. prefix). Allows sending mail as your domain.

**Remediation:** Revoke in the SendGrid console and rotate; store in a secret manager.

- <https://www.twilio.com/docs/sendgrid/api-reference>

## APF-SEC-014 — Telegram bot token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Telegram bot token (numeric ID:AA prefix). Grants full control of the bot.

**Remediation:** Revoke via @BotFather (/revoke) and rotate.

- <https://core.telegram.org/bots/api#authorizing-your-bot>

## APF-SEC-015 — Slack webhook URL

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Incoming webhook URL for a Slack workspace (hooks.slack.com/services/...).

**Remediation:** Delete the webhook in the Slack app config; anyone with the URL can post to the channel.

- <https://api.slack.com/messaging/webhooks>

## APF-SEC-016 — Shopify token

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Shopify API/shared/advanced/public app token (shpat_/shpss_/shpca_/shppa_ prefix).

**Remediation:** Revoke the token in the Shopify admin and rotate.

- <https://shopify.dev/docs/apps/auth>

## APF-SEC-017 — Azure storage connection key

- **Severity:** high
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Azure Storage account key embedded in a connection string (AccountKey=...).

**Remediation:** Rotate the storage account key in the Azure portal and prefer SAS or managed identities.

- <https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage>

## APF-SEC-018 — Square token

- **Severity:** medium
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Square OAuth/application token (sq0atp-/sq0csp- prefix).

**Remediation:** Revoke the token in the Square developer dashboard and rotate.

- <https://developer.squareup.com/docs/oauth-api/overview>

## APF-SEC-019 — Meta/Facebook access token

- **Severity:** medium
- **Confidence:** high
- **Category:** secret
- **Applies to:** all text files

Facebook/Meta long-lived user access token (EAACEdEose0cBA prefix).

**Remediation:** Invalidate the token via the Graph API debug endpoints and rotate.

- <https://developers.facebook.com/docs/facebook-login/guides/access-tokens>

## APF-SEC-020 — Generic embedded credential

- **Severity:** medium
- **Confidence:** medium
- **Category:** secret
- **Applies to:** all text files

Assignment of a generated-looking value to a credential-like key (password, secret, token, api key)in config or code.

**Remediation:** Confirm whether the value is real. If it is, move it to environment variables or a secret manager and rotate it.

- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>

## APF-ART-001 — Environment file present

- **Severity:** high
- **Confidence:** high
- **Category:** artifact
- **Applies to:** file names matching .env or .env.<name>

A .env file (not .env.example) exists in the scan scope. Env files very often contain realcredentials.

**Remediation:** Move secrets out of the file, delete it from the working tree and history, and commit a .env.example with placeholder values instead.

- <https://dotenvx.com/docs>

## APF-ART-002 — Private key or keystore file

- **Severity:** high
- **Confidence:** high
- **Category:** artifact
- **Applies to:** id_rsa and friends, *.pem/*.key/*.p12/*.pfx/*.jks/*.keystore/*.ppk

File name matches a private key, TLS key, or Java/Android keystore convention.

**Remediation:** If this is a real key: rotate it, remove it from the repository and history. If it is a fixture or documentation, add an inline allow marker or an ignore entry.

- <https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html>

## APF-ART-003 — Known credential file

- **Severity:** high
- **Confidence:** high
- **Category:** artifact
- **Applies to:** .netrc, .npmrc (with auth), .aws/credentials, .docker/config.json, credentials.json, .kube/config,.git-credentials, serviceAccount*.json

File name matches a known credential store (.netrc, .aws/credentials, .docker/config.json,.kube/config, .git-credentials, ...).

**Remediation:** Remove the file from the repository and history; these formats store plaintext credentials.

- <https://docs.docker.com/engine/reference/commandline/login/>

## APF-ART-004 — Database dump or backup file

- **Severity:** medium
- **Confidence:** medium
- **Category:** artifact
- **Applies to:** *.sql, *.dump, *.bak, *.backup, *.sql.gz, *.rdb

File name looks like a database dump or editor/DB backup (.sql, .dump, .bak, .backup, .sql.gz,.rdb).

**Remediation:** Keep dumps out of the repository; restore from backups stored outside Git if needed.

## APF-ART-005 — OS cruft file

- **Severity:** low
- **Confidence:** high
- **Category:** artifact
- **Applies to:** .DS_Store, Thumbs.db, desktop.ini, ehthumbs.db

Operating-system metadata file (.DS_Store, Thumbs.db, desktop.ini).

**Remediation:** Delete the file and add it to .gitignore.

## APF-ART-007 — Database file in repository

- **Severity:** low
- **Confidence:** medium
- **Category:** artifact
- **Applies to:** *.sqlite, *.sqlite3, *.db

Binary/SQLite database file present (.sqlite, .sqlite3, .db).

**Remediation:** Move runtime data outside the repository; commit a schema or migration instead.

## APF-DEF-001 — Django DEBUG enabled

- **Severity:** high
- **Confidence:** high
- **Category:** default
- **Applies to:** Python settings modules

DEBUG = True in Django settings exposes stack traces, settings and secret keys in production.

**Remediation:** Set DEBUG from an environment variable and default it to False outside local development.

- <https://docs.djangoproject.com/en/stable/ref/settings/#debug>

## APF-DEF-002 — Flask/Django dev server debug

- **Severity:** medium
- **Confidence:** high
- **Category:** default
- **Applies to:** Python files

Application started with debug=True (Flask/Werkzeug dev server or similar). The interactive debuggerallows arbitrary code execution on errors.

**Remediation:** Enable debug mode only via an environment variable, and never bind the debugger to a publicinterface.

- <https://flask.palletsprojects.com/en/stable/debugging/>

## APF-DEF-003 — TLS verification disabled

- **Severity:** high
- **Confidence:** high
- **Category:** default
- **Applies to:** Python files

verify=False in an HTTP client call disables certificate validation, enabling machine-in-the-middleattacks.

**Remediation:** Remove verify=False. For self-signed certificates, add the CA to the trust store instead.

- <https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification>

## APF-DEF-004 — SSL/context verification bypass

- **Severity:** high
- **Confidence:** high
- **Category:** default
- **Applies to:** Python/JS/TS files, env files, shell scripts

Unverified SSL context or hostname check disabled (ssl._create_unverified_context,check_hostname=False, NODE_TLS_REJECT_UNAUTHORIZED=0).

**Remediation:** Use a verified context; add your CA to the trust store rather than disabling checks.

- <https://docs.python.org/3/library/ssl.html#ssl.create_default_context>

## APF-DEF-005 — CORS wildcard origin

- **Severity:** medium
- **Confidence:** high
- **Category:** default
- **Applies to:** Python/JS/TS code and server config

CORS configured to allow any origin ('*'), combined with credential support this leaks authenticateddata cross-origin.

**Remediation:** List the exact allowed origins; never combine '*' with credentials.

- <https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS>

## APF-DEF-006 — Default or weak password in config

- **Severity:** medium
- **Confidence:** medium
- **Category:** default
- **Applies to:** configuration files (YAML/TOML/INI/JSON/env/properties)

A password field is set to a well-known default/weak value (admin, root, password, 123456, changeme,...).

**Remediation:** Set real credentials via environment variables or a secret manager; fail fast if a default isdetected at startup.

## APF-DEF-007 — Ansible host key checking disabled

- **Severity:** medium
- **Confidence:** high
- **Category:** default
- **Applies to:** ansible.cfg, Ansible playbooks, CI environment

host_key_checking = False disables SSH host verification for Ansible, enabling MITM attacks againstdeployments.

**Remediation:** Populate known_hosts (or use ssh-keyscan once, deliberately) and re-enable host key checking.

- <https://docs.ansible.com/ansible/latest/user_guide/configuration.html>

## APF-DEF-008 — Container runs as root

- **Severity:** medium
- **Confidence:** medium
- **Category:** default
- **Applies to:** Dockerfiles

Dockerfile has no USER instruction (containers run as root), or a run command uses --privileged /escalates via sudo.

**Remediation:** Create an unprivileged user and set USER; avoid --privileged and sudo inside images.

- <https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user>

## APF-DEF-010 — Insecure Kubernetes workload settings

- **Severity:** high
- **Confidence:** medium
- **Category:** default
- **Applies to:** Kubernetes/Helm YAML

Kubernetes manifest enables privileged containers, privilege escalation, host namespaces or hostports.

**Remediation:** Remove privileged/host settings; run with a restricted Pod Security Standard.

- <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

## APF-DEF-011 — Weak hash algorithm

- **Severity:** medium
- **Confidence:** low
- **Category:** default
- **Applies to:** Python/JS/TS/Java/Ruby/PHP files

Use of MD5 or SHA-1. Fine for cache keys, dangerous for passwords, signatures or integrity ofuntrusted data — verify the usage.

**Remediation:** Use SHA-256+ or a password hash (argon2, bcrypt, scrypt, PBKDF2). For HMACs, keep MD5/SHA-1 out ofnew code.

- <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>

## APF-DEF-012 — JWT verification disabled

- **Severity:** high
- **Confidence:** high
- **Category:** default
- **Applies to:** Python/JS/TS files

JWT decoded with signature verification disabled or 'none' algorithm allowed — accepts forgedtokens.

**Remediation:** Always verify signatures with an explicit algorithm allowlist and a real key.

- <https://datatracker.ietf.org/doc/html/rfc8725#section-3.1>

## APF-DEF-014 — World-writable permissions

- **Severity:** low
- **Confidence:** medium
- **Category:** default
- **Applies to:** shell scripts, Dockerfiles, Makefiles

chmod 777 in scripts or Dockerfiles makes files world-writable.

**Remediation:** Grant the minimum permissions required (e.g. chmod 750 / 640).

## APF-DEP-001 — Remote script piped to shell

- **Severity:** high
- **Confidence:** high
- **Category:** supply
- **Applies to:** Dockerfiles, CI workflows, shell scripts, docs

curl/wget output piped directly into a shell. A compromise of the host or CDN executes arbitrarycode with the caller's privileges.

**Remediation:** Download the script, review it (or verify a checksum/signature), then execute the pinned version.

- <https://disman.tl/2015/07/02/how-to-safely-execute-remote-scripts.html>

## APF-DEP-002 — Unpinned Python dependency

- **Severity:** info
- **Confidence:** high
- **Category:** supply
- **Applies to:** requirements*.txt

requirements-style file lists dependencies without exact pins (no '=='). Builds are not reproducibleand a malicious release could be pulled automatically.

**Remediation:** Pin exact versions ('==') or use a lockfile; consider hash-pinning (pip-compile --generate-hashes).

## APF-DEP-003 — pull_request_target with untrusted checkout

- **Severity:** critical
- **Confidence:** high
- **Category:** supply
- **Applies to:** .github/workflows/*.yml

Workflow uses pull_request_target together with a checkout of the pull request head. This executesuntrusted PR code with access to repository secrets — a classic sandbox escape.

**Remediation:** Never check out PR code in pull_request_target workflows. Use pull_request for untrusted builds, or split into a trusted workflow triggered by labels.

- <https://securitylab.github.com/research/github-actions-preventing-pwn-requests/>
- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/keeping-your-github-actions-and-workflows-secure>

## APF-DEP-004 — Overly broad workflow permissions

- **Severity:** medium
- **Confidence:** high
- **Category:** supply
- **Applies to:** .github/workflows/*.yml

Workflow grants write-all or contents:write permissions, or grants write permissions in workflowsthat run against untrusted pull requests.

**Remediation:** Apply least-privilege permissions per job and only grant write access in workflows that need it.

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication>

## APF-DEP-005 — Third-party Action not pinned to a commit

- **Severity:** low
- **Confidence:** high
- **Category:** supply
- **Applies to:** .github/workflows/*.yml, action.yml

GitHub Action referenced by tag or branch instead of an immutable commit SHA. A force-push to thetag would run different code in your pipeline.

**Remediation:** Pin third-party actions to the full 40-character commit SHA of a reviewed release.

- <https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-third-party-actions>

## APF-DEP-006 — Node project install hooks / missing lockfile

- **Severity:** low
- **Confidence:** medium
- **Category:** supply
- **Applies to:** package.json

package.json defines pre/post-install hooks (arbitrary code on npm install) or the project has nolockfile (non-reproducible installs).

**Remediation:** Remove install hooks unless essential; commit a lockfile (package-lock.json or equivalent).

## APF-DEP-008 — CI job exposes secrets to untrusted input

- **Severity:** medium
- **Confidence:** medium
- **Category:** supply
- **Applies to:** .gitlab-ci.yml

GitLab CI job with secrets/environment exposure runs scripts from the repository without trustseparation (e.g. include of remote templates with variables).

**Remediation:** Split untrusted validation from privileged jobs; never pass secrets to jobs that execute fork code.

- <https://docs.gitlab.com/ee/ci/security/>

## APF-ART-006 — Generated or vendored directory in repository

- **Severity:** low
- **Confidence:** high
- **Category:** artifact
- **Applies to:** repository inventory

A vendored, generated or IDE directory (node_modules, __pycache__, .idea, build output, ...) ispresent in the scan scope.

**Remediation:** Remove the directory from the repository (git rm -r --cached if tracked), restore dependencies from the lockfile at build time, and add it to .gitignore.

## APF-ART-008 — IDE configuration directory in repository

- **Severity:** low
- **Confidence:** medium
- **Category:** artifact
- **Applies to:** repository inventory

.idea/ or .vscode/ directory present. May contain local paths, tokens in settings, or just noise.

**Remediation:** Add .idea/ and .vscode/ to .gitignore; keep shared editorconfig in .editorconfig instead.

