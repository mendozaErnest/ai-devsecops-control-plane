# Security Policy

## Supported versions

|Version|Supported|
|-|-|
|`main` branch|✅ Active development — patches applied here first|
|Tagged releases|✅ Critical fixes backported on a best-effort basis|
|Older branches|❌ No longer maintained|

\---

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use one of the following channels:

1. **GitHub Private Security Advisory** (preferred) — go to the [Security tab](../../security/advisories/new) of this repository and click **Report a vulnerability**. This keeps the report confidential until a fix is ready.
2. **Email** — if you are unable to use the advisory flow, contact the maintainer directly through their GitHub profile.

### What to include

A useful report contains:

* A clear description of the vulnerability and its potential impact.
* The affected component (`src/api/`, `src/scanners/`, `src/integrations/`, etc.) and, if known, the relevant file and line numbers.
* Step-by-step reproduction instructions, including any specific configuration or environment required.
* Proof-of-concept code or a curl command if applicable.
* Your assessment of exploitability (local-only, requires auth, unauthenticated remote, etc.).

### Response timeline

|Stage|Target|
|-|-|
|Acknowledgement|Within 48 hours|
|Initial assessment|Within 5 business days|
|Fix or mitigation shipped|Within 30 days for Critical/High; 90 days for Medium/Low|
|Public disclosure|Coordinated with reporter after fix is available|

We will credit reporters in the release notes unless they prefer to remain anonymous.

\---

## Security design decisions

This project is a security tool — it should be held to a higher standard than the code it scans. The following decisions were made deliberately.

### GitHub App authentication

The platform authenticates to GitHub using a **GitHub App** (JWT RS256), not a personal access token. This provides scoped, per-installation permissions (`contents: write`, `pull\\\_requests: write`) that can be revoked independently per repository. The private key is never stored in the database or logged.

### Webhook signature verification

All incoming GitHub webhook payloads are verified with **HMAC-SHA256** (`X-Hub-Signature-256`) before any processing occurs. Payloads that fail signature verification are rejected with `403`.

### Scan target allowlist (path traversal prevention)

The API endpoint `POST /api/scan` validates the requested `target\\\_path` against a configurable allowlist (`SCAN\\\_ALLOWED\\\_ROOTS` environment variable). Paths that resolve outside the allowlist (e.g. `../../../etc/passwd`) are rejected with `400` before any scanner is invoked. This prevents a compromised API consumer from scanning arbitrary filesystem paths.

### AI patch validation before commit

Generated patches are never committed directly. Before a branch is created:

* **Python patches** are parsed with `ast.parse`. Invalid syntax, empty output, or patches that shrink the file to below 60% of the original size are rejected.
* **Angular / TypeScript patches** use brace-counting to locate the enclosing method or class. Patches that delete functions, introduce stub comments (`// TODO: implement`, `refactoredFunction`, etc.), or replace more than 20% of source lines are blocked.
* **Java patches** apply the same brace-counting guardrails plus annotation-aware method range detection.

Patches rejected by these guardrails fall back to a **proposal-only PR** — a Markdown file in `docs/remediations/` describing the recommended fix. No source code is modified without passing validation.

### No external data egress

The LLM used for remediation (Ollama, `qwen2.5-coder:14b`) runs entirely on the operator's infrastructure. Source code, scan results, and credentials are never sent to an external AI service. The only outbound network calls are to the GitHub API (for PR creation) and, optionally, to SonarQube running in the operator's own Docker environment.

### Secrets are never stored

* `.env`, `.pem` (GitHub App private key), SQLite database files, and the `workspace/uploads/` directory are listed in `.gitignore` and must never be committed.
* The `GITHUB\\\_PRIVATE\\\_KEY\\\_PATH` environment variable points to a file on disk; the key material is read at runtime and never persisted in the database.
* CI logs are not configured to print environment variables.

### Dependency scanning on every PR

The repository's own GitHub Actions workflow (`.github/workflows/devsecops-scan.yml`) runs **Bandit**, **pip-audit**, and **Semgrep** on every pull request and push to `main`. The project eats its own cooking.

\---

## Known limitations

The following are acknowledged limitations that do not constitute reportable vulnerabilities, but are worth understanding when deploying the platform:

|Limitation|Detail|
|-|-|
|SQLite path validation|`ensure\\\_sqlite\\\_schema()` uses SQLite-specific migrations. When switching to PostgreSQL via `DATABASE\\\_URL`, review schema initialization separately.|
|Heuristic TS/Java patching|TypeScript and Java patch application uses brace-counting, not a full AST parser. Unusual formatting (e.g. deeply nested lambdas) may produce incorrect range detection.|
|DAST adapter is a placeholder|`ZapAdapter` currently returns an empty finding list. No active vulnerability probing is performed until Phase 3 is complete.|
|Workspace uploads|Files uploaded via `POST /api/projects/upload-zip` are extracted to a temporary workspace directory. This directory is not automatically cleaned up and should be managed by the operator.|

\---

## Secure deployment checklist

Before deploying to a shared or production environment:

* \[ ] Set `SCAN\\\_ALLOWED\\\_ROOTS` to the minimum required paths.
* \[ ] Store the GitHub App private key (`.pem`) outside the repository and outside the Docker build context.
* \[ ] Set `GITHUB\\\_WEBHOOK\\\_SECRET` and verify it matches the value configured in the GitHub App settings.
* \[ ] Run the platform behind a reverse proxy (nginx, Caddy) with TLS. The built-in Uvicorn server is not hardened for direct Internet exposure.
* \[ ] Restrict access to port `8000` at the network level. The dashboard does not implement authentication by default.
* \[ ] Rotate the Ollama model periodically and pin to a specific digest in `docker-compose.yml` to avoid supply-chain drift.
* \[ ] Review and prune `workspace/uploads/` regularly to avoid accumulating extracted source trees on disk.

\---

## Scope

The following are **in scope** for vulnerability reports:

* Unauthenticated access to API endpoints that should be restricted.
* Path traversal or arbitrary file read/write via the scan or upload endpoints.
* HMAC bypass or webhook replay attacks.
* Injection vulnerabilities in scan target handling (command injection, SSRF).
* Secrets leaking through API responses, logs, or generated PR content.
* Insecure deserialization in any JSON or file-parsing path.

The following are **out of scope**:

* Vulnerabilities in third-party tools (Bandit, Semgrep, Ollama, SonarQube, OWASP ZAP). Please report those to the respective upstream projects.
* Issues that require physical access to the host machine.
* Social engineering attacks against the maintainer.
* Findings produced by automated scanners against the public GitHub interface (e.g. missing security headers on `github.com` itself).

