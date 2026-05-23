# AI DevSecOps Control Plane - Handoff Context

Last updated: 2026-05-21

## Purpose

AI DevSecOps Control Plane is a local/self-hosted security automation platform. It scans source code, stores normalized findings, generates remediation proposals with a local LLM, and opens GitHub Pull Requests through a GitHub App. The key product narrative is: source code should not leave the user's infrastructure, and AI remediation should be reviewable, auditable, and safe.

## Current Repository

Local path:

```text
/home/zamaer/Documentos/codigo-general/AI-DevSecOps-Control-Plane
```

Important files:

```text
src/api/main.py
src/api/models.py
src/api/database.py
src/scanners/escaneo.py
src/ai_engine/remediator.py
src/integrations/github_client.py
src/dashboard/index.html
code/requirements.txt
.gitignore
```

## Stack

- FastAPI backend.
- SQLModel with SQLite by default.
- Bandit for current SAST scanning.
- Ollama for local LLM remediation.
- GitHub App integration for real Pull Requests.
- Static HTML/Tailwind dashboard served from `GET /`.

Current Python dependencies in `code/requirements.txt`:

```text
fastapi
uvicorn
bandit
sqlmodel
psycopg2-binary
httpx>=0.27.0
PyJWT>=2.8.0
cryptography>=42.0.0
```

## Environment Variables

The project uses `.env`, protected by `.gitignore`.

GitHub App variables:

```env
GITHUB_APP_ID=<github-app-id>
GITHUB_INSTALLATION_ID=<installation-id>
GITHUB_PRIVATE_KEY_PATH=<path-to-private-key-pem>
GITHUB_REPO=mendozaErnest/ai-devsecops-control-plane
GITHUB_BASE_BRANCH=main
```

Database:

```env
DATABASE_URL=<optional; defaults to local SQLite dev_database.db>
```

Do not commit tokens, `.env`, `.pem` keys, or SQLite WAL/SHM files. `.gitignore` currently covers `.env*`, `*.pem`, `dev_database.db`, `dev_database.db-shm`, and `dev_database.db-wal`.

## Implemented API Surface

In `src/api/main.py`:

- `GET /`: serves `src/dashboard/index.html`.
- `GET /api/findings`: returns findings with `has_remediation` and `remediation_status`.
- `POST /api/scan`: runs Bandit via `src.scanners.escaneo.run_scan()`.
- `POST /api/remediate/{finding_id}`: generates a remediation with Ollama and stores a `Remediation`.
- `POST /api/remediate/{finding_id}/pr`: opens a GitHub PR using the latest remediation for a finding.
- `DELETE /api/remediate/{finding_id}/pr`: deletes the branch `security-fix-{finding_id}` from GitHub.
- `GET /api/ping?ip=...`: validates IPv4 with `ipaddress.IPv4Address` and runs `ping` without `shell=True`.

The PR endpoint catches `GitHubClientError` and returns HTTP 502 with the error detail.

## GitHub App Integration

Implemented in `src/integrations/github_client.py`.

Authentication flow:

1. Read `GITHUB_APP_ID`, `GITHUB_INSTALLATION_ID`, `GITHUB_PRIVATE_KEY_PATH`, `GITHUB_REPO`, and `GITHUB_BASE_BRANCH`.
2. Generate a JWT signed with RS256 using the private key.
3. Exchange the JWT for an installation token through:

```text
POST /app/installations/{installation_id}/access_tokens
```

4. Use the installation token in:

```text
Authorization: Bearer <installation_token>
```

Required headers:

```text
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28
User-Agent: AI-DevSecOps-Control-Plane
```

The token extraction handles both dictionaries and object-style responses:

- `response["token"]` / `response["access_token"]` when response is a dict.
- `response.token` / `response.access_token` when response is an object.

## PR Creation Flow

`create_security_pr(finding_details, remediation_text)`:

1. Gets the base branch SHA:

```text
GET /repos/{repo}/git/ref/heads/{base_branch}
```

2. Ensures branch `security-fix-{finding_id}` exists. If it already exists, it is force-reset to the base SHA using:

```text
PATCH /repos/{repo}/git/refs/heads/{branch_name}
```

This avoids GitHub's `branch has no history in common with main` error.

3. Extracts a valid Python code block from `remediation_text`.

4. Downloads the affected file from GitHub:

```text
GET /repos/{repo}/contents/{file_path}?ref={branch}
```

5. Builds safe patched content and commits it with:

```text
PUT /repos/{repo}/contents/{file_path}
```

6. Opens the PR:

```text
POST /repos/{repo}/pulls
```

If a PR already exists for that branch, the code fetches the open PR with:

```text
GET /repos/{repo}/pulls?head={owner}:{branch}&state=open
```

## Critical Patch Safety Logic

The latest critical fix prevents replacing an entire source file with a short LLM snippet.

Key functions in `src/integrations/github_client.py`:

- `extract_python_code_block(remediation_text)`: extracts only the contents of a ```python fenced code block and validates it with `ast.parse`.
- `should_replace_full_file(original_content, patch_content)`: blocks full-file replacement when the original file has more than 100 lines and the patch has fewer than 30 lines.
- `find_enclosing_function_range(original_content, line_start)`: parses the original file with AST and finds the smallest function containing the Bandit finding line.
- `find_function_range_by_name(original_content, function_name)`: fallback lookup by function name from the patch.
- `replace_line_range(original_content, patch_content, start_line, end_line)`: replaces only the affected function's line range.
- `build_safe_patched_content(original_content, patch_content, finding_details)`: central guardrail; validates the final file with `ast.parse`, refuses empty output, and refuses unexpectedly short output for large files.

Rule of thumb:

- If the LLM returns a near-complete file, full replacement is allowed.
- If the LLM returns a short function/snippet, only the affected function is replaced.
- If the affected function cannot be located safely, raise `GitHubClientError` and do not commit.

This was added after a destructive PR attempt where `src/api/main.py` was replaced by a tiny snippet.

## No Markdown Garbage

The GitHub integration must not create or commit files under `docs/remediations/*.md`.

All explanation from Ollama belongs in the Pull Request body only.

Current check:

```bash
rg "docs/remediations|build_remediation_markdown|markdown_path|\\.md" src/integrations/github_client.py src/api/main.py src/dashboard/index.html
```

Expected result: no matches related to GitHub remediation documents.

## Dashboard

`src/dashboard/index.html` includes:

- Run scan button.
- Findings table.
- Auto-Fix button.
- Remediation modal.
- PR button with states:
  - idle: `🚀 Convertir a Pull Request`
  - loading: `⏳ Creando PR…`
  - success: link `🔗 Ver Pull Request en GitHub`
  - delete branch: red `🗑️ Eliminar Rama` button with native `confirm()`
  - error: inline red message from API `detail`

The delete button calls:

```text
DELETE /api/remediate/{finding_id}/pr
```

## Scanner State

`src/scanners/escaneo.py` currently runs Bandit against:

```text
src/dummy_vulnerable_app.py
```

It persists `Target`, `Scan`, and `Finding` rows. It deduplicates by SHA-256 fingerprint. In the current code inspected on 2026-05-21, existing findings are set back to `open`; the more advanced regression logic (`fixed` -> `regression`, accepted risk / false positive untouched) is still a desired next step unless reintroduced.

## Validation

Use:

```bash
python3 -m compileall src
```

Latest validation after the surgical patch logic:

```text
Listing 'src'...
Listing 'src/ai_engine'...
Listing 'src/api'...
Listing 'src/dashboard'...
Listing 'src/integrations'...
Compiling 'src/integrations/github_client.py'...
Listing 'src/scanners'...
```

## Current Risks And Next Steps

High-priority next work:

1. Add tests for `build_safe_patched_content()` with:
   - short function patch into large file,
   - invalid Python block,
   - missing function range,
   - full-file patch allowed only when comparable size.
2. Reintroduce/finish robust finding lifecycle:
   - `open` seen again updates `last_seen_at`,
   - `fixed` seen again becomes `regression`,
   - `accepted_risk` and `false_positive` are not reopened.
3. Create scanner adapter abstraction:
   - `base.py`,
   - `bandit_adapter.py`,
   - `pip_audit_adapter.py`.
4. Add remediation verification:
   - apply patch branch,
   - re-scan,
   - mark success/failure.
5. Improve prompts so Ollama returns either a complete affected function or a proper unified diff, not prose mixed with partial snippets.
