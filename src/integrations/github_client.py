import asyncio
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


GITHUB_API_URL = "https://api.github.com"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class GitHubClientError(RuntimeError):
    pass


def load_env_file() -> None:
    env_path = PROJECT_ROOT / ".env"

    if not env_path.exists():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_github_config() -> tuple[str, str]:
    load_env_file()
    token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPO")

    if not token or not repo:
        raise GitHubClientError("Missing GITHUB_TOKEN or GITHUB_REPO environment variable.")

    if "/" not in repo:
        raise GitHubClientError("GITHUB_REPO must use the format owner/repository.")

    return token, repo


def github_request(method: str, path: str, token: str, payload: dict | None = None) -> dict:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        f"{GITHUB_API_URL}{path}",
        data=data,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "AI-DevSecOps-Control-Plane",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise GitHubClientError(f"GitHub API {method} {path} failed with {exc.code}: {error_body}") from exc
    except urllib.error.URLError as exc:
        raise GitHubClientError(f"GitHub API connection failed: {exc}") from exc


def build_remediation_markdown(finding_details: dict, remediation_text: str) -> str:
    return f"""# Security Remediation Proposal

Finding ID: `{finding_details.get("id", "UNKNOWN")}`
Rule: `{finding_details.get("rule_id", "UNKNOWN")}`
Severity: `{finding_details.get("severity", "UNKNOWN")}`
Confidence: `{finding_details.get("confidence", "UNKNOWN")}`
File: `{finding_details.get("file_path", "UNKNOWN")}`
Lines: `{finding_details.get("line_start", "UNKNOWN")}` - `{finding_details.get("line_end", "UNKNOWN")}`

## Finding

{finding_details.get("description", "No description provided.")}

## Current Code Context

```python
{finding_details.get("code_snippet", "")}
```

## AI Suggested Remediation

{remediation_text}

## Review Notes

This PR intentionally stores the AI remediation as a proposal for human review.
Apply the patch manually or convert it into code changes after validation.
"""


def build_pr_body(finding_details: dict, remediation_text: str) -> str:
    return f"""## AI Security Remediation Proposal

This PR was opened by the AI DevSecOps Control Plane.

### Finding

- Finding ID: `{finding_details.get("id", "UNKNOWN")}`
- Rule: `{finding_details.get("rule_id", "UNKNOWN")}`
- Severity: `{finding_details.get("severity", "UNKNOWN")}`
- File: `{finding_details.get("file_path", "UNKNOWN")}`
- Lines: `{finding_details.get("line_start", "UNKNOWN")}` - `{finding_details.get("line_end", "UNKNOWN")}`

### Description

{finding_details.get("description", "No description provided.")}

### Suggested patch for human review

{remediation_text}
"""


def _create_security_pr(finding_details: dict, remediation_text: str) -> dict:
    token, repo = get_github_config()
    repo_info = github_request("GET", f"/repos/{repo}", token)
    base_branch = os.getenv("GITHUB_BASE_BRANCH", repo_info.get("default_branch", "main"))
    finding_id = str(finding_details.get("id", "unknown"))
    branch_name = f"security-fix-{finding_id}"

    base_ref = github_request(
        "GET",
        f"/repos/{repo}/git/ref/heads/{urllib.parse.quote(base_branch, safe='')}",
        token,
    )
    base_sha = base_ref["object"]["sha"]

    try:
        github_request(
            "POST",
            f"/repos/{repo}/git/refs",
            token,
            {
                "ref": f"refs/heads/{branch_name}",
                "sha": base_sha,
            },
        )
    except GitHubClientError as exc:
        if "Reference already exists" not in str(exc):
            raise

    markdown_path = f"docs/remediations/security-fix-{finding_id}.md"
    markdown = build_remediation_markdown(finding_details, remediation_text)
    encoded_content = base64.b64encode(markdown.encode("utf-8")).decode("utf-8")
    contents_path = urllib.parse.quote(markdown_path, safe="/")
    file_payload = {
        "message": f"docs: add security remediation proposal for {finding_id}",
        "content": encoded_content,
        "branch": branch_name,
    }

    try:
        existing = github_request(
            "GET",
            f"/repos/{repo}/contents/{contents_path}?ref={urllib.parse.quote(branch_name, safe='')}",
            token,
        )
        file_payload["sha"] = existing.get("sha")
    except GitHubClientError:
        pass

    github_request(
        "PUT",
        f"/repos/{repo}/contents/{contents_path}",
        token,
        file_payload,
    )

    pr_title = f"Security fix proposal: {finding_details.get('rule_id', 'finding')} in {finding_details.get('file_path', 'code')}"
    pr_body = build_pr_body(finding_details, remediation_text)

    try:
        pull_request = github_request(
            "POST",
            f"/repos/{repo}/pulls",
            token,
            {
                "title": pr_title,
                "head": branch_name,
                "base": base_branch,
                "body": pr_body,
                "maintainer_can_modify": True,
            },
        )
    except GitHubClientError as exc:
        if "A pull request already exists" not in str(exc):
            raise

        pulls = github_request(
            "GET",
            f"/repos/{repo}/pulls?head={urllib.parse.quote(repo.split('/')[0] + ':' + branch_name, safe='')}&state=open",
            token,
        )
        pull_request = pulls[0] if pulls else {}

    if not pull_request.get("html_url"):
        raise GitHubClientError("GitHub did not return a pull request URL.")

    return {
        "branch": branch_name,
        "url": pull_request["html_url"],
        "number": pull_request.get("number"),
    }


async def create_security_pr(finding_details: dict, remediation_text: str) -> dict:
    return await asyncio.to_thread(_create_security_pr, finding_details, remediation_text)
