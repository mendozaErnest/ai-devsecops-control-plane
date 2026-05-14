import asyncio
import json
import urllib.error
import urllib.request


OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5-coder:14b"


def build_prompt(finding_details: dict) -> str:
    return f"""
You are an AI DevSecOps remediation engine. Generate a safe Python code patch
for the following security finding. Return only the proposed patch or concise
replacement code with a short explanation as comments.

Rule ID: {finding_details.get("rule_id", "UNKNOWN")}
Severity: {finding_details.get("severity", "UNKNOWN")}
Confidence: {finding_details.get("confidence", "UNKNOWN")}
File: {finding_details.get("file_path", "UNKNOWN")}
Lines: {finding_details.get("line_start", "UNKNOWN")} - {finding_details.get("line_end", "UNKNOWN")}
Description: {finding_details.get("description", "")}

Code context:
```python
{finding_details.get("code_snippet", "")}
```

Security context:
- Prefer parameterized SQL queries over string concatenation.
- Prefer secrets over random for security tokens.
- Never use shell=True with user input.
- Never deserialize untrusted pickle or unsafe YAML.
- Use modern password hashing and avoid MD5/SHA1.
- Keep TLS certificate validation enabled.
- Validate and normalize paths to prevent traversal.
""".strip()


def fallback_patch(finding_details: dict) -> str:
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    description = finding_details.get("description", "Security finding")
    file_path = finding_details.get("file_path", "the affected file")

    return f"""Fallback Patch

Ollama is not available locally, so this simulated remediation explains the safe fix.

Finding: {rule_id}
File: {file_path}
Issue: {description}

Suggested Python remediation:
```python
# Replace the vulnerable implementation with a safer pattern.
# 1. Remove hardcoded secrets and load them from environment variables or a secret manager.
# 2. Validate all user-controlled input before use.
# 3. Use safe framework/library APIs instead of raw string execution or parsing.
# 4. Add a regression test that proves the vulnerable path is no longer reachable.
```

For this specific finding, inspect the highlighted code context and replace the risky call
with the secure equivalent recommended by the Bandit rule {rule_id}.
"""


def _request_patch(prompt: str) -> str:
    payload = json.dumps(
        {
            "model": OLLAMA_MODEL,
            "prompt": prompt,
            "stream": False,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=45) as response:
        body = response.read().decode("utf-8")

    data = json.loads(body)
    return data.get("response", "").strip() or fallback_patch({"description": "Empty Ollama response"})


async def generate_patch(finding_details: dict) -> str:
    prompt = build_prompt(finding_details)

    try:
        return await asyncio.to_thread(_request_patch, prompt)
    except urllib.error.HTTPError as exc:
        error_text = exc.read().decode("utf-8", errors="replace")
        print(f"Ollama request failed with status {exc.code}: {error_text}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: HTTP {exc.code}: {error_text})",
            }
        )
    except urllib.error.URLError as exc:
        print(f"Ollama request failed: {exc}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: {exc})",
            }
        )
    except (OSError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Ollama request failed: {exc}")
        return fallback_patch(
            {
                **finding_details,
                "description": f"{finding_details.get('description', '')} (Fallback reason: {exc})",
            }
        )
