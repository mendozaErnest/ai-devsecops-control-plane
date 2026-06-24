import ast
import base64
import binascii
import logging
import os
import re
import textwrap
import time
import urllib.parse
from pathlib import Path

import httpx
import jwt

from src.ai_engine.patch_validation import validate_python_security_semantics

GITHUB_API_URL = "https://api.github.com"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
GITHUB_TIMEOUT_SECONDS = 45
PATCH_CSS_EXTENSIONS = (".css", ".scss", ".sass", ".less")
PATCH_HTML_EXTENSIONS = (".html", ".htm", ".jinja", ".j2")
PATCH_JS_EXTENSIONS = (".js", ".ts", ".jsx", ".tsx", ".vue", ".mjs", ".cjs")
PATCH_JAVA_EXTENSIONS = (".java", ".kt", ".kts", ".groovy", ".scala")

_log = logging.getLogger(__name__)


class GitHubClientError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        code: str = "github_client_error",
        user_message: str | None = None,
        retryable: bool = False,
        details: dict | None = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = user_message or message
        self.retryable = retryable
        self.details = details or {}
        self.http_status = http_status

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.user_message,
            "technical_detail": str(self),
            "retryable": self.retryable,
            "details": self.details,
        }


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


def get_required_env(name: str) -> str:
    value = os.getenv(name)

    if not value:
        raise GitHubClientError(f"Missing {name} environment variable.")

    return value


def get_private_key_path() -> Path:
    raw_path = get_required_env("GITHUB_PRIVATE_KEY_PATH")
    key_path = Path(raw_path).expanduser()

    if not key_path.is_absolute():
        key_path = PROJECT_ROOT / key_path

    if not key_path.exists():
        raise GitHubClientError(f"GitHub App private key not found: {key_path}")

    return key_path


def get_github_config() -> tuple[str, str, str, Path, str]:
    load_env_file()
    app_id = get_required_env("GITHUB_APP_ID")
    installation_id = get_required_env("GITHUB_INSTALLATION_ID")
    private_key_path = get_private_key_path()
    repo = get_required_env("GITHUB_REPO")
    base_branch = os.getenv("GITHUB_BASE_BRANCH", "main")

    if "/" not in repo:
        raise GitHubClientError("GITHUB_REPO must use the format owner/repository.")

    return app_id, installation_id, repo, private_key_path, base_branch


def build_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AI-DevSecOps-Control-Plane",
    }


def generate_app_jwt(app_id: str, private_key_path: Path) -> str:
    now = int(time.time())
    private_key = private_key_path.read_text(encoding="utf-8")
    payload = {
        "iat": now - 60,
        "exp": now + 540,
        "iss": app_id,
    }

    return jwt.encode(payload, private_key, algorithm="RS256")


async def github_request(
    client: httpx.AsyncClient,
    method: str,
    path: str,
    payload: dict | None = None,
    params: dict | None = None,
) -> dict | list:
    try:
        response = await client.request(method, path, json=payload, params=params)
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code
        body = exc.response.text
        raise GitHubClientError(
            f"GitHub API {method} {path} failed with {status_code}: {body}",
            http_status=status_code,
        ) from exc
    except httpx.HTTPError as exc:
        raise GitHubClientError(f"GitHub API {method} {path} failed: {exc}") from exc

    if not response.content:
        return {}

    return response.json()


async def get_installation_token(app_id: str, installation_id: str, private_key_path: Path) -> str:
    app_jwt = generate_app_jwt(app_id, private_key_path)

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(app_jwt),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        response = await github_request(
            client,
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
        )

    token = extract_installation_token(response)

    if not token:
        raise GitHubClientError("GitHub App installation token response did not include a token.")

    return token


def extract_installation_token(response: object) -> str | None:
    if isinstance(response, dict):
        token = response.get("token") or response.get("access_token")
        return str(token) if token else None

    for attribute_name in ("token", "access_token"):
        token = getattr(response, attribute_name, None)

        if token:
            return str(token)

    return None


def is_valid_python(code: str) -> bool:
    try:
        ast.parse(code)
    except SyntaxError:
        return False

    return True


def syntax_error_details(exc: SyntaxError) -> dict:
    return {
        "message": exc.msg,
        "line": exc.lineno,
        "offset": exc.offset,
        "end_line": exc.end_lineno,
        "end_offset": exc.end_offset,
        "text": exc.text.strip() if exc.text else None,
        "filename": exc.filename,
    }


def syntax_error_summary(exc: SyntaxError) -> str:
    location = f"line {exc.lineno}" if exc.lineno else "unknown line"

    if exc.offset:
        location = f"{location}, column {exc.offset}"

    token = f" near `{exc.text.strip()}`" if exc.text and exc.text.strip() else ""
    return f"{exc.msg} at {location}{token}"


def clean_python_candidate(code: str) -> str:
    lines = code.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    cleaned_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            continue

        cleaned_lines.append(re.sub(r"^\s*\d+\s+", "", line))

    cleaned = "\n".join(cleaned_lines).strip()
    return textwrap.dedent(cleaned).strip()


def line_looks_like_python_boundary(line: str) -> bool:
    stripped = line.strip()

    if not stripped:
        return False

    return bool(
        re.match(
            r"^(@|async\s+def\s+|def\s+|class\s+|from\s+\S+\s+import\s+|import\s+|[A-Za-z_]\w*\s*=)",
            stripped,
        )
    )


def probable_python_line(line: str) -> bool:
    stripped = line.strip()

    if not stripped or stripped.startswith("#"):
        return True

    if line_looks_like_python_boundary(line):
        return True

    return bool(
        re.match(
            r"^(if|elif|else|for|while|try|except|finally|with|return|raise|yield|await|assert|pass|break|continue)\b",
            stripped,
        )
        or stripped in {"(", ")", "[", "]", "{", "}"}
        or stripped.endswith(("(", ",", ":", "\\", ")", "]", "}"))
    )


def strip_prose_wrappers(code: str) -> str:
    lines = clean_python_candidate(code).splitlines()

    while lines and not line_looks_like_python_boundary(lines[0]):
        lines.pop(0)

    while lines and not probable_python_line(lines[-1]):
        lines.pop()

    return "\n".join(lines).strip()


def remove_obvious_prose_lines(code: str) -> str:
    lines = strip_prose_wrappers(code).splitlines()
    filtered: list[str] = []

    for line in lines:
        if probable_python_line(line):
            filtered.append(line)

    return "\n".join(filtered).strip()


def extract_parseable_python_span(code: str) -> str | None:
    lines = clean_python_candidate(code).splitlines()
    best: str | None = None
    best_len = 0

    for start, line in enumerate(lines):
        if not line_looks_like_python_boundary(line):
            continue

        for end in range(len(lines), start, -1):
            candidate = textwrap.dedent("\n".join(lines[start:end])).strip()

            if not candidate:
                continue

            if is_valid_python(candidate):
                candidate_len = end - start

                if candidate_len > best_len:
                    best = candidate
                    best_len = candidate_len

                break

    return best


def extract_python_code_block(remediation_text: str) -> str | None:
    fenced_blocks = re.findall(
        r"```(?:python|py)?\s*(.*?)```",
        remediation_text,
        re.DOTALL | re.IGNORECASE,
    )
    candidates = fenced_blocks or [remediation_text]

    for candidate in candidates:
        for cleaner in (
            clean_python_candidate,
            strip_prose_wrappers,
            remove_obvious_prose_lines,
        ):
            cleaned = cleaner(candidate)

            if cleaned and is_valid_python(cleaned):
                return cleaned

        span = extract_parseable_python_span(candidate)

        if span:
            return span

    return None


def normalize_patch_technology(value: object) -> str:
    technology = str(value or "python").strip().lower()

    if technology in {"typescript", "javascript"}:
        return "angular"

    if technology in {"python", "angular", "java", "css", "html"}:
        return technology

    return "python"


def normalize_patch_technology_for_finding(finding_details: dict) -> str:
    technology = normalize_patch_technology(finding_details.get("technology"))
    rule_id = str(finding_details.get("rule_id") or "").strip().lower()
    file_path = str(finding_details.get("file_path") or "").strip().lower()

    if rule_id.startswith(("css:", "web:css")):
        return "css"
    if rule_id.startswith(("html.", "html:", "web:html")):
        return "html"
    if rule_id.startswith(("javascript:", "typescript:", "jsts.")):
        return "angular"
    if rule_id.startswith(("java:", "kotlin:", "squid:", "semgrep.java.", "java.lang.", "java.spring.")):
        return "java"

    if technology != "python":
        return technology

    if any(file_path.endswith(ext) for ext in PATCH_CSS_EXTENSIONS):
        return "css"
    if any(file_path.endswith(ext) for ext in PATCH_HTML_EXTENSIONS):
        return "html"
    if any(file_path.endswith(ext) for ext in PATCH_JS_EXTENSIONS):
        return "angular"
    if any(file_path.endswith(ext) for ext in PATCH_JAVA_EXTENSIONS):
        return "java"

    return technology


def code_fence_label_for_technology(technology: str, file_path: str = "") -> str:
    file_path = file_path.lower()

    if technology == "angular":
        if file_path.endswith((".html", ".htm")):
            return "html"
        if file_path.endswith((".js", ".jsx", ".mjs", ".cjs")):
            return "javascript"
        return "typescript"
    if technology in {"css", "html"}:
        return technology

    return technology


def clean_generic_candidate(code: str) -> str:
    lines = code.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    cleaned_lines = []

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("```"):
            continue

        cleaned_lines.append(re.sub(r"^\s*\d+\s+", "", line))

    return "\n".join(cleaned_lines).strip()


def extract_generic_code_block(remediation_text: str, technology: str, file_path: str = "") -> str | None:
    labels_by_technology = {
        "angular": ("typescript", "ts", "javascript", "js", "html", "angular"),
        "java": ("java",),
        "css": ("css", "scss", "sass", "less"),
        "html": ("html", "htm"),
    }
    labels = labels_by_technology.get(technology, (technology,))
    fenced_blocks = re.findall(
        r"```([A-Za-z0-9_-]*)\s*(.*?)```",
        remediation_text,
        re.DOTALL,
    )
    candidates = [
        block
        for label, block in fenced_blocks
        if not label or label.strip().lower() in labels
    ]

    if fenced_blocks and not candidates:
        return None

    candidates = candidates or [remediation_text]

    for candidate in candidates:
        cleaned = clean_generic_candidate(candidate)

        if cleaned:
            return cleaned

    return None


def looks_like_python_function_patch(code: str) -> bool:
    return bool(re.search(r"(?m)^\s*(?:async\s+def|def)\s+[A-Za-z_]\w*\s*\(", code))


def looks_like_python_only_prose(code: str) -> bool:
    lowered = code.strip().lower()
    return (
        "no python code is needed" in lowered
        or "no python code required" in lowered
        or lowered.startswith("# no python")
    )


def extract_code_block_for_technology(
    remediation_text: str,
    technology: str,
    file_path: str = "",
) -> str | None:
    technology = normalize_patch_technology(technology)

    if technology == "python":
        return extract_python_code_block(remediation_text)

    patch_content = extract_generic_code_block(remediation_text, technology, file_path)

    if not patch_content:
        return None

    if looks_like_python_function_patch(patch_content) or looks_like_python_only_prose(patch_content):
        return None

    return patch_content


def has_balanced_delimiters(code: str, *, track_strings: bool = True) -> bool:
    pairs = {"}": "{", ")": "(", "]": "["}
    opening = set(pairs.values())
    stack: list[str] = []
    in_string: str | None = None
    escape = False

    for character in code:
        if in_string:
            if escape:
                escape = False
            elif character == "\\":
                escape = True
            elif character == in_string:
                in_string = None

            continue

        if track_strings and character in {"'", '"', "`"}:
            in_string = character
            continue

        if character in opening:
            stack.append(character)
            continue

        if character in pairs:
            if not stack or stack.pop() != pairs[character]:
                return False

    return not stack and in_string is None


def include_leading_decorators(lines: list[str], signature_index: int) -> int:
    start_index = signature_index
    inside_multiline_decorator = False

    for index in range(signature_index - 1, -1, -1):
        stripped = lines[index].strip()

        if not stripped:
            break

        if stripped.startswith("@"):
            start_index = index
            inside_multiline_decorator = False
            continue

        if (
            inside_multiline_decorator
            or stripped in {")", "})", "});", "]", "])", "]);"}
            or stripped.endswith((")", "})", "});", "]", "])", "]);", ","))
        ):
            start_index = index
            inside_multiline_decorator = True
            continue

        break

    return start_index


def count_code_braces(line: str) -> int:
    balance = 0
    in_string: str | None = None
    escape = False

    for character in line:
        if in_string:
            if escape:
                escape = False
            elif character == "\\":
                escape = True
            elif character == in_string:
                in_string = None

            continue

        if character in {"'", '"', "`"}:
            in_string = character
            continue

        if character == "{":
            balance += 1
        elif character == "}":
            balance -= 1

    return balance


def find_braced_block_range(lines: list[str], signature_index: int) -> tuple[int, int] | None:
    brace_balance = 0
    found_opening_brace = False

    for index in range(signature_index, len(lines)):
        brace_delta = count_code_braces(lines[index])

        if "{" in lines[index]:
            found_opening_brace = True

        if found_opening_brace:
            brace_balance += brace_delta

            if brace_balance == 0:
                return include_leading_decorators(lines, signature_index) + 1, index + 1

    return None


def ts_line_looks_like_method_signature(line: str) -> bool:
    stripped = line.strip()

    if not stripped or stripped.startswith(("//", "*", "/*", "@")):
        return False

    if re.match(r"^(if|for|while|switch|catch|function)\b", stripped):
        return False

    modifier_pattern = r"(?:async|public|private|protected|readonly|static|override)\s+"
    identifier_pattern = r"[A-Za-z_$][\w$]*"
    method_pattern = (
        rf"^(?:{modifier_pattern})*(?:{identifier_pattern}\s+)?"
        rf"{identifier_pattern}\s*\([^)]*\)\s*(?::\s*[^{{=>]+)?\s*(?:{{|$)"
    )

    return bool(
        re.search(r"\b(?:async|public|private|protected|readonly|ngOnInit|ngOnDestroy|constructor)\b", stripped)
        or re.match(method_pattern, stripped)
    )


def find_ts_method_range(original_content: str, line_start: object) -> tuple[int, int] | None:
    line_start = coerce_line_number(line_start)

    if line_start is None:
        return None

    try:
        lines = original_content.splitlines()
        search_index = min(max(line_start - 1, 0), len(lines) - 1)

        for index in range(search_index, -1, -1):
            if not ts_line_looks_like_method_signature(lines[index]):
                continue

            block_range = find_braced_block_range(lines, index)

            if block_range and block_range[0] <= line_start <= block_range[1]:
                return block_range

        return None
    except Exception:
        return None


def extract_ts_class_name(patch_content: str) -> str | None:
    match = re.search(r"\bclass\s+([A-Za-z_$][\w$]*)\b", patch_content)
    return match.group(1) if match else None


def find_ts_class_range(original_content: str, class_name: str | None) -> tuple[int, int] | None:
    if not class_name:
        return None

    try:
        lines = original_content.splitlines()
        class_pattern = re.compile(rf"\bclass\s+{re.escape(class_name)}\b")

        for index, line in enumerate(lines):
            if not class_pattern.search(line):
                continue

            return find_braced_block_range(lines, index)

        return None
    except Exception:
        return None


JAVA_CONTROL_KEYWORDS = {"if", "for", "while", "switch", "catch", "return", "new"}


def java_line_looks_like_method_signature(line: str) -> bool:
    stripped = line.strip()

    if not stripped or stripped.startswith(("//", "*", "/*", "@")):
        return False

    if "(" not in stripped or ")" not in stripped:
        return False

    if re.match(r"^(if|for|while|switch|catch)\b", stripped):
        return False

    signature_pattern = re.compile(
        r"^(?:public|private|protected|static|final|synchronized|abstract|default|native|strictfp|\s)*"
        r"(?:<[^>]+>\s*)?"
        r"([A-Za-z_$][\w$<>\[\], ?]*\s+)?"
        r"([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*(?:\{|$)"
    )
    match = signature_pattern.match(stripped)

    if not match:
        return False

    method_name = match.group(2)
    return method_name not in JAVA_CONTROL_KEYWORDS


def find_java_method_range(original_content: str, line_start: object) -> tuple[int, int] | None:
    line_start = coerce_line_number(line_start)

    if line_start is None:
        return None

    try:
        lines = original_content.splitlines()
        search_index = min(max(line_start - 1, 0), len(lines) - 1)

        for index in range(search_index, -1, -1):
            if not java_line_looks_like_method_signature(lines[index]):
                continue

            block_range = find_braced_block_range(lines, index)

            if block_range and block_range[0] <= line_start <= block_range[1]:
                return block_range

        return None
    except Exception:
        return None


def extract_java_class_name(patch_content: str) -> str | None:
    match = re.search(r"\b(?:class|interface)\s+([A-Za-z_$][\w$]*)\b", patch_content)
    return match.group(1) if match else None


def find_java_class_range(original_content: str, class_name: str | None) -> tuple[int, int] | None:
    if not class_name:
        return None

    try:
        lines = original_content.splitlines()
        class_pattern = re.compile(rf"\b(?:class|interface)\s+{re.escape(class_name)}\b")

        for index, line in enumerate(lines):
            if not class_pattern.search(line):
                continue

            return find_braced_block_range(lines, index)

        return None
    except Exception:
        return None


def find_semantic_patch_range(
    original_content: str,
    patch_content: str,
    line_start: int | None,
    technology: str,
) -> tuple[int, int] | None:
    if technology == "angular":
        return (
            find_ts_method_range(original_content, line_start)
            or find_ts_class_range(original_content, extract_ts_class_name(patch_content))
        )

    if technology == "java":
        return (
            find_java_method_range(original_content, line_start)
            or find_java_class_range(original_content, extract_java_class_name(patch_content))
        )

    return None


def build_lightweight_patched_content(
    original_content: str,
    patch_content: str,
    finding_details: dict,
    technology: str,
) -> str:
    if not patch_content.strip():
        raise GitHubClientError(
            f"AI {technology} code block is empty. Refusing to patch source file.",
            code="ai_code_block_empty",
            retryable=True,
        )

    if should_replace_full_file(original_content, patch_content):
        candidate = patch_content
    else:
        line_start = coerce_line_number(finding_details.get("line_start"))
        line_end = coerce_line_number(finding_details.get("line_end")) or line_start

        if line_start is None or line_end is None:
            raise GitHubClientError(
                f"Could not safely locate the affected {technology} lines in the original file.",
                code="patch_target_not_found",
                user_message=(
                    "No pude ubicar de forma segura las lineas afectadas en GitHub. "
                    "Regenera la remediación o revisa si el archivo remoto cambió."
                ),
                retryable=True,
                details={
                    "file_path": finding_details.get("file_path"),
                    "technology": technology,
                    "line_start": finding_details.get("line_start"),
                    "line_end": finding_details.get("line_end"),
                },
            )

        patch_range = find_semantic_patch_range(
            original_content,
            patch_content,
            line_start,
            technology,
        ) or (line_start, line_end)
        candidate = replace_line_range(original_content, patch_content, patch_range[0], patch_range[1])

    if not candidate.strip():
        raise GitHubClientError("Patched source file is empty. Refusing to commit.")

    is_html_patch = str(finding_details.get("file_path", "")).lower().endswith(".html")

    if not has_balanced_delimiters(candidate, track_strings=not is_html_patch):
        raise GitHubClientError(
            f"Patched {technology} source has unbalanced delimiters. Refusing to commit.",
            code="patched_source_unbalanced",
            user_message=(
                f"La remediación generada no supera la validación ligera de {technology}: "
                "delimitadores desbalanceados."
            ),
            retryable=True,
            details={"file_path": finding_details.get("file_path"), "technology": technology},
        )

    if line_count(original_content) > 30 and line_count(candidate) < line_count(original_content) * 0.6:
        raise GitHubClientError(
            "Patched source file is unexpectedly short after semantic patching. "
            "Refusing to commit because the result is below 60% of the original file size.",
            code="patched_source_too_short",
            user_message=(
                "La remediación generada redujo demasiado el archivo. "
                "No se empujaron cambios porque el resultado queda por debajo del 60% del tamaño original."
            ),
            retryable=True,
            details={
                "file_path": finding_details.get("file_path"),
                "technology": technology,
                "original_lines": line_count(original_content),
                "patched_lines": line_count(candidate),
            },
        )

    return candidate


def get_source_segment(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)

    if segment is not None:
        return textwrap.dedent(segment).strip()

    start_line = getattr(node, "lineno", None)
    end_line = getattr(node, "end_lineno", None)

    if start_line is None or end_line is None:
        return ""

    return textwrap.dedent("\n".join(source.splitlines()[start_line - 1:end_line])).strip()


def split_patch_imports_and_function(patch_content: str) -> tuple[list[str], str | None, str | None]:
    try:
        tree = ast.parse(patch_content)
    except SyntaxError as exc:
        raise GitHubClientError(
            "AI Python code block is not valid Python.",
            code="ai_python_block_invalid",
            user_message=f"El bloque Python de la IA no compila: {syntax_error_summary(exc)}.",
            retryable=True,
            details={"syntax_error": syntax_error_details(exc)},
        ) from exc

    imports: list[str] = []
    function_source: str | None = None
    function_name: str | None = None

    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_source = get_source_segment(patch_content, node)

            if import_source:
                imports.append(import_source)

            continue

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and function_source is None:
            function_source = get_source_segment(patch_content, node)
            function_name = node.name

    return imports, function_source, function_name


def find_import_insertion_line(original_content: str) -> int:
    try:
        tree = ast.parse(original_content)
    except SyntaxError:
        return 0

    insertion_line = 0
    body = list(tree.body)

    if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant):
        if isinstance(body[0].value.value, str):
            insertion_line = getattr(body[0], "end_lineno", 0) or 0
            body = body[1:]

    for node in body:
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            break

        insertion_line = getattr(node, "end_lineno", insertion_line) or insertion_line

    return insertion_line


def insert_missing_imports(original_content: str, imports: list[str]) -> str:
    unique_imports = []
    existing_lines = {line.strip() for line in original_content.splitlines()}

    for import_source in imports:
        import_lines = [line.rstrip() for line in import_source.splitlines() if line.strip()]

        if not import_lines:
            continue

        import_text = "\n".join(import_lines)

        if all(line.strip() in existing_lines for line in import_lines):
            continue

        if import_text not in unique_imports:
            unique_imports.append(import_text)

    if not unique_imports:
        return original_content

    original_lines = original_content.splitlines(keepends=True)
    insertion_line = find_import_insertion_line(original_content)
    import_block = "\n".join(unique_imports) + "\n"

    if insertion_line > 0 and insertion_line < len(original_lines):
        next_line = original_lines[insertion_line]

        if next_line.strip():
            import_block += "\n"

    elif insertion_line == 0 and original_lines and original_lines[0].strip():
        import_block += "\n"

    return "".join(original_lines[:insertion_line] + [import_block] + original_lines[insertion_line:])


def is_python_duplicate_literal_rule(finding_details: dict) -> bool:
    rule_id = str(finding_details.get("rule_id") or "").lower()
    return normalize_patch_technology_for_finding(finding_details) == "python" and rule_id.endswith("s1192")


def is_python_weak_hash_rule(finding_details: dict) -> bool:
    rule_id = str(finding_details.get("rule_id") or "").upper()
    return normalize_patch_technology_for_finding(finding_details) == "python" and rule_id == "B324"


def is_deterministic_python_rule(finding_details: dict) -> bool:
    return is_python_duplicate_literal_rule(finding_details) or is_python_weak_hash_rule(finding_details)


def extract_python_duplicate_literal(finding_details: dict) -> str | None:
    description = str(finding_details.get("description") or "")
    match = re.search(r"literal\s+([\"'])(.+?)\1", description)

    if not match:
        return None

    quoted = f"{match.group(1)}{match.group(2)}{match.group(1)}"

    try:
        value = ast.literal_eval(quoted)
    except (SyntaxError, ValueError):
        value = match.group(2)

    return value if isinstance(value, str) and value else None


def python_constant_name_for_literal(literal: str) -> str:
    words = re.findall(r"[A-Za-z0-9]+", literal)
    if not words:
        return "DUPLICATED_LITERAL"

    constant_name = "_".join(words[:8]).upper()
    if constant_name[0].isdigit():
        constant_name = f"LITERAL_{constant_name}"

    return constant_name


def python_string_literal(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def python_module_names(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)

    return names


def choose_python_constant_name(source: str, literal: str) -> str:
    base_name = python_constant_name_for_literal(literal)
    names = python_module_names(source)

    if base_name not in names:
        return base_name

    for suffix in ("MESSAGE", "TEXT", "VALUE"):
        candidate = f"{base_name}_{suffix}"
        if candidate not in names:
            return candidate

    index = 2
    while f"{base_name}_{index}" in names:
        index += 1

    return f"{base_name}_{index}"


def find_existing_python_constant_for_literal(source: str, literal: str) -> str | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    for node in tree.body:
        targets: list[ast.expr] = []
        value: ast.expr | None = None

        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value

        if not isinstance(value, ast.Constant) or value.value != literal:
            continue

        for target in targets:
            if isinstance(target, ast.Name) and target.id.isupper():
                return target.id

    return None


def byte_col_to_char_col(line: str, byte_col: int) -> int:
    return len(line.encode("utf-8")[:byte_col].decode("utf-8", errors="ignore"))


def count_python_string_literal(source: str, literal: str) -> int:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0

    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and node.value == literal
    )


def parent_map_for_tree(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def is_docstring_literal(node: ast.Constant, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    grandparent = parents.get(parent) if parent is not None else None

    if not isinstance(parent, ast.Expr):
        return False

    if not isinstance(grandparent, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
        return False

    return bool(grandparent.body and grandparent.body[0] is parent)


def is_constant_definition_value(
    node: ast.Constant,
    parents: dict[ast.AST, ast.AST],
    constant_name: str,
) -> bool:
    parent = parents.get(node)
    if isinstance(parent, ast.Assign) and parent.value is node:
        return any(isinstance(target, ast.Name) and target.id == constant_name for target in parent.targets)

    return (
        isinstance(parent, ast.AnnAssign)
        and parent.value is node
        and isinstance(parent.target, ast.Name)
        and parent.target.id == constant_name
    )


def replace_python_string_literals(source: str, literal: str, constant_name: str) -> tuple[str, int]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise GitHubClientError("Original GitHub source file is not valid Python.") from exc

    parents = parent_map_for_tree(tree)
    replacements: list[tuple[int, int, int, int]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or node.value != literal:
            continue

        if is_docstring_literal(node, parents):
            continue

        if is_constant_definition_value(node, parents, constant_name):
            continue

        start_line = getattr(node, "lineno", None)
        start_col = getattr(node, "col_offset", None)
        end_line = getattr(node, "end_lineno", None)
        end_col = getattr(node, "end_col_offset", None)

        if None in (start_line, start_col, end_line, end_col) or start_line != end_line:
            raise GitHubClientError(
                "Duplicate string literal spans multiple lines; refusing deterministic S1192 patch.",
                code="deterministic_patch_unsupported_literal",
                user_message=(
                    "El literal duplicado ocupa varias líneas. "
                    "Se requiere revisión manual para evitar un reemplazo incorrecto."
                ),
                retryable=False,
            )

        replacements.append((start_line, start_col, end_line, end_col))

    if len(replacements) < 2:
        raise GitHubClientError(
            "S1192 deterministic patch requires at least two replaceable string literal occurrences.",
            code="deterministic_patch_not_applicable",
            user_message=(
                "No encontré suficientes ocurrencias reemplazables del literal duplicado. "
                "Se requiere revisión manual."
            ),
            retryable=False,
            details={"literal": literal, "constant_name": constant_name},
        )

    lines = source.splitlines(keepends=True)
    for start_line, start_col, _end_line, end_col in sorted(replacements, reverse=True):
        line = lines[start_line - 1]
        char_start = byte_col_to_char_col(line, start_col)
        char_end = byte_col_to_char_col(line, end_col)
        lines[start_line - 1] = f"{line[:char_start]}{constant_name}{line[char_end:]}"

    return "".join(lines), len(replacements)


def insert_python_module_constant(source: str, constant_name: str, literal: str) -> str:
    original_lines = source.splitlines(keepends=True)
    insert_at = find_import_insertion_line(source)

    while insert_at < len(original_lines) and not original_lines[insert_at].strip():
        insert_at += 1

    constant_block = f"{constant_name} = {python_string_literal(literal)}\n\n"
    return "".join(original_lines[:insert_at] + [constant_block] + original_lines[insert_at:])


def build_python_s1192_constant_patch(original_content: str, finding_details: dict) -> tuple[str, dict]:
    if not is_python_duplicate_literal_rule(finding_details):
        raise GitHubClientError(
            "Deterministic S1192 patch requested for a non-S1192 finding.",
            code="deterministic_patch_not_applicable",
            retryable=False,
        )

    literal = extract_python_duplicate_literal(finding_details)
    if not literal:
        raise GitHubClientError(
            "Could not extract duplicate literal from S1192 finding description.",
            code="deterministic_patch_literal_not_found",
            user_message=(
                "No pude extraer el literal duplicado desde la descripción del finding S1192. "
                "Se requiere revisión manual."
            ),
            retryable=False,
        )

    original_literal_count = count_python_string_literal(original_content, literal)
    existing_constant_name = find_existing_python_constant_for_literal(original_content, literal)
    constant_name = existing_constant_name or choose_python_constant_name(original_content, literal)

    candidate, replacement_count = replace_python_string_literals(
        original_content,
        literal,
        constant_name,
    )

    if existing_constant_name is None:
        candidate = insert_python_module_constant(candidate, constant_name, literal)

    try:
        ast.parse(candidate)
    except SyntaxError as exc:
        raise GitHubClientError(
            "Deterministic S1192 patch produced invalid Python. Refusing to commit.",
            code="deterministic_patch_invalid_python",
            user_message=(
                "El parche determinístico para S1192 produjo Python inválido. "
                f"{syntax_error_summary(exc)}."
            ),
            retryable=False,
            details={"syntax_error": syntax_error_details(exc)},
        ) from exc

    final_literal_count = count_python_string_literal(candidate, literal)
    if final_literal_count >= original_literal_count:
        raise GitHubClientError(
            "Deterministic S1192 patch did not reduce duplicate literal occurrences.",
            code="deterministic_patch_no_effect",
            user_message=(
                "El parche determinístico no redujo las ocurrencias del literal duplicado. "
                "Se requiere revisión manual."
            ),
            retryable=False,
            details={
                "literal": literal,
                "original_literal_count": original_literal_count,
                "final_literal_count": final_literal_count,
            },
        )

    return candidate, {
        "literal": literal,
        "constant_name": constant_name,
        "replacement_count": replacement_count,
        "original_literal_count": original_literal_count,
        "final_literal_count": final_literal_count,
        "inserted_constant": existing_constant_name is None,
    }


def build_python_s1192_remediation_text(details: dict) -> str:
    literal = str(details["literal"])
    constant_name = str(details["constant_name"])
    replacement_count = int(details["replacement_count"])

    return f"""Deterministic remediation for python:S1192.

The duplicate literal is promoted to a module-level constant and all exact string-literal occurrences are replaced.

```python
{constant_name} = {python_string_literal(literal)}
# Replaced {replacement_count} duplicated occurrences with {constant_name}.
```
"""


def remediation_text_matches_python_s1192(remediation_text: str, finding_details: dict) -> bool:
    if not is_python_duplicate_literal_rule(finding_details):
        return False

    literal = extract_python_duplicate_literal(finding_details)
    if not literal:
        return False

    patch_content = extract_code_block_for_technology(
        remediation_text,
        "python",
        str(finding_details.get("file_path") or ""),
    )

    if not patch_content:
        return False

    constant_name = python_constant_name_for_literal(literal)
    has_function = bool(re.search(r"^\s*(?:async\s+def|def)\s+\w+\s*\(", patch_content, re.MULTILINE))
    return constant_name in patch_content and python_string_literal(literal) in patch_content and not has_function


def find_enclosing_python_function_node(
    original_content: str,
    line_start: object,
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    line_number = coerce_line_number(line_start)
    if line_number is None:
        return None

    try:
        tree = ast.parse(original_content)
    except SyntaxError as exc:
        raise GitHubClientError("Original GitHub source file is not valid Python.") from exc

    candidates: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        node_start = getattr(node, "lineno", None)
        node_end = getattr(node, "end_lineno", None)
        if node_start is None or node_end is None:
            continue

        if node_start <= line_number <= node_end:
            candidates.append(node)

    if not candidates:
        return None

    return min(candidates, key=lambda node: getattr(node, "end_lineno") - getattr(node, "lineno"))


def first_runtime_arg_name(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    args = list(node.args.posonlyargs) + list(node.args.args)

    for arg in args:
        if arg.arg not in {"self", "cls"}:
            return arg.arg

    return None


def detect_weak_hash_algorithm(function_source: str, finding_details: dict) -> str | None:
    haystack = f"{function_source}\n{finding_details.get('description', '')}".lower()

    if "hashlib.sha1" in haystack or "sha1" in haystack:
        return "sha1"

    if "hashlib.md5" in haystack or "md5" in haystack:
        return "md5"

    return None


def build_python_b324_weak_hash_patch(original_content: str, finding_details: dict) -> tuple[str, dict]:
    if not is_python_weak_hash_rule(finding_details):
        raise GitHubClientError(
            "Deterministic B324 patch requested for a non-B324 finding.",
            code="deterministic_patch_not_applicable",
            retryable=False,
        )

    function_node = find_enclosing_python_function_node(original_content, finding_details.get("line_start"))
    if function_node is None:
        raise GitHubClientError(
            "Could not locate the Python function containing the B324 finding.",
            code="deterministic_patch_target_not_found",
            user_message=(
                "No pude ubicar la función que contiene el hash débil. "
                "Se requiere revisión manual."
            ),
            retryable=False,
        )

    function_source = get_source_segment(original_content, function_node)
    weak_algorithm = detect_weak_hash_algorithm(function_source, finding_details)
    value_arg = first_runtime_arg_name(function_node)

    if weak_algorithm is None or value_arg is None:
        raise GitHubClientError(
            "Could not infer enough context to replace the weak hash deterministically.",
            code="deterministic_patch_not_applicable",
            user_message=(
                "No pude inferir el algoritmo débil o el argumento a proteger. "
                "Se requiere revisión manual."
            ),
            retryable=False,
        )

    original_lines = original_content.splitlines()
    def_line = original_lines[function_node.lineno - 1].rstrip()
    base_indent = " " * indentation_width(def_line)
    body_indent = base_indent + " " * 4
    function_patch = "\n".join(
        [
            def_line.strip() if not base_indent else def_line,
            f"{body_indent}# Use PBKDF2-HMAC with a per-value salt instead of insecure {weak_algorithm.upper()}.",
            f"{body_indent}salt = secrets.token_bytes(16)",
            (
                f"{body_indent}digest = hashlib.pbkdf2_hmac("
                f'"sha256", {value_arg}.encode("utf-8"), salt, 600_000)'
            ),
            f'{body_indent}return f"{{salt.hex()}}:{{digest.hex()}}"',
        ]
    )

    candidate = replace_line_range(
        original_content,
        function_patch,
        function_node.lineno,
        function_node.end_lineno,
    )
    candidate = insert_missing_imports(candidate, ["import hashlib", "import secrets"])

    try:
        ast.parse(candidate)
    except SyntaxError as exc:
        raise GitHubClientError(
            "Deterministic B324 patch produced invalid Python. Refusing to commit.",
            code="deterministic_patch_invalid_python",
            user_message=(
                "El parche determinístico para B324 produjo Python inválido. "
                f"{syntax_error_summary(exc)}."
            ),
            retryable=False,
            details={"syntax_error": syntax_error_details(exc)},
        ) from exc

    patched_function = function_patch
    if f"hashlib.{weak_algorithm}" in patched_function or "pbkdf2_hmac" not in patched_function:
        raise GitHubClientError(
            "Deterministic B324 patch did not remove the weak hash from the target function.",
            code="deterministic_patch_no_effect",
            user_message=(
                "El parche determinístico no eliminó el hash débil de la función afectada. "
                "Se requiere revisión manual."
            ),
            retryable=False,
        )

    return candidate, {
        "function_name": function_node.name,
        "value_arg": value_arg,
        "weak_algorithm": weak_algorithm,
        "function_patch": function_patch,
    }


def build_python_b324_remediation_text(details: dict) -> str:
    weak_algorithm = str(details["weak_algorithm"]).upper()
    function_patch = str(details["function_patch"])

    return f"""Deterministic remediation for Bandit B324.

The affected function keeps its original name and signature, replacing insecure {weak_algorithm} with PBKDF2-HMAC and a per-value salt.

```python
import secrets

{function_patch}
```
"""


def remediation_text_matches_python_b324(remediation_text: str, finding_details: dict) -> bool:
    if not is_python_weak_hash_rule(finding_details):
        return False

    patch_content = extract_code_block_for_technology(
        remediation_text,
        "python",
        str(finding_details.get("file_path") or ""),
    )
    if not patch_content:
        return False

    patch_function = get_function_name_from_patch(patch_content)
    expected_function = str(finding_details.get("expected_function") or "")
    if expected_function and patch_function != expected_function:
        return False

    has_weak_hash = bool(re.search(r"hashlib\.(?:md5|sha1)\s*\(", patch_content))
    return patch_function is not None and not has_weak_hash and "pbkdf2_hmac" in patch_content


def decode_github_file_content(encoded_content: str) -> str:
    compact_content = encoded_content.replace("\n", "")

    try:
        return base64.b64decode(compact_content).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise GitHubClientError("GitHub source file content could not be decoded safely.") from exc


def encode_content(content: str) -> str:
    return base64.b64encode(content.encode("utf-8")).decode("utf-8")


def normalize_file_path_for_github(file_path: str) -> str:
    # Pattern 1: cloned repos — everything after /repo/
    if "/repo/" in file_path:
        return file_path.split("/repo/", 1)[1]

    # Pattern 2: ZIP uploads — everything after /source/
    if "/source/" in file_path:
        return file_path.split("/source/", 1)[1]

    # Pattern 3: workspace/uploads/ without a recognised type segment
    if "workspace/uploads/" in file_path:
        after_uploads = file_path.split("workspace/uploads/", 1)[1]
        segments = after_uploads.split("/", 2)
        if len(segments) >= 3:
            return segments[2]

    # Already relative — return unchanged without a warning
    if not file_path.startswith("/"):
        return file_path

    # Absolute path we couldn't normalise — warn and return unchanged
    _log.warning("normalize_file_path_for_github: could not extract relative path from %r", file_path)
    return file_path


def line_count(content: str) -> int:
    return len(content.splitlines())


def should_replace_full_file(original_content: str, patch_content: str) -> bool:
    original_lines = line_count(original_content)
    patch_lines = line_count(patch_content)

    if original_lines > 100 and patch_lines < 30:
        return False

    return patch_lines >= max(1, int(original_lines * 0.8))


def get_function_name_from_patch(patch_content: str) -> str | None:
    try:
        tree = ast.parse(patch_content)
    except SyntaxError:
        return None

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name

    return None


def get_python_function_names(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()

    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def coerce_line_number(value: object) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def find_enclosing_python_function(original_content: str, line_start: object) -> tuple[str, int, int] | None:
    line_start = coerce_line_number(line_start)

    if line_start is None:
        return None

    try:
        tree = ast.parse(original_content)
    except SyntaxError as exc:
        raise GitHubClientError("Original GitHub source file is not valid Python.") from exc

    candidates: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        node_start = getattr(node, "lineno", None)
        node_end = getattr(node, "end_lineno", None)

        if node_start is None or node_end is None:
            continue

        if node_start <= line_start <= node_end:
            candidates.append(node)

    if not candidates:
        return None

    smallest = min(
        candidates,
        key=lambda node: getattr(node, "end_lineno") - getattr(node, "lineno"),
    )
    return smallest.name, getattr(smallest, "lineno"), getattr(smallest, "end_lineno")


def find_enclosing_function_range(original_content: str, line_start: object) -> tuple[int, int] | None:
    function_info = find_enclosing_python_function(original_content, line_start)

    if not function_info:
        return None

    return function_info[1], function_info[2]


def find_function_range_by_name(original_content: str, function_name: str) -> tuple[int, int] | None:
    try:
        tree = ast.parse(original_content)
    except SyntaxError as exc:
        raise GitHubClientError("Original GitHub source file is not valid Python.") from exc

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        if node.name == function_name and getattr(node, "end_lineno", None):
            return node.lineno, node.end_lineno

    return None


def indentation_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def find_block_end_by_indentation(lines: list[str], start_index: int) -> int:
    def_line = lines[start_index]
    def_indent = indentation_width(def_line)
    last_non_empty = start_index

    for index in range(start_index + 1, len(lines)):
        line = lines[index]

        if not line.strip():
            continue

        current_indent = indentation_width(line)

        if current_indent <= def_indent and not line.lstrip().startswith(("#", "@")):
            break

        last_non_empty = index

    return last_non_empty + 1


def find_function_range_by_signature(original_content: str, function_name: str) -> tuple[int, int] | None:
    escaped_name = re.escape(function_name)
    signature_pattern = re.compile(rf"^\s*(?:async\s+def|def)\s+{escaped_name}\s*\(", re.MULTILINE)
    lines = original_content.splitlines()
    match = signature_pattern.search(original_content)

    if not match:
        return None

    start_line = original_content[: match.start()].count("\n") + 1
    end_line = find_block_end_by_indentation(lines, start_line - 1)
    return start_line, end_line


def find_function_range(original_content: str, line_start: int | None, patch_content: str) -> tuple[int, int] | None:
    function_range = find_enclosing_function_range(original_content, line_start)

    if function_range is not None:
        return function_range

    function_name = get_function_name_from_patch(patch_content)

    if not function_name:
        return None

    return (
        find_function_range_by_name(original_content, function_name)
        or find_function_range_by_signature(original_content, function_name)
    )


def replace_line_range(original_content: str, patch_content: str, start_line: int, end_line: int) -> str:
    original_lines = original_content.splitlines(keepends=True)
    patch_lines = patch_content.splitlines()
    replacement = [f"{line}\n" for line in patch_lines]

    if original_content and not original_content.endswith("\n"):
        replacement[-1] = replacement[-1].rstrip("\n")

    return "".join(
        original_lines[: start_line - 1]
        + replacement
        + original_lines[end_line:]
    )


def build_safe_python_patched_content(
    original_content: str,
    patch_content: str,
    finding_details: dict,
) -> str:
    if not patch_content.strip():
        raise GitHubClientError("AI Python code block is empty. Refusing to patch source file.")

    patch_imports, function_patch, function_name = split_patch_imports_and_function(patch_content)

    if function_patch is None:
        raise GitHubClientError(
            "AI Python code block did not include a complete function to replace.",
            code="ai_patch_missing_function",
            user_message=(
                "La remediación de IA no incluyó una función completa reemplazable. "
                "Debe devolver `def ...:` o `async def ...:` con todo el cuerpo corregido."
            ),
            retryable=True,
            details={
                "file_path": finding_details.get("file_path"),
                "detected_imports": patch_imports,
                "expected_format": "```python\\nimport optional_dependency\\n\\ndef affected_function(...):\\n    ...\\n```",
            },
        )

    line_start = finding_details.get("line_start")
    enclosing_function = find_enclosing_python_function(original_content, line_start)
    full_file_replacement = should_replace_full_file(original_content, patch_content)

    if enclosing_function:
        expected_function = enclosing_function[0]
        patch_function_names = get_python_function_names(patch_content)
        patch_matches_target = (
            expected_function in patch_function_names
            if full_file_replacement
            else function_name == expected_function
        )

        if not patch_matches_target:
            raise GitHubClientError(
                "AI Python patch targets a different function than the finding line. "
                "Refusing to replace the enclosing function with unrelated code.",
                code="ai_patch_function_mismatch",
                user_message=(
                    "La remediación de IA intenta reemplazar "
                    f"`{expected_function}` con `{function_name or 'código sin función equivalente'}`. "
                    "No se empujaron cambios porque el parche no corresponde al finding."
                ),
                retryable=True,
                details={
                    "file_path": finding_details.get("file_path"),
                    "line_start": line_start,
                    "expected_function": expected_function,
                    "patch_function": function_name,
                    "patch_functions": sorted(patch_function_names),
                },
            )

    if full_file_replacement:
        candidate = patch_content
    else:
        function_range = (
            (enclosing_function[1], enclosing_function[2])
            if enclosing_function
            else find_function_range(original_content, line_start, function_patch)
        )

        if function_range is None:
            raise GitHubClientError(
                "Could not safely locate the affected Python function in the original file. "
                "Refusing to replace the full file with a short patch.",
                code="patch_target_not_found",
                user_message=(
                    "No pude ubicar de forma segura la función afectada en GitHub. "
                    "Regenera la remediación o revisa si el archivo remoto cambió de línea."
                ),
                retryable=True,
                details={
                    "file_path": finding_details.get("file_path"),
                    "line_start": line_start,
                    "function_name": function_name or get_function_name_from_patch(function_patch),
                },
            )

        candidate = replace_line_range(
            original_content,
            function_patch,
            function_range[0],
            function_range[1],
        )
        candidate = insert_missing_imports(candidate, patch_imports)

    try:
        ast.parse(candidate)
    except SyntaxError as exc:
        raise GitHubClientError(
            "Patched source file is not valid Python. Refusing to commit.",
            code="patched_python_invalid",
            user_message=(
                "La remediación generada no produce Python válido después de aplicar el parche: "
                f"{syntax_error_summary(exc)}."
            ),
            retryable=True,
            details={
                "syntax_error": syntax_error_details(exc),
                "file_path": finding_details.get("file_path"),
                "function_name": function_name,
                "patch_imports": patch_imports,
            },
        ) from exc

    if not candidate.strip():
        raise GitHubClientError("Patched source file is empty. Refusing to commit.")

    if line_count(original_content) > 100 and line_count(candidate) < line_count(original_content) * 0.5:
        raise GitHubClientError("Patched source file is unexpectedly short. Refusing to commit.")

    return candidate


def build_safe_patched_content(
    original_content: str,
    patch_content: str,
    finding_details: dict,
) -> str:
    technology = normalize_patch_technology_for_finding(finding_details)

    if technology == "python":
        return build_safe_python_patched_content(
            original_content,
            patch_content,
            finding_details,
        )

    return build_lightweight_patched_content(
        original_content,
        patch_content,
        finding_details,
        technology,
    )


def _apply_approximate_anchor(
    original_content: str,
    patch_content: str,
    finding_details: dict,
) -> tuple[str, str]:
    """Fallback when semantic function detection fails (patch_target_not_found).

    Tries three strategies in order, always returns (patched_content, warning_message).
    Never raises — the caller must create the PR with the warning note.
    Does NOT touch build_safe_patched_content — existing tests are unaffected.
    """
    line_start = coerce_line_number(finding_details.get("line_start")) or 1

    try:
        patch_imports, function_patch, _ = split_patch_imports_and_function(patch_content)
    except GitHubClientError:
        function_patch = None
        patch_imports = []

    # If no extractable function body, fall back to the raw patch text
    if not function_patch or not function_patch.strip():
        function_patch = patch_content.strip()
        patch_imports = []

    total = line_count(original_content)
    fb_start = max(1, line_start)
    fb_end = min(total, fb_start + line_count(function_patch))

    # Strategy 1: replace the line range and validate with ast.parse
    candidate = replace_line_range(original_content, function_patch, fb_start, fb_end)
    if patch_imports:
        try:
            candidate = insert_missing_imports(candidate, patch_imports)
        except Exception:
            pass

    if candidate.strip():
        try:
            ast.parse(candidate)
            return candidate, (
                f"⚠️ Nota: No se pudo anclar el fix al snippet exacto. "
                f"El código fue insertado cerca de la línea {line_start}. Por favor revisa manualmente."
            )
        except SyntaxError:
            pass

    # Strategy 2: insert the patch as a commented block right after line_start
    # (avoids breaking existing syntax while still surfacing the proposed change)
    original_lines = original_content.splitlines(keepends=True)
    insert_at = min(line_start, total)
    comment_lines: list[str] = ["# === AI Security Fix (approximate anchor) ===\n"]
    for cl in function_patch.splitlines():
        comment_lines.append(f"# {cl}\n")
    comment_lines.append("# === End of AI Security Fix ===\n")
    candidate2 = "".join(original_lines[:insert_at] + comment_lines + original_lines[insert_at:])
    if candidate2.strip():
        try:
            ast.parse(candidate2)
            return candidate2, (
                f"⚠️ Nota: No se pudo insertar el fix directamente en la línea {line_start}. "
                "El código propuesto fue insertado como comentario — aplícalo manualmente."
            )
        except SyntaxError:
            pass

    # Strategy 3: force-use the Strategy 1 result without AST validation
    # The PR description will warn the reviewer to check manually.
    final = candidate if candidate.strip() else original_content
    return final, (
        f"⚠️ Nota: Fix insertado de forma aproximada cerca de la línea {line_start}. "
        "El resultado puede requerir ajustes manuales antes del merge."
    )


def _extract_named_functions(source: str) -> set[str]:
    """Return all named function/method names from Python and JavaScript/TypeScript source.

    Matches:
    - Python:               ``def funcName(``  /  ``async def funcName(``
    - JS/TS declarations:   ``function funcName(``  /  ``async function funcName(``
    """
    names: set[str] = set()
    # Python functions (def / async def)
    names |= set(re.findall(r"\bdef\s+(\w+)\s*\(", source))
    # JavaScript / TypeScript named function declarations (async or not)
    names |= set(re.findall(r"\bfunction\s+(\w+)\s*\(", source))
    return names


def is_safe_to_apply(original_content: str, patched_content: str) -> tuple[bool, str]:
    """Validate a patch before committing it to GitHub.

    Returns (True, "ok") if the patch is safe to apply, or (False, reason)
    if any guardrail is triggered.  Three checks are performed:

    1. The patch must not remove more than 20 % of the original lines.
    2. The patch must not contain generic placeholder signals injected by the LLM.
    3. The patch must not delete any function that exists in the original file
       (checked for both Python ``def`` and JavaScript/TypeScript ``function``).
    """
    original_lines = original_content.splitlines()
    patched_lines  = patched_content.splitlines()

    if original_content == patched_content:
        return False, (
            "La remediación no cambia el archivo; el hallazgo seguiría presente. "
            "Debe regenerarse o pasar a revisión manual."
        )

    # 1 — Excessive line removal
    lines_removed = len(original_lines) - len(patched_lines)
    if original_lines and lines_removed > len(original_lines) * 0.20:
        pct = int(lines_removed / len(original_lines) * 100)
        return False, (
            f"El patch eliminaría {lines_removed} líneas ({pct}% del archivo). "
            "Requiere revisión manual antes de aplicarse."
        )

    # 2 — Generic LLM stub signals (introduced by the model, absent from original)
    stub_signals = [
        # Python stubs
        "some_api_endpoint",
        "some_dependency",
        "some_type",
        "# Function body remains unchanged",
        "pass  # placeholder",
        "hypothetical function",
        "# Original code snippet",
        "Original code snippet",
        "# Patched code snippet",
        "Function implementation",
        # JavaScript/TypeScript stubs — common hallucination markers
        "// Method implementation here",
        "// Example of a method that",
        "// Corrected usage of the method",
        "// Assuming the problematic function",
        "problematicFunction",
        "callProblematic",
        # Placeholder / refactoring stubs generated for Cognitive Complexity rules
        "function refactoredFunction",
        "refactoredFunction()",
        "// Placeholder for the refactored function",
        "// Implement the refactored logic",
        "// TODO: implement",
        "// TODO: refactor",
        "// implement refactored",
        "// insert refactored",
    ]
    for signal in stub_signals:
        if signal in patched_content and signal not in original_content:
            return False, (
                f"El patch contiene código placeholder genérico: '{signal}'. "
                "El modelo generó un stub en lugar de un fix real."
            )

    # 3 — Function deletion (Python + JavaScript/TypeScript named functions)
    original_funcs = _extract_named_functions(original_content)
    patched_funcs  = _extract_named_functions(patched_content)
    deleted_funcs  = original_funcs - patched_funcs
    if deleted_funcs:
        names = ", ".join(sorted(deleted_funcs))
        return False, (
            f"El patch eliminaría funciones existentes: {names}. "
            "No se puede aplicar automáticamente — requiere revisión manual."
        )

    return True, "ok"


async def create_proposal_pr(
    finding_details: dict,
    remediation_text: str,
    safety_reason: str,
) -> dict:
    """Create a PR that contains only a Markdown proposal in docs/remediations/.

    No source-code file is modified.  This is used when ``is_safe_to_apply``
    rejects the patch so the human reviewer can inspect the LLM output and
    apply it manually.
    """
    app_id, installation_id, repo, private_key_path, base_branch = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)

    finding_id  = str(finding_details.get("id", "unknown"))
    rule_id     = finding_details.get("rule_id", "UNKNOWN")
    file_path   = finding_details.get("file_path", "UNKNOWN")
    line_number = finding_details.get("line_start", "?")
    branch_name   = f"security-proposal-{finding_id}"
    proposal_path = f"docs/remediations/{finding_id}.md"

    proposal_content = (
        f"# Revisión manual requerida — {rule_id}\n\n"
        f"**Archivo:** `{file_path}:{line_number}`  \n"
        f"**Razón:** {safety_reason}\n\n"
        "## Propuesta de Ollama\n\n"
        f"{remediation_text}\n"
    )

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(installation_token),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        base_ref = await github_request(
            client,
            "GET",
            f"/repos/{repo}/git/ref/heads/{urllib.parse.quote(base_branch, safe='')}",
        )
        base_sha = base_ref["object"]["sha"]

        await ensure_security_branch(client, repo, branch_name, base_sha)

        # Get SHA of the proposal file if it already exists (needed for update)
        encoded_path = urllib.parse.quote(proposal_path, safe="/")
        existing_sha: str | None = None
        try:
            existing_file = await github_request(
                client,
                "GET",
                f"/repos/{repo}/contents/{encoded_path}",
                params={"ref": branch_name},
            )
            if isinstance(existing_file, dict):
                existing_sha = existing_file.get("sha")
        except GitHubClientError:
            pass  # file does not exist yet — create it

        put_payload: dict = {
            "message": f"docs(security): add AI proposal for {rule_id} ({finding_id})",
            "content": encode_content(proposal_content),
            "branch":  branch_name,
        }
        if existing_sha:
            put_payload["sha"] = existing_sha

        await github_request(
            client,
            "PUT",
            f"/repos/{repo}/contents/{encoded_path}",
            put_payload,
        )

        owner    = repo.split("/", 1)[0]
        pr_title = f"⚠️ Manual review: {rule_id} in {file_path}"
        pr_body  = (
            "## ⚠️ Revisión manual requerida\n\n"
            f"**Regla:** `{rule_id}`  \n"
            f"**Archivo:** `{file_path}:{line_number}`\n\n"
            "### Por qué este PR no aplica el parche directamente\n\n"
            f"{safety_reason}\n\n"
            "### Qué hacer\n\n"
            f"Revisa el archivo `{proposal_path}` en esta rama para ver la propuesta "
            "completa de Ollama y aplícala manualmente si es correcta.\n\n"
            "---\n"
            "*Generado automáticamente por AI DevSecOps Control Plane — "
            "requiere revisión humana antes del merge.*\n"
        )

        try:
            pull_request = await github_request(
                client,
                "POST",
                f"/repos/{repo}/pulls",
                {
                    "title": pr_title,
                    "head":  branch_name,
                    "base":  base_branch,
                    "body":  pr_body,
                    "maintainer_can_modify": True,
                },
            )
        except GitHubClientError as exc:
            existing_pr = await get_existing_open_pr(client, repo, owner, branch_name)
            if not existing_pr:
                raise exc
            pull_request = existing_pr

    if not pull_request.get("html_url"):
        raise GitHubClientError(
            "GitHub did not return a pull request URL for the proposal.",
            code="proposal_pr_no_url",
        )

    return {
        "branch":        branch_name,
        "url":           pull_request["html_url"],
        "number":        pull_request.get("number"),
        "pr_type":       "proposal",
        "safety_reason": safety_reason,
        "anchor_warning": None,
    }


def is_existing_reference_error(exc: GitHubClientError) -> bool:
    return "422" in str(exc) and "Reference already exists" in str(exc)


async def ensure_security_branch(
    client: httpx.AsyncClient,
    repo: str,
    branch_name: str,
    base_sha: str,
) -> None:
    try:
        await github_request(
            client,
            "POST",
            f"/repos/{repo}/git/refs",
            {
                "ref": f"refs/heads/{branch_name}",
                "sha": base_sha,
            },
        )
    except GitHubClientError as exc:
        if not is_existing_reference_error(exc):
            raise

        try:
            await github_request(
                client,
                "PATCH",
                f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(branch_name, safe='/')}",
                {
                    "sha": base_sha,
                    "force": True,
                },
            )
        except GitHubClientError as reset_exc:
            raise GitHubClientError(
                f"Could not reset branch {branch_name} to base SHA {base_sha}: {reset_exc}",
                code="security_branch_reset_failed",
                user_message=(
                    f"No pude reanclar la rama {branch_name}. Puede estar protegida, "
                    "bloqueada por reglas del repositorio o en un estado inconsistente."
                ),
                retryable=False,
                details={"branch": branch_name, "base_sha": base_sha},
            ) from reset_exc


async def get_existing_open_pr(
    client: httpx.AsyncClient,
    repo: str,
    owner: str,
    branch_name: str,
) -> dict | None:
    pulls = await github_request(
        client,
        "GET",
        f"/repos/{repo}/pulls",
        params={
            "head": f"{owner}:{branch_name}",
            "state": "open",
        },
    )

    if isinstance(pulls, list) and pulls:
        return pulls[0]

    return None


def build_pr_body(finding_details: dict, remediation_text: str) -> str:
    technology = normalize_patch_technology_for_finding(finding_details)
    fence_label = code_fence_label_for_technology(
        technology,
        str(finding_details.get("file_path", "")),
    )

    severity = finding_details.get("severity", "UNKNOWN")
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    file_path = finding_details.get("file_path", "UNKNOWN")
    line_start = finding_details.get("line_start", "")
    description = finding_details.get("description", "No description provided.")
    code_snippet = finding_details.get("code_snippet", "")
    cwe_raw = finding_details.get("cwe_id") or finding_details.get("cwe") or ""
    cwe_number = re.search(r"\d+", str(cwe_raw)).group() if re.search(r"\d+", str(cwe_raw)) else None

    # Extract the code block for the "Fix aplicado" section
    patch_content = extract_code_block_for_technology(remediation_text, technology, file_path)
    if patch_content:
        fix_section = f"```{fence_label}\n{patch_content}\n```"
    else:
        fix_section = remediation_text

    cwe_ref = (
        f"- CWE-{cwe_number}: https://cwe.mitre.org/data/definitions/{cwe_number}.html"
        if cwe_number
        else "- CWE: no disponible para este hallazgo"
    )

    loc = f"`{file_path}:{line_start}`" if line_start else f"`{file_path}`"

    return f"""## \U0001f512 Security Fix — {severity} [{rule_id}]

**Herramienta:** {technology} | **Archivo:** {loc}

### Problema

{description}

### Contexto original

```{fence_label}
{code_snippet}
```

### Fix aplicado

{fix_section}

### Referencias

{cwe_ref}
- Generado por: Ollama `qwen2.5-coder:14b` (inferencia local)

---
*Este PR fue generado automáticamente por AI DevSecOps Control Plane.*
*Revisar antes de hacer merge.*
"""


def build_file_commit_message(finding_details: dict) -> str:
    finding_id = str(finding_details.get("id", "unknown"))
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    return f"fix: apply AI security patch for {rule_id} ({finding_id})"


async def create_security_pr(finding_details: dict, remediation_text: str) -> dict:
    app_id, installation_id, repo, private_key_path, base_branch = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)
    owner = repo.split("/", 1)[0]
    finding_id = str(finding_details.get("id", "unknown"))
    branch_name = f"security-fix-{finding_id}"
    rule_id = finding_details.get("rule_id", "UNKNOWN")
    file_path = normalize_file_path_for_github(finding_details.get("file_path", ""))
    technology = normalize_patch_technology_for_finding({**finding_details, "file_path": file_path})
    patch_content = extract_code_block_for_technology(remediation_text, technology, file_path)
    deterministic_details = {**finding_details, "file_path": file_path}
    deterministic_s1192 = is_python_duplicate_literal_rule(deterministic_details)
    deterministic_b324 = is_python_weak_hash_rule(deterministic_details)

    if not patch_content and not (deterministic_s1192 or deterministic_b324):
        label = code_fence_label_for_technology(technology, file_path)
        raise GitHubClientError(
            f"AI remediation did not include a valid non-empty {technology} code block. "
            "No branch changes were pushed.",
            code="invalid_ai_code_block",
            user_message=(
                f"La remediación de IA no incluyó un bloque {technology} válido y no se empujaron cambios. "
                f"Regenera la remediación para que devuelva solo código dentro de ```{label}."
            ),
            retryable=True,
        )

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(installation_token),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        base_ref = await github_request(
            client,
            "GET",
            f"/repos/{repo}/git/ref/heads/{urllib.parse.quote(base_branch, safe='')}",
        )
        base_sha = base_ref["object"]["sha"]

        await ensure_security_branch(client, repo, branch_name, base_sha)

        encoded_path = urllib.parse.quote(file_path, safe="/")
        try:
            source_file = await github_request(
                client,
                "GET",
                f"/repos/{repo}/contents/{encoded_path}",
                params={"ref": branch_name},
            )
        except GitHubClientError as exc:
            if exc.http_status == 404:
                raise GitHubClientError(
                    f"File not found in GitHub repository: {file_path}",
                    code="file_not_found_in_repo",
                    user_message=(
                        f"El archivo '{file_path}' no existe en el repositorio de GitHub "
                        f"({repo}). Verifica que el proyecto fue clonado desde el repositorio "
                        "correcto y que la ruta del archivo coincide con la estructura del repo."
                    ),
                    retryable=False,
                    http_status=404,
                ) from exc
            raise

        if not isinstance(source_file, dict):
            raise GitHubClientError(f"GitHub source path {file_path} did not resolve to a file.")

        encoded_content = source_file.get("content", "")
        original_content = decode_github_file_content(encoded_content)

        if not original_content:
            raise GitHubClientError(
                f"GitHub source file {file_path} decoded to empty content. "
                "Refusing to replace it."
            )

        anchor_warning: str | None = None
        applied_remediation_text = remediation_text

        if deterministic_s1192:
            patched_content, deterministic_details = build_python_s1192_constant_patch(
                original_content,
                {**finding_details, "file_path": file_path},
            )
            applied_remediation_text = build_python_s1192_remediation_text(deterministic_details)
        elif deterministic_b324:
            patched_content, weak_hash_details = build_python_b324_weak_hash_patch(
                original_content,
                {**finding_details, "file_path": file_path},
            )
            applied_remediation_text = build_python_b324_remediation_text(weak_hash_details)
        else:
            try:
                patched_content = build_safe_patched_content(
                    original_content,
                    patch_content,
                    finding_details,
                )
            except GitHubClientError as patch_exc:
                if patch_exc.code != "patch_target_not_found":
                    raise
                if technology == "python":
                    raise
                # Fallback: apply patch at approximate line range and create the PR with a warning
                patched_content, anchor_warning = _apply_approximate_anchor(
                    original_content, patch_content, finding_details
                )
                _log.warning(
                    "create_security_pr: using approximate anchor for finding %s — %s",
                    finding_id, anchor_warning,
                )

        # P3 safety check: validate the final patched content before committing.
        # Catches LLM-generated stubs, function deletions, and excessive removals
        # that slip past build_safe_patched_content (e.g. Python AST still parses
        # a stub function).  If it fails, raise safety_check_failed so the caller
        # can route to create_proposal_pr instead.
        is_safe, safety_reason = is_safe_to_apply(original_content, patched_content)
        if not is_safe:
            _log.warning(
                "create_security_pr: safety check failed for finding %s — %s",
                finding_id, safety_reason,
            )
            raise GitHubClientError(
                f"Safety check failed: {safety_reason}",
                code="safety_check_failed",
                user_message=safety_reason,
                retryable=False,
                details={"safety_reason": safety_reason, "finding_id": finding_id},
            )

        if technology == "python":
            semantic_safe, semantic_reason = validate_python_security_semantics(
                original_content, patched_content, finding_details
            )
            if not semantic_safe:
                raise GitHubClientError(
                    f"Semantic safety check failed: {semantic_reason}",
                    code="semantic_safety_check_failed",
                    user_message=semantic_reason,
                    retryable=True,
                    details={"safety_reason": semantic_reason, "finding_id": finding_id},
                )

        source_sha = source_file["sha"]

        await github_request(
            client,
            "PUT",
            f"/repos/{repo}/contents/{encoded_path}",
            {
                "message": build_file_commit_message(finding_details),
                "content": encode_content(patched_content),
                "sha": source_sha,
                "branch": branch_name,
            },
        )

        pull_request = await create_pull_request(
            client,
            repo,
            owner,
            branch_name,
            base_branch,
            rule_id,
            file_path,
            finding_details,
            applied_remediation_text,
        )

    if not pull_request.get("html_url"):
        raise GitHubClientError("GitHub did not return a pull request URL.")

    return {
        "branch":        branch_name,
        "url":           pull_request["html_url"],
        "number":        pull_request.get("number"),
        "pr_type":       "code_fix",
        "anchor_warning": anchor_warning,
        "applied_remediation_text": applied_remediation_text,
    }


async def create_pull_request(
    client: httpx.AsyncClient,
    repo: str,
    owner: str,
    branch_name: str,
    base_branch: str,
    rule_id: str,
    file_path: str,
    finding_details: dict,
    remediation_text: str,
) -> dict:
    pr_title = f"Security fix: {rule_id} in {file_path}"
    pr_body = build_pr_body(finding_details, remediation_text)

    try:
        return await github_request(
            client,
            "POST",
            f"/repos/{repo}/pulls",
            {
                "title": pr_title,
                "head": branch_name,
                "base": base_branch,
                "body": pr_body,
                "maintainer_can_modify": True,
            },
        )
    except GitHubClientError as exc:
        existing_pr = await get_existing_open_pr(client, repo, owner, branch_name)

        if not existing_pr:
            raise exc

        return existing_pr


async def create_check_run(
    repo: str,
    head_sha: str,
    name: str = "AI DevSecOps Security Scan",
    status: str = "in_progress",
) -> dict:
    app_id, installation_id, _repo, private_key_path, _base = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers={**build_headers(installation_token), "Accept": "application/vnd.github+json"},
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        return await github_request(
            client,
            "POST",
            f"/repos/{repo}/check-runs",
            {
                "name": name,
                "head_sha": head_sha,
                "status": status,
            },
        )


async def update_check_run(
    repo: str,
    check_run_id: int,
    conclusion: str,
    summary: str,
    details_url: str | None = None,
) -> dict:
    app_id, installation_id, _repo, private_key_path, _base = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)

    payload: dict = {
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": "AI DevSecOps Security Scan",
            "summary": summary,
        },
    }
    if details_url:
        payload["details_url"] = details_url

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers={**build_headers(installation_token), "Accept": "application/vnd.github+json"},
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        return await github_request(
            client,
            "PATCH",
            f"/repos/{repo}/check-runs/{check_run_id}",
            payload,
        )


async def delete_security_branch(branch_name: str) -> dict:
    app_id, installation_id, repo, private_key_path, _base_branch = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)
    safe_branch_name = branch_name.removeprefix("refs/heads/")

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(installation_token),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        try:
            await github_request(
                client,
                "DELETE",
                f"/repos/{repo}/git/refs/heads/{urllib.parse.quote(safe_branch_name, safe='/')}",
            )
        except GitHubClientError as exc:
            error_text = str(exc)
            if (
                "failed with 404" in error_text
                or ("failed with 422" in error_text and "Reference does not exist" in error_text)
            ):
                return {"branch": safe_branch_name, "deleted": False}
            raise

    return {"branch": safe_branch_name, "deleted": True}


async def close_open_pr_for_branch(branch_name: str) -> dict:
    app_id, installation_id, repo, private_key_path, _base_branch = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)
    owner, _, _repo_name = repo.partition("/")
    safe_branch_name = branch_name.removeprefix("refs/heads/")

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(installation_token),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        existing_pr = await get_existing_open_pr(client, repo, owner, safe_branch_name)
        if not existing_pr:
            return {"branch": safe_branch_name, "closed": False, "number": None}

        number = existing_pr.get("number")
        if not number:
            return {"branch": safe_branch_name, "closed": False, "number": None}

        await github_request(
            client,
            "PATCH",
            f"/repos/{repo}/pulls/{number}",
            {"state": "closed"},
        )

    return {"branch": safe_branch_name, "closed": True, "number": number}


async def get_existing_open_pr_for_branch(branch_name: str) -> dict | None:
    """
    Wrapper around get_existing_open_pr that manages the httpx client internally.
    Returns the open PR dict or None if not found.
    Callers should handle exceptions — this function does not swallow them.
    """
    app_id, installation_id, repo_full, private_key_path, _ = get_github_config()
    installation_token = await get_installation_token(app_id, installation_id, private_key_path)
    owner, _, _ = repo_full.partition("/")

    async with httpx.AsyncClient(
        base_url=GITHUB_API_URL,
        headers=build_headers(installation_token),
        timeout=GITHUB_TIMEOUT_SECONDS,
    ) as client:
        return await get_existing_open_pr(client, repo_full, owner, branch_name)


async def get_pr_diff(pr_url: str) -> dict | None:
    """
    Returns the unified diff of a GitHub PR as {"diff": str, "pr_number": str}.
    Uses GitHub App installation token auth.
    Returns None if the URL is invalid, the PR is inaccessible, or any error occurs.
    """
    if not pr_url or "github.com" not in pr_url:
        return None

    parts = pr_url.rstrip("/").split("/")
    try:
        pull_idx = parts.index("pull")
        owner = parts[pull_idx - 2]
        repo_name = parts[pull_idx - 1]
        pr_number = parts[pull_idx + 1]
    except (ValueError, IndexError):
        _log.warning("get_pr_diff: cannot parse pr_url=%s", pr_url)
        return None

    repo = f"{owner}/{repo_name}"

    try:
        app_id, installation_id, _, private_key_path, _ = get_github_config()
        installation_token = await get_installation_token(app_id, installation_id, private_key_path)

        headers = {
            "Authorization": f"Bearer {installation_token}",
            "Accept": "application/vnd.github.v3.diff",
            "User-Agent": "AI-DevSecOps-Control-Plane",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient(timeout=GITHUB_TIMEOUT_SECONDS) as client:
            response = await client.get(
                f"{GITHUB_API_URL}/repos/{repo}/pulls/{pr_number}",
                headers=headers,
            )

        if response.status_code == 200:
            return {"diff": response.text, "pr_number": pr_number}

        _log.warning("get_pr_diff: GitHub returned %s for %s", response.status_code, pr_url)
    except Exception as exc:
        _log.warning("get_pr_diff failed for %s: %s", pr_url, exc)

    return None
