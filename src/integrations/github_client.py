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


APPLICATION_VND_GITHUB_JSON = "application/vnd.github+json"

GITHUB_API_URL = "https://api.github.com"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
GITHUB_TIMEOUT_SECONDS = 45

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
    ) -> None:
        super().__init__(message)
        self.code = code
        self.user_message = user_message or message
        self.retryable = retryable
        self.details = details or {}

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
        "Accept": APPLICATION_VND_GITHUB_JSON,
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
            f"GitHub API {method} {path} failed with {status_code}: {body}"
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

    if technology == "typescript":
        return "angular"

    if technology in {"python", "angular", "java"}:
        return technology

    return "python"


def code_fence_label_for_technology(technology: str, file_path: str = "") -> str:
    if technology == "angular":
        return "html" if file_path.lower().endswith(".html") else "typescript"

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
        "angular": ("typescript", "ts", "html", "angular"),
        "java": ("java",),
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


def coerce_line_number(value: object) -> int | None:
    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def find_enclosing_function_range(original_content: str, line_start: object) -> tuple[int, int] | None:
    line_start = coerce_line_number(line_start)

    if line_start is None:
        return None

    try:
        tree = ast.parse(original_content)
    except SyntaxError as exc:
        raise GitHubClientError("Original GitHub source file is not valid Python.") from exc

    candidates: list[ast.AST] = []

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
    return getattr(smallest, "lineno"), getattr(smallest, "end_lineno")


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

    if should_replace_full_file(original_content, patch_content):
        candidate = patch_content
    else:
        line_start = finding_details.get("line_start")
        function_range = find_function_range(original_content, line_start, function_patch)

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
    technology = normalize_patch_technology(finding_details.get("technology"))

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
    technology = normalize_patch_technology(finding_details.get("technology"))
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
    patch_content = (
        extract_python_code_block(remediation_text)
        if technology == "python"
        else extract_generic_code_block(remediation_text, technology, file_path)
    )
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
    technology = normalize_patch_technology(finding_details.get("technology"))
    patch_content = (
        extract_python_code_block(remediation_text)
        if technology == "python"
        else extract_generic_code_block(remediation_text, technology, file_path)
    )

    if not patch_content:
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
        source_file = await github_request(
            client,
            "GET",
            f"/repos/{repo}/contents/{encoded_path}",
            params={"ref": branch_name},
        )

        if not isinstance(source_file, dict):
            raise GitHubClientError(f"GitHub source path {file_path} did not resolve to a file.")

        encoded_content = source_file.get("content", "")
        original_content = decode_github_file_content(encoded_content)

        if not original_content:
            raise GitHubClientError(
                f"GitHub source file {file_path} decoded to empty content. "
                "Refusing to replace it."
            )

        patched_content = build_safe_patched_content(
            original_content,
            patch_content,
            finding_details,
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
            remediation_text,
        )

    if not pull_request.get("html_url"):
        raise GitHubClientError("GitHub did not return a pull request URL.")

    return {
        "branch": branch_name,
        "url": pull_request["html_url"],
        "number": pull_request.get("number"),
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
        headers={**build_headers(installation_token), "Accept": APPLICATION_VND_GITHUB_JSON},
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
        headers={**build_headers(installation_token), "Accept": APPLICATION_VND_GITHUB_JSON},
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
    repo_full = os.getenv("GITHUB_REPO", "/")
    owner, _, _ = repo_full.partition("/")

    async with httpx.AsyncClient() as client:
        return await get_existing_open_pr(client, repo_full, owner, branch_name)
