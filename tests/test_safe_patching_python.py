"""Tests for build_safe_patched_content() and its Python patching helpers."""

import textwrap

import pytest

from src.integrations.github_client import (
    GitHubClientError,
    build_python_b324_remediation_text,
    build_python_b324_weak_hash_patch,
    build_python_s1192_constant_patch,
    build_python_s1192_remediation_text,
    build_safe_patched_content,
    insert_missing_imports,
    is_safe_to_apply,
    remediation_text_matches_python_b324,
    remediation_text_matches_python_s1192,
)


# ---------------------------------------------------------------------------
# Helpers — inline fixtures (no disk I/O)
# ---------------------------------------------------------------------------

def _big_file_with_short_function() -> str:
    """110-line Python module; vulnerable_function lives at lines 16–17."""
    lines = [
        "import os",
        "import sys",
        "",
        "",
        'MODULE_VAR = "constant"',
        "",
        "",
        "def helper_one():",
        "    return 1",
        "",
        "",
        "def helper_two():",
        "    return 2",
        "",
        "",
        "def vulnerable_function(data):",  # line 16
        "    return eval(data)",            # line 17
        "",
    ]
    while len(lines) < 110:
        lines.append(f"# padding line {len(lines)}")
    return "\n".join(lines)


def _big_file_with_giant_function() -> str:
    """121-line Python module; giant_vulnerable occupies lines 4–100 (97 lines)."""
    lines = ["import os", "", ""]
    lines.append("def giant_vulnerable(data):")  # line 4 (index 3)
    for i in range(95):
        lines.append(f"    # complex step {i}")  # lines 5–99
    lines.append("    return eval(data)")         # line 100
    lines.append("")                              # line 101
    for i in range(20):
        lines.append(f"# footer {i}")             # lines 102–121
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# B1 — Test cases
# ---------------------------------------------------------------------------

def test_short_patch_preserves_surrounding_code():
    """Semantic patch replaces only the target function; all other lines are untouched."""
    original = _big_file_with_short_function()
    patch = textwrap.dedent("""\
        def vulnerable_function(data):
            if not isinstance(data, (int, float)):
                raise ValueError(f"unsafe input: {data!r}")
            return data
    """).strip()

    result = build_safe_patched_content(
        original,
        patch,
        {"line_start": 16, "file_path": "utils.py", "technology": "python"},
    )

    assert "eval(" not in result, "vulnerability must be removed"
    assert "isinstance(data, (int, float))" in result, "safe guard must appear"
    assert "def helper_one():" in result, "helper_one must be preserved"
    assert "def helper_two():" in result, "helper_two must be preserved"
    assert "# padding line 50" in result, "filler lines must be preserved"
    assert "def vulnerable_function(" in result, "function signature must remain"


def test_invalid_patch_raises_on_syntax_error():
    """An LLM-provided Python block with a SyntaxError is rejected before patching."""
    original = _big_file_with_short_function()
    # Missing closing parenthesis → SyntaxError in split_patch_imports_and_function
    broken_patch = "def vulnerable_function(data:\n    return int(data)\n"

    with pytest.raises(GitHubClientError) as exc_info:
        build_safe_patched_content(
            original,
            broken_patch,
            {"line_start": 16, "file_path": "utils.py", "technology": "python"},
        )

    # Production raises "ai_python_block_invalid" when the patch itself is invalid Python
    # (split_patch_imports_and_function catches the SyntaxError before patching begins).
    assert exc_info.value.code == "ai_python_block_invalid"


def test_patch_target_not_found_raises_when_function_absent():
    """When line_start is outside any function and the patch name is absent, code='patch_target_not_found'."""
    original = _big_file_with_short_function()
    # Patch names a function that does not exist in the original file
    patch = textwrap.dedent("""\
        def nonexistent_helper(x):
            return x * 2
    """).strip()

    with pytest.raises(GitHubClientError) as exc_info:
        build_safe_patched_content(
            original,
            patch,
            # line 5 = MODULE_VAR = "constant" — not inside any function
            {"line_start": 5, "file_path": "utils.py", "technology": "python"},
        )

    assert exc_info.value.code == "patch_target_not_found"


def test_rejects_replacing_endpoint_with_unrelated_function_name():
    """Regression guard for destructive PRs that replace an endpoint with a fake helper."""
    original = textwrap.dedent("""\
        from fastapi import FastAPI

        app = FastAPI()

        @app.get("/api/projects/{project_id}/findings")
        async def get_project_findings_endpoint(project_id: str):
            return [{"id": project_id}]
    """).strip()
    patch = textwrap.dedent("""\
        from typing import Annotated

        def get_user(user_id: int):
            # Function implementation
            pass
    """).strip()

    with pytest.raises(GitHubClientError) as exc_info:
        build_safe_patched_content(
            original,
            patch,
            {"line_start": 7, "file_path": "src/api/main.py", "technology": "python"},
        )

    assert exc_info.value.code == "ai_patch_function_mismatch"
    assert exc_info.value.details["expected_function"] == "get_project_findings_endpoint"
    assert exc_info.value.details["patch_function"] == "get_user"


def test_safety_check_detects_async_function_deletion():
    original = textwrap.dedent("""\
        async def get_project_findings_endpoint(project_id: str):
            return [{"id": project_id}]
    """).strip()
    patched = textwrap.dedent("""\
        def get_user(user_id: int):
            pass
    """).strip()

    safe, reason = is_safe_to_apply(original, patched)

    assert safe is False
    assert "get_project_findings_endpoint" in reason


def test_full_file_replacement_when_patch_at_least_80_percent():
    """A patch >= 80% of original triggers full-file replacement; result passes ast.parse."""
    # 40-line original
    original_lines = [f"# line {i}" for i in range(40)]
    original_lines[0] = "import os"
    original_lines[5] = "def old_function(x):"
    original_lines[6] = "    return eval(x)"
    original = "\n".join(original_lines)  # 40 lines

    # 32-line patch = exactly 80% of 40 → should_replace_full_file returns True
    patch_lines = [f"# patched line {i}" for i in range(32)]
    patch_lines[0] = "import os"
    patch_lines[1] = "import hmac"
    patch_lines[2] = ""
    patch_lines[3] = "def old_function(x):"
    patch_lines[4] = "    return int(x)"
    patch = "\n".join(patch_lines)

    result = build_safe_patched_content(
        original,
        patch,
        {"file_path": "utils.py", "technology": "python"},
    )

    assert "import hmac" in result, "new import must appear in full-file replacement"
    assert "old_function" in result, "function must be present"
    assert "eval(" not in result, "original vulnerability must be gone"


def test_result_too_short_raises_error():
    """Replacing a 97-line function with a 4-line patch shrinks the file below 50%; raises error."""
    original = _big_file_with_giant_function()
    patch = textwrap.dedent("""\
        def giant_vulnerable(data):
            if not data:
                raise ValueError("empty input")
            return int(data)
    """).strip()

    with pytest.raises(GitHubClientError, match="unexpectedly short"):
        build_safe_patched_content(
            original,
            patch,
            {"line_start": 50, "file_path": "big.py", "technology": "python"},
        )


def test_insert_missing_imports_adds_new_without_duplication():
    """insert_missing_imports adds absent imports and never duplicates existing ones."""
    original = "import os\nimport sys\n\ndef foo():\n    return os.getcwd()\n"
    imports_from_patch = ["import os", "import hmac", "import hashlib"]

    result = insert_missing_imports(original, imports_from_patch)

    assert "import hmac" in result, "new import must be inserted"
    assert "import hashlib" in result, "new import must be inserted"
    assert result.count("import os") == 1, "existing import must not be duplicated"
    assert "import sys" in result, "unrelated existing import must be preserved"
    assert "def foo():" in result, "function body must be preserved"


def test_python_s1192_uses_deterministic_constant_extraction():
    original = textwrap.dedent("""\
        from fastapi import HTTPException

        app_name = "demo"

        def get_project(project):
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
            return project

        def scan_project(project):
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
            return {"detail": "Project not found"}
    """).strip()

    patched, details = build_python_s1192_constant_patch(
        original,
        {
            "rule_id": "python:S1192",
            "description": 'Define a constant instead of duplicating this literal "Project not found" 3 times.',
            "file_path": "src/api/main.py",
            "technology": "python",
        },
    )

    assert 'PROJECT_NOT_FOUND = "Project not found"' in patched
    assert "detail=PROJECT_NOT_FOUND" in patched
    assert '{"detail": PROJECT_NOT_FOUND}' in patched
    assert patched.count('"Project not found"') == 1
    assert details["replacement_count"] == 3


def test_python_s1192_remediation_text_rejects_invented_functions():
    wrong_remediation = textwrap.dedent("""\
        ```python
        PROJECT_NOT_FOUND = "Project not found"

        def find_project(project_id):
            return PROJECT_NOT_FOUND, 404
        ```
    """).strip()
    finding_details = {
        "rule_id": "python:S1192",
        "description": 'Define a constant instead of duplicating this literal "Project not found" 4 times.',
        "file_path": "src/api/main.py",
        "technology": "python",
    }

    assert remediation_text_matches_python_s1192(wrong_remediation, finding_details) is False

    valid_remediation = build_python_s1192_remediation_text(
        {
            "literal": "Project not found",
            "constant_name": "PROJECT_NOT_FOUND",
            "replacement_count": 4,
        }
    )
    assert remediation_text_matches_python_s1192(valid_remediation, finding_details) is True


def test_python_b324_uses_deterministic_pbkdf2_patch_and_preserves_function_name():
    original = textwrap.dedent("""\
        import hashlib

        def hash_password_sha1(password):
            # Vulnerability: broken cryptography for password hashing with SHA1.
            return hashlib.sha1(password.encode("utf-8")).hexdigest()

        def generate_session_token():
            return "abc"
    """).strip()

    patched, details = build_python_b324_weak_hash_patch(
        original,
        {
            "rule_id": "B324",
            "description": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
            "file_path": "src/dummy_vulnerable_app.py",
            "line_start": 5,
            "technology": "python",
        },
    )

    assert "import secrets" in patched
    assert "def hash_password_sha1(password):" in patched
    assert "hashlib.pbkdf2_hmac" in patched
    assert "hashlib.sha1" not in patched
    assert "def generate_session_token():" in patched
    assert details["function_name"] == "hash_password_sha1"
    assert details["weak_algorithm"] == "sha1"


def test_python_b324_remediation_text_rejects_renamed_sha256_function():
    wrong_remediation = textwrap.dedent("""\
        ```python
        import hashlib

        def hash_password(password):
            return hashlib.sha256(password.encode("utf-8")).hexdigest()
        ```
    """).strip()
    finding_details = {
        "rule_id": "B324",
        "description": "Use of weak SHA1 hash for security. Consider usedforsecurity=False",
        "file_path": "src/dummy_vulnerable_app.py",
        "technology": "python",
    }

    assert remediation_text_matches_python_b324(wrong_remediation, finding_details) is False

    valid_remediation = build_python_b324_remediation_text(
        {
            "function_name": "hash_password_sha1",
            "value_arg": "password",
            "weak_algorithm": "sha1",
            "function_patch": (
                "def hash_password_sha1(password):\n"
                "    salt = secrets.token_bytes(16)\n"
                "    digest = hashlib.pbkdf2_hmac(\"sha256\", password.encode(\"utf-8\"), salt, 600_000)\n"
                "    return f\"{salt.hex()}:{digest.hex()}\""
            ),
        }
    )
    assert remediation_text_matches_python_b324(valid_remediation, finding_details) is True
