"""Tests for infer_technology_from_finding — ensures that the actual language
of a finding (derived from rule_id namespace or file extension) takes precedence
over the project-level technology so the right AI prompt and patch strategy are
used.

Regression guard for the bug where a Python project with SonarQube / Semgrep
findings in .html / .css / .js / .java files was sending Python prompts to
Ollama, causing Python code to be proposed for frontend / Java files.
"""
import pytest

from src.ai_engine.remediator import infer_technology_from_finding


# ── SonarQube JavaScript rule namespace ──────────────────────────────────────
@pytest.mark.parametrize("rule_id", [
    "javascript:S3358",
    "javascript:S1234",
    "typescript:S2201",
    "jsts.S3358",
])
def test_sonarqube_js_rules_infer_angular(rule_id):
    result = infer_technology_from_finding(rule_id, "src/dashboard/index.html")
    assert result == "angular", (
        f"Expected 'angular' for JS/TS rule_id={rule_id!r}, got {result!r}"
    )


# ── SonarQube Web / HTML rules ───────────────────────────────────────────────
def test_sonarqube_web_rule_in_html_file_infers_html():
    assert infer_technology_from_finding("web:UnclosedTagCheck", "src/dashboard/index.html") == "html"


# ── SonarQube Python rule namespace ──────────────────────────────────────────
@pytest.mark.parametrize("rule_id", [
    "python:S8415",
    "python:S1481",
    "python:S3776",
])
def test_sonarqube_python_rules_infer_python(rule_id):
    result = infer_technology_from_finding(rule_id, "src/api/main.py")
    assert result == "python", (
        f"Expected 'python' for Python rule_id={rule_id!r}, got {result!r}"
    )


# ── Bandit rules (B + 3 digits) ──────────────────────────────────────────────
@pytest.mark.parametrize("rule_id", [
    "B101",
    "B501",
    "B307",
    "b201",  # lowercase should also match
])
def test_bandit_rules_infer_python(rule_id):
    result = infer_technology_from_finding(rule_id, "src/api/main.py")
    assert result == "python", (
        f"Expected 'python' for Bandit rule_id={rule_id!r}, got {result!r}"
    )


# ── Semgrep namespaces ────────────────────────────────────────────────────────
def test_semgrep_python_namespace_infers_python():
    assert infer_technology_from_finding("python.lang.security.audit.exec", "app.py") == "python"


def test_semgrep_gitlab_bandit_namespace_infers_python():
    assert infer_technology_from_finding("gitlab.bandit.B307", "app.py") == "python"


def test_semgrep_java_namespace_infers_java():
    assert infer_technology_from_finding("java.lang.security.sql-injection", "App.java") == "java"


# ── SonarQube Java rule namespace ────────────────────────────────────────────
@pytest.mark.parametrize("rule_id", [
    "java:S1010",
    "kotlin:S1234",
    "squid:S2095",
])
def test_sonarqube_java_rules_infer_java(rule_id):
    result = infer_technology_from_finding(rule_id, "src/Main.java")
    assert result == "java", (
        f"Expected 'java' for Java rule_id={rule_id!r}, got {result!r}"
    )


# ── File extension fallback (when rule_id is generic) ────────────────────────
@pytest.mark.parametrize("file_path,expected", [
    ("src/dashboard/main.js",       "angular"),
    ("src/dashboard/main.ts",       "angular"),
    ("src/dashboard/index.html",    "html"),
    ("src/component.jsx",           "angular"),
    ("src/app.tsx",                 "angular"),
    ("src/api/main.py",             "python"),
    ("src/Main.java",               "java"),
    ("src/App.kt",                  "java"),
])
def test_file_extension_fallback(file_path, expected):
    # Use a generic / unknown rule_id to force file-extension path
    result = infer_technology_from_finding("GENERIC-001", file_path)
    assert result == expected, (
        f"Expected {expected!r} for file_path={file_path!r}, got {result!r}"
    )


# ── Returns None when no evidence ────────────────────────────────────────────
def test_returns_none_when_no_evidence():
    result = infer_technology_from_finding("CUSTOM-RULE", "/some/file.txt")
    assert result is None, f"Expected None for unknown rule+extension, got {result!r}"


def test_returns_none_for_empty_inputs():
    assert infer_technology_from_finding("", "") is None


# ── Key regression: javascript:S3358 in a Python project ─────────────────────
def test_js_rule_in_html_file_beats_project_python_technology():
    """Regression test for the reported bug.

    Before the fix: build_finding_details returned technology='python' for
    javascript:S3358 in src/dashboard/index.html because the project was Python.
    After the fix: infer_technology_from_finding returns 'angular' which takes
    precedence, so Ollama receives the Angular/JS prompt instead of Python.
    """
    inferred = infer_technology_from_finding("javascript:S3358", "src/dashboard/index.html")
    assert inferred == "angular", (
        "javascript:S3358 in an .html file must infer 'angular', "
        f"but got {inferred!r}"
    )
