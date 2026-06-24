import asyncio
from unittest.mock import patch

from src.ai_engine.patch_validation import validate_python_security_semantics
from src.ai_engine.remediator import build_prompt, enrich_finding_details, generate_patch


def test_css_technology_detection():
    details = {"rule_id": "css:S4666", "file_path": "src/dashboard/index.html"}

    enriched = enrich_finding_details(details)

    assert enriched["technology"] == "css"


def test_html_file_technology_detection():
    details = {"rule_id": "web:something", "file_path": "templates/base.html"}

    enriched = enrich_finding_details(details)

    assert enriched["technology"] == "html"


def test_css_prompt_no_python():
    details = {
        "rule_id": "css:S4666",
        "file_path": "src/dashboard/index.html",
        "description": "Unexpected duplicate selector '.fb-error'",
        "code_snippet": ".fb-error { background: red; }",
    }

    prompt = build_prompt(details)

    assert "```css" in prompt
    assert "Python" not in prompt
    assert "def " not in prompt

def _command_finding_details():
    return {
        "rule_id": "B602",
        "file_path": "src/dummy_vulnerable_app.py",
        "line_start": 1,
        "expected_function": "run_backup",
        "expected_function_source": (
            "def run_backup(user_supplied_path):\n"
            "    return subprocess.Popen(\"tar czf backup.tgz \" + user_supplied_path, shell=True)"
        ),
        "code_snippet": (
            "def run_backup(user_supplied_path):\n"
            "    return subprocess.Popen(\"tar czf backup.tgz \" + user_supplied_path, shell=True)"
        ),
    }


def test_command_prompt_preserves_contract_and_avoids_universal_regex():
    prompt = build_prompt(_command_finding_details())

    assert "keep returning a Popen handle" in prompt
    assert "after the -- end-of-options separator" in prompt
    assert "Do not invent a universal regex" in prompt
    assert "re.fullmatch" not in prompt
    assert "subprocess.run(list_form)" not in prompt


def test_command_validator_rejects_screenshot_fix_that_changes_return_contract():
    original = _command_finding_details()["expected_function_source"]
    patched = """
+import re
+def run_backup(user_supplied_path):
+    if not re.fullmatch(r'^[a-zA-Z0-9.\\-_]+$', user_supplied_path):
+        raise ValueError('Invalid path provided')
+    result = subprocess.run(['tar', 'czf', 'backup.tgz', user_supplied_path], timeout=30)
+    return result.returncode
+""".replace("+", "").strip()

    safe, reason = validate_python_security_semantics(
        original, patched, _command_finding_details()
    )

    assert safe is False
    assert "contrato de retorno" in reason


def test_command_validator_rejects_tar_operand_without_end_of_options():
    original = _command_finding_details()["expected_function_source"]
    patched = """
+def run_backup(user_supplied_path):
+    return subprocess.Popen(['tar', 'czf', 'backup.tgz', user_supplied_path])
+""".replace("+", "").strip()

    safe, reason = validate_python_security_semantics(
        original, patched, _command_finding_details()
    )

    assert safe is False
    assert "option injection" in reason


def test_command_validator_accepts_contract_preserving_tar_fix():
    original = _command_finding_details()["expected_function_source"]
    patched = """
+def run_backup(user_supplied_path):
+    return subprocess.Popen(['tar', 'czf', 'backup.tgz', '--', user_supplied_path])
+""".replace("+", "").strip()

    safe, reason = validate_python_security_semantics(
        original, patched, _command_finding_details()
    )

    assert safe is True, reason


def test_python_validator_rejects_signature_changes():
    details = {
        "rule_id": "B311",
        "line_start": 1,
        "expected_function": "generate_token",
    }
    original = "def generate_token(length=32):\n    return random.random()"
    patched = "def generate_token(length, alphabet):\n    return secrets.token_urlsafe(length)"

    safe, reason = validate_python_security_semantics(original, patched, details)

    assert safe is False
    assert "firma pública" in reason


def test_generate_patch_retries_with_validator_feedback():
    details = {
        "rule_id": "B602",
        "file_path": "example.py",
        "code_snippet": "def run_backup(path):\n    return path",
        "expected_function": "run_backup",
    }
    responses = iter(["```python\nbad\n```", "```python\ngood\n```"])
    prompts = []

    def fake_request(prompt_text, _details):
        prompts.append(prompt_text)
        return next(responses)

    def validator(candidate, _details):
        return (candidate.endswith("good\n```"), "shell=True remains")

    with patch("src.ai_engine.remediator._request_patch", side_effect=fake_request):
        result = asyncio.run(generate_patch(details, validator=validator, max_attempts=2))

    assert result == "```python\ngood\n```"
    assert len(prompts) == 2
    assert "shell=True remains" in prompts[1]
    assert "UNTRUSTED DATA" in prompts[1]
