from src.ai_engine.remediator import build_angular_prompt


def test_angular_secret_rule_includes_ci_cd_guidance():
    prompt = build_angular_prompt(
        {
            "rule_id": "ANG-SECRET-001",
            "file_path": "src/environments/environment.ts",
            "code_snippet": 'export const environment = { apiKey: "abc123456789" };',
        }
    )

    assert "CI/CD" in prompt or "pipeline" in prompt or "process.env" in prompt
    assert "INSTRUCCION ESPECIAL" in prompt


def test_angular_xss_rule_does_not_include_secret_instruction():
    prompt = build_angular_prompt(
        {
            "rule_id": "ANG-XSS-001",
            "file_path": "src/app/app.component.html",
            "code_snippet": '<div [innerHTML]="content"></div>',
        }
    )

    assert "INSTRUCCION ESPECIAL" not in prompt
    assert "CI/CD" not in prompt
    assert "ConfigService" not in prompt


def test_angular_secret_keywords_in_snippet_activate_secret_instruction():
    prompt = build_angular_prompt(
        {
            "rule_id": "ANG-CONFIG-001",
            "file_path": "src/environments/environment.ts",
            "code_snippet": 'export const environment = { apiKey: "abc123456789" };',
        }
    )

    assert "INSTRUCCION ESPECIAL" in prompt
    assert "CI/CD" in prompt or "pipeline" in prompt or "process.env" in prompt


def test_angular_semgrep_secret_prefix_activates_secret_instruction():
    prompt = build_angular_prompt(
        {
            "rule_id": "javascript.lang.security.audit.hardcoded-secret",
            "file_path": "src/app/config.ts",
            "code_snippet": 'export const token = "abc123456789";',
        }
    )

    assert "INSTRUCCION ESPECIAL" in prompt
    assert "CI/CD" in prompt or "pipeline" in prompt or "process.env" in prompt
