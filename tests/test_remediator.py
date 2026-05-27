from src.ai_engine.remediator import build_prompt, enrich_finding_details


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
