import pytest

from src.scanners.semgrep_adapter import SemgrepAdapter


def test_semgrep_adapter_can_be_instantiated():
    adapter = SemgrepAdapter("python")

    assert adapter.tool_name == "semgrep"
    assert adapter.technology == "python"


def test_semgrep_severity_normalization():
    adapter = SemgrepAdapter("python")

    assert adapter.normalize_severity("ERROR") == "high"
    assert adapter.normalize_severity("WARNING") == "medium"
    assert adapter.normalize_severity("INFO") == "low"


def test_semgrep_fingerprint_is_stable_for_same_input():
    adapter = SemgrepAdapter("python")

    first = adapter.generate_fingerprint("python.lang.security.audit", "src/app.py", 10)
    second = adapter.generate_fingerprint("python.lang.security.audit", "src/app.py", 10)

    assert first == second
    assert len(first) == 64


def test_semgrep_not_installed_raises_clear_error(monkeypatch):
    adapter = SemgrepAdapter("python")
    monkeypatch.setattr(adapter, "get_semgrep_command", lambda: None)

    with pytest.raises(RuntimeError, match="semgrep no encontrado, instalar con pip install semgrep"):
        adapter.execute_scan("src")


def test_semgrep_detects_django_ruleset(tmp_path):
    (tmp_path / "manage.py").write_text("# django entrypoint\n")
    adapter = SemgrepAdapter("python")

    assert adapter.get_rulesets_for_target("python", str(tmp_path)) == [
        "p/bandit",
        "p/python",
        "p/owasp-top-ten",
        "p/django",
    ]


def test_semgrep_detects_flask_ruleset(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==3.0.0\n")
    adapter = SemgrepAdapter("python")

    assert adapter.get_rulesets_for_target("python", str(tmp_path)) == [
        "p/bandit",
        "p/python",
        "p/owasp-top-ten",
        "p/flask",
    ]


def test_semgrep_detects_spring_ruleset(tmp_path):
    (tmp_path / "pom.xml").write_text("<artifactId>spring-boot-starter-web</artifactId>\n")
    adapter = SemgrepAdapter("java")

    assert adapter.get_rulesets_for_target("java", str(tmp_path)) == [
        "p/java",
        "p/owasp-top-ten",
        "p/find-sec-bugs",
        "p/java-spring",
    ]
