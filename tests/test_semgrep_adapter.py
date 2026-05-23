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
