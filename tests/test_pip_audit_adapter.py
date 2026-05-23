import json
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.scanners.pip_audit_adapter import PipAuditAdapter


PIP_AUDIT_JSON = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.0.0",
            "vulns": [
                {
                    "id": "PYSEC-2014-13",
                    "fix_versions": ["2.3.0"],
                    "aliases": ["CVE-2014-1829", "GHSA-cfj3-7x9c-4p3h"],
                    "description": "Requests before 2.3.0 leaks netrc credentials.",
                }
            ],
        },
        {
            "name": "flask",
            "version": "0.1",
            "vulns": [],
        },
    ],
    "fixes": [],
})


def _run_adapter_with_mock_output(target_path: str, stdout: str, returncode: int):
    mock_process = MagicMock()
    mock_process.returncode = returncode
    mock_process.stdout = stdout
    mock_process.stderr = ""

    with patch("subprocess.run", return_value=mock_process):
        with patch("shutil.which", return_value="/usr/bin/pip-audit"):
            adapter = PipAuditAdapter()
            findings = adapter.execute_scan(target_path)
    return adapter, findings


def test_pip_audit_finds_vulnerable_dependency():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("requests==2.0.0\nflask==0.1\n")

        adapter, findings = _run_adapter_with_mock_output(tmpdir, PIP_AUDIT_JSON, 1)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "CVE-2014-1829"
        assert "requests" in f.title
        assert "2.0.0" in f.title
        assert f.severity == "HIGH"
        assert f.confidence == "HIGH"
        assert "requirements.txt" in f.file_path
        assert "2.3.0" in f.code_snippet


def test_pip_audit_no_requirements_file_returns_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("shutil.which", return_value="/usr/bin/pip-audit"):
            adapter = PipAuditAdapter()
            findings = adapter.execute_scan(tmpdir)

        assert findings == []
        assert adapter.returncode == 0


def test_pip_audit_no_vulns_returns_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("flask==2.3.0\n")

        clean_json = json.dumps({"dependencies": [{"name": "flask", "version": "2.3.0", "vulns": []}], "fixes": []})
        adapter, findings = _run_adapter_with_mock_output(tmpdir, clean_json, 0)

        assert findings == []
        assert adapter.returncode == 0


def test_pip_audit_severity_medium_for_pysec_only():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("some-lib==1.0\n")

        pysec_json = json.dumps({
            "dependencies": [{
                "name": "some-lib",
                "version": "1.0",
                "vulns": [{
                    "id": "PYSEC-2021-99",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "Some internal advisory.",
                }],
            }],
            "fixes": [],
        })
        adapter, findings = _run_adapter_with_mock_output(tmpdir, pysec_json, 1)

        assert len(findings) == 1
        assert findings[0].severity == "MEDIUM"
        assert findings[0].rule_id == "PYSEC-2021-99"


def test_pip_audit_not_installed_returns_empty():
    with tempfile.TemporaryDirectory() as tmpdir:
        req = Path(tmpdir) / "requirements.txt"
        req.write_text("requests==2.0.0\n")

        with patch("shutil.which", return_value=None):
            from pathlib import Path as PPath
            with patch.object(PPath, "exists", return_value=False):
                adapter = PipAuditAdapter()
                findings = adapter.execute_scan(tmpdir)

        assert findings == []
        assert adapter.returncode == 127
        assert "pip-audit" in adapter.error
