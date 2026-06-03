import json
import os
import subprocess
import tempfile
from unittest.mock import patch, mock_open

from src.scanners.gitleaks_adapter import GitleaksAdapter


def _completed(returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["gitleaks"],
        returncode=returncode,
        stdout="",
        stderr=stderr,
    )


_LEAKS_PAYLOAD = [
    {
        "Description": "Generic API Key",
        "StartLine": 10,
        "EndLine": 10,
        "StartColumn": 1,
        "EndColumn": 40,
        "Match": "api_key = 'AKIAIOSFODNN7EXAMPLE'",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "config/settings.py",
        "RuleID": "generic-api-key",
        "Fingerprint": "abc123fingerprint",
    },
    {
        "Description": "AWS Access Token",
        "StartLine": 22,
        "EndLine": 22,
        "StartColumn": 5,
        "EndColumn": 60,
        "Match": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "src/aws_client.py",
        "RuleID": "aws-access-token",
        "Fingerprint": "def456fingerprint",
    },
]


def _write_report_side_effect(report_payload: list):
    """
    Returns a mock for subprocess.run that writes a JSON report file before
    returning, simulating how gitleaks writes --report-path output.
    """
    def _mock_run(command, *args, **kwargs):
        report_path = None
        for i, arg in enumerate(command):
            if arg == "--report-path" and i + 1 < len(command):
                report_path = command[i + 1]
                break
        if report_path:
            with open(report_path, "w") as fh:
                json.dump(report_payload, fh)
        return _completed(returncode=0)

    return _mock_run


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_gitleaks_adapter_normalizes_leaks():
    with (
        patch.object(GitleaksAdapter, "_get_gitleaks_command", return_value=["gitleaks"]),
        patch(
            "src.scanners.gitleaks_adapter.subprocess.run",
            side_effect=_write_report_side_effect(_LEAKS_PAYLOAD),
        ),
    ):
        findings = GitleaksAdapter().execute_scan("/project")

    assert len(findings) == 2
    assert all(f.severity == "HIGH" for f in findings)
    assert all(f.tool == "gitleaks" for f in findings)

    first = findings[0]
    assert first.rule_id == "generic-api-key"
    assert first.file_path == "config/settings.py"
    assert first.line_start == 10
    assert first.fingerprint

    second = findings[1]
    assert second.rule_id == "aws-access-token"
    assert second.file_path == "src/aws_client.py"


def test_gitleaks_adapter_no_leaks_returns_empty():
    with (
        patch.object(GitleaksAdapter, "_get_gitleaks_command", return_value=["gitleaks"]),
        patch(
            "src.scanners.gitleaks_adapter.subprocess.run",
            side_effect=_write_report_side_effect([]),
        ),
    ):
        findings = GitleaksAdapter().execute_scan("/project")

    assert findings == []


def test_gitleaks_adapter_missing_binary_returns_no_findings():
    adapter = GitleaksAdapter()

    with patch.object(GitleaksAdapter, "_get_gitleaks_command", return_value=None):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.returncode == 127
    assert "gitleaks not found" in adapter.error


def test_gitleaks_adapter_file_not_found_graceful():
    """subprocess raises FileNotFoundError if binary truly absent from PATH."""
    adapter = GitleaksAdapter()

    with (
        patch.object(GitleaksAdapter, "_get_gitleaks_command", return_value=["gitleaks"]),
        patch(
            "src.scanners.gitleaks_adapter.subprocess.run",
            side_effect=FileNotFoundError,
        ),
    ):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.returncode == 127
    assert adapter.error
