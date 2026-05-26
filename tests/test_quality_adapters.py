import json
import subprocess
from unittest.mock import patch

import httpx

from src.scanners.eslint_adapter import EslintAdapter
from src.scanners.pylint_adapter import PylintAdapter
from src.scanners.sonarqube_adapter import SonarQubeAdapter


def completed(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["scanner"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def test_pylint_adapter_normalizes_json_messages():
    payload = [
        {
            "type": "error",
            "module": "app",
            "path": "src/app.py",
            "line": 12,
            "symbol": "undefined-variable",
            "message-id": "E0602",
            "message": "Undefined variable 'name'",
        },
        {
            "type": "warning",
            "path": "src/app.py",
            "line": 20,
            "symbol": "unused-import",
            "message-id": "W0611",
            "message": "Unused import os",
        },
        {
            "type": "convention",
            "path": "src/app.py",
            "line": 1,
            "symbol": "missing-module-docstring",
            "message-id": "C0114",
            "message": "Missing module docstring",
        },
    ]

    with patch.object(PylintAdapter, "_get_pylint_command", return_value=["pylint"]), \
         patch("src.scanners.pylint_adapter.subprocess.run", return_value=completed(json.dumps(payload))):
        findings = PylintAdapter().execute_scan("src")

    assert [finding.severity for finding in findings] == ["HIGH", "MEDIUM", "LOW"]
    assert findings[0].rule_id == "E0602"
    assert findings[0].file_path == "src/app.py"
    assert findings[0].line_start == 12
    assert findings[0].fingerprint


def test_pylint_adapter_missing_binary_returns_no_findings():
    adapter = PylintAdapter()

    with patch.object(PylintAdapter, "_get_pylint_command", return_value=None):
        findings = adapter.execute_scan("src")

    assert findings == []
    assert adapter.returncode == 127
    assert "pylint not found" in adapter.error


def test_eslint_adapter_normalizes_json_messages(tmp_path):
    payload = [
        {
            "filePath": str(tmp_path / "src/app/app.component.ts"),
            "messages": [
                {
                    "ruleId": "@typescript-eslint/no-explicit-any",
                    "severity": 2,
                    "message": "Unexpected any. Specify a different type.",
                    "line": 8,
                    "endLine": 8,
                    "source": "const value: any = input;",
                },
                {
                    "ruleId": "no-console",
                    "severity": 1,
                    "message": "Unexpected console statement.",
                    "line": 12,
                },
            ],
        }
    ]

    with patch.object(EslintAdapter, "_get_eslint_command", return_value=(["eslint"], tmp_path)), \
         patch("src.scanners.eslint_adapter.subprocess.run", return_value=completed(json.dumps(payload), returncode=1)):
        findings = EslintAdapter().execute_scan(str(tmp_path))

    assert [finding.severity for finding in findings] == ["HIGH", "MEDIUM"]
    assert findings[0].rule_id == "@typescript-eslint/no-explicit-any"
    assert findings[0].file_path.endswith("app.component.ts")
    assert findings[0].line_start == 8
    assert findings[0].fingerprint


def test_eslint_adapter_missing_binary_returns_no_findings(tmp_path):
    adapter = EslintAdapter()

    with patch.object(EslintAdapter, "_get_eslint_command", return_value=(None, tmp_path)):
        findings = adapter.execute_scan(str(tmp_path))

    assert findings == []
    assert adapter.returncode == 127
    assert "eslint not found" in adapter.error


def test_sonarqube_adapter_normalizes_rest_issues(tmp_path):
    payload = {
        "issues": [
            {
                "key": "issue-1",
                "rule": "typescript:S3776",
                "component": "demo-project:src/app/app.component.ts",
                "line": 14,
                "message": "Refactor this function to reduce its Cognitive Complexity.",
                "severity": "MAJOR",
            },
            {
                "key": "issue-2",
                "rule": "python:S1481",
                "component": "demo-project:src/app.py",
                "textRange": {"startLine": 7},
                "message": "Remove this unused local variable.",
                "impacts": [{"severity": "HIGH"}],
            },
        ]
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/issues/search"
        assert request.url.params["componentKeys"] == "demo-project"
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    adapter = SonarQubeAdapter(
        base_url="http://sonarqube.local",
        token="token",
        project_key="demo-project",
    )

    with patch("src.scanners.sonarqube_adapter.httpx.Client", return_value=httpx.Client(transport=transport, base_url=adapter.base_url, auth=(adapter.token, ""))):
        findings = adapter.execute_scan(str(tmp_path))

    assert [finding.severity for finding in findings] == ["MEDIUM", "HIGH"]
    assert findings[0].rule_id == "typescript:S3776"
    assert findings[0].file_path.endswith("src/app/app.component.ts")
    assert findings[0].line_start == 14
    assert findings[0].fingerprint


def test_sonarqube_adapter_missing_token_returns_no_findings(tmp_path):
    adapter = SonarQubeAdapter(token="", project_key="demo-project")

    findings = adapter.execute_scan(str(tmp_path))

    assert findings == []
    assert adapter.returncode == 127
    assert "SONARQUBE_TOKEN" in adapter.error


def test_sonarqube_adapter_auth_failure_returns_clear_error(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(401, json={"errors": []}))
    adapter = SonarQubeAdapter(
        base_url="http://sonarqube.local",
        token="bad-token",
        project_key="demo-project",
    )

    with patch("src.scanners.sonarqube_adapter.httpx.Client", return_value=httpx.Client(transport=transport, base_url=adapter.base_url, auth=(adapter.token, ""))):
        findings = adapter.execute_scan(str(tmp_path))

    assert findings == []
    assert "authentication failed" in adapter.error
