import json
import subprocess
from unittest.mock import patch

from src.scanners.checkov_adapter import CheckovAdapter


def _completed(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["checkov"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

_SINGLE_FRAMEWORK_PAYLOAD = {
    "results": {
        "passed_checks": [],
        "failed_checks": [
            {
                "check_id": "CKV_DOCKER_2",
                "check": {"name": "Ensure that HEALTHCHECK instructions have been added"},
                "file_path": "/Dockerfile",
                "file_line_range": [1, 3],
                "severity": "HIGH",
                "resource": "Dockerfile.",
            },
            {
                "check_id": "CKV_K8S_14",
                "check": {"name": "Image should use a tag"},
                "file_path": "/k8s/deployment.yaml",
                "file_line_range": [10, 10],
                "severity": "MEDIUM",
                "resource": "Deployment.default.myapp",
            },
            {
                "check_id": "CKV_TF_1",
                "check": {"name": "Ensure module sources use a commit hash"},
                "file_path": "/terraform/main.tf",
                "file_line_range": [5, 5],
                # severity absent → should default to MEDIUM
                "resource": "module.vpc",
            },
        ],
    }
}

_MULTI_FRAMEWORK_PAYLOAD = [
    {
        "check_type": "dockerfile",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_DOCKER_1",
                    "check": {"name": "Ensure a user is specified"},
                    "file_path": "/Dockerfile",
                    "file_line_range": [1, 1],
                    "severity": "HIGH",
                    "resource": "Dockerfile.",
                }
            ]
        },
    },
    {
        "check_type": "kubernetes",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_1",
                    "check": {"name": "Do not admit root containers"},
                    "file_path": "/k8s/pod.yaml",
                    "file_line_range": [1, 5],
                    "severity": "CRITICAL",
                    "resource": "Pod.default.myapp",
                }
            ]
        },
    },
]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_checkov_adapter_normalizes_single_framework_json():
    with (
        patch.object(CheckovAdapter, "_get_checkov_command", return_value=["checkov"]),
        patch(
            "src.scanners.checkov_adapter.subprocess.run",
            return_value=_completed(json.dumps(_SINGLE_FRAMEWORK_PAYLOAD)),
        ),
    ):
        findings = CheckovAdapter().execute_scan("/project")

    assert len(findings) == 3
    assert [f.severity for f in findings] == ["HIGH", "MEDIUM", "MEDIUM"]
    assert findings[0].rule_id == "CKV_DOCKER_2"
    assert findings[0].file_path == "/Dockerfile"
    assert findings[0].line_start == 1
    assert findings[0].tool == "checkov"
    assert findings[0].fingerprint


def test_checkov_adapter_normalizes_multi_framework_json():
    with (
        patch.object(CheckovAdapter, "_get_checkov_command", return_value=["checkov"]),
        patch(
            "src.scanners.checkov_adapter.subprocess.run",
            return_value=_completed(json.dumps(_MULTI_FRAMEWORK_PAYLOAD)),
        ),
    ):
        findings = CheckovAdapter().execute_scan("/project")

    assert len(findings) == 2
    assert findings[0].rule_id == "CKV_DOCKER_1"
    assert findings[0].severity == "HIGH"
    assert findings[1].rule_id == "CKV_K8S_1"
    assert findings[1].severity == "CRITICAL"


def test_checkov_adapter_missing_binary_returns_no_findings():
    adapter = CheckovAdapter()

    with patch.object(CheckovAdapter, "_get_checkov_command", return_value=None):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.returncode == 127
    assert "checkov not found" in adapter.error


def test_checkov_adapter_empty_stdout_returns_no_findings():
    adapter = CheckovAdapter()

    with (
        patch.object(CheckovAdapter, "_get_checkov_command", return_value=["checkov"]),
        patch(
            "src.scanners.checkov_adapter.subprocess.run",
            return_value=_completed("", returncode=0, stderr="some error"),
        ),
    ):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.error
