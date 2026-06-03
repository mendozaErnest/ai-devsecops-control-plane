import json
import subprocess
from unittest.mock import patch

from src.scanners.trivy_adapter import TrivyAdapter


def _completed(stdout: str, returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess(
        args=["trivy"],
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


# ── Fixtures ──────────────────────────────────────────────────────────────────

_TRIVY_PAYLOAD = {
    "SchemaVersion": 2,
    "ArtifactName": "/project",
    "Results": [
        {
            "Target": "requirements.txt",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-32681",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Title": "Requests: proxy-authorization unintended leak",
                    "Description": "Since Requests v2.3.0, Requests has been leaking Proxy-Authorization headers.",
                    "Severity": "MEDIUM",
                    "CVSS": {
                        "nvd": {
                            "V3Score": 6.1,
                        }
                    },
                },
                {
                    "VulnerabilityID": "CVE-2024-12345",
                    "PkgName": "flask",
                    "InstalledVersion": "2.0.0",
                    "FixedVersion": "3.0.0",
                    "Title": "Flask critical RCE",
                    "Severity": "CRITICAL",
                    "CVSS": {
                        "nvd": {
                            "V3Score": 9.8,
                        }
                    },
                },
            ],
        },
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-44270",
                    "PkgName": "postcss",
                    "InstalledVersion": "8.4.20",
                    "FixedVersion": "8.4.31",
                    "Title": "PostCSS: line return parsing error",
                    "Severity": "MEDIUM",
                },
            ],
        },
    ],
}

_TRIVY_PAYLOAD_NO_SEVERITY = {
    "Results": [
        {
            "Target": "go.sum",
            "Class": "lang-pkgs",
            "Type": "gomod",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-99999",
                    "PkgName": "golang.org/x/net",
                    "InstalledVersion": "0.5.0",
                    "FixedVersion": "0.17.0",
                    "Title": "HTTP/2 rapid reset",
                    # No Severity field — falls back to CVSS
                    "CVSS": {"nvd": {"V3Score": 7.5}},
                }
            ],
        }
    ]
}


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_trivy_adapter_normalizes_vulnerabilities():
    with (
        patch.object(TrivyAdapter, "_get_trivy_command", return_value=["trivy"]),
        patch(
            "src.scanners.trivy_adapter.subprocess.run",
            return_value=_completed(json.dumps(_TRIVY_PAYLOAD)),
        ),
    ):
        findings = TrivyAdapter().execute_scan("/project")

    assert len(findings) == 3
    severities = [f.severity for f in findings]
    assert "CRITICAL" in severities
    assert severities.count("MEDIUM") == 2

    cve_finding = next(f for f in findings if f.rule_id == "CVE-2023-32681")
    assert cve_finding.severity == "MEDIUM"
    assert "requests" in cve_finding.description
    assert "2.31.0" in cve_finding.description   # fixed version in description
    assert cve_finding.tool == "trivy"
    assert cve_finding.fingerprint


def test_trivy_adapter_severity_from_cvss_when_absent():
    with (
        patch.object(TrivyAdapter, "_get_trivy_command", return_value=["trivy"]),
        patch(
            "src.scanners.trivy_adapter.subprocess.run",
            return_value=_completed(json.dumps(_TRIVY_PAYLOAD_NO_SEVERITY)),
        ),
    ):
        findings = TrivyAdapter().execute_scan("/project")

    assert len(findings) == 1
    assert findings[0].severity == "HIGH"   # V3Score 7.5 → HIGH


def test_trivy_adapter_missing_binary_returns_no_findings():
    adapter = TrivyAdapter()

    with patch.object(TrivyAdapter, "_get_trivy_command", return_value=None):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.returncode == 127
    assert "trivy not found" in adapter.error


def test_trivy_adapter_empty_stdout_returns_no_findings():
    adapter = TrivyAdapter()

    with (
        patch.object(TrivyAdapter, "_get_trivy_command", return_value=["trivy"]),
        patch(
            "src.scanners.trivy_adapter.subprocess.run",
            return_value=_completed("", stderr="connection refused"),
        ),
    ):
        findings = adapter.execute_scan("/project")

    assert findings == []
    assert adapter.error
