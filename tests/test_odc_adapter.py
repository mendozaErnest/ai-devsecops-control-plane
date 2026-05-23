import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.scanners.odc_adapter import OdcAdapter


ODC_REPORT = {
    "dependencies": [
        {
            "fileName": "log4j-core-2.14.1.jar",
            "filePath": "/app/libs/log4j-core-2.14.1.jar",
            "packages": [{"id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}],
            "vulnerabilities": [
                {
                    "name": "CVE-2021-44228",
                    "severity": "CRITICAL",
                    "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                    "cvssv3": {"baseScore": 10.0},
                    "vulnerableSoftware": [
                        {"software": {"version": "2.14.1", "versionEndExcluding": "2.15.0"}}
                    ],
                }
            ],
        },
        {
            "fileName": "commons-text-1.9.jar",
            "filePath": "/app/libs/commons-text-1.9.jar",
            "packages": [{"id": "pkg:maven/org.apache.commons/commons-text@1.9"}],
            "vulnerabilities": [],
        },
    ]
}


def _run_adapter_with_report(report: dict, returncode: int = 1):
    with tempfile.TemporaryDirectory() as out_dir:
        report_file = Path(out_dir) / "dependency-check-report.json"
        report_file.write_text(json.dumps(report))

        mock_process = MagicMock()
        mock_process.returncode = returncode
        mock_process.stdout = ""
        mock_process.stderr = ""

        with patch("subprocess.run", return_value=mock_process):
            with patch("shutil.which", return_value="/usr/bin/dependency-check"):
                with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                    mock_tmpdir.return_value.__enter__ = lambda s: out_dir
                    mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
                    adapter = OdcAdapter()
                    findings = adapter.execute_scan("/app")

    return adapter, findings


def test_odc_finds_log4shell():
    adapter, findings = _run_adapter_with_report(ODC_REPORT)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CVE-2021-44228"
    assert "log4j-core-2.14.1.jar" in f.title
    assert "(CVSS 10.0)" in f.title
    assert f.severity == "CRITICAL"
    assert f.confidence == "HIGH"
    assert "log4j-core" in f.file_path
    assert "pkg:maven" in f.code_snippet


def test_odc_skips_deps_without_vulns():
    adapter, findings = _run_adapter_with_report(ODC_REPORT)
    titles = [f.title for f in findings]
    assert not any("commons-text" in t for t in titles)


def test_odc_severity_mapping():
    report = {
        "dependencies": [{
            "fileName": "some.jar",
            "filePath": "/app/some.jar",
            "packages": [{"id": "pkg:maven/org/some@1.0"}],
            "vulnerabilities": [
                {"name": "CVE-1111-0001", "severity": "HIGH", "description": "High sev vuln.", "cvssv3": {"baseScore": 7.5}},
                {"name": "CVE-1111-0002", "severity": "MEDIUM", "description": "Medium sev.", "cvssv2": {"score": 5.0}},
                {"name": "CVE-1111-0003", "severity": "LOW", "description": "Low sev.", "cvssv3": {}},
            ],
        }]
    }
    adapter, findings = _run_adapter_with_report(report)

    severities = {f.rule_id: f.severity for f in findings}
    assert severities["CVE-1111-0001"] == "HIGH"
    assert severities["CVE-1111-0002"] == "MEDIUM"
    assert severities["CVE-1111-0003"] == "LOW"


def test_odc_not_installed_returns_empty():
    with patch("shutil.which", return_value=None):
        with patch("pathlib.Path.exists", return_value=False):
            adapter = OdcAdapter()
            findings = adapter.execute_scan("/app")

    assert findings == []
    assert adapter.returncode == 127
    assert "dependency-check" in adapter.error


def test_odc_no_report_file_returns_empty():
    mock_process = MagicMock()
    mock_process.returncode = 1
    mock_process.stdout = ""
    mock_process.stderr = "NVD update failed"

    with tempfile.TemporaryDirectory() as out_dir:
        with patch("subprocess.run", return_value=mock_process):
            with patch("shutil.which", return_value="/usr/bin/dependency-check"):
                with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
                    mock_tmpdir.return_value.__enter__ = lambda s: out_dir
                    mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
                    adapter = OdcAdapter()
                    findings = adapter.execute_scan("/app")

    assert findings == []
    assert adapter.error is not None
