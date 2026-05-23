"""OWASP Dependency Check adapter for Java SCA (CVE scanning of JARs/pom.xml).

Wraps the `dependency-check` CLI. If not installed, returns empty findings
so the combined scanner can still proceed with SAST results.

JSON report format reference:
  https://jeremylong.github.io/DependencyCheck/data/schema/
"""

import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter

_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

_WELL_KNOWN_LOCATIONS = [
    "/usr/local/bin/dependency-check",
    "/opt/dependency-check/bin/dependency-check.sh",
    "/opt/dependency-check/bin/dependency-check",
]


class OdcAdapter(BaseScannerAdapter):
    tool_name = "owasp-dependency-check"

    def __init__(self) -> None:
        self.raw_output: dict = {}
        self.returncode: int | None = None
        self.error: str | None = None

    def _find_odc_command(self) -> list[str] | None:
        for candidate in ("dependency-check", "dependency-check.sh"):
            path = shutil.which(candidate)
            if path:
                return [path]

        for location in _WELL_KNOWN_LOCATIONS:
            if Path(location).exists():
                return [location]

        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._find_odc_command()
        if cmd is None:
            self.returncode = 127
            self.error = (
                "dependency-check not found. "
                "Install from https://jeremylong.github.io/DependencyCheck/"
            )
            return []

        with tempfile.TemporaryDirectory() as out_dir:
            command = [
                *cmd,
                "--scan", target_path,
                "--format", "JSON",
                "--out", out_dir,
                "--noupdate",
                "--prettyPrint",
            ]

            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
            except FileNotFoundError:
                self.returncode = 127
                self.error = "dependency-check not found."
                return []

            self.returncode = process.returncode

            report_path = Path(out_dir) / "dependency-check-report.json"
            if not report_path.exists():
                self.error = process.stderr.strip() or "dependency-check produced no report."
                return []

            try:
                report = json.loads(report_path.read_text())
            except json.JSONDecodeError as exc:
                self.error = f"Could not parse dependency-check JSON report: {exc}"
                return []

            self.raw_output = report
            return self._parse_findings(report)

    def _parse_findings(self, report: dict) -> list[Finding]:
        findings: list[Finding] = []

        for dep in report.get("dependencies", []):
            vulns = dep.get("vulnerabilities", [])
            if not vulns:
                continue

            file_name = dep.get("fileName", "")
            file_path = dep.get("filePath", file_name)

            packages = dep.get("packages", [])
            pkg_id = packages[0].get("id", "") if packages else ""

            for vuln in vulns:
                name = vuln.get("name", "UNKNOWN")
                severity_raw = vuln.get("severity", "UNKNOWN").lower()
                severity = _SEVERITY_MAP.get(severity_raw, "UNKNOWN")
                description = vuln.get("description", "")

                cvssv3 = vuln.get("cvssv3", {})
                cvssv2 = vuln.get("cvssv2", {})
                base_score = cvssv3.get("baseScore") or cvssv2.get("score")

                fix_info = ""
                if vuln.get("vulnerableSoftware"):
                    versions = [
                        s.get("software", {}).get("version", "")
                        for s in vuln["vulnerableSoftware"]
                        if s.get("software", {}).get("versionEndExcluding")
                    ]
                    if versions:
                        fix_info = f"  # upgrade past {versions[0]}"

                score_label = f" (CVSS {base_score})" if base_score else ""
                title = f"Vulnerable dependency: {file_name} [{name}{score_label}]"

                findings.append(Finding(
                    scan_id=uuid.UUID(int=0),
                    rule_id=name,
                    title=title,
                    description=description,
                    severity=severity,
                    confidence="HIGH",
                    file_path=file_path,
                    line_start=None,
                    line_end=None,
                    code_snippet=f"{pkg_id}{fix_info}" if pkg_id else file_name,
                    status="open",
                    fingerprint="",
                ))

        return findings
