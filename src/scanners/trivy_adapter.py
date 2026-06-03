import hashlib
import json
import logging
import shutil
import subprocess
import uuid

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


LOGGER = logging.getLogger(__name__)

# Trivy CVSS-based severity map (also used as direct severity fallback)
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "unknown": "LOW",
    "none": "LOW",
}

# CVSS V3 score → severity when Trivy Severity field is absent
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


class TrivyAdapter(BaseScannerAdapter):
    tool_name = "trivy"

    def __init__(self) -> None:
        self.raw_output: dict = {}
        self.returncode: int | None = None
        self.error: str | None = None

    def _get_trivy_command(self) -> list[str] | None:
        path = shutil.which("trivy")
        if path:
            return [path]
        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._get_trivy_command()
        if cmd is None:
            self.returncode = 127
            self.error = (
                "trivy not found. "
                "Install from https://aquasecurity.github.io/trivy/latest/getting-started/installation/"
            )
            self.raw_output = {"error": self.error}
            LOGGER.warning(self.error)
            return []

        command = [*cmd, "fs", "--format", "json", target_path]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            self.returncode = 127
            self.error = "trivy not found."
            self.raw_output = {"error": self.error}
            LOGGER.warning(self.error)
            return []

        self.returncode = process.returncode
        stdout = (process.stdout or "").strip()

        if not stdout:
            self.error = (process.stderr or "").strip() or "trivy returned no output"
            LOGGER.warning("Trivy: %s", self.error)
            return []

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            self.raw_output = {}
            self.error = f"Could not parse trivy JSON output: {stdout[:200]}"
            LOGGER.warning("Trivy JSON parse error: %s", self.error)
            return []

        self.raw_output = parsed
        if not isinstance(parsed, dict):
            self.error = "Unexpected trivy JSON output shape."
            return []

        return self._extract_findings(parsed)

    def _extract_findings(self, parsed: dict) -> list[Finding]:
        results = parsed.get("Results") or []
        if not isinstance(results, list):
            return []

        findings: list[Finding] = []
        for result in results:
            target = str(result.get("Target") or "")
            vulns = result.get("Vulnerabilities") or []
            if not isinstance(vulns, list):
                continue
            for vuln in vulns:
                finding = self._normalize_vuln(vuln, target)
                if finding:
                    findings.append(finding)

        return findings

    def _normalize_vuln(self, vuln: dict, target: str) -> Finding | None:
        if not isinstance(vuln, dict):
            return None

        cve_id = str(vuln.get("VulnerabilityID") or "CVE-UNKNOWN")
        pkg_name = str(vuln.get("PkgName") or "unknown")
        installed_version = str(vuln.get("InstalledVersion") or "")
        fixed_version = str(vuln.get("FixedVersion") or "")
        title = str(vuln.get("Title") or vuln.get("Description") or cve_id)

        # Severity: prefer direct Trivy Severity over CVSS score
        raw_severity = str(vuln.get("Severity") or "").lower()
        severity = _SEVERITY_MAP.get(raw_severity)
        if not severity:
            cvss_score = self._extract_cvss_score(vuln)
            severity = _cvss_to_severity(cvss_score) if cvss_score is not None else "MEDIUM"

        description_parts = [f"{pkg_name}@{installed_version}: {title}"]
        if fixed_version:
            description_parts.append(f"Fix: upgrade to {fixed_version}")
        description = " — ".join(description_parts)

        fingerprint_source = f"trivy|{cve_id}|{pkg_name}|{target}"
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()

        return Finding(
            scan_id=uuid.UUID(int=0),
            tool="trivy",
            rule_id=cve_id,
            title=f"Trivy: {cve_id} in {pkg_name}",
            description=description,
            severity=severity,
            confidence="HIGH",
            file_path=target,
            line_start=None,
            line_end=None,
            code_snippet=f"{pkg_name}@{installed_version}",
            status="open",
            fingerprint=fingerprint,
        )

    def _extract_cvss_score(self, vuln: dict) -> float | None:
        cvss = vuln.get("CVSS") or {}
        if not isinstance(cvss, dict):
            return None
        for source_data in cvss.values():
            if not isinstance(source_data, dict):
                continue
            v3 = source_data.get("V3Score")
            if v3 is not None:
                try:
                    return float(v3)
                except (TypeError, ValueError):
                    pass
            v2 = source_data.get("V2Score")
            if v2 is not None:
                try:
                    return float(v2)
                except (TypeError, ValueError):
                    pass
        return None
