import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter

_REQ_FILENAMES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "requirements/base.txt",
    "requirements/prod.txt",
]


def _infer_severity(vuln: dict) -> str:
    aliases = vuln.get("aliases", [])
    if any(a.startswith("CVE-") or a.startswith("GHSA-") for a in aliases):
        return "HIGH"
    return "MEDIUM"


class PipAuditAdapter(BaseScannerAdapter):
    tool_name = "pip-audit"

    def __init__(self) -> None:
        self.raw_output: dict = {}
        self.returncode: int | None = None
        self.error: str | None = None

    def _find_requirements_file(self, target_path: str) -> Path | None:
        p = Path(target_path)
        if p.is_file() and p.suffix == ".txt":
            return p
        if p.is_dir():
            for name in _REQ_FILENAMES:
                candidate = p / name
                if candidate.exists():
                    return candidate
        return None

    def _get_pip_audit_command(self) -> list[str] | None:
        path = shutil.which("pip-audit")
        if path:
            return [path]
        env_path = Path(sys.executable).with_name("pip-audit")
        if env_path.exists():
            return [str(env_path)]
        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._get_pip_audit_command()
        if cmd is None:
            self.returncode = 127
            self.error = "pip-audit not found. Install with: pip install pip-audit"
            return []

        req_file = self._find_requirements_file(target_path)
        if req_file is None:
            self.returncode = 0
            self.raw_output = {"dependencies": [], "skipped": "no requirements file found"}
            return []

        command = [*cmd, "--format", "json", "--output", "-", "-r", str(req_file)]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            self.returncode = 127
            self.error = "pip-audit not found."
            return []

        self.returncode = process.returncode

        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        # pip-audit emits informational lines to stderr before JSON on stdout
        try:
            self.raw_output = json.loads(stdout or "{}")
        except json.JSONDecodeError:
            self.raw_output = {}
            self.error = f"Could not parse pip-audit JSON output: {stdout[:200]}"
            return []

        if process.returncode not in (0, 1):
            self.error = stderr or "pip-audit scan failed."

        findings: list[Finding] = []
        for dep in self.raw_output.get("dependencies", []):
            pkg = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []):
                vuln_id = vuln.get("id", "UNKNOWN")
                aliases = vuln.get("aliases", [])
                cve = next((a for a in aliases if a.startswith("CVE-")), None)
                rule_id = cve or vuln_id
                fix = ", ".join(vuln.get("fix_versions", [])) or "no fix available"
                description = vuln.get("description", "")

                findings.append(Finding(
                    scan_id=uuid.UUID(int=0),
                    rule_id=rule_id,
                    title=f"Vulnerable dependency: {pkg}@{version} ({vuln_id})",
                    description=description,
                    severity=_infer_severity(vuln),
                    confidence="HIGH",
                    file_path=str(req_file),
                    line_start=None,
                    line_end=None,
                    code_snippet=f"{pkg}=={version}  # fix: {fix}",
                    status="open",
                    fingerprint="",
                ))

        # returncode 1 means vulnerabilities found — treat as success
        if self.returncode == 1 and findings:
            self.returncode = 1
        elif self.returncode == 0:
            self.returncode = 0

        return findings
