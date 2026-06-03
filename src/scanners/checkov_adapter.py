import hashlib
import json
import logging
import shutil
import subprocess
import uuid

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


LOGGER = logging.getLogger(__name__)

# Checkov uses HIGH/MEDIUM/LOW/CRITICAL/INFO; normalise to our schema
_SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "LOW",
    "unknown": "MEDIUM",
}


class CheckovAdapter(BaseScannerAdapter):
    tool_name = "checkov"

    def __init__(self) -> None:
        self.raw_output: list | dict = []
        self.returncode: int | None = None
        self.error: str | None = None

    def _get_checkov_command(self) -> list[str] | None:
        path = shutil.which("checkov")
        if path:
            return [path]
        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._get_checkov_command()
        if cmd is None:
            self.returncode = 127
            self.error = "checkov not found. Install with: pip install checkov"
            self.raw_output = {"error": self.error}
            LOGGER.warning(self.error)
            return []

        command = [*cmd, "-d", target_path, "--compact", "-o", "json"]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            self.returncode = 127
            self.error = "checkov not found."
            self.raw_output = {"error": self.error}
            LOGGER.warning(self.error)
            return []

        self.returncode = process.returncode
        stdout = (process.stdout or "").strip()

        if not stdout:
            self.error = (process.stderr or "").strip() or "checkov returned no output"
            LOGGER.warning("Checkov: %s", self.error)
            return []

        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError:
            self.raw_output = {}
            self.error = f"Could not parse checkov JSON output: {stdout[:200]}"
            LOGGER.warning("Checkov JSON parse error: %s", self.error)
            return []

        self.raw_output = parsed
        return self._extract_findings(parsed)

    def _extract_findings(self, parsed: list | dict) -> list[Finding]:
        # Checkov can return a list (multi-framework) or a dict (single framework)
        if isinstance(parsed, dict):
            blocks = [parsed]
        elif isinstance(parsed, list):
            blocks = parsed
        else:
            return []

        findings: list[Finding] = []
        for block in blocks:
            results = block.get("results") or block.get("check_results") or {}
            if not isinstance(results, dict):
                continue
            failed_checks = results.get("failed_checks") or []
            if not isinstance(failed_checks, list):
                continue
            for check in failed_checks:
                finding = self._normalize_check(check)
                if finding:
                    findings.append(finding)

        return findings

    def _normalize_check(self, check: dict) -> Finding | None:
        if not isinstance(check, dict):
            return None

        check_id = str(check.get("check_id") or "CKV-UNKNOWN")

        # check name can be nested in check.check or at top level
        inner = check.get("check") or {}
        check_name = str(inner.get("name") or check.get("check_name") or check_id)

        file_path = str(check.get("file_path") or check.get("file_abs_path") or "")

        line_range = check.get("file_line_range") or []
        line_start = int(line_range[0]) if line_range else None
        line_end = int(line_range[1]) if len(line_range) > 1 else line_start

        # Severity: try top-level first, then nested check.severity
        raw_severity = (
            str(check.get("severity") or inner.get("severity") or "").lower()
        )
        severity = _SEVERITY_MAP.get(raw_severity, "MEDIUM")

        resource = str(check.get("resource") or "")
        description = check_name
        if resource:
            description = f"{check_name} [{resource}]"

        fingerprint_source = f"checkov|{check_id}|{file_path}|{line_start or ''}"
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()

        return Finding(
            scan_id=uuid.UUID(int=0),
            tool="checkov",
            rule_id=check_id,
            title=f"Checkov: {check_id}",
            description=description,
            severity=severity,
            confidence="HIGH",
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=description,
            status="open",
            fingerprint=fingerprint,
        )
