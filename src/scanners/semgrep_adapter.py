import hashlib
import json
import logging
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


LOGGER = logging.getLogger(__name__)
SEMGREP_TIMEOUT_SECONDS = 120

SEMGREP_RULESETS = {
    "python": ["p/bandit", "p/python", "p/owasp-top-ten"],
    "angular": ["p/javascript", "p/typescript", "p/owasp-top-ten"],
    "typescript": ["p/javascript", "p/typescript", "p/owasp-top-ten"],
    "java": ["p/java", "p/owasp-top-ten", "p/find-sec-bugs"],
}

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class SemgrepAdapter(BaseScannerAdapter):
    tool_name = "semgrep"

    def __init__(self, technology: str) -> None:
        self.technology = self.normalize_technology(technology)
        self.raw_output: dict = {
            "results": [],
            "errors": [],
            "rulesets": self.get_rulesets(self.technology),
        }
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        semgrep_command = self.get_semgrep_command()

        if semgrep_command is None:
            raise RuntimeError("semgrep no encontrado, instalar con pip install semgrep")

        findings: list[Finding] = []
        combined_results: list[dict] = []
        errors: list[dict] = []
        returncodes: list[int] = []

        for ruleset in self.get_rulesets(self.technology):
            command = [
                *semgrep_command,
                "--config",
                ruleset,
                "--json",
                target_path,
            ]

            try:
                process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=SEMGREP_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                message = f"Semgrep ruleset {ruleset} timed out after {SEMGREP_TIMEOUT_SECONDS} seconds."
                LOGGER.warning(message)
                errors.append({"ruleset": ruleset, "error": message})
                continue
            except FileNotFoundError as exc:
                raise RuntimeError("semgrep no encontrado, instalar con pip install semgrep") from exc

            returncodes.append(process.returncode)

            try:
                parsed_output = json.loads(process.stdout or "{}")
            except json.JSONDecodeError as exc:
                message = f"Could not parse Semgrep JSON output for {ruleset}: {exc}"
                errors.append({"ruleset": ruleset, "error": message})
                continue

            ruleset_results = parsed_output.get("results", [])
            combined_results.extend(ruleset_results)
            findings.extend(self.normalize_result(result) for result in ruleset_results)

            if process.returncode not in (0, 1):
                errors.append(
                    {
                        "ruleset": ruleset,
                        "returncode": process.returncode,
                        "stderr": process.stderr.strip(),
                    }
                )

        self.returncode = self.aggregate_returncode(findings, errors, returncodes)
        self.error = "; ".join(error.get("error") or error.get("stderr") or "" for error in errors).strip() or None
        self.raw_output = {
            "results": combined_results,
            "errors": errors,
            "rulesets": self.get_rulesets(self.technology),
            "metrics": {
                "rulesets_requested": len(self.get_rulesets(self.technology)),
                "rulesets_completed": len(returncodes),
                "total_findings": len(findings),
            },
        }
        return findings

    def get_semgrep_command(self) -> list[str] | None:
        semgrep_path = shutil.which("semgrep")

        if semgrep_path:
            return [semgrep_path]

        env_semgrep_path = Path(sys.executable).with_name("semgrep")

        if env_semgrep_path.exists():
            return [str(env_semgrep_path)]

        return None

    def get_rulesets(self, technology: str) -> list[str]:
        return SEMGREP_RULESETS.get(self.normalize_technology(technology), [])

    def normalize_result(self, result: dict) -> Finding:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        check_id = str(result.get("check_id", ""))
        file_path = str(result.get("path", ""))
        line_start = self.get_line(result.get("start"))
        line_end = self.get_line(result.get("end")) or line_start

        return Finding(
            scan_id=uuid.UUID(int=0),
            rule_id=check_id,
            title=self.build_title(check_id, metadata),
            description=str(extra.get("message") or check_id),
            severity=self.normalize_severity(extra.get("severity")),
            confidence="HIGH",
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=extra.get("lines"),
            status="open",
            fingerprint=self.generate_fingerprint(check_id, file_path, line_start),
        )

    def normalize_severity(self, severity: object) -> str:
        return SEVERITY_MAP.get(str(severity or "").upper(), "low")

    def generate_fingerprint(self, check_id: str, path: str, line_start: int | None) -> str:
        source = f"{check_id}{path}{line_start}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def normalize_technology(self, technology: str) -> str:
        normalized = technology.strip().lower()
        return "angular" if normalized == "typescript" else normalized

    def get_line(self, position: object) -> int | None:
        if not isinstance(position, dict):
            return None

        line = position.get("line")

        try:
            return int(line)
        except (TypeError, ValueError):
            return None

    def build_title(self, check_id: str, metadata: dict) -> str:
        cwe = metadata.get("cwe")

        if isinstance(cwe, list) and cwe:
            return f"{check_id} ({', '.join(str(item) for item in cwe)})"

        if cwe:
            return f"{check_id} ({cwe})"

        return check_id

    def aggregate_returncode(
        self,
        findings: list[Finding],
        errors: list[dict],
        returncodes: list[int],
    ) -> int:
        if findings:
            return 1

        if errors and not returncodes:
            return 2

        if any(code not in (0, 1) for code in returncodes):
            return 2

        return 0
