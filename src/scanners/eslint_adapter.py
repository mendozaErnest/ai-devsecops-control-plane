import hashlib
import json
import shutil
import subprocess
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


ESLINT_SEVERITY_MAP = {
    2: "HIGH",
    1: "MEDIUM",
    0: "LOW",
}


class EslintAdapter(BaseScannerAdapter):
    tool_name = "eslint"

    def __init__(self) -> None:
        self.raw_output: list[dict] | dict = []
        self.returncode: int | None = None
        self.error: str | None = None

    def _get_eslint_command(self, target_path: str) -> tuple[list[str] | None, Path | None]:
        target = Path(target_path).resolve()
        search_dir = target if target.is_dir() else target.parent

        for directory in [search_dir, *search_dir.parents]:
            local_eslint = directory / "node_modules" / ".bin" / "eslint"
            if local_eslint.exists():
                return [str(local_eslint)], directory

        npx = shutil.which("npx")
        if npx:
            return [npx, "--no-install", "eslint"], search_dir

        return None, search_dir

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd, cwd = self._get_eslint_command(target_path)
        if cmd is None:
            self.returncode = 127
            self.error = "eslint not found. Install project dependencies or provide npx."
            self.raw_output = {"error": self.error}
            return []

        command = [*cmd, "--format", "json", target_path]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                cwd=str(cwd) if cwd else None,
            )
        except FileNotFoundError:
            self.returncode = 127
            self.error = "eslint not found."
            self.raw_output = {"error": self.error}
            return []

        self.returncode = process.returncode
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        try:
            parsed = json.loads(stdout or "[]")
        except json.JSONDecodeError:
            self.raw_output = {}
            self.error = f"Could not parse eslint JSON output: {stdout[:200] or stderr[:200]}"
            return []

        if not isinstance(parsed, list):
            self.raw_output = parsed
            self.error = "Unexpected eslint JSON output shape."
            return []

        self.raw_output = parsed
        findings = [
            self.normalize_message(file_result, message)
            for file_result in parsed
            for message in file_result.get("messages", [])
        ]

        # ESLint returns 1 for lint findings and 2 for configuration/runtime errors.
        if process.returncode == 2 and not findings:
            self.error = stderr or "eslint scan failed."
        elif process.returncode not in (0, 1, 2):
            self.error = stderr or "eslint scan failed."

        return findings

    def normalize_message(self, file_result: dict, message: dict) -> Finding:
        path = str(file_result.get("filePath") or "")
        rule_id = str(message.get("ruleId") or "eslint-parser")
        line = self._as_int(message.get("line"))
        end_line = self._as_int(message.get("endLine")) or line
        description = str(message.get("message") or rule_id)
        eslint_severity = self._as_int(message.get("severity")) or 0

        return Finding(
            scan_id=uuid.UUID(int=0),
            rule_id=rule_id,
            title=f"ESLint: {rule_id}",
            description=description,
            severity=ESLINT_SEVERITY_MAP.get(eslint_severity, "LOW"),
            confidence="MEDIUM",
            file_path=path,
            line_start=line,
            line_end=end_line,
            code_snippet=message.get("source") or description,
            status="open",
            fingerprint=self.generate_fingerprint(rule_id, path, line, description),
        )

    def generate_fingerprint(
        self,
        rule_id: str,
        path: str,
        line_start: int | None,
        description: str,
    ) -> str:
        source = f"eslint|{rule_id}|{path}|{line_start or ''}|{description}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def _as_int(self, value: object) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
