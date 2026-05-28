import hashlib
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


PYLINT_SEVERITY_MAP = {
    "fatal": "HIGH",
    "error": "HIGH",
    "warning": "MEDIUM",
    "convention": "LOW",
    "refactor": "LOW",
    "info": "LOW",
}


class PylintAdapter(BaseScannerAdapter):
    tool_name = "pylint"

    def __init__(self) -> None:
        self.raw_output: list[dict] | dict = []
        self.returncode: int | None = None
        self.error: str | None = None

    def _get_pylint_command(self) -> list[str] | None:
        path = shutil.which("pylint")
        if path:
            return [path]
        env_path = Path(sys.executable).with_name("pylint")
        if env_path.exists():
            return [str(env_path)]
        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._get_pylint_command()
        if cmd is None:
            self.returncode = 127
            self.error = "pylint not found. Install with: pip install pylint"
            self.raw_output = {"error": self.error}
            return []

        command = [*cmd, "--output-format=json", "--exit-zero", target_path]
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            self.returncode = 127
            self.error = "pylint not found."
            self.raw_output = {"error": self.error}
            return []

        self.returncode = process.returncode
        stdout = process.stdout.strip()
        stderr = process.stderr.strip()

        try:
            parsed = json.loads(stdout or "[]")
        except json.JSONDecodeError:
            self.raw_output = {}
            self.error = f"Could not parse pylint JSON output: {stdout[:200]}"
            return []

        if not isinstance(parsed, list):
            self.raw_output = parsed
            self.error = "Unexpected pylint JSON output shape."
            return []

        self.raw_output = parsed
        if process.returncode not in (0,):
            self.error = stderr or "pylint scan failed."

        return [self.normalize_message(message) for message in parsed]

    def normalize_message(self, message: dict) -> Finding:
        rule_id = str(message.get("message-id") or message.get("symbol") or "pylint")
        symbol = str(message.get("symbol") or rule_id)
        path = str(message.get("path") or "")
        line = self._as_int(message.get("line"))
        msg_type = str(message.get("type") or "").lower()
        description = str(message.get("message") or symbol)

        return Finding(
            scan_id=uuid.UUID(int=0),
            tool="pylint",
            rule_id=rule_id,
            title=f"Pylint: {symbol}",
            description=description,
            severity=PYLINT_SEVERITY_MAP.get(msg_type, "LOW"),
            confidence="MEDIUM",
            file_path=path,
            line_start=line,
            line_end=line,
            code_snippet=description,
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
        source = f"pylint|{rule_id}|{path}|{line_start or ''}|{description}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def _as_int(self, value: object) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
