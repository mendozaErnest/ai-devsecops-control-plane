import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


class BanditAdapter(BaseScannerAdapter):
    tool_name = "bandit"

    def __init__(self) -> None:
        self.raw_output: dict = {}
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        bandit_command = self.get_bandit_command()

        if bandit_command is None:
            self.returncode = 127
            self.error = "Bandit is not installed or is not available in PATH."
            return []

        command = [
            *bandit_command,
            *self.build_target_arguments(target_path),
            "-f",
            "json",
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
            self.error = "Bandit is not installed or is not available in PATH."
            return []

        self.returncode = process.returncode

        try:
            self.raw_output = json.loads(process.stdout or "{}")
        except json.JSONDecodeError as exc:
            self.raw_output = {}
            self.error = f"Could not parse Bandit JSON output: {exc}"
            return []

        if process.returncode not in (0, 1):
            self.error = process.stderr.strip() or "Bandit scan failed."

        return [
            self.normalize_result(result)
            for result in self.raw_output.get("results", [])
        ]

    def get_bandit_command(self) -> list[str] | None:
        bandit_path = shutil.which("bandit")

        if bandit_path:
            return [bandit_path]

        env_bandit_path = Path(sys.executable).with_name("bandit")

        if env_bandit_path.exists():
            return [str(env_bandit_path)]

        return None

    def build_target_arguments(self, target_path: str) -> list[str]:
        path = Path(target_path)

        if path.is_dir():
            return ["-r", str(path)]

        return [str(path)]

    def normalize_result(self, result: dict) -> Finding:
        line_start = result.get("line_number")
        line_range = result.get("line_range") or []
        line_end = line_range[-1] if line_range else line_start

        return Finding(
            scan_id=uuid.UUID(int=0),
            rule_id=result.get("test_id", ""),
            title=result.get("test_name", result.get("test_id", "")),
            description=result.get("issue_text", ""),
            severity=result.get("issue_severity", "UNKNOWN"),
            confidence=result.get("issue_confidence", "UNKNOWN"),
            file_path=result.get("filename", ""),
            line_start=line_start,
            line_end=line_end,
            code_snippet=result.get("code"),
            status="open",
            fingerprint="",
        )
