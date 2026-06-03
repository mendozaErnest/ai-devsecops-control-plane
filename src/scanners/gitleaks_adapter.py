import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


LOGGER = logging.getLogger(__name__)


class GitleaksAdapter(BaseScannerAdapter):
    tool_name = "gitleaks"

    def __init__(self) -> None:
        self.raw_output: list | dict = []
        self.returncode: int | None = None
        self.error: str | None = None

    def _get_gitleaks_command(self) -> list[str] | None:
        path = shutil.which("gitleaks")
        if path:
            return [path]
        return None

    def execute_scan(self, target_path: str) -> list[Finding]:
        cmd = self._get_gitleaks_command()
        if cmd is None:
            self.returncode = 127
            self.error = (
                "gitleaks not found. "
                "Install from https://github.com/gitleaks/gitleaks#installing"
            )
            self.raw_output = {"error": self.error}
            LOGGER.warning(self.error)
            return []

        report_fd, report_path = tempfile.mkstemp(suffix=".json", prefix="gitleaks-")
        os.close(report_fd)

        try:
            command = [
                *cmd,
                "detect",
                "--source", target_path,
                "--report-format", "json",
                "--report-path", report_path,
                "--no-git",
                "--exit-code", "0",   # always exit 0 so we can read the report
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
                self.error = "gitleaks not found."
                self.raw_output = {"error": self.error}
                LOGGER.warning(self.error)
                return []

            self.returncode = process.returncode

            # Read report file; gitleaks may return empty array when no leaks
            try:
                with open(report_path, encoding="utf-8") as fh:
                    content = fh.read().strip()
                parsed = json.loads(content) if content else []
            except (OSError, json.JSONDecodeError) as exc:
                self.error = f"Could not read gitleaks report: {exc}"
                LOGGER.warning("Gitleaks: %s", self.error)
                return []

            if not isinstance(parsed, list):
                self.error = "Unexpected gitleaks JSON output shape."
                return []

            self.raw_output = parsed
            return [self._normalize_leak(leak) for leak in parsed if isinstance(leak, dict)]

        finally:
            try:
                os.unlink(report_path)
            except OSError:
                pass

    def _normalize_leak(self, leak: dict) -> Finding:
        rule_id = str(leak.get("RuleID") or leak.get("rule") or "secret-detected")
        description = str(leak.get("Description") or leak.get("Match") or rule_id)
        file_path = str(leak.get("File") or leak.get("file") or "")
        line_start = self._as_int(leak.get("StartLine") or leak.get("line"))
        line_end = self._as_int(leak.get("EndLine")) or line_start
        snippet = str(leak.get("Match") or leak.get("Secret") or "")[:200]

        fingerprint_source = (
            f"gitleaks|{rule_id}|{file_path}|{line_start or ''}|{snippet[:50]}"
        )
        fingerprint = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()

        return Finding(
            scan_id=uuid.UUID(int=0),
            tool="gitleaks",
            rule_id=rule_id,
            title=f"Gitleaks: {rule_id}",
            description=description,
            severity="HIGH",   # secrets are always high-risk
            confidence="HIGH",
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet,
            status="open",
            fingerprint=fingerprint,
        )

    def _as_int(self, value: object) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
