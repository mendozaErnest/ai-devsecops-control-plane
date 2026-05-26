import hashlib
import logging
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import httpx

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter

logger = logging.getLogger(__name__)

SONAR_SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "HIGH": "HIGH",
    "MAJOR": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "MINOR": "LOW",
    "LOW": "LOW",
    "INFO": "LOW",
}


def _sonar_env() -> tuple[str, str, str]:
    """Returns (base_url, token, project_key) from environment."""
    base_url = (os.getenv("SONARQUBE_URL") or "http://localhost:9000").rstrip("/")
    token = os.getenv("SONARQUBE_TOKEN", "")
    project_key = (
        os.getenv("SONARQUBE_PROJECT_KEY")
        or os.getenv("SONAR_PROJECT_KEY")
        or ""
    )
    return base_url, token, project_key


def run_sonar_scan(target_path: str) -> dict:
    """Execute sonar-scanner CLI against target_path.

    Raises RuntimeError if CLI is not in PATH or the scan fails.
    """
    base_url, token, project_key = _sonar_env()

    _FALLBACK_PATHS = [
        Path.home() / ".local" / "bin" / "sonar-scanner",
        Path("/opt/sonar-scanner/bin/sonar-scanner"),
        Path("/usr/local/bin/sonar-scanner"),
    ]

    scanner_bin = shutil.which("sonar-scanner") or next(
        (str(p) for p in _FALLBACK_PATHS if p.exists()), None
    )
    if not scanner_bin:
        raise RuntimeError(
            "sonar-scanner not found in PATH. "
            "Install from: https://docs.sonarsource.com/sonarqube/latest/"
            "analyzing-source-code/scanners/sonarscanner/"
        )

    if not project_key:
        project_key = re.sub(
            r"[^A-Za-z0-9_.:-]+", "-", Path(target_path).resolve().name or "project"
        ).strip("-")

    cmd = [
        scanner_bin,
        f"-Dsonar.projectKey={project_key}",
        f"-Dsonar.sources={target_path}",
        f"-Dsonar.host.url={base_url}",
        f"-Dsonar.token={token}",
        "-Dsonar.language=py",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(
            f"sonar-scanner failed (rc={result.returncode}): {result.stderr[:500]}"
        )

    return {"status": "scan_submitted", "stdout": result.stdout[-1000:]}


def fetch_sonar_issues(page_size: int = 500) -> list[dict]:
    """Fetch unresolved issues from SonarQube REST API using env vars."""
    base_url, token, project_key = _sonar_env()

    if not token:
        raise ValueError("SONARQUBE_TOKEN is not configured in .env")
    if not project_key:
        raise ValueError("SONARQUBE_PROJECT_KEY is not configured in .env")

    url = f"{base_url}/api/issues/search"
    params = {"componentKeys": project_key, "ps": page_size, "resolved": "false"}
    headers = {"Authorization": f"Bearer {token}"}

    with httpx.Client(timeout=30) as client:
        response = client.get(url, params=params, headers=headers)

    if response.status_code == 401:
        raise PermissionError(
            "Invalid or expired SonarQube token. Check SONARQUBE_TOKEN in .env"
        )
    if response.status_code == 404:
        raise ValueError(
            f"Project '{project_key}' not found in SonarQube. Did you create it?"
        )
    response.raise_for_status()

    return response.json().get("issues", [])


class SonarQubeAdapter(BaseScannerAdapter):
    tool_name = "sonarqube"

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        project_key: str | None = None,
    ) -> None:
        env_base_url, env_token, env_project_key = _sonar_env()
        self.base_url = (base_url or env_base_url).rstrip("/")
        self.token = token if token is not None else env_token
        self.project_key = project_key or env_project_key
        self.raw_output: dict = {}
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        if not self.token:
            self.returncode = 127
            self.error = "SONARQUBE_TOKEN is not configured."
            self.raw_output = {"error": self.error}
            return []

        project_key = self.project_key or self.derive_project_key(target_path)
        if not project_key:
            self.returncode = 127
            self.error = "SONARQUBE_PROJECT_KEY is not configured and could not be derived."
            self.raw_output = {"error": self.error}
            return []

        # SonarQube Community v26+ uses Bearer token authentication
        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            with httpx.Client(
                base_url=self.base_url, timeout=30.0, headers=headers
            ) as client:
                response = client.get(
                    "/api/issues/search",
                    params={
                        "componentKeys": project_key,
                        "resolved": "false",
                        "ps": "500",
                    },
                )
        except httpx.HTTPError as exc:
            self.returncode = 2
            self.error = f"Could not connect to SonarQube: {exc}"
            self.raw_output = {"error": self.error}
            return []

        self.returncode = 0 if response.status_code == 200 else 2
        try:
            parsed = response.json()
        except ValueError:
            self.error = f"Could not parse SonarQube response: {response.text[:200]}"
            self.raw_output = {}
            return []

        self.raw_output = parsed
        if response.status_code in (401, 403):
            self.error = "SonarQube authentication failed. Check SONARQUBE_TOKEN."
            return []
        if response.status_code != 200:
            self.error = (
                self.extract_error(parsed)
                or f"SonarQube API returned HTTP {response.status_code}"
            )
            return []

        issues = parsed.get("issues", [])
        if not isinstance(issues, list):
            self.error = "Unexpected SonarQube issues response shape."
            return []

        return [self.normalize_issue(issue, target_path, project_key) for issue in issues]

    def derive_project_key(self, target_path: str) -> str:
        name = Path(target_path).resolve().name or "project"
        return re.sub(r"[^A-Za-z0-9_.:-]+", "-", name).strip("-")

    def normalize_issue(self, issue: dict, target_path: str, project_key: str) -> Finding:
        rule_id = str(issue.get("rule") or issue.get("key") or "sonarqube")
        message = str(issue.get("message") or rule_id)
        line = self._as_int(issue.get("line") or issue.get("textRange", {}).get("startLine"))
        component_path = self.normalize_component_path(
            str(issue.get("component") or ""),
            target_path,
            project_key,
        )

        return Finding(
            scan_id=uuid.UUID(int=0),
            rule_id=rule_id,
            title=f"SonarQube: {rule_id}",
            description=message,
            severity=self.normalize_severity(issue),
            confidence="MEDIUM",
            file_path=component_path,
            line_start=line,
            line_end=line,
            code_snippet=message,
            status="open",
            fingerprint=self.generate_fingerprint(issue, rule_id, component_path, line, message),
        )

    def normalize_component_path(
        self, component: str, target_path: str, project_key: str
    ) -> str:
        path = component
        prefix = f"{project_key}:"
        if path.startswith(prefix):
            path = path[len(prefix):]
        elif ":" in path:
            path = path.split(":", 1)[1]

        if not path:
            return target_path

        component_path = Path(path)
        if component_path.is_absolute():
            return str(component_path)

        return str((Path(target_path) / component_path).resolve())

    def normalize_severity(self, issue: dict) -> str:
        severity = str(issue.get("severity") or "").upper()
        if severity:
            return SONAR_SEVERITY_MAP.get(severity, "LOW")

        impacts = issue.get("impacts") or []
        if impacts and isinstance(impacts, list):
            impact_severity = str(impacts[0].get("severity") or "").upper()
            return SONAR_SEVERITY_MAP.get(impact_severity, "LOW")

        return "LOW"

    def generate_fingerprint(
        self,
        issue: dict,
        rule_id: str,
        path: str,
        line_start: int | None,
        message: str,
    ) -> str:
        issue_key = issue.get("key")
        source = f"sonarqube|{issue_key or ''}|{rule_id}|{path}|{line_start or ''}|{message}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    def extract_error(self, payload: dict) -> str | None:
        errors = payload.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                return first.get("msg") or first.get("message")
        return None

    def _as_int(self, value: object) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
