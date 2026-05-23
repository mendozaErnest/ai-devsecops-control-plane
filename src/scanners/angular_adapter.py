import re
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


SKIP_DIRECTORIES = {
    ".angular",
    ".git",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "tmp",
}


class AngularAdapter(BaseScannerAdapter):
    tool_name = "angular-static-rules"

    def __init__(self) -> None:
        self.raw_output: dict = {"results": [], "ruleset": "angular-static-rules"}
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        root = Path(target_path)
        findings: list[Finding] = []

        for file_path in self.iter_source_files(root):
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                self.error = f"Could not read {file_path}: {exc}"
                continue

            for index, line in enumerate(lines, start=1):
                findings.extend(self.evaluate_line(file_path, lines, index, line))

        self.returncode = 1 if findings else 0
        self.raw_output = {
            "results": [
                {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "description": finding.description,
                    "code": finding.code_snippet,
                }
                for finding in findings
            ],
            "metrics": {"files_scanned": len(list(self.iter_source_files(root)))},
            "ruleset": "angular-static-rules",
        }
        return findings

    def iter_source_files(self, root: Path):
        for file_path in root.rglob("*"):
            if not file_path.is_file():
                continue

            if any(part in SKIP_DIRECTORIES for part in file_path.parts):
                continue

            if file_path.suffix.lower() in {".ts", ".html"}:
                yield file_path

    def evaluate_line(
        self,
        file_path: Path,
        lines: list[str],
        line_number: int,
        line: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stripped = line.strip()

        if re.search(r"\bbypassSecurityTrust(?:Html|Script)\s*\(", stripped):
            findings.append(
                self.build_finding(
                    "ANG-XSS-001",
                    "Angular sanitizer bypass can enable DOM XSS",
                    "Use of DomSanitizer bypassSecurityTrustHtml/Script trusts attacker-controlled markup or script.",
                    "CRITICAL",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if self.has_unsafe_inner_html(stripped):
            findings.append(
                self.build_finding(
                    "ANG-XSS-002",
                    "Unsafe innerHTML binding",
                    "innerHTML is assigned or bound without an obvious sanitizer, which can introduce DOM XSS.",
                    "HIGH",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if self.has_lax_cors(stripped):
            findings.append(
                self.build_finding(
                    "ANG-CONFIG-001",
                    "Lax CORS origin configuration",
                    "Wildcard or permissive CORS configuration was found in frontend configuration code.",
                    "HIGH",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if self.has_exposed_token(file_path, stripped):
            findings.append(
                self.build_finding(
                    "ANG-SECRET-001",
                    "Exposed frontend token or secret",
                    "Environment or configuration file appears to contain a hardcoded token, API key, password, or secret.",
                    "CRITICAL",
                    file_path,
                    lines,
                    line_number,
                )
            )

        return findings

    def has_unsafe_inner_html(self, line: str) -> bool:
        if "innerHTML" not in line:
            return False

        if re.search(r"(sanitize|sanitizer|dompurify|safeHtml)", line, re.IGNORECASE):
            return False

        return bool(re.search(r"(\[innerHTML\]\s*=|\.innerHTML\s*=|innerHTML\s*:)", line))

    def has_lax_cors(self, line: str) -> bool:
        return bool(
            re.search(r"Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*", line, re.IGNORECASE)
            or re.search(r"(allowedOrigins|origin|origins)\s*[:=]\s*(\[[^\]]*['\"]\*['\"]|['\"]\*['\"])", line)
            or re.search(r"\bcors\s*[:=]\s*true\b", line, re.IGNORECASE)
        )

    def has_exposed_token(self, file_path: Path, line: str) -> bool:
        path_text = str(file_path).lower()

        if "environment" not in path_text and not re.search(r"(apiKey|token|secret|password|clientSecret)", line, re.IGNORECASE):
            return False

        return bool(
            re.search(
                r"(apiKey|accessToken|authToken|token|secret|password|clientSecret)\s*[:=]\s*['\"][A-Za-z0-9_\-./+=]{12,}['\"]",
                line,
                re.IGNORECASE,
            )
        )

    def build_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        file_path: Path,
        lines: list[str],
        line_number: int,
    ) -> Finding:
        return Finding(
            scan_id=uuid.UUID(int=0),
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence="HIGH",
            file_path=str(file_path),
            line_start=line_number,
            line_end=line_number,
            code_snippet=self.extract_context(lines, line_number),
            status="open",
            fingerprint="",
        )

    def extract_context(self, lines: list[str], line_number: int, radius: int = 2) -> str:
        start = max(1, line_number - radius)
        end = min(len(lines), line_number + radius)
        return "\n".join(
            f"{index}    {lines[index - 1]}"
            for index in range(start, end + 1)
        )
