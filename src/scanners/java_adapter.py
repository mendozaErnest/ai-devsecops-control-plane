import re
import uuid
from pathlib import Path

from src.api.models import Finding
from src.scanners.base import BaseScannerAdapter


SKIP_DIRECTORIES = {
    ".git",
    ".gradle",
    "build",
    "out",
    "target",
}


class JavaAdapter(BaseScannerAdapter):
    tool_name = "java-static-rules"

    def __init__(self) -> None:
        self.raw_output: dict = {"results": [], "ruleset": "java-static-rules"}
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        root = Path(target_path)
        findings: list[Finding] = []
        files = list(self.iter_source_files(root))

        for file_path in files:
            try:
                lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                self.error = f"Could not read {file_path}: {exc}"
                continue

            for index, line in enumerate(lines, start=1):
                findings.extend(self.evaluate_line(file_path, lines, index, line))

            findings.extend(self.evaluate_rsa_key_sizes(file_path, lines))

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
            "metrics": {"files_scanned": len(files)},
            "ruleset": "java-static-rules",
        }
        return findings

    def iter_source_files(self, root: Path):
        for file_path in root.rglob("*.java"):
            if any(part in SKIP_DIRECTORIES for part in file_path.parts):
                continue

            if file_path.is_file():
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

        if re.search(r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\']\s*\)', stripped):
            findings.append(
                self.build_finding(
                    "JAVA-CRYPTO-001",
                    "Weak cryptographic digest",
                    "Legacy MD5 or SHA-1 hashing is vulnerable to collision attacks and unsuitable for security controls.",
                    "HIGH",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if re.search(r'Cipher\.getInstance\s*\(\s*["\']RSA(?:/[^"\']*)?["\']\s*\)', stripped):
            findings.append(
                self.build_finding(
                    "JAVA-CRYPTO-002",
                    "Raw or legacy RSA cipher usage",
                    "RSA cipher usage should specify modern padding and use keys of at least 2048 bits as a minimum baseline.",
                    "HIGH",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if self.has_sql_concatenation(stripped):
            findings.append(
                self.build_finding(
                    "JAVA-SQLI-001",
                    "JDBC query built with string concatenation",
                    "SQL query construction appears to concatenate user-controlled data instead of using bind parameters.",
                    "CRITICAL",
                    file_path,
                    lines,
                    line_number,
                )
            )

        if "ObjectInputStream" in stripped:
            findings.append(
                self.build_finding(
                    "JAVA-DESER-001",
                    "Unsafe Java deserialization primitive",
                    "ObjectInputStream can deserialize attacker-controlled object graphs unless strict allowlisting is enforced.",
                    "CRITICAL",
                    file_path,
                    lines,
                    line_number,
                )
            )

        return findings

    def evaluate_rsa_key_sizes(self, file_path: Path, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        for index, line in enumerate(lines, start=1):
            if not re.search(r'KeyPairGenerator\.getInstance\s*\(\s*["\']RSA["\']\s*\)', line):
                continue

            window = lines[index - 1:min(len(lines), index + 8)]
            window_text = "\n".join(window)
            key_size_match = re.search(r"\.initialize\s*\(\s*(\d{3,5})\s*\)", window_text)

            if key_size_match and int(key_size_match.group(1)) < 2048:
                findings.append(
                    self.build_finding(
                        "JAVA-CRYPTO-003",
                        "RSA key size below 2048 bits",
                        "RSA keys below 2048 bits are weak for modern systems and increase harvest-now-decrypt-later risk.",
                        "CRITICAL",
                        file_path,
                        lines,
                        index,
                    )
                )

        return findings

    def has_sql_concatenation(self, line: str) -> bool:
        query_call = re.search(r"\b(createStatement|executeQuery|executeUpdate|prepareStatement)\s*\(", line)
        sql_text = re.search(r'["\']\s*(SELECT|INSERT|UPDATE|DELETE)\b', line, re.IGNORECASE)
        return bool(query_call and sql_text and "+" in line)

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
