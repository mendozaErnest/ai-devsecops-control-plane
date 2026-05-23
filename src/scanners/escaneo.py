import asyncio
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.database import create_db_and_tables, engine
from src.api.models import Finding, FindingAuditEvent, Project, Scan, Target
from src.scanners.angular_adapter import AngularAdapter
from src.scanners.base import BaseScannerAdapter
from src.scanners.bandit_adapter import BanditAdapter
from src.scanners.java_adapter import JavaAdapter
from src.scanners.semgrep_adapter import SemgrepAdapter


OPEN_STATUS = "open"
FIXED_STATUS = "fixed"
REGRESSION_STATUS = "regression"
ACCEPTED_RISK_STATUS = "accepted_risk"
FALSE_POSITIVE_STATUS = "false_positive"
IGNORED_FINDING_STATUSES = {ACCEPTED_RISK_STATUS, FALSE_POSITIVE_STATUS}


class CombinedScannerAdapter(BaseScannerAdapter):
    tool_name = "combined"

    def __init__(self, adapters: list[BaseScannerAdapter]) -> None:
        self.adapters = adapters
        self.tool_name = "+".join(adapter.tool_name for adapter in adapters)
        self.raw_output: dict = {"engines": []}
        self.returncode: int | None = None
        self.error: str | None = None

    def execute_scan(self, target_path: str) -> list[Finding]:
        findings_by_fingerprint: dict[str, Finding] = {}
        raw_outputs = []
        errors = []
        returncodes = []

        for adapter in self.adapters:
            try:
                findings = adapter.execute_scan(target_path)
            except RuntimeError as exc:
                errors.append(f"{adapter.tool_name}: {exc}")
                continue

            raw_outputs.append(
                {
                    "tool": adapter.tool_name,
                    "returncode": getattr(adapter, "returncode", None),
                    "raw_output": getattr(adapter, "raw_output", {}),
                }
            )
            returncodes.append(getattr(adapter, "returncode", None))

            for finding in findings:
                fingerprint = finding.fingerprint or build_fingerprint(finding)
                findings_by_fingerprint.setdefault(fingerprint, finding)

        self.raw_output = {
            "engines": raw_outputs,
            "errors": errors,
            "metrics": {"total_findings": len(findings_by_fingerprint)},
        }
        self.error = "; ".join(errors) or None
        self.returncode = 1 if findings_by_fingerprint else 0

        if errors and not returncodes:
            self.returncode = 2

        return list(findings_by_fingerprint.values())


def get_finding_value(finding: Finding | dict, key: str, default: object = "") -> object:
    if isinstance(finding, dict):
        return finding.get(key, default)

    return getattr(finding, key, default)


def build_fingerprint(finding: Finding | dict, project_id: uuid.UUID | None = None) -> str:
    fingerprint_source = "|".join(
        [
            str(project_id or ""),
            str(get_finding_value(finding, "rule_id") or get_finding_value(finding, "test_id") or ""),
            str(get_finding_value(finding, "file_path") or get_finding_value(finding, "filename") or ""),
            str(get_finding_value(finding, "line_start") or get_finding_value(finding, "line_number") or ""),
            str(get_finding_value(finding, "description") or get_finding_value(finding, "issue_text") or ""),
            str(get_finding_value(finding, "code_snippet") or get_finding_value(finding, "code") or ""),
        ]
    )
    return hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()


def get_or_create_target(session: Session, target_path: str, technology: str) -> Target:
    target = session.exec(
        select(Target).where(
            Target.path == target_path,
            Target.type == technology,
        )
    ).first()

    if target:
        return target

    target = Target(
        name=Path(target_path).name or target_path,
        type=technology,
        path=target_path,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def get_default_scanner_adapter(technology: str) -> BaseScannerAdapter | None:
    normalized_technology = technology.strip().lower()

    if normalized_technology == "python":
        return BanditAdapter()

    if normalized_technology in {"angular", "typescript"}:
        return AngularAdapter()

    if normalized_technology == "java":
        return JavaAdapter()

    return None


def get_scanner_adapter(technology: str) -> BaseScannerAdapter | None:
    normalized_technology = technology.strip().lower()
    scanner_engine = os.getenv("SCANNER_ENGINE", "").strip().lower()
    default_adapter = get_default_scanner_adapter(normalized_technology)

    if scanner_engine == "semgrep":
        if normalized_technology in {"python", "angular", "typescript", "java"}:
            return SemgrepAdapter(normalized_technology)

        return None

    if scanner_engine == "both":
        if default_adapter is None:
            return None

        if normalized_technology in {"python", "angular", "typescript", "java"}:
            return CombinedScannerAdapter([default_adapter, SemgrepAdapter(normalized_technology)])

        return default_adapter

    if scanner_engine == "bandit" and normalized_technology == "python":
        return BanditAdapter()

    return default_adapter


def persist_scan(
    target_path: str,
    technology: str,
    adapter: BaseScannerAdapter,
    findings: list[Finding],
    project_id: uuid.UUID | None = None,
) -> int:
    create_db_and_tables()

    raw_output = getattr(adapter, "raw_output", {})
    returncode = getattr(adapter, "returncode", None)
    metrics = raw_output.get("metrics", {}) if isinstance(raw_output, dict) else {}
    now = datetime.utcnow()

    with Session(engine) as session:
        target = get_or_create_target(session, target_path, technology)
        project = session.get(Project, project_id) if project_id else None
        scan = Scan(
            target_id=target.id,
            project_id=project.id if project else None,
            tool=adapter.tool_name,
            surface=target_path,
            triggered_by="api",
            status="completed" if returncode in (0, 1) else "failed",
            started_at=now,
            finished_at=now,
            raw_output=raw_output,
            summary={
                "returncode": returncode,
                "total_findings": len(findings),
                "metrics": metrics,
                "technology": technology,
            },
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        saved_findings = 0

        for normalized_finding in findings:
            fingerprint = normalized_finding.fingerprint or build_fingerprint(normalized_finding, project_id)

            finding = session.exec(
                select(Finding).where(Finding.fingerprint == fingerprint)
            ).first()

            if finding:
                if finding.status in IGNORED_FINDING_STATUSES:
                    continue

                prev_status = finding.status
                is_regression = prev_status == FIXED_STATUS
                finding.scan_id = scan.id
                finding.last_seen_at = now
                finding.status = REGRESSION_STATUS if is_regression else OPEN_STATUS
                finding.severity = normalized_finding.severity
                finding.confidence = normalized_finding.confidence
                finding.description = normalized_finding.description
                finding.file_path = normalized_finding.file_path
                finding.line_start = normalized_finding.line_start
                finding.line_end = normalized_finding.line_end
                finding.code_snippet = normalized_finding.code_snippet

                if is_regression:
                    finding.regression_count += 1
                    session.add(FindingAuditEvent(
                        finding_id=finding.id,
                        event_type="regression",
                        from_status=prev_status,
                        to_status=REGRESSION_STATUS,
                    ))
            else:
                finding = Finding(
                    scan_id=scan.id,
                    rule_id=normalized_finding.rule_id,
                    title=normalized_finding.title,
                    description=normalized_finding.description,
                    severity=normalized_finding.severity,
                    confidence=normalized_finding.confidence,
                    file_path=normalized_finding.file_path,
                    line_start=normalized_finding.line_start,
                    line_end=normalized_finding.line_end,
                    code_snippet=normalized_finding.code_snippet,
                    status="open",
                    first_seen_at=now,
                    last_seen_at=now,
                    fingerprint=fingerprint,
                )
                session.add(finding)

            saved_findings += 1

        session.commit()

    return saved_findings


def upsert_finding(
    session: Session,
    scan_id: uuid.UUID,
    result: dict,
    now: datetime,
) -> tuple[str, Finding | None]:
    fingerprint = build_fingerprint(result)
    existing_finding = session.exec(
        select(Finding).where(Finding.fingerprint == fingerprint)
    ).first()

    if existing_finding and existing_finding.status in IGNORED_FINDING_STATUSES:
        return "ignored", existing_finding

    severity = result.get("issue_severity", "UNKNOWN")
    confidence = result.get("issue_confidence", "UNKNOWN")
    line_start = result.get("line_number")
    line_range = result.get("line_range") or []
    line_end = line_range[-1] if line_range else line_start

    if existing_finding:
        prev_status = existing_finding.status
        action = "regression" if prev_status == FIXED_STATUS else "seen_again"
        existing_finding.scan_id = scan_id
        existing_finding.last_seen_at = now
        existing_finding.status = REGRESSION_STATUS if action == "regression" else OPEN_STATUS
        existing_finding.rule_id = result.get("test_id", existing_finding.rule_id)
        existing_finding.title = result.get("test_name", existing_finding.title)
        existing_finding.description = result.get("issue_text", existing_finding.description)
        existing_finding.severity = severity
        existing_finding.confidence = confidence
        existing_finding.file_path = result.get("filename", existing_finding.file_path)
        existing_finding.line_start = line_start
        existing_finding.line_end = line_end
        existing_finding.code_snippet = result.get("code")

        if action == "regression":
            existing_finding.regression_count += 1
            session.add(FindingAuditEvent(
                finding_id=existing_finding.id,
                event_type="regression",
                from_status=prev_status,
                to_status=REGRESSION_STATUS,
            ))

        return action, existing_finding

    finding = Finding(
        scan_id=scan_id,
        rule_id=result.get("test_id", ""),
        title=result.get("test_name", result.get("test_id", "")),
        description=result.get("issue_text", ""),
        severity=severity,
        confidence=confidence,
        file_path=result.get("filename", ""),
        line_start=line_start,
        line_end=line_end,
        code_snippet=result.get("code"),
        status=OPEN_STATUS,
        first_seen_at=now,
        last_seen_at=now,
        fingerprint=fingerprint,
    )
    session.add(finding)
    return "created", finding


async def run_scan(
    target_path: str,
    technology: str,
    project_id: uuid.UUID | None = None,
) -> dict:
    adapter = get_scanner_adapter(technology)

    if adapter is None:
        return {
            "status": "supported_soon",
            "message": "Adapter integration pending",
            "technology": technology,
            "target_path": target_path,
        }

    findings = await asyncio.to_thread(adapter.execute_scan, target_path)
    returncode = getattr(adapter, "returncode", None)
    error = getattr(adapter, "error", None)

    saved_findings = persist_scan(
        target_path,
        technology,
        adapter,
        findings,
        project_id,
    )

    return {
        "success": returncode in (0, 1),
        "saved_findings": saved_findings,
        "returncode": returncode,
        "tool": adapter.tool_name,
        "technology": technology,
        "target_path": target_path,
        "project_id": str(project_id) if project_id else None,
        "error": error,
    }


async def run_default_scan() -> dict:
    return await run_scan("src/dummy_vulnerable_app.py", "python")


def main():
    import asyncio

    target_path = sys.argv[1] if len(sys.argv) > 1 else "src/dummy_vulnerable_app.py"
    technology = sys.argv[2] if len(sys.argv) > 2 else "python"
    result = asyncio.run(run_scan(target_path, technology))
    print(json.dumps(result, indent=2))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
