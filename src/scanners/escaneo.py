import asyncio
import hashlib
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.database import create_db_and_tables, engine
from src.api.models import Finding, Project, Scan, Target
from src.scanners.angular_adapter import AngularAdapter
from src.scanners.base import BaseScannerAdapter
from src.scanners.bandit_adapter import BanditAdapter
from src.scanners.java_adapter import JavaAdapter


def build_fingerprint(finding: Finding, project_id: uuid.UUID | None = None) -> str:
    fingerprint_source = "|".join(
        [
            str(project_id or ""),
            finding.rule_id or "",
            finding.file_path or "",
            str(finding.line_start or ""),
            finding.description or "",
            finding.code_snippet or "",
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


def get_scanner_adapter(technology: str) -> BaseScannerAdapter | None:
    normalized_technology = technology.strip().lower()

    if normalized_technology == "python":
        return BanditAdapter()

    if normalized_technology in {"angular", "typescript"}:
        return AngularAdapter()

    if normalized_technology == "java":
        return JavaAdapter()

    return None


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
            fingerprint = build_fingerprint(normalized_finding, project_id)

            finding = session.exec(
                select(Finding).where(Finding.fingerprint == fingerprint)
            ).first()

            if finding:
                finding.scan_id = scan.id
                finding.last_seen_at = now
                finding.status = "open"
                finding.severity = normalized_finding.severity
                finding.confidence = normalized_finding.confidence
                finding.description = normalized_finding.description
                finding.file_path = normalized_finding.file_path
                finding.line_start = normalized_finding.line_start
                finding.line_end = normalized_finding.line_end
                finding.code_snippet = normalized_finding.code_snippet
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
