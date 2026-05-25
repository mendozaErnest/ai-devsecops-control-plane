from pathlib import Path
import asyncio
import hashlib
import hmac
import ipaddress
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlmodel import Session, select

from .database import create_db_and_tables, engine
from .models import Finding, FindingAuditEvent, Project, Remediation, Scan, ScanProfile
from src.ai_engine.remediator import (
    OLLAMA_MODEL,
    build_prompt,
    check_ollama_status,
    generate_patch,
)
from src.integrations.github_client import (
    GitHubClientError,
    create_check_run,
    create_security_pr,
    delete_security_branch,
    update_check_run,
)
from src.scanners.escaneo import persist_scan, run_scan
from src.scanners.orchestrator import ScanOrchestrator


app = FastAPI()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_INDEX = PROJECT_ROOT / "src" / "dashboard" / "index.html"
WORKSPACE_ROOT = PROJECT_ROOT / "workspace" / "uploads"


class ScanRequest(BaseModel):
    target_path: str
    technology: str


class CloneRepoRequest(BaseModel):
    name: str
    repo_url: str
    technology: str
    scan_profile_id: int | None = None


class FindingLifecycleRequest(BaseModel):
    reason: str


class ScanProfileCreate(BaseModel):
    name: str
    description: str | None = None
    sast_enabled: bool = True
    sast_tools: str = "semgrep"
    sast_rulesets: str | None = None
    dast_enabled: bool = False
    dast_tool: str | None = None
    quality_enabled: bool = False
    quality_tool: str | None = None


class ScanProfileUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    sast_enabled: bool | None = None
    sast_tools: str | None = None
    sast_rulesets: str | None = None
    dast_enabled: bool | None = None
    dast_tool: str | None = None
    quality_enabled: bool | None = None
    quality_tool: str | None = None


@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)


@app.get("/")
async def index():
    return FileResponse(DASHBOARD_INDEX)


@app.get("/api/profiles")
async def list_profiles():
    with Session(engine) as session:
        profiles = session.exec(select(ScanProfile).order_by(ScanProfile.id)).all()
        return [p.model_dump(mode="json") for p in profiles]


@app.post("/api/profiles", status_code=201)
async def create_profile(body: ScanProfileCreate):
    with Session(engine) as session:
        profile = ScanProfile(**body.model_dump())
        session.add(profile)
        session.commit()
        session.refresh(profile)
        return profile.model_dump(mode="json")


@app.get("/api/profiles/{profile_id}")
async def get_profile(profile_id: int):
    with Session(engine) as session:
        profile = session.get(ScanProfile, profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="ScanProfile not found")
        return profile.model_dump(mode="json")


@app.put("/api/profiles/{profile_id}")
async def update_profile(profile_id: int, body: ScanProfileUpdate):
    with Session(engine) as session:
        profile = session.get(ScanProfile, profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="ScanProfile not found")
        for field, value in body.model_dump(exclude_unset=True).items():
            setattr(profile, field, value)
        session.add(profile)
        session.commit()
        session.refresh(profile)
        return profile.model_dump(mode="json")


@app.get("/api/findings")
async def get_findings():
    with Session(engine) as session:
        findings = session.exec(select(Finding)).all()
        remediations = session.exec(select(Remediation)).all()
        remediated_finding_ids = {remediation.finding_id for remediation in remediations}

        return [
            {
                **finding.model_dump(mode="json"),
                "has_remediation": finding.id in remediated_finding_ids,
                "remediation_status": "Parche listo"
                if finding.id in remediated_finding_ids
                else "Sin parche",
            }
            for finding in findings
        ]


def get_allowed_scan_roots() -> list[Path]:
    raw_roots = os.getenv("SCAN_ALLOWED_ROOTS")

    if not raw_roots:
        return [PROJECT_ROOT.resolve(), WORKSPACE_ROOT.resolve()]

    roots = [
        Path(raw_root).expanduser().resolve()
        for raw_root in raw_roots.split(os.pathsep)
        if raw_root.strip()
    ]
    workspace = WORKSPACE_ROOT.resolve()

    if workspace not in roots:
        roots.append(workspace)

    return roots


def validate_scan_target(target_path: str) -> str:
    if not target_path.strip():
        raise HTTPException(status_code=400, detail="target_path is required")

    expanded_path = Path(target_path).expanduser()

    if not os.path.exists(expanded_path):
        raise HTTPException(status_code=404, detail="target_path does not exist")

    resolved_path = expanded_path.resolve()
    allowed_roots = get_allowed_scan_roots()

    if not any(resolved_path == root or resolved_path.is_relative_to(root) for root in allowed_roots):
        raise HTTPException(
            status_code=403,
            detail="target_path is outside the allowed scan roots",
        )

    return str(resolved_path)


def normalize_technology(technology: str) -> str:
    normalized = technology.strip().lower()

    if normalized not in {"python", "angular", "typescript", "java"}:
        raise HTTPException(status_code=400, detail="Unsupported technology value")

    return normalized


def get_last_scans_for_projects(
    session: Session, project_ids: list[uuid.UUID]
) -> dict[uuid.UUID, tuple[str | None, object]]:
    """Single query: returns {project_id: (tool, started_at)} for the latest scan of each project."""
    if not project_ids:
        return {}
    subq = (
        select(Scan.project_id, func.max(Scan.started_at).label("latest_at"))
        .where(Scan.project_id.in_(project_ids))
        .group_by(Scan.project_id)
        .subquery()
    )
    scans = session.exec(
        select(Scan).join(
            subq,
            (Scan.project_id == subq.c.project_id) & (Scan.started_at == subq.c.latest_at),
        )
    ).all()
    return {scan.project_id: (scan.tool, scan.started_at) for scan in scans}


def project_to_response(
    project: Project,
    findings: list[Finding] | None = None,
    last_scan: tuple | None = None,
) -> dict:
    findings = findings or []
    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = str(f.severity or "").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    last_scan_tool, last_scan_at = last_scan if last_scan else (None, None)
    return {
        **project.model_dump(mode="json"),
        "critical_findings": sev_counts["CRITICAL"] + sev_counts["HIGH"],
        "finding_count": len(findings),
        "findings_summary": {**sev_counts, "total": len(findings)},
        "last_scan_tool": last_scan_tool,
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
    }


def get_project_findings(session: Session, project_id: uuid.UUID) -> list[Finding]:
    return session.exec(
        select(Finding)
        .join(Scan)
        .where(Scan.project_id == project_id)
    ).all()


def get_finding_technology(session: Session, finding: Finding) -> str:
    scan = session.get(Scan, finding.scan_id)

    if not scan or not scan.project_id:
        return "python"

    project = session.get(Project, scan.project_id)

    if not project:
        return "python"

    technology = project.technology.strip().lower()
    return "angular" if technology == "typescript" else technology


def build_finding_details(session: Session, finding: Finding) -> dict:
    return {
        "id": str(finding.id),
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "file_path": finding.file_path,
        "line_start": finding.line_start,
        "line_end": finding.line_end,
        "code_snippet": finding.code_snippet,
        "technology": get_finding_technology(session, finding),
    }


def safe_project_name(name: str | None, fallback: str) -> str:
    raw_name = (name or fallback).strip() or fallback
    safe_chars = [
        character if character.isalnum() or character in ("-", "_", ".") else "-"
        for character in raw_name
    ]
    return "".join(safe_chars).strip("-")[:80] or fallback


def ensure_workspace_project_dir(project_id: uuid.UUID) -> Path:
    project_dir = WORKSPACE_ROOT / str(project_id)
    project_dir.mkdir(parents=True, exist_ok=False)
    return project_dir


def extract_zip_safely(zip_path: Path, destination: Path) -> None:
    destination = destination.resolve()

    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)

            if member_path.is_absolute() or ".." in member_path.parts:
                raise HTTPException(status_code=400, detail="Unsafe path detected inside ZIP archive")

            target_path = (destination / member.filename).resolve()

            if not (target_path == destination or target_path.is_relative_to(destination)):
                raise HTTPException(status_code=400, detail="Unsafe path detected inside ZIP archive")

            if member.is_dir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)

            with archive.open(member) as source, target_path.open("wb") as target:
                shutil.copyfileobj(source, target)


_DEFAULT_PROFILE_BY_TECH: dict[str, str] = {
    "python": "Python SAST",
    "angular": "Angular SAST",
    "typescript": "Angular SAST",
    "java": "Java SAST",
}


def resolve_scan_profile_id(session: Session, technology: str, requested_id: int | None) -> int | None:
    if requested_id is not None:
        return requested_id
    default_name = _DEFAULT_PROFILE_BY_TECH.get(technology.lower())
    if not default_name:
        return None
    profile = session.exec(select(ScanProfile).where(ScanProfile.name == default_name)).first()
    return profile.id if profile else None


def create_project_record(
    name: str,
    source_type: str,
    target_path: Path,
    technology: str,
    project_id: uuid.UUID | None = None,
    scan_profile_id: int | None = None,
) -> Project:
    with Session(engine) as session:
        resolved_profile_id = resolve_scan_profile_id(session, technology, scan_profile_id)
        project = Project(
            id=project_id or uuid.uuid4(),
            name=name,
            source_type=source_type,
            target_path=str(target_path.resolve()),
            technology=technology,
            scan_profile_id=resolved_profile_id,
        )
        session.add(project)
        session.commit()
        session.refresh(project)
        return project


async def scan_project(project: Project) -> dict:
    if project.scan_profile_id is not None:
        with Session(engine) as session:
            profile = session.get(ScanProfile, project.scan_profile_id)
        if profile is not None:
            return await _scan_with_profile(project, profile)

    return await run_scan(project.target_path, project.technology, project.id)


async def _scan_with_profile(project: Project, profile: ScanProfile) -> dict:
    orchestrator = ScanOrchestrator()
    result = await asyncio.to_thread(
        orchestrator.run,
        profile,
        project.target_path,
        project.technology,
        project.id,
    )

    from src.scanners.escaneo import get_scanner_adapter

    adapter = get_scanner_adapter(project.technology)
    saved = await asyncio.to_thread(
        persist_scan,
        project.target_path,
        project.technology,
        adapter or _NullAdapter(profile.sast_tools),
        result.findings,
        project.id,
    )

    return {
        "success": True,
        "saved_findings": saved,
        "tools_run": result.tools_run,
        "errors": result.errors,
        "technology": project.technology,
        "target_path": project.target_path,
        "project_id": str(project.id),
        "profile": profile.name,
    }


class _NullAdapter:
    """Minimal adapter stub used when the orchestrator already ran the scan."""
    def __init__(self, tool_name: str = "orchestrated") -> None:
        self.tool_name = tool_name
        self.raw_output: dict = {}
        self.returncode: int = 1
        self.error: str | None = None


@app.get("/api/projects")
async def list_projects():
    with Session(engine) as session:
        projects = session.exec(select(Project).order_by(Project.created_at.desc())).all()
        project_ids = [p.id for p in projects]
        last_scans = get_last_scans_for_projects(session, project_ids)
        return [
            project_to_response(
                project,
                get_project_findings(session, project.id),
                last_scans.get(project.id),
            )
            for project in projects
        ]


@app.get("/api/projects/{project_id}")
async def get_project(project_id: uuid.UUID):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        last_scans = get_last_scans_for_projects(session, [project_id])
        return project_to_response(
            project,
            get_project_findings(session, project.id),
            last_scans.get(project_id),
        )


@app.get("/api/projects/{project_id}/findings")
async def get_project_findings_endpoint(project_id: uuid.UUID):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        findings = get_project_findings(session, project.id)
        remediations = session.exec(select(Remediation)).all()
        remediated_finding_ids = {remediation.finding_id for remediation in remediations}

        return [
            {
                **finding.model_dump(mode="json"),
                "has_remediation": finding.id in remediated_finding_ids,
                "remediation_status": "Parche listo"
                if finding.id in remediated_finding_ids
                else "Sin parche",
                "project_source_type": project.source_type,
            }
            for finding in findings
        ]


@app.post("/api/projects/{project_id}/scan")
async def scan_project_endpoint(project_id: uuid.UUID):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        target_path = validate_scan_target(project.target_path)
        project.target_path = target_path
        session.add(project)
        session.commit()
        session.refresh(project)

    return await scan_project(project)


@app.post("/api/projects/upload-zip")
async def upload_zip_project(
    file: UploadFile = File(...),
    technology: str = Form("python"),
    name: str | None = Form(None),
    scan_profile_id: int | None = Form(None),
):
    technology = normalize_technology(technology)
    filename = file.filename or "uploaded-project.zip"

    if not filename.lower().endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip uploads are supported")

    project_id = uuid.uuid4()
    project_dir = ensure_workspace_project_dir(project_id)
    archive_path = project_dir / "source.zip"
    extract_dir = project_dir / "source"

    try:
        with archive_path.open("wb") as target:
            shutil.copyfileobj(file.file, target)

        extract_dir.mkdir(parents=True, exist_ok=False)
        await asyncio.to_thread(extract_zip_safely, archive_path, extract_dir)

        project = create_project_record(
            safe_project_name(name, Path(filename).stem),
            "zip",
            extract_dir,
            technology,
            project_id,
            scan_profile_id,
        )
        scan_result = await scan_project(project)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Uploaded ZIP archive is corrupt") from exc
    except OSError as exc:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Could not process uploaded ZIP: {exc}") from exc
    except HTTPException:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise
    except Exception:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise
    finally:
        await file.close()

    return {
        "project": project_to_response(project),
        "scan": scan_result,
    }


def clone_repository(repo_url: str, destination: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, str(destination)],
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def validate_repo_url(repo_url: str) -> str:
    value = repo_url.strip()

    if value.startswith("git@"):
        return value

    parsed = urlparse(value)

    if parsed.scheme in {"https", "http", "ssh", "git"} and parsed.netloc:
        return value

    raise HTTPException(status_code=400, detail="repo_url must be an HTTP(S), SSH, or git repository URL")


@app.post("/api/projects/clone-repo")
async def clone_repo_project(request: CloneRepoRequest):
    technology = normalize_technology(request.technology)
    repo_url = validate_repo_url(request.repo_url)
    project_id = uuid.uuid4()
    project_dir = ensure_workspace_project_dir(project_id)
    clone_dir = project_dir / "repo"

    try:
        result = await asyncio.to_thread(clone_repository, repo_url, clone_dir)

        if result.returncode != 0:
            raise HTTPException(
                status_code=502,
                detail=result.stderr.strip() or "git clone failed",
            )

        project = create_project_record(
            safe_project_name(request.name, "cloned-repository"),
            "repo",
            clone_dir,
            technology,
            project_id,
            request.scan_profile_id,
        )
        scan_result = await scan_project(project)
    except Exception:
        shutil.rmtree(project_dir, ignore_errors=True)
        raise

    return {
        "project": project_to_response(project),
        "scan": scan_result,
    }


@app.post("/api/scan")
async def scan_code(request: ScanRequest | None = None):
    if request is None:
        request = ScanRequest(
            target_path=str(PROJECT_ROOT / "src"),
            technology="python",
        )

    technology = request.technology.strip().lower()

    if technology not in {"python", "angular", "typescript", "java"}:
        raise HTTPException(status_code=400, detail="Unsupported technology value")

    target_path = validate_scan_target(request.target_path)
    return await run_scan(target_path, technology)


@app.get("/api/ai-status")
async def ai_status():
    return await check_ollama_status()


@app.post("/api/remediate/{finding_id}")
async def remediate_finding(finding_id: uuid.UUID):
    status = await check_ollama_status()

    if not status.get("available"):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "local_ai_unavailable",
                "message": "AI Engine is offline. Local remediation is disabled until Ollama is available.",
                "reason": status.get("reason", "Ollama service offline"),
            },
        )

    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_details = build_finding_details(session, finding)

    patch = await generate_patch(finding_details)

    with Session(engine) as session:
        remediation = Remediation(
            finding_id=finding_id,
            strategy="llm-suggested-patch",
            model_used=f"ollama/{OLLAMA_MODEL}",
            prompt_used=build_prompt(finding_details),
            patch_diff=patch,
            applied_at=None,
            verified_at=None,
            outcome="suggested",
        )
        session.add(remediation)
        session.commit()
        session.refresh(remediation)

        return {
            "finding_id": finding_id,
            "remediation_id": remediation.id,
            "patch": patch,
        }


@app.post("/api/remediate/{finding_id}/pr")
async def create_remediation_pr(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        remediations = session.exec(
            select(Remediation).where(Remediation.finding_id == finding_id)
        ).all()

        if not remediations:
            raise HTTPException(status_code=404, detail="No remediation found for this finding")

        remediation = remediations[-1]
        finding_details = build_finding_details(session, finding)
        remediation_text = remediation.patch_diff

    try:
        pr = await create_security_pr(finding_details, remediation_text)
    except GitHubClientError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc

    return {
        "finding_id": finding_id,
        "remediation_id": remediation.id,
        "pr_url": pr["url"],
        "branch": pr["branch"],
        "number": pr.get("number"),
    }


@app.delete("/api/remediate/{finding_id}/pr")
async def delete_remediation_pr_branch(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    branch_name = f"security-fix-{finding_id}"

    try:
        result = await delete_security_branch(branch_name)
    except GitHubClientError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc

    return {
        "finding_id": finding_id,
        "branch": result["branch"],
        "deleted": result["deleted"],
    }


def _set_finding_lifecycle_status(
    finding_id: uuid.UUID,
    new_status: str,
    event_type: str,
    reason: str,
) -> dict:
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        from_status = finding.status
        finding.status = new_status
        session.add(FindingAuditEvent(
            finding_id=finding_id,
            event_type=event_type,
            from_status=from_status,
            to_status=new_status,
            reason=reason,
        ))
        session.commit()

    return {"finding_id": str(finding_id), "status": new_status}


@app.post("/api/findings/{finding_id}/accept-risk")
async def accept_finding_risk(finding_id: uuid.UUID, request: FindingLifecycleRequest):
    return _set_finding_lifecycle_status(finding_id, "accepted_risk", "accept_risk", request.reason)


@app.post("/api/findings/{finding_id}/false-positive")
async def mark_finding_false_positive(finding_id: uuid.UUID, request: FindingLifecycleRequest):
    return _set_finding_lifecycle_status(finding_id, "false_positive", "false_positive", request.reason)


@app.get("/api/findings/{finding_id}/audit")
async def get_finding_audit(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        events = session.exec(
            select(FindingAuditEvent)
            .where(FindingAuditEvent.finding_id == finding_id)
            .order_by(FindingAuditEvent.created_at)
        ).all()

        return {
            "finding_id": str(finding_id),
            "current_status": finding.status,
            "regression_count": finding.regression_count,
            "events": [event.model_dump(mode="json") for event in events],
        }


@app.get("/api/reports/project/{project_id}")
async def get_project_report(project_id: uuid.UUID):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        findings = get_project_findings(session, project.id)

        by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        by_status: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        overdue: list[dict] = []
        from datetime import datetime, timezone

        now_utc = datetime.now(timezone.utc)

        for f in findings:
            sev = str(f.severity or "UNKNOWN").upper()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_status[f.status] = by_status.get(f.status, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

            if f.sla_deadline and f.status not in {"fixed", "accepted_risk", "false_positive"}:
                deadline_utc = f.sla_deadline.replace(tzinfo=timezone.utc) if f.sla_deadline.tzinfo is None else f.sla_deadline
                if deadline_utc < now_utc:
                    overdue.append({
                        "id": str(f.id),
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "sla_deadline": f.sla_deadline.isoformat(),
                        "days_overdue": (now_utc - deadline_utc).days,
                    })

        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "project_id": str(project_id),
            "project_name": project.name,
            "technology": project.technology,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_status": by_status,
            "top_rules": [{"rule_id": r, "count": c} for r, c in top_rules],
            "overdue_findings": overdue,
            "overdue_count": len(overdue),
        }


def _verify_github_signature(body: bytes, signature_header: str | None, secret: str) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _detect_technology_from_files(changed_files: list[str]) -> str:
    for f in changed_files:
        if f.endswith((".ts", ".html", ".component.ts")):
            return "angular"
        if f.endswith(".java"):
            return "java"
    return "python"


@app.post("/api/webhooks/github")
async def github_webhook(request: Request):
    body = await request.body()
    event_type = request.headers.get("X-GitHub-Event", "")
    signature = request.headers.get("X-Hub-Signature-256")

    webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if webhook_secret:
        if not _verify_github_signature(body, signature, webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    if event_type == "ping":
        return {"status": "pong"}

    if event_type != "pull_request":
        return {"status": "ignored", "event": event_type}

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    action = payload.get("action", "")
    if action not in {"opened", "synchronize", "reopened"}:
        return {"status": "ignored", "action": action}

    pr = payload.get("pull_request", {})
    head = pr.get("head", {})
    head_sha = head.get("sha", "")
    clone_url = head.get("repo", {}).get("clone_url", "")
    head_ref = head.get("ref", "")
    repo_full = payload.get("repository", {}).get("full_name", "")

    if not head_sha or not clone_url or not repo_full:
        raise HTTPException(status_code=422, detail="Missing required PR fields")

    # Start check run asynchronously
    asyncio.create_task(_run_pr_scan(repo_full, head_sha, clone_url, head_ref, pr))
    return {"status": "accepted", "head_sha": head_sha}


async def _run_pr_scan(repo: str, head_sha: str, clone_url: str, head_ref: str, pr: dict) -> None:
    check_run_id: int | None = None
    try:
        check_run = await create_check_run(repo, head_sha)
        check_run_id = check_run.get("id")
    except Exception:
        pass  # proceed even if check run creation fails

    try:
        with tempfile.TemporaryDirectory() as clone_dir:
            clone_result = await asyncio.to_thread(
                subprocess.run,
                ["git", "clone", "--depth=1", "--branch", head_ref, clone_url, clone_dir],
                capture_output=True,
                text=True,
                check=False,
            )

            if clone_result.returncode != 0:
                raise RuntimeError(f"git clone failed: {clone_result.stderr[:200]}")

            # Detect technology from PR changed files list if available
            changed_files = [f.get("filename", "") for f in pr.get("changed_files_detail", [])]
            if not changed_files:
                py_files = list(Path(clone_dir).rglob("*.py"))
                java_files = list(Path(clone_dir).rglob("*.java"))
                ts_files = list(Path(clone_dir).rglob("*.ts"))
                changed_files = (
                    [str(f) for f in py_files[:3]]
                    + [str(f) for f in java_files[:3]]
                    + [str(f) for f in ts_files[:3]]
                )

            technology = _detect_technology_from_files(changed_files)
            result = await run_scan(clone_dir, technology)

        saved = result.get("saved_findings", 0)

        # Count criticals from db
        with Session(engine) as session:
            all_findings = session.exec(select(Finding).where(Finding.status == "open")).all()
            criticals = sum(1 for f in all_findings if str(f.severity or "").upper() == "CRITICAL")

        has_criticals = criticals > 0
        conclusion = "failure" if has_criticals else "success"
        summary = (
            f"Found **{saved}** new findings ({criticals} CRITICAL). "
            "Merge blocked until critical findings are resolved."
            if has_criticals
            else f"Found **{saved}** findings. No critical issues — safe to merge."
        )

        if check_run_id:
            await update_check_run(repo, check_run_id, conclusion, summary)

    except Exception as exc:
        if check_run_id:
            try:
                await update_check_run(repo, check_run_id, "failure", f"Scan error: {exc}")
            except Exception:
                pass


def validate_ipv4(ip: str) -> str:
    try:
        return str(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IPv4 address") from exc


@app.get("/api/ping")
async def ping(ip: str):
    safe_ip = validate_ipv4(ip)
    command = ["ping", "-c", "4", safe_ip]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
