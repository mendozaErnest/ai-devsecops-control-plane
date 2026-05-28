from datetime import datetime, timedelta, timezone
from pathlib import Path
import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from urllib.parse import urlparse

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sqlalchemy import func
from sqlmodel import Session, select

from .database import create_db_and_tables, engine
from .models import Finding, FindingAuditEvent, Project, Remediation, Scan, ScanProfile
from src.ai_engine.remediator import (
    OLLAMA_MODEL,
    build_prompt,
    check_ollama_status,
    generate_patch,
    infer_technology_from_finding,
)
from src.integrations.github_client import (
    GitHubClientError,
    build_python_b324_remediation_text,
    build_python_b324_weak_hash_patch,
    build_python_s1192_constant_patch,
    build_python_s1192_remediation_text,
    build_safe_patched_content,
    close_open_pr_for_branch,
    create_check_run,
    create_proposal_pr,
    create_security_pr,
    delete_security_branch,
    extract_code_block_for_technology,
    find_braced_block_range,
    find_enclosing_python_function_node,
    get_source_segment,
    get_existing_open_pr_for_branch,
    get_pr_diff,
    is_deterministic_python_rule,
    is_python_duplicate_literal_rule,
    is_python_weak_hash_rule,
    is_safe_to_apply,
    looks_like_python_only_prose,
    normalize_patch_technology_for_finding,
    remediation_text_matches_python_b324,
    remediation_text_matches_python_s1192,
    ts_line_looks_like_method_signature,
    update_check_run,
)
from src.scanners.escaneo import persist_scan, run_scan
from src.scanners.orchestrator import ScanOrchestrator
from typing import Annotated


app = FastAPI()
_logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_INDEX = PROJECT_ROOT / "src" / "dashboard" / "index.html"
DASHBOARD_STATIC = PROJECT_ROOT / "src" / "dashboard"
WORKSPACE_ROOT = PROJECT_ROOT / "workspace" / "uploads"

app.mount("/static", StaticFiles(directory=str(DASHBOARD_STATIC)), name="static")


def validate_target_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"target_url must be http or https: {url}")
    return url


class ScanRequest(BaseModel):
    project_id: uuid.UUID | None = None
    target_path: str | None = None
    target_url: str | None = None
    profile_id: int | None = None
    technology: str | None = None

    @field_validator("target_url")
    @classmethod
    def validate_scan_target_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            return None
        return validate_target_url(stripped)


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
    technologies: str | None = None
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
    technologies: str | None = None
    sast_enabled: bool | None = None
    sast_tools: str | None = None
    sast_rulesets: str | None = None
    dast_enabled: bool | None = None
    dast_tool: str | None = None
    quality_enabled: bool | None = None
    quality_tool: str | None = None


class ProjectProfileUpdate(BaseModel):
    scan_profile_id: int | None = None


@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)


@app.get("/")
async def index():
    return FileResponse(DASHBOARD_INDEX)


@app.get("/health")
async def health():
    return {"status": "ok"}


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


_SLA_EXEMPT_STATUSES = {"accepted_risk", "false_positive", "fixed"}


def get_sla_status(finding: Finding, now: datetime) -> str:
    if finding.status in _SLA_EXEMPT_STATUSES:
        return "exempt"
    if not finding.sla_deadline:
        return "unknown"
    # Normalize naive deadline to UTC-aware for comparison
    deadline = (
        finding.sla_deadline.replace(tzinfo=timezone.utc)
        if finding.sla_deadline.tzinfo is None
        else finding.sla_deadline
    )
    if now > deadline:
        return "breached"
    if now > deadline - timedelta(days=3):
        return "warning"
    return "ok"


@app.get("/api/findings")
async def get_findings(sla_status: str | None = None):
    with Session(engine) as session:
        findings = list(session.exec(select(Finding)).all())
        remediated_finding_ids = latest_valid_remediation_ids(session, findings)
        now = datetime.now(timezone.utc)

        result = [
            {
                **finding.model_dump(mode="json"),
                "has_remediation": finding.id in remediated_finding_ids,
                "remediation_status": "Parche listo"
                if finding.id in remediated_finding_ids
                else "Sin parche",
                "sla_status": get_sla_status(finding, now),
            }
            for finding in findings
        ]

        if sla_status:
            result = [f for f in result if f.get("sla_status") == sla_status]

        return result


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


def remap_legacy_path(target_path: str) -> str:
    """Translate a host-absolute path to the current PROJECT_ROOT if it no longer exists.

    Handles the case where projects were registered while the API ran on the host
    (path: /home/user/.../workspace/uploads/UUID/repo) but now the API runs inside
    Docker where the same tree is mounted at /app/workspace/uploads/UUID/repo.
    """
    path = Path(target_path)
    if path.exists():
        return target_path

    _ANCHORS = ("workspace/uploads/", "workspace/")
    for anchor in _ANCHORS:
        anchor_str = str(path)
        idx = anchor_str.find(anchor)
        if idx != -1:
            relative_tail = anchor_str[idx:]
            remapped = PROJECT_ROOT / relative_tail
            if remapped.exists():
                return str(remapped)

    return target_path


def validate_scan_target(target_path: str) -> str:
    if not target_path.strip():
        raise HTTPException(status_code=400, detail="target_path is required")

    target_path = remap_legacy_path(target_path)
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


def is_allowed_scan_path(path: Path) -> bool:
    resolved_path = path.resolve()
    return any(
        resolved_path == root or resolved_path.is_relative_to(root)
        for root in get_allowed_scan_roots()
    )


def resolve_finding_file_path(file_path: str) -> Path:
    raw_path = Path(file_path).expanduser()
    candidates: list[Path] = []

    if raw_path.is_absolute():
        candidates.append(raw_path)
    else:
        candidates.append(PROJECT_ROOT / raw_path)

    parts = raw_path.parts
    for marker in ("workspace", "src", "code", "tests", "docs", "helm"):
        if marker in parts:
            marker_index = parts.index(marker)
            candidates.append(PROJECT_ROOT / Path(*parts[marker_index:]))

    for candidate in candidates:
        if candidate.exists() and is_allowed_scan_path(candidate):
            return candidate.resolve()

    return candidates[0]


def normalize_technology(technology: str) -> str:
    normalized = technology.strip().lower()

    if normalized not in {"python", "angular", "typescript", "java"}:
        raise HTTPException(status_code=400, detail="Unsupported technology value")

    return normalized


def profile_api_technologies(profile: ScanProfile) -> set[str]:
    raw_technologies = profile.technologies or ""
    builder_to_api = {
        "python": "python",
        "django": "python",
        "flask": "python",
        "angular": "angular",
        "typescript": "typescript",
        "react": "typescript",
        "java": "java",
        "java-spring": "java",
    }

    try:
        builder_ids = json.loads(raw_technologies) if raw_technologies else []
    except json.JSONDecodeError:
        builder_ids = []

    api_technologies = {
        builder_to_api[item]
        for item in builder_ids
        if item in builder_to_api
    }
    if api_technologies:
        return api_technologies

    name = (profile.name or "").lower()
    if "python" in name:
        return {"python"}
    if "angular" in name:
        return {"angular", "typescript"}
    if "typescript" in name or "react" in name:
        return {"typescript"}
    if "java" in name:
        return {"java"}

    if profile.sast_tools == "bandit" or profile.quality_tool == "pylint":
        return {"python"}
    if profile.quality_tool == "eslint":
        return {"angular", "typescript"}

    return {"python", "angular", "typescript", "java"}


def ensure_profile_matches_project(profile: ScanProfile, project: Project) -> None:
    project_technology = normalize_technology(project.technology)
    if project_technology not in profile_api_technologies(profile):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Profile '{profile.name}' is not compatible with "
                f"project technology '{project_technology}'"
            ),
        )


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


def read_finding_source_file(file_path: str | None) -> str | None:
    if not file_path:
        return None

    try:
        resolved_file_path = resolve_finding_file_path(file_path)
        if not resolved_file_path.exists() or not is_allowed_scan_path(resolved_file_path):
            return None

        return resolved_file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        _logger.warning("read_finding_source_file: could not read %s: %s", file_path, exc)
        return None


def enrich_python_finding_context(details: dict) -> dict:
    if normalize_patch_technology_for_finding(details) != "python":
        return details

    source = read_finding_source_file(str(details.get("file_path") or ""))
    if not source:
        return details

    try:
        function_node = find_enclosing_python_function_node(source, details.get("line_start"))
    except GitHubClientError as exc:
        _logger.warning(
            "enrich_python_finding_context: could not parse %s: %s",
            details.get("file_path"),
            exc,
        )
        return details

    if not function_node:
        return details

    function_source = get_source_segment(source, function_node)
    if not function_source:
        return details

    return {
        **details,
        "expected_function": function_node.name,
        "expected_function_source": function_source,
        "code_snippet": function_source,
    }


# Patterns for standalone JS/TS function declarations (class methods are handled
# by the existing ts_line_looks_like_method_signature helper from github_client).
_JS_FUNC_PATTERNS = [
    # function name(...) { / async function name(...) {
    re.compile(r"^\s*(?:async\s+)?function\s+(\w+)\s*\("),
    # const/let/var name = function(...) {
    re.compile(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*[\w$]*\s*\("),
    # const/let/var name = (...) => {
    re.compile(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>"),
    # const/let/var name = async singleArg => {
    re.compile(r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*async\s+\w+\s*=>"),
]


def find_enclosing_js_function(source: str, line_number: Annotated[object, "Line number"]) -> tuple[str | None, str | None]:
    """Return (function_name, function_source) for the JS/TS function that contains
    the given 1-based line number.

    Handles:
    - Standalone ``function name()`` declarations
    - ``const name = function()`` / ``const name = () =>`` expressions
    - TypeScript class methods (via ``ts_line_looks_like_method_signature``)

    Returns ``(None, None)`` when extraction fails.
    """
    if not source or not line_number:
        return None, None

    try:
        line_num = int(line_number)
    except (TypeError, ValueError):
        return None, None

    lines = source.splitlines()
    if line_num < 1 or line_num > len(lines):
        return None, None

    target_idx = line_num - 1  # 0-based

    best_start: int | None = None
    best_name: str | None = None

    for i in range(target_idx, -1, -1):
        line = lines[i]

        # Try standalone function patterns first (more specific)
        for pat in _JS_FUNC_PATTERNS:
            m = pat.match(line)
            if m:
                best_start = i
                best_name = m.group(1)
                break

        if best_start is not None:
            break

        # Fallback: TypeScript class method signature
        if ts_line_looks_like_method_signature(line):
            best_start = i
            m = re.search(r"(?:async\s+)?(\w+)\s*\(", line)
            best_name = m.group(1) if m else None
            break

    if best_start is None:
        return None, None

    block_range = find_braced_block_range(lines, best_start)
    if block_range is None:
        return None, None

    # find_braced_block_range returns 1-based (start_inclusive, end_inclusive)
    block_start, block_end = block_range
    func_source = "\n".join(lines[block_start - 1 : block_end])
    return best_name, func_source


def enrich_js_finding_context(details: dict) -> dict:
    """Attach the full enclosing JS/TS function to an Angular/JS finding.

    Mirrors ``enrich_python_finding_context`` but for TypeScript / JavaScript /
    inline-JS-in-HTML files.  The extracted function text replaces the (often
    sparse) ``code_snippet`` stored by the scanner, giving Ollama enough context
    to generate a real fix instead of a placeholder.

    Returns the dict unchanged when:
    - technology is not "angular"
    - source file cannot be read
    - no enclosing function is found
    """
    if normalize_patch_technology_for_finding(details) != "angular":
        return details

    source = read_finding_source_file(str(details.get("file_path") or ""))
    if not source:
        return details

    try:
        func_name, func_source = find_enclosing_js_function(source, details.get("line_start"))
    except Exception as exc:
        _logger.warning(
            "enrich_js_finding_context: extraction failed for %s: %s",
            details.get("file_path"),
            exc,
        )
        return details

    if not func_source:
        return details

    return {
        **details,
        "expected_function": func_name or "",
        "expected_function_source": func_source,
        "code_snippet": func_source,
    }


def build_finding_details(session: Session, finding: Finding) -> dict:
    # Prefer rule_id / file_path inference over project technology.
    # This fixes the case where a Python project has SonarQube/Semgrep findings
    # in .js / .html / .java files: those findings should use the JS or Java
    # prompt and patch strategy, not the Python one.
    project_technology = get_finding_technology(session, finding)
    effective_technology = (
        infer_technology_from_finding(finding.rule_id or "", finding.file_path or "")
        or project_technology
    )
    details = {
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
        "technology": effective_technology,
    }
    details = enrich_python_finding_context(details)
    details = enrich_js_finding_context(details)
    return details


def remediation_matches_finding_technology(remediation_text: str, finding_details: dict) -> bool:
    if is_python_duplicate_literal_rule(finding_details):
        return remediation_text_matches_python_s1192(remediation_text or "", finding_details)

    if is_python_weak_hash_rule(finding_details):
        return remediation_text_matches_python_b324(remediation_text or "", finding_details)

    return validate_remediation_patch(remediation_text or "", finding_details)[0]


def build_deterministic_remediation_text(finding_details: dict) -> str | None:
    if not is_deterministic_python_rule(finding_details):
        return None

    try:
        resolved_file_path = resolve_finding_file_path(str(finding_details.get("file_path") or ""))
        if not resolved_file_path.exists() or not is_allowed_scan_path(resolved_file_path):
            return None

        original_content = resolved_file_path.read_text(encoding="utf-8", errors="replace")
        if is_python_duplicate_literal_rule(finding_details):
            _, details = build_python_s1192_constant_patch(original_content, finding_details)
            return build_python_s1192_remediation_text(details)

        if is_python_weak_hash_rule(finding_details):
            _, details = build_python_b324_weak_hash_patch(original_content, finding_details)
            return build_python_b324_remediation_text(details)
    except Exception as exc:
        _logger.warning(
            "build_deterministic_remediation_text: could not build deterministic remediation "
            "for finding %s: %s",
            finding_details.get("id"),
            exc,
        )
        return None

    return None


def validate_remediation_patch(remediation_text: str, finding_details: dict) -> tuple[bool, str]:
    technology = normalize_patch_technology_for_finding(finding_details)
    file_path = str(finding_details.get("file_path") or "")
    patch_content = extract_code_block_for_technology(remediation_text or "", technology, file_path)

    if not patch_content:
        return False, (
            f"La remediación no contiene un bloque de código {technology} válido para `{file_path}`."
        )

    if not finding_details.get("line_start"):
        return True, "language-only validation"

    original_content = read_finding_source_file(file_path)
    if not original_content:
        return False, (
            f"No pude leer el archivo fuente `{file_path}` para validar la remediación antes de guardarla."
        )

    try:
        patched_content = build_safe_patched_content(
            original_content,
            patch_content,
            finding_details,
        )
        safe, reason = is_safe_to_apply(original_content, patched_content)
        if not safe:
            return False, reason
    except GitHubClientError as exc:
        return False, exc.user_message
    except Exception as exc:
        return False, str(exc)

    return True, "ok"


def cached_remediation_is_reusable(patch_diff: str, finding_details: dict) -> bool:
    """Lightweight cache check: verify the stored patch contains a valid code block.

    Unlike ``validate_remediation_patch``, this function does NOT read the local
    source file or re-apply the patch.  Local edits to source files must never
    invalidate a previously-validated remediation — the user's complaint was that
    each ``POST /api/remediate`` call produced a *different* Ollama-generated fix
    because a locally-modified file caused the cache check to fail and triggered a
    new LLM call.
    """
    if is_python_duplicate_literal_rule(finding_details):
        return remediation_text_matches_python_s1192(patch_diff or "", finding_details)
    if is_python_weak_hash_rule(finding_details):
        return remediation_text_matches_python_b324(patch_diff or "", finding_details)
    technology = normalize_patch_technology_for_finding(finding_details)
    file_path = str(finding_details.get("file_path") or "")
    patch_content = extract_code_block_for_technology(patch_diff or "", technology, file_path)
    if not patch_content:
        return False
    if looks_like_python_only_prose(patch_content):
        return False
    return True


def latest_valid_remediation_ids(session: Session, findings: list[Finding]) -> set[uuid.UUID]:
    finding_ids = {finding.id for finding in findings}
    if not finding_ids:
        return set()

    remediations = session.exec(
        select(Remediation)
        .where(Remediation.finding_id.in_(finding_ids))
        .order_by(Remediation.id.desc())
    ).all()
    latest_by_finding: dict[uuid.UUID, Remediation] = {}

    for remediation in remediations:
        latest_by_finding.setdefault(remediation.finding_id, remediation)

    valid_ids: set[uuid.UUID] = set()
    for finding in findings:
        remediation = latest_by_finding.get(finding.id)
        if not remediation:
            continue

        finding_details = build_finding_details(session, finding)
        if remediation_matches_finding_technology(remediation.patch_diff, finding_details):
            valid_ids.add(finding.id)

    return valid_ids


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


async def scan_project(project: Project, target_url: str | None = None) -> dict:
    if project.scan_profile_id is not None:
        with Session(engine) as session:
            profile = session.get(ScanProfile, project.scan_profile_id)
        if profile is not None:
            return await _scan_with_profile(project, profile, target_url)

    return await run_scan(project.target_path, project.technology, project.id)


async def _scan_with_profile(
    project: Project,
    profile: ScanProfile,
    target_url: str | None = None,
) -> dict:
    orchestrator = ScanOrchestrator()
    result = await asyncio.to_thread(
        orchestrator.run,
        profile,
        project.target_path,
        project.technology,
        project.id,
        target_url,
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
        "target_url": target_url,
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


@app.put("/api/projects/{project_id}/profile")
async def update_project_profile(project_id: uuid.UUID, body: ProjectProfileUpdate):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        if body.scan_profile_id is None:
            project.scan_profile_id = None
        else:
            profile = session.get(ScanProfile, body.scan_profile_id)
            if not profile:
                raise HTTPException(status_code=404, detail="ScanProfile not found")
            ensure_profile_matches_project(profile, project)
            project.scan_profile_id = profile.id

        session.add(project)
        session.commit()
        session.refresh(project)
        last_scans = get_last_scans_for_projects(session, [project.id])
        return project_to_response(
            project,
            get_project_findings(session, project.id),
            last_scans.get(project.id),
        )


@app.get("/api/projects/{project_id}/findings")
async def get_project_findings_endpoint(project_id: uuid.UUID):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        findings = get_project_findings(session, project.id)
        remediated_finding_ids = latest_valid_remediation_ids(session, findings)
        now = datetime.now(timezone.utc)

        return [
            {
                **finding.model_dump(mode="json"),
                "has_remediation": finding.id in remediated_finding_ids,
                "remediation_status": "Parche listo"
                if finding.id in remediated_finding_ids
                else "Sin parche",
                "project_source_type": project.source_type,
                "sla_status": get_sla_status(finding, now),
            }
            for finding in findings
        ]


@app.post("/api/projects/{project_id}/scan")
async def scan_project_endpoint(project_id: uuid.UUID, request: ScanRequest | None = None):
    with Session(engine) as session:
        project = session.get(Project, project_id)

        if not project:
            raise HTTPException(status_code=404, detail="Project not found")

        target_path = validate_scan_target(project.target_path)
        project.target_path = target_path
        session.add(project)
        session.commit()
        session.refresh(project)

    return await scan_project(project, request.target_url if request else None)


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
        request = ScanRequest()

    # Priority 1: explicit target_path in body
    if request.target_path is not None:
        technology = (request.technology or "python").strip().lower()
        if technology not in {"python", "angular", "typescript", "java"}:
            raise HTTPException(status_code=400, detail="Unsupported technology value")
        target_path = validate_scan_target(request.target_path)
        return await run_scan(target_path, technology)

    # Priority 2: project_id → look up workspace path in DB
    if request.project_id is not None:
        with Session(engine) as session:
            project = session.get(Project, request.project_id)
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        if project.target_path:
            target_path = validate_scan_target(project.target_path)
            with Session(engine) as session:
                db_project = session.get(Project, project.id)
                if db_project:
                    db_project.target_path = target_path
                    session.add(db_project)
                    session.commit()
                    session.refresh(db_project)
                    project = db_project
            if request.profile_id is not None:
                with Session(engine) as session:
                    profile = session.get(ScanProfile, request.profile_id)
                if profile:
                    return await _scan_with_profile(project, profile, request.target_url)
            return await scan_project(project, request.target_url)
        # project.target_path is null → fall through to dummy

    # Priority 3: fallback — retro-compat, no target provided
    fallback = str(PROJECT_ROOT / "src" / "dummy_vulnerable_app.py")
    return await run_scan(fallback, "python")


@app.post("/api/scan/sonar")
async def scan_with_sonar(target_path: str = "."):
    """Fetch SonarQube issues and persist them. Optionally triggers sonar-scanner CLI first."""
    import logging as _logging
    from src.scanners.sonarqube_adapter import SonarQubeAdapter, run_sonar_scan

    _logger = _logging.getLogger(__name__)

    resolved_path = (
        str(PROJECT_ROOT)
        if target_path == "."
        else validate_scan_target(target_path)
    )

    # Try CLI scan; skip gracefully if sonar-scanner is not installed
    cli_result = None
    try:
        cli_result = await asyncio.to_thread(run_sonar_scan, resolved_path)
    except RuntimeError as exc:
        _logger.warning("sonar-scanner CLI skipped: %s", exc)

    adapter = SonarQubeAdapter()
    findings = await asyncio.to_thread(adapter.execute_scan, resolved_path)

    if adapter.error and not findings:
        raise HTTPException(status_code=500, detail=adapter.error)

    saved = await asyncio.to_thread(
        persist_scan,
        resolved_path,
        "python",
        adapter,
        findings,
    )

    return {
        "scan_submitted": cli_result is not None,
        "issues_fetched": len(findings),
        "new_findings": saved,
        "sonarqube_url": adapter.base_url,
        "project_key": adapter.project_key or adapter.derive_project_key(resolved_path),
        "warning": adapter.error,
    }


@app.get("/api/ai-status")
async def ai_status():
    return await check_ollama_status()


@app.post("/api/remediate/{finding_id}")
async def remediate_finding(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_details = build_finding_details(session, finding)

        # Cache hit: return existing remediation without calling Ollama.
        # Use cached_remediation_is_reusable (does NOT re-read local source file)
        # so that a locally-edited file never invalidates a valid cached patch.
        existing = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .order_by(Remediation.id.desc())
        ).first()

        if existing and cached_remediation_is_reusable(existing.patch_diff, finding_details):
            return {
                "finding_id": str(finding_id),
                "remediation_id": str(existing.id),
                "patch": existing.patch_diff,
                "cached": True,
            }

        if existing:
            _logger.warning(
                "remediate_finding: ignoring stale remediation %s for finding %s; "
                "patch does not match inferred technology %s",
                existing.id,
                finding_id,
                normalize_patch_technology_for_finding(finding_details),
            )

    deterministic_patch = build_deterministic_remediation_text(finding_details)
    if deterministic_patch:
        rule_id = str(finding_details.get("rule_id") or "deterministic")
        with Session(engine) as session:
            remediation = Remediation(
                finding_id=finding_id,
                strategy="deterministic-rule-patch",
                model_used=f"rule/{rule_id}",
                prompt_used=f"deterministic remediation for {rule_id}",
                patch_diff=deterministic_patch,
                applied_at=None,
                verified_at=None,
                outcome="suggested",
            )
            session.add(remediation)
            session.commit()
            session.refresh(remediation)

            return {
                "finding_id": str(finding_id),
                "remediation_id": str(remediation.id),
                "patch": deterministic_patch,
                "cached": False,
            }

    # No prior remediation — validate Ollama before generating
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

    patch = await generate_patch(finding_details)
    valid_patch, validation_reason = validate_remediation_patch(patch, finding_details)

    # Always save and return the patch so the modal opens.
    # When validation fails we mark it as "manual_review" and surface a
    # validation_warning field — the frontend shows the patch with a warning
    # banner and the PR creation flow will fall back to a proposal-only PR.
    patch_outcome = "suggested" if valid_patch else "manual_review"
    _logger.info(
        "remediate_finding: patch for finding %s outcome=%s valid=%s reason=%s",
        finding_id, patch_outcome, valid_patch, validation_reason,
    )

    with Session(engine) as session:
        remediation = Remediation(
            finding_id=finding_id,
            strategy="llm-suggested-patch",
            model_used=f"ollama/{OLLAMA_MODEL}",
            prompt_used=build_prompt(finding_details),
            patch_diff=patch,
            applied_at=None,
            verified_at=None,
            outcome=patch_outcome,
        )
        session.add(remediation)
        session.commit()
        session.refresh(remediation)

        response: dict = {
            "finding_id": str(finding_id),
            "remediation_id": str(remediation.id),
            "patch": patch,
            "cached": False,
        }
        if not valid_patch:
            response["validation_warning"] = validation_reason
        return response


@app.get("/api/remediate/{finding_id}/pr")
async def get_remediation_pr(finding_id: uuid.UUID):
    """Return persisted PR data for a finding, or 404 if none exists."""
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        remediation = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .where(Remediation.pr_url != None)  # noqa: E711
            .order_by(Remediation.id.desc())
        ).first()

        if not remediation or not remediation.pr_url:
            raise HTTPException(status_code=404, detail="No PR found for this finding")

        finding_details = build_finding_details(session, finding)
        if not remediation_matches_finding_technology(remediation.patch_diff, finding_details):
            raise HTTPException(
                status_code=404,
                detail="Stored PR remediation is stale; regenerate before showing it as applied",
            )

        pr_type = (
            "proposal"
            if (remediation.pr_branch or "").startswith("security-proposal-")
            else "code_fix"
        )

        return {
            "finding_id": str(finding_id),
            "pr_url": remediation.pr_url,
            "branch": remediation.pr_branch,
            "pr_type": pr_type,
        }


@app.get("/api/findings/{finding_id}/pr-diff")
async def get_finding_pr_diff(finding_id: uuid.UUID):
    """Return the real unified diff of the GitHub PR associated with a finding."""
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        remediation = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .where(Remediation.pr_url != None)  # noqa: E711
            .order_by(Remediation.id.desc())
        ).first()

        if not remediation:
            return {"diff": None, "message": "Este finding no tiene PR asociado"}

        finding_details = build_finding_details(session, finding)
        if not remediation_matches_finding_technology(remediation.patch_diff, finding_details):
            return {
                "diff": None,
                "message": "El PR asociado proviene de una remediación obsoleta; regenera el fix.",
            }

        pr_url = remediation.pr_url

    diff_data = await get_pr_diff(pr_url)
    if not diff_data:
        return {"diff": None, "message": "No se pudo obtener el diff del PR"}

    return diff_data


@app.get("/api/remediate/{finding_id}/preview-diff")
async def get_remediation_preview_diff(finding_id: uuid.UUID):
    """Return the exact before/after file contents that a remediation PR would commit.

    Applies ``build_safe_patched_content`` to the LOCAL source file using the stored
    patch, so the dashboard can render an accurate diff preview *before* any PR is
    created — matching what the PR will actually contain.
    """
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_details = build_finding_details(session, finding)

        existing = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .order_by(Remediation.id.desc())
        ).first()

    if not existing:
        raise HTTPException(status_code=404, detail="No remediation found")

    file_path = str(finding_details.get("file_path") or "")
    technology = normalize_patch_technology_for_finding(finding_details)

    original_content = read_finding_source_file(file_path)
    if not original_content:
        raise HTTPException(
            status_code=404,
            detail=f"Source file not accessible locally: {file_path}",
        )

    patch_content = extract_code_block_for_technology(existing.patch_diff, technology, file_path)
    if not patch_content:
        raise HTTPException(
            status_code=422,
            detail=f"No valid {technology} code block found in remediation",
        )

    try:
        patched_content = build_safe_patched_content(original_content, patch_content, finding_details)
    except GitHubClientError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"Cannot compute preview: {exc.user_message}",
        ) from exc

    return {"original": original_content, "patched": patched_content}


@app.post("/api/remediate/{finding_id}/pr")
async def create_remediation_pr(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        remediations = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .order_by(Remediation.id.desc())
        ).all()

        if not remediations:
            raise HTTPException(status_code=404, detail="No remediation found for this finding")

        remediation = remediations[0]
        finding_details = build_finding_details(session, finding)
        remediation_text = remediation.patch_diff

    deterministic_rule = is_deterministic_python_rule(finding_details)
    is_manual_review = remediation.outcome == "manual_review"

    # A "manual_review" patch never passed full validation — skip the language
    # check and go straight to proposal PR creation so the modal can still work.
    # A genuine language/technology mismatch (stale patch) still gets a 409.
    if (
        not deterministic_rule
        and not is_manual_review
        and not remediation_matches_finding_technology(remediation_text, finding_details)
    ):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "stale_remediation_language_mismatch",
                "message": (
                    "La remediación guardada no coincide con la tecnología actual del finding. "
                    "Regenera la remediación antes de abrir el PR."
                ),
                "technology": normalize_patch_technology_for_finding(finding_details),
                "file_path": finding_details.get("file_path"),
                "rule_id": finding_details.get("rule_id"),
            },
        )

    # Proactive check: return existing open PR without creating a duplicate
    if remediation.pr_url and remediation.pr_branch and not deterministic_rule:
        try:
            existing_pr = await get_existing_open_pr_for_branch(remediation.pr_branch)
            if existing_pr:
                return {
                    "finding_id": str(finding_id),
                    "remediation_id": str(remediation.id),
                    "pr_url": remediation.pr_url,
                    "branch": remediation.pr_branch,
                    "number": existing_pr.get("number"),
                    "pr_type": "proposal"
                    if remediation.pr_branch.startswith("security-proposal-")
                    else "code_fix",
                    "cached": True,
                }
            # PR was closed/merged — fall through to create a new one
        except Exception:
            pass  # Silently continue if GitHub is unreachable

    # Attempt to create a real code-fix PR.  If the safety guardrails reject the
    # patch (stub detected, functions deleted, etc.) we fall back to a proposal-
    # only PR that contains just a Markdown file — no source code is modified.
    # "manual_review" patches never passed full validation so they go straight
    # to a proposal PR without attempting a source-code commit.
    pr_type = "code_fix"
    safety_reason: str | None = None
    if is_manual_review:
        safety_reason = (
            "El parche generado por la IA requiere revisión manual antes de aplicarse "
            "(no pasó la validación automática del parche)."
        )
        _logger.info(
            "create_remediation_pr: manual_review outcome for finding %s — creating proposal PR",
            finding_id,
        )
        try:
            pr = await create_proposal_pr(finding_details, remediation_text, safety_reason)
            pr_type = "proposal"
        except GitHubClientError as prop_exc:
            raise HTTPException(status_code=502, detail=prop_exc.to_dict()) from prop_exc
    else:
        try:
            pr = await create_security_pr(finding_details, remediation_text)
            pr_type = pr.get("pr_type", "code_fix")
        except GitHubClientError as exc:
            if exc.code != "safety_check_failed":
                raise HTTPException(status_code=502, detail=exc.to_dict()) from exc
            # Safety check failed → create a proposal-only PR instead of touching code
            safety_reason = exc.user_message
            _logger.warning(
                "create_remediation_pr: safety check failed for finding %s — %s",
                finding_id, safety_reason,
            )
            try:
                pr = await create_proposal_pr(finding_details, remediation_text, safety_reason)
                pr_type = "proposal"
            except GitHubClientError as prop_exc:
                raise HTTPException(status_code=502, detail=prop_exc.to_dict()) from prop_exc

    # Persist PR data on the remediation row
    with Session(engine) as session:
        rem = session.get(Remediation, remediation.id)
        if rem:
            rem.pr_url = pr["url"]
            rem.pr_branch = pr["branch"]
            applied_remediation_text = pr.get("applied_remediation_text")
            if applied_remediation_text:
                rem.patch_diff = applied_remediation_text
            session.add(rem)
            session.commit()

    response_data: dict = {
        "finding_id":     str(finding_id),
        "remediation_id": str(remediation.id),
        "pr_url":         pr["url"],
        "branch":         pr["branch"],
        "number":         pr.get("number"),
        "pr_type":        pr_type,
        "cached":         False,
    }
    anchor_warning = pr.get("anchor_warning")
    if anchor_warning:
        response_data["warning"] = anchor_warning
        response_data["status"]  = "created_with_warning"
    if safety_reason:
        response_data["warning"] = safety_reason
        response_data["status"]  = "created_proposal"
    return response_data


@app.delete("/api/remediate/{finding_id}/pr")
async def delete_remediation_pr_branch(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        remediations = session.exec(
            select(Remediation)
            .where(Remediation.finding_id == finding_id)
            .order_by(Remediation.id.desc())
        ).all()

        persisted_branch = next((rem.pr_branch for rem in remediations if rem.pr_branch), None)

    branch_name = persisted_branch or f"security-fix-{finding_id}"

    try:
        close_result = await close_open_pr_for_branch(branch_name)
        result = await delete_security_branch(branch_name)
    except GitHubClientError as exc:
        raise HTTPException(status_code=502, detail=exc.to_dict()) from exc

    with Session(engine) as session:
        remediations = session.exec(
            select(Remediation).where(Remediation.finding_id == finding_id)
        ).all()
        for remediation in remediations:
            remediation.pr_url = None
            remediation.pr_branch = None
            session.add(remediation)
        session.commit()

    return {
        "finding_id": str(finding_id),
        "branch": result["branch"],
        "deleted": result["deleted"],
        "pr_closed": close_result["closed"],
        "pr_number": close_result["number"],
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


@app.get("/api/findings/{finding_id}/file_content")
async def get_finding_file_content(finding_id: uuid.UUID):
    """Devuelve el contenido completo del archivo fuente asociado al finding."""
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        if not finding.file_path:
            raise HTTPException(status_code=404, detail="Finding has no file_path")
    try:
        resolved_file_path = resolve_finding_file_path(finding.file_path)
        if not resolved_file_path.exists():
            raise FileNotFoundError(str(resolved_file_path))
        if not is_allowed_scan_path(resolved_file_path):
            raise HTTPException(status_code=403, detail="Finding file is outside the allowed scan roots")

        with resolved_file_path.open("r", encoding="utf-8", errors="replace") as f:
            content = f.read()
        return {
            "content": content,
            "file_path": str(resolved_file_path),
            "line_number": finding.line_start if finding.line_start else 1,
        }
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {finding.file_path}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="ping binary not available in this container. Rebuild the image.",
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Ping timeout")

    return {
        "ip": safe_ip,
        "returncode": result.returncode,
        "reachable": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }
