from pathlib import Path
import ipaddress
import subprocess
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from sqlmodel import Session, select

from .database import create_db_and_tables, engine
from .models import Finding, Remediation
from src.ai_engine.remediator import OLLAMA_MODEL, build_prompt, generate_patch
from src.integrations.github_client import GitHubClientError, create_security_pr
from src.scanners.escaneo import run_scan


app = FastAPI()

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_INDEX = PROJECT_ROOT / "src" / "dashboard" / "index.html"


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
async def index():
    return FileResponse(DASHBOARD_INDEX)


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


@app.post("/api/scan")
async def scan_code():
    return await run_scan()


@app.post("/api/remediate/{finding_id}")
async def remediate_finding(finding_id: uuid.UUID):
    with Session(engine) as session:
        finding = session.get(Finding, finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_details = {
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
        }

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
        finding_details = {
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
        }
        remediation_text = remediation.patch_diff

    try:
        pr = await create_security_pr(finding_details, remediation_text)
    except GitHubClientError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "finding_id": finding_id,
        "remediation_id": remediation.id,
        "pr_url": pr["url"],
        "branch": pr["branch"],
        "number": pr.get("number"),
    }


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
