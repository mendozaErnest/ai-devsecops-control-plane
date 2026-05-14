import asyncio
import hashlib
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

from sqlmodel import Session, select

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.api.database import create_db_and_tables, engine
from src.api.models import Finding, Scan, Target


TARGET_NAME = "Backend FastAPI"
TARGET_TYPE = "api"
TARGET_PATH = "src/dummy_vulnerable_app.py"


def get_bandit_command() -> list[str] | None:
    bandit_path = shutil.which("bandit")

    if bandit_path:
        return [bandit_path]

    env_bandit_path = Path(sys.executable).with_name("bandit")

    if env_bandit_path.exists():
        return [str(env_bandit_path)]

    return None


def build_fingerprint(result: dict) -> str:
    fingerprint_source = "|".join(
        [
            result.get("test_id", ""),
            result.get("filename", ""),
            str(result.get("line_number", "")),
            result.get("issue_text", ""),
            result.get("code", ""),
        ]
    )
    return hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()


def get_or_create_target(session: Session) -> Target:
    target = session.exec(select(Target).where(Target.name == TARGET_NAME)).first()

    if target:
        return target

    target = Target(name=TARGET_NAME, type=TARGET_TYPE, path=TARGET_PATH)
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def persist_scan(raw_output: dict, returncode: int) -> int:
    create_db_and_tables()

    results = raw_output.get("results", [])
    metrics = raw_output.get("metrics", {})
    now = datetime.utcnow()

    with Session(engine) as session:
        target = get_or_create_target(session)
        scan = Scan(
            target_id=target.id,
            tool="bandit",
            surface=TARGET_PATH,
            triggered_by="local-script",
            status="completed" if returncode in (0, 1) else "failed",
            started_at=now,
            finished_at=now,
            raw_output=raw_output,
            summary={
                "returncode": returncode,
                "total_findings": len(results),
                "metrics": metrics,
            },
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)

        saved_findings = 0

        for result in results:
            line_start = result.get("line_number")
            line_range = result.get("line_range") or []
            line_end = line_range[-1] if line_range else line_start
            fingerprint = build_fingerprint(result)

            finding = session.exec(
                select(Finding).where(Finding.fingerprint == fingerprint)
            ).first()

            if finding:
                finding.scan_id = scan.id
                finding.last_seen_at = now
                finding.status = "open"
                finding.severity = result.get("issue_severity", "UNKNOWN")
                finding.confidence = result.get("issue_confidence", "UNKNOWN")
                finding.description = result.get("issue_text", "")
                finding.file_path = result.get("filename", "")
                finding.line_start = line_start
                finding.line_end = line_end
                finding.code_snippet = result.get("code")
            else:
                finding = Finding(
                    scan_id=scan.id,
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
                    first_seen_at=now,
                    last_seen_at=now,
                    fingerprint=fingerprint,
                )
                session.add(finding)

            saved_findings += 1

        session.commit()

    return saved_findings


async def run_scan() -> dict:
    bandit_command = get_bandit_command()

    if bandit_command is None:
        return {
            "success": False,
            "saved_findings": 0,
            "error": "Bandit is not installed or is not available in PATH.",
        }

    try:
        process = await asyncio.create_subprocess_exec(
            *bandit_command,
            TARGET_PATH,
            "-f",
            "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {
            "success": False,
            "saved_findings": 0,
            "error": "Bandit is not installed or is not available in PATH.",
        }

    stdout, stderr = await process.communicate()
    stdout_text = stdout.decode("utf-8")
    stderr_text = stderr.decode("utf-8")

    try:
        raw_output = json.loads(stdout_text or "{}")
    except json.JSONDecodeError as exc:
        return {
            "success": False,
            "saved_findings": 0,
            "returncode": process.returncode,
            "error": f"Could not parse Bandit JSON output: {exc}",
        }

    saved_findings = await asyncio.to_thread(
        persist_scan,
        raw_output,
        process.returncode,
    )

    return {
        "success": process.returncode in (0, 1),
        "saved_findings": saved_findings,
        "returncode": process.returncode,
        "tool": "bandit",
    }


def main():
    result = asyncio.run(run_scan())
    print(json.dumps(result, indent=2))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
