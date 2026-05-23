from datetime import datetime, timedelta

from sqlmodel import Session, SQLModel, create_engine, select

from src.api.models import Finding, FindingAuditEvent, Scan, Target
from src.scanners.escaneo import (
    ACCEPTED_RISK_STATUS,
    FALSE_POSITIVE_STATUS,
    FIXED_STATUS,
    OPEN_STATUS,
    REGRESSION_STATUS,
    build_fingerprint,
    upsert_finding,
)


def make_session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    return Session(engine)


def bandit_result(line_number=10):
    return {
        "test_id": "B602",
        "test_name": "subprocess_popen_with_shell_equals_true",
        "issue_text": "subprocess call with shell=True identified",
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "filename": "src/example.py",
        "line_number": line_number,
        "line_range": [line_number],
        "code": "subprocess.Popen(cmd, shell=True)",
    }


def create_scan(session: Session) -> Scan:
    target = Target(name="test target", type="python_project", path="src/example.py")
    session.add(target)
    session.commit()
    session.refresh(target)

    scan = Scan(
        target_id=target.id,
        tool="bandit",
        surface="sast",
        triggered_by="test",
        status="completed",
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def test_upsert_finding_creates_open_finding():
    with make_session() as session:
        scan = create_scan(session)
        now = datetime.utcnow()

        action, finding = upsert_finding(session, scan.id, bandit_result(), now)
        session.commit()

        assert action == "created"
        assert finding is not None
        assert finding.status == OPEN_STATUS
        assert finding.first_seen_at == now
        assert finding.last_seen_at == now


def test_upsert_finding_updates_open_finding_without_new_row():
    with make_session() as session:
        scan = create_scan(session)
        first_seen = datetime.utcnow()
        later = first_seen + timedelta(minutes=5)

        upsert_finding(session, scan.id, bandit_result(), first_seen)
        session.commit()

        action, finding = upsert_finding(session, scan.id, bandit_result(), later)
        session.commit()

        findings = session.exec(select(Finding)).all()
        assert action == "seen_again"
        assert finding is not None
        assert finding.status == OPEN_STATUS
        assert finding.last_seen_at == later
        assert len(findings) == 1


def test_upsert_finding_marks_fixed_finding_as_regression():
    with make_session() as session:
        scan = create_scan(session)
        result = bandit_result()
        fingerprint = build_fingerprint(result)
        finding = Finding(
            scan_id=scan.id,
            rule_id="B602",
            title="old fixed issue",
            description="old",
            severity="LOW",
            confidence="LOW",
            file_path="src/example.py",
            line_start=10,
            status=FIXED_STATUS,
            fingerprint=fingerprint,
        )
        session.add(finding)
        session.commit()

        action, updated = upsert_finding(session, scan.id, result, datetime.utcnow())
        session.commit()

        assert action == "regression"
        assert updated is not None
        assert updated.status == REGRESSION_STATUS
        assert updated.severity == "HIGH"


def test_upsert_finding_ignores_accepted_risk_and_false_positive():
    for ignored_status in (ACCEPTED_RISK_STATUS, FALSE_POSITIVE_STATUS):
        with make_session() as session:
            scan = create_scan(session)
            result = bandit_result()
            fingerprint = build_fingerprint(result)
            first_seen = datetime.utcnow()
            finding = Finding(
                scan_id=scan.id,
                rule_id="B602",
                title="ignored issue",
                description="leave this alone",
                severity="LOW",
                confidence="LOW",
                file_path="src/example.py",
                line_start=10,
                status=ignored_status,
                first_seen_at=first_seen,
                last_seen_at=first_seen,
                fingerprint=fingerprint,
            )
            session.add(finding)
            session.commit()

            action, ignored = upsert_finding(
                session,
                scan.id,
                result,
                first_seen + timedelta(minutes=5),
            )
            session.commit()

            assert action == "ignored"
            assert ignored is not None
            assert ignored.status == ignored_status
            assert ignored.description == "leave this alone"
            assert ignored.last_seen_at == first_seen


def test_upsert_finding_regression_increments_count():
    with make_session() as session:
        scan = create_scan(session)
        result = bandit_result()
        fingerprint = build_fingerprint(result)
        finding = Finding(
            scan_id=scan.id,
            rule_id="B602",
            title="fixed issue",
            description="was fixed",
            severity="LOW",
            confidence="LOW",
            file_path="src/example.py",
            line_start=10,
            status=FIXED_STATUS,
            regression_count=0,
            fingerprint=fingerprint,
        )
        session.add(finding)
        session.commit()

        action, updated = upsert_finding(session, scan.id, result, datetime.utcnow())
        session.commit()

        assert action == "regression"
        assert updated.regression_count == 1


def test_upsert_finding_regression_creates_audit_event():
    with make_session() as session:
        scan = create_scan(session)
        result = bandit_result()
        fingerprint = build_fingerprint(result)
        finding = Finding(
            scan_id=scan.id,
            rule_id="B602",
            title="fixed issue",
            description="was fixed",
            severity="LOW",
            confidence="LOW",
            file_path="src/example.py",
            line_start=10,
            status=FIXED_STATUS,
            regression_count=0,
            fingerprint=fingerprint,
        )
        session.add(finding)
        session.commit()
        finding_id = finding.id

        upsert_finding(session, scan.id, result, datetime.utcnow())
        session.commit()

        events = session.exec(
            select(FindingAuditEvent).where(FindingAuditEvent.finding_id == finding_id)
        ).all()

        assert len(events) == 1
        assert events[0].event_type == "regression"
        assert events[0].from_status == FIXED_STATUS
        assert events[0].to_status == REGRESSION_STATUS
