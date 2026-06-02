"""Tests for Prometheus security metrics integration.

Coverage:
- GET /metrics returns 200 text/plain (requires prometheus_client installed).
- findings_total increments after persist_scan with new findings.
- remediations_generated_total{source="db_cache"} increments on remediation cache hit.
- sla_breached_findings gauge reflects the real count of breached findings.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid

import pytest
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from src.api.models import Finding, Scan, Target


# ── helpers ──────────────────────────────────────────────────────────────────

def make_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _make_finding(session: Session, severity: str, status: str, sla_deadline: datetime | None = None) -> Finding:
    target = Target(name="t", type="python", path="/tmp/t.py")
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

    finding = Finding(
        scan_id=scan.id,
        rule_id="B101",
        title="Test finding",
        description="Test",
        severity=severity,
        confidence="HIGH",
        file_path="/tmp/t.py",
        line_start=1,
        status=status,
        fingerprint=uuid.uuid4().hex,
        first_seen_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow(),
        sla_deadline=sla_deadline,
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


# ── test GET /metrics ─────────────────────────────────────────────────────────

def test_metrics_endpoint_returns_200():
    """GET /metrics must return 200 with Content-Type: text/plain when
    prometheus_client and prometheus_fastapi_instrumentator are installed."""
    pytest.importorskip("prometheus_client", reason="prometheus_client not installed")
    pytest.importorskip(
        "prometheus_fastapi_instrumentator",
        reason="prometheus_fastapi_instrumentator not installed",
    )

    from fastapi.testclient import TestClient
    from src.api import main as app_module

    with patch.object(app_module, "create_db_and_tables", lambda: None), \
         patch.object(app_module, "WORKSPACE_ROOT", MagicMock(mkdir=lambda **_: None)), \
         patch.object(app_module, "_refresh_sla_breached_gauge", lambda: None):
        client = TestClient(app_module.app)
        response = client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers.get("content-type", "")


# ── test record_finding helper ────────────────────────────────────────────────

def test_record_finding_does_not_raise():
    """record_finding() must not raise regardless of prometheus availability."""
    from src.metrics.security_metrics import record_finding
    record_finding("high", "bandit")
    record_finding("critical", "semgrep")
    record_finding("UNKNOWN", "unknown_tool")


def test_record_regression_does_not_raise():
    """record_regression() must not raise regardless of prometheus availability."""
    from src.metrics.security_metrics import record_regression
    record_regression()


# ── test findings_total increments on persist_scan ────────────────────────────

def test_persist_scan_calls_record_finding_per_finding():
    """persist_scan() must call record_finding once per saved finding."""
    engine = make_engine()

    finding = Finding(
        rule_id="B101",
        title="Assert",
        description="Use of assert",
        severity="low",
        confidence="HIGH",
        file_path="/tmp/app.py",
        line_start=5,
        status="open",
        tool="bandit",
        fingerprint=uuid.uuid4().hex,
        first_seen_at=datetime.utcnow(),
        last_seen_at=datetime.utcnow(),
    )

    adapter = MagicMock()
    adapter.tool_name = "bandit"
    adapter.raw_output = {}
    adapter.returncode = 1

    call_log: list[tuple] = []

    def fake_record_finding(severity: str, tool: str) -> None:
        call_log.append((severity, tool))

    with patch("src.scanners.escaneo.engine", engine), \
         patch("src.scanners.escaneo.create_db_and_tables", lambda: None), \
         patch("src.scanners.escaneo.record_finding", fake_record_finding):
        from src.scanners.escaneo import persist_scan
        persist_scan("/tmp", "python", adapter, [finding])

    assert len(call_log) == 1
    assert call_log[0][0] == "low"


# ── test remediations_generated_total on cache hit ────────────────────────────

def test_record_remediation_cache_hit():
    """record_remediation must be called with source='db_cache' on cache hit."""
    from src.metrics.security_metrics import record_remediation

    calls: list[str] = []

    try:
        from prometheus_client import Counter
        with patch("src.metrics.security_metrics.remediations_generated_total") as mock_counter:
            mock_counter.labels.return_value = MagicMock()
            record_remediation("db_cache")
            mock_counter.labels.assert_called_once_with(source="db_cache")
    except ImportError:
        # Noop stubs: just call and verify no exception
        record_remediation("db_cache")


def test_record_remediation_ollama_tracks_latency():
    """record_remediation with source='ollama' must observe latency when provided."""
    from src.metrics.security_metrics import record_remediation, remediation_latency_seconds

    with patch("src.metrics.security_metrics.remediation_latency_seconds") as mock_hist:
        mock_hist.labels.return_value = MagicMock()
        record_remediation("ollama", latency_seconds=1.5)
        mock_hist.labels.assert_called_once_with(source="ollama")
        mock_hist.labels.return_value.observe.assert_called_once_with(1.5)


# ── test sla_breached_gauge reflects breached findings ────────────────────────

def test_sla_breached_gauge_reflects_breached_count():
    """_refresh_sla_breached_gauge() must set the gauge to the count of open/regression
    findings whose sla_deadline is in the past."""
    engine = make_engine()
    past = datetime.utcnow() - timedelta(days=5)
    future = datetime.utcnow() + timedelta(days=5)

    gauge_values: list[int] = []

    def fake_update(count: int) -> None:
        gauge_values.append(count)

    with Session(engine) as session:
        _make_finding(session, "HIGH", "open", sla_deadline=past)    # breached
        _make_finding(session, "HIGH", "regression", sla_deadline=past)  # breached
        _make_finding(session, "LOW", "open", sla_deadline=future)   # not breached
        _make_finding(session, "MEDIUM", "fixed", sla_deadline=past)  # exempt

    import src.api.main as app_module
    with patch("src.api.main.engine", engine), \
         patch("src.api.main.update_sla_breached_gauge", fake_update):
        app_module._refresh_sla_breached_gauge()

    assert gauge_values == [2]
