"""Tests for ScanProfile model, default seeding, ScanOrchestrator, and API endpoints."""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine, select

from src.api.database import seed_default_profiles
from src.api.models import ScanProfile
from src.scanners.orchestrator import OrchestratorResult, ScanOrchestrator


# ─────────────────────────────────────────────────────────────────────────────
# Shared in-memory DB helpers
# ─────────────────────────────────────────────────────────────────────────────

def make_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


# ─────────────────────────────────────────────────────────────────────────────
# test_create_default_profiles
# ─────────────────────────────────────────────────────────────────────────────

def test_create_default_profiles():
    engine = make_engine()
    with patch("src.api.database.engine", engine):
        seed_default_profiles()

    with Session(engine) as session:
        profiles = session.exec(select(ScanProfile)).all()

    names = {p.name for p in profiles}
    assert "Python SAST" in names
    assert "Angular SAST" in names
    assert "Java SAST" in names
    assert "Full Scan" in names
    assert len(profiles) == 4


def test_seed_is_idempotent():
    """Calling seed twice must not create duplicate rows."""
    engine = make_engine()
    with patch("src.api.database.engine", engine):
        seed_default_profiles()
        seed_default_profiles()

    with Session(engine) as session:
        profiles = session.exec(select(ScanProfile)).all()

    assert len(profiles) == 4


# ─────────────────────────────────────────────────────────────────────────────
# test_orchestrator_sast_only
# ─────────────────────────────────────────────────────────────────────────────

def test_orchestrator_sast_only():
    profile = ScanProfile(
        name="Test SAST",
        sast_enabled=True,
        sast_tools="bandit",
        dast_enabled=False,
        quality_enabled=False,
    )

    mock_finding = MagicMock()
    mock_finding.fingerprint = "abc123"

    with patch("src.scanners.bandit_adapter.BanditAdapter") as MockBandit:
        MockBandit.return_value.execute_scan.return_value = [mock_finding]
        orchestrator = ScanOrchestrator()
        result = orchestrator.run(profile, "/some/path", "python")

    assert isinstance(result, OrchestratorResult)
    assert len(result.findings) == 1
    assert "sast" in result.tools_run
    assert "dast" not in result.tools_run
    assert "quality" not in result.tools_run


# ─────────────────────────────────────────────────────────────────────────────
# test_orchestrator_dast_placeholder
# ─────────────────────────────────────────────────────────────────────────────

def test_orchestrator_dast_placeholder():
    profile = ScanProfile(
        name="DAST profile",
        sast_enabled=False,
        dast_enabled=True,
        dast_tool="zap",
        quality_enabled=False,
    )

    orchestrator = ScanOrchestrator()
    result = orchestrator.run(profile, "/some/path", "python")

    assert isinstance(result, OrchestratorResult)
    assert result.findings == []
    assert result.errors == []
    assert "dast" in result.tools_run


def test_orchestrator_quality_runs_when_enabled():
    profile = ScanProfile(
        name="Python Quality",
        sast_enabled=False,
        dast_enabled=False,
        quality_enabled=True,
        quality_tool="pylint",
    )

    mock_finding = MagicMock()
    mock_finding.fingerprint = "quality-fp"

    with patch("src.scanners.pylint_adapter.PylintAdapter") as MockPylint:
        MockPylint.return_value.execute_scan.return_value = [mock_finding]
        MockPylint.return_value.error = None
        orchestrator = ScanOrchestrator()
        result = orchestrator.run(profile, "/some/path", "python")

    assert len(result.findings) == 1
    assert "quality" in result.tools_run
    assert result.errors == []


def test_orchestrator_quality_missing_tool_is_reported_without_crashing():
    profile = ScanProfile(
        name="Python Quality",
        sast_enabled=False,
        dast_enabled=False,
        quality_enabled=True,
        quality_tool="pylint",
    )

    with patch("src.scanners.pylint_adapter.PylintAdapter") as MockPylint:
        MockPylint.return_value.execute_scan.return_value = []
        MockPylint.return_value.error = "pylint not found"
        orchestrator = ScanOrchestrator()
        result = orchestrator.run(profile, "/some/path", "python")

    assert result.findings == []
    assert "quality: pylint not found" in result.errors
    assert "quality" not in result.tools_run


# ─────────────────────────────────────────────────────────────────────────────
# test_orchestrator_deduplication
# ─────────────────────────────────────────────────────────────────────────────

def test_orchestrator_deduplication():
    profile = ScanProfile(
        name="Dedup test",
        sast_enabled=True,
        sast_tools="both",
        dast_enabled=False,
        quality_enabled=False,
    )

    shared_fp = "deadbeef" * 8

    def make_finding(title):
        f = MagicMock()
        f.fingerprint = shared_fp
        f.title = title
        return f

    # Two findings with identical fingerprint from different "engines"
    finding_a = make_finding("Finding from bandit")
    finding_b = make_finding("Finding from semgrep")

    with patch("src.scanners.escaneo.CombinedScannerAdapter") as MockCombined:
        MockCombined.return_value.execute_scan.return_value = [finding_a, finding_b]
        orchestrator = ScanOrchestrator()
        result = orchestrator.run(profile, "/some/path", "python")

    assert len(result.findings) == 1, "Identical fingerprints must be deduplicated to one finding"


# ─────────────────────────────────────────────────────────────────────────────
# API endpoint tests (using FastAPI TestClient with fresh in-memory DB)
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def test_client():
    """TestClient with isolated in-memory database."""
    from sqlmodel import create_engine as _ce
    from src.api import main as app_module
    from src.api import database as db_module
    # Ensure all models are registered in metadata before create_all
    import src.api.models  # noqa: F401

    # StaticPool ensures all connections share the same in-memory DB so tables
    # created by create_all() are visible inside route handler Sessions.
    test_engine = _ce(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(test_engine)

    original_db_engine = db_module.engine
    original_app_engine = app_module.engine
    db_module.engine = test_engine
    app_module.engine = test_engine

    with patch("src.api.database.engine", test_engine):
        seed_default_profiles()

    client = TestClient(app_module.app)
    yield client

    db_module.engine = original_db_engine
    app_module.engine = original_app_engine


def test_api_get_profiles(test_client):
    response = test_client.get("/api/profiles")
    assert response.status_code == 200
    profiles = response.json()
    assert isinstance(profiles, list)
    assert len(profiles) >= 4
    names = {p["name"] for p in profiles}
    assert "Python SAST" in names


def test_api_create_profile(test_client):
    payload = {
        "name": "My Custom Profile",
        "description": "Custom SAST config",
        "sast_enabled": True,
        "sast_tools": "both",
        "dast_enabled": False,
        "quality_enabled": False,
    }
    response = test_client.post("/api/profiles", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "My Custom Profile"
    assert data["sast_tools"] == "both"
    assert data["id"] is not None
