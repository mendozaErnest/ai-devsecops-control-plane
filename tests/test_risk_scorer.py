"""Tests for ML risk scorer — XGBoost-based per-finding risk score.

Coverage:
- score_finding() returns deterministic severity-based fallback when no model is persisted.
- train_model() trains on ≥10 mixed-label findings, saves model, returns metric keys.
- POST /api/ml/train returns HTTP 400 when fewer than 10 findings exist in the DB.
- GET /api/findings includes a float risk_score for each finding.
- src.ml.risk_scorer can always be imported, and score_finding() degrades gracefully
  when _ML_AVAILABLE is False (i.e. when xgboost/sklearn are absent at install time).
"""
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel, create_engine

from src.api.models import Finding, Project, Scan


# ── shared helpers ────────────────────────────────────────────────────────────

def _make_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    return engine


def _app_patches(app_module, engine):
    """Return a dict of patches needed to run TestClient against an in-memory engine."""
    return {
        app_module: {"engine": engine},
    }


# ── test 1: severity fallback when no model file exists ──────────────────────

def test_score_finding_fallback_by_severity(tmp_path, monkeypatch):
    """score_finding() returns the severity-based constant when no model is persisted."""
    monkeypatch.setenv("RISK_MODEL_PATH", str(tmp_path / "nonexistent.joblib"))

    from src.ml.risk_scorer import score_finding

    assert score_finding({"severity": "CRITICAL", "status": "open"}) == pytest.approx(0.9)
    assert score_finding({"severity": "HIGH",     "status": "open"}) == pytest.approx(0.7)
    assert score_finding({"severity": "MEDIUM",   "status": "open"}) == pytest.approx(0.4)
    assert score_finding({"severity": "LOW",      "status": "open"}) == pytest.approx(0.2)


# ── test 2: train_model with minimal dataset ──────────────────────────────────

def test_train_model_minimal_dataset(tmp_path, monkeypatch):
    """train_model() trains on ≥10 mixed-label findings, persists model, returns metric keys."""
    pytest.importorskip("xgboost", reason="xgboost not installed")
    pytest.importorskip("sklearn", reason="scikit-learn not installed")

    monkeypatch.setenv("RISK_MODEL_PATH", str(tmp_path / "risk_model.joblib"))

    from src.ml.risk_scorer import train_model

    # New label = outcome (regression OR SLA breach), NOT severity/status leakage.
    # 6 positives (3 regression + 3 SLA-breached) + 8 negatives → two classes, ≥10 total.
    past = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    findings = [
        # 3 positives via regression
        {"severity": "HIGH", "status": "regression", "tool": "bandit", "confidence": "HIGH",
         "regression_count": 2, "first_seen_at": None, "sla_deadline": None}
        if i < 3 else
        # 3 positives via SLA breach (deadline in the past, still open)
        {"severity": "MEDIUM", "status": "open", "tool": "semgrep", "confidence": "MEDIUM",
         "regression_count": 0, "first_seen_at": None, "sla_deadline": past}
        if i < 6 else
        # 8 negatives: open, no regression, no overdue deadline
        {"severity": "LOW", "status": "open", "tool": "pylint", "confidence": "LOW",
         "regression_count": 0, "first_seen_at": None, "sla_deadline": None}
        for i in range(14)
    ]

    result = train_model(findings)

    assert set(result.keys()) == {"precision", "recall", "roc_auc", "n_samples"}
    assert result["n_samples"] == 14
    assert (tmp_path / "risk_model.joblib").exists()


# ── test 2b: features exclude leakage columns (status / regression_count) ────

def test_features_exclude_leakage_columns():
    """Feature vector is length 5 and ignores the columns that define the label.

    Two findings identical except for `status` (open vs regression) and
    `regression_count` (0 vs 5) must produce the SAME feature vector — because
    those columns are no longer features — yet a DIFFERENT label.
    """
    from src.ml.risk_scorer import _features_from_finding, _label_from_finding

    base = {
        "severity": "HIGH", "confidence": "HIGH", "tool": "bandit",
        "first_seen_at": None, "sla_deadline": None,
    }
    negative = {**base, "status": "open",       "regression_count": 0}
    positive = {**base, "status": "regression", "regression_count": 5}

    feats_neg = _features_from_finding(negative)
    feats_pos = _features_from_finding(positive)

    assert len(feats_neg) == 5
    assert len(feats_pos) == 5
    # status / regression_count are NOT features → identical vectors
    assert feats_neg == feats_pos

    # but the label distinguishes them via the real outcome
    assert _label_from_finding(negative) == 0
    assert _label_from_finding(positive) == 1


# ── test 3: POST /api/ml/train returns 400 with < 10 findings ────────────────

def test_ml_train_endpoint_insufficient_findings():
    """POST /api/ml/train returns HTTP 400 when the DB contains fewer than 10 findings."""
    engine = _make_engine()

    import src.api.main as app_module

    with patch.object(app_module, "engine", engine), \
         patch.object(app_module, "create_db_and_tables", lambda: None), \
         patch.object(app_module, "WORKSPACE_ROOT", MagicMock(mkdir=lambda **_: None)), \
         patch.object(app_module, "_refresh_sla_breached_gauge", lambda: None):
        client = TestClient(app_module.app)
        resp = client.post("/api/ml/train")

    assert resp.status_code == 400
    assert "10" in resp.json().get("detail", "")


# ── test 4: risk_score present in GET /api/findings ──────────────────────────

def test_risk_score_in_get_findings():
    """GET /api/findings includes a float risk_score field for every finding."""
    engine = _make_engine()

    with Session(engine) as session:
        project = Project(
            name="test-project",
            source_type="zip",
            target_path="/tmp/p",
            technology="python",
        )
        session.add(project)
        session.commit()
        session.refresh(project)

        scan = Scan(
            project_id=project.id,
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
            description="Use of assert",
            severity="HIGH",
            confidence="HIGH",
            file_path="/tmp/test.py",
            line_start=1,
            status="open",
            fingerprint=uuid.uuid4().hex,
            first_seen_at=datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
        )
        session.add(finding)
        session.commit()

    import src.api.main as app_module

    with patch.object(app_module, "engine", engine), \
         patch.object(app_module, "create_db_and_tables", lambda: None), \
         patch.object(app_module, "WORKSPACE_ROOT", MagicMock(mkdir=lambda **_: None)), \
         patch.object(app_module, "_refresh_sla_breached_gauge", lambda: None):
        client = TestClient(app_module.app)
        resp = client.get("/api/findings")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert "risk_score" in data[0]
    assert isinstance(data[0]["risk_score"], float)


# ── test 5: graceful degradation when ML libs are unavailable ────────────────

def test_score_finding_degrades_when_ml_unavailable(tmp_path, monkeypatch):
    """score_finding() returns severity fallback when _ML_AVAILABLE is False.

    This exercises the first guard in score_finding() that activates when
    xgboost or scikit-learn are not installed in the environment.
    """
    monkeypatch.setenv("RISK_MODEL_PATH", str(tmp_path / "nonexistent.joblib"))

    import src.ml.risk_scorer as rs

    original = rs._ML_AVAILABLE
    try:
        rs._ML_AVAILABLE = False
        assert rs.score_finding({"severity": "CRITICAL", "status": "open"}) == pytest.approx(0.9)
        assert rs.score_finding({"severity": "LOW",      "status": "open"}) == pytest.approx(0.2)
    finally:
        rs._ML_AVAILABLE = original
