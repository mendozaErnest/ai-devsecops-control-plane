"""Tests for target_path resolution and security validation in POST /api/scan."""
from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from src.api import main as app_module


# ── validate_scan_target unit tests ──────────────────────────────────────────


def test_valid_path_inside_workspace(monkeypatch, tmp_path):
    """A file inside an allowed root passes validation and returns resolved path."""
    target_file = tmp_path / "project" / "app.py"
    target_file.parent.mkdir(parents=True)
    target_file.write_text("x = 1\n", encoding="utf-8")

    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", tmp_path / "workspace" / "uploads")

    resolved = app_module.validate_scan_target(str(target_file))
    assert resolved == str(target_file.resolve())


def test_path_outside_workspace_raises(monkeypatch, tmp_path):
    """A path outside all allowed roots (path traversal) raises HTTP 403."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()

    outside_file = tmp_path / "outside.py"
    outside_file.write_text("secret = 1\n", encoding="utf-8")

    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", allowed)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", allowed / "uploads")

    with pytest.raises(HTTPException) as exc_info:
        app_module.validate_scan_target(str(outside_file))
    assert exc_info.value.status_code == 403


def test_nonexistent_path_raises(monkeypatch, tmp_path):
    """A path that does not exist on disk raises HTTP 404."""
    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", tmp_path)

    with pytest.raises(HTTPException) as exc_info:
        app_module.validate_scan_target(str(tmp_path / "does_not_exist.py"))
    assert exc_info.value.status_code == 404


# ── POST /api/scan fallback integration test ─────────────────────────────────


def test_fallback_to_dummy_when_no_target(monkeypatch, tmp_path):
    """POST /api/scan with no body scans dummy_vulnerable_app.py (retro-compat)."""
    dummy = tmp_path / "src" / "dummy_vulnerable_app.py"
    dummy.parent.mkdir(parents=True)
    dummy.write_text("import os\nos.system('ls')\n", encoding="utf-8")

    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", tmp_path / "workspace" / "uploads")
    monkeypatch.setattr(app_module, "create_db_and_tables", lambda: None)

    captured: dict = {}

    async def fake_run_scan(target_path, technology, project_id=None):
        captured["target_path"] = target_path
        captured["technology"] = technology
        return {"success": True, "saved_findings": 0, "target_path": target_path}

    monkeypatch.setattr(app_module, "run_scan", fake_run_scan)

    client = TestClient(app_module.app)
    response = client.post("/api/scan", json={})
    assert response.status_code == 200
    assert "dummy_vulnerable_app.py" in captured["target_path"]
    assert captured["technology"] == "python"
