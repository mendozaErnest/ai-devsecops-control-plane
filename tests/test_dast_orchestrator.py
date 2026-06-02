"""Tests for DAST URL plumbing: ScanRequest → orchestrator → ZapAdapter."""
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api.models import ScanProfile
from src.scanners.orchestrator import ScanOrchestrator
from src.scanners.zap_adapter import ZapAdapter


# ── Unit: orchestrator skips DAST when no URL provided ──────────────────────


def test_orchestrator_skips_dast_without_url(monkeypatch):
    """profile.dast_enabled=True but no target_url → DAST runner returns [] without raising."""
    monkeypatch.delenv("DAST_DEFAULT_URL", raising=False)

    profile = ScanProfile(
        name="dast-only",
        sast_enabled=False,
        dast_enabled=True,
        dast_tool="zap",
        quality_enabled=False,
    )

    orchestrator = ScanOrchestrator()
    result = orchestrator.run(profile, "/some/path", "python", target_url=None)

    assert result.findings == []
    assert result.errors == []


# ── Unit: orchestrator forwards URL to ZapAdapter.execute_scan ──────────────


def test_orchestrator_forwards_dast_url(monkeypatch):
    """profile.dast_enabled=True + target_url=http://example.com → ZapAdapter.execute_scan called with URL."""
    profile = ScanProfile(
        name="dast-only",
        sast_enabled=False,
        dast_enabled=True,
        dast_tool="zap",
        quality_enabled=False,
    )

    captured: dict = {}

    class _FakeAdapter:
        def __init__(self, *args, **kwargs):
            self.error = None

        def execute_scan(self, target):
            captured["target"] = target
            return []

    monkeypatch.setattr("src.scanners.zap_adapter.ZapAdapter", _FakeAdapter)

    orchestrator = ScanOrchestrator()
    orchestrator.run(
        profile, "/some/path", "python", target_url="http://target.example.com:3000"
    )

    assert captured.get("target") == "http://target.example.com:3000"


# ── Unit: ZapAdapter sends URL to ZAP spider (mock httpx) ───────────────────


def test_zap_adapter_calls_spider_with_target_url():
    """ZapAdapter.scan(url) → first GET hits /JSON/spider/action/scan/?url=<url>."""
    captured_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_urls.append(str(request.url))
        path = request.url.path

        if path == "/JSON/spider/action/scan/":
            return httpx.Response(200, json={"scan": "1"})
        if path == "/JSON/spider/view/status/":
            return httpx.Response(200, json={"status": "100"})
        if path == "/JSON/ascan/action/scan/":
            return httpx.Response(200, json={"scan": "2"})
        if path == "/JSON/ascan/view/status/":
            return httpx.Response(200, json={"status": "100"})
        if path == "/JSON/alert/view/alerts/":
            return httpx.Response(200, json={"alerts": []})

        return httpx.Response(404, json={})

    client = httpx.Client(
        base_url="http://zap:8090", transport=httpx.MockTransport(handler)
    )
    adapter = ZapAdapter(client=client, poll_interval=0)
    target = "http://target.example.com:3000"

    findings = adapter.scan(target)

    assert findings == []
    spider_call = next(u for u in captured_urls if "spider/action/scan" in u)
    assert f"url={target.replace(':', '%3A').replace('/', '%2F')}" in spider_call or target in spider_call

    client.close()


# ── Endpoint: POST /api/scan rejects invalid DAST URL with 400 ──────────────


@pytest.fixture()
def app_client(monkeypatch, tmp_path):
    """TestClient with stubbed scanner so the endpoint just records request args."""
    from src.api import main as app_module

    monkeypatch.setattr(app_module, "create_db_and_tables", lambda: None)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", tmp_path / "workspace" / "uploads")
    monkeypatch.delenv("SCAN_ALLOWED_ROOTS", raising=False)

    dummy = tmp_path / "src" / "dummy_vulnerable_app.py"
    dummy.parent.mkdir(parents=True, exist_ok=True)
    dummy.write_text("x = 1\n", encoding="utf-8")

    async def fake_run_scan(target_path, technology, project_id=None):
        return {"success": True, "saved_findings": 0, "target_path": target_path}

    monkeypatch.setattr(app_module, "run_scan", fake_run_scan)
    return TestClient(app_module.app)


def test_post_scan_rejects_ftp_dast_url(app_client):
    """ftp:// is not http/https → HTTP 400, not 422 or 500."""
    response = app_client.post(
        "/api/scan", json={"dast_target_url": "ftp://localhost:9000"}
    )
    assert response.status_code == 400
    assert "http" in response.json().get("detail", "").lower()


def test_post_scan_accepts_blank_dast_url(app_client):
    """Empty string for dast_target_url is treated as None (no DAST), still 200."""
    response = app_client.post("/api/scan", json={"dast_target_url": ""})
    assert response.status_code == 200


def test_post_scan_passes_valid_dast_url_to_project(monkeypatch, app_client):
    """When a project + valid dast_target_url is sent, scan_project receives the URL."""
    import uuid as _uuid

    from src.api import main as app_module
    from src.api.models import Project

    project_id = _uuid.uuid4()

    fake_project = Project(
        id=project_id,
        name="probe",
        source_type="zip",
        target_path=str(app_module.PROJECT_ROOT / "src" / "dummy_vulnerable_app.py"),
        technology="python",
    )

    captured: dict = {}

    class _FakeSession:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, model, key):
            return fake_project

        def add(self, obj):
            pass

        def commit(self):
            pass

        def refresh(self, obj):
            pass

    async def fake_scan_project(project, dast_target_url=None):
        captured["dast_target_url"] = dast_target_url
        captured["project_id"] = str(project.id)
        return {"success": True, "saved_findings": 0, "dast_target_url": dast_target_url}

    monkeypatch.setattr(app_module, "Session", _FakeSession)
    monkeypatch.setattr(app_module, "scan_project", fake_scan_project)

    response = app_client.post(
        "/api/scan",
        json={
            "project_id": str(project_id),
            "dast_target_url": "http://host.docker.internal:3000",
        },
    )

    assert response.status_code == 200
    assert captured.get("dast_target_url") == "http://host.docker.internal:3000"
