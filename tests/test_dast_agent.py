"""Tests for the agentic DAST loop and its API endpoint."""
from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from src.dast_agent import graph as graph_module
from src.dast_agent import runner as runner_module
from src.dast_agent import tools as tools_module
from src.dast_agent.state import empty_state


# ── should_continue: control-flow logic ─────────────────────────────────────


def test_should_continue_terminates_after_max_iterations():
    state = empty_state("http://x", max_iterations=2)
    state["iteration"] = 2
    state["discovered_routes"] = ["http://x/admin"]
    assert graph_module.should_continue(state) == graph_module.END


def test_should_continue_loops_when_routes_remain():
    state = empty_state("http://x", max_iterations=3)
    state["iteration"] = 1
    state["discovered_routes"] = ["http://x/admin"]
    assert graph_module.should_continue(state) == "attacker"


def test_should_continue_terminates_when_no_routes():
    state = empty_state("http://x", max_iterations=3)
    state["iteration"] = 1
    state["discovered_routes"] = []
    assert graph_module.should_continue(state) == graph_module.END


def test_should_continue_terminates_on_error():
    state = empty_state("http://x")
    state["error"] = "boom"
    state["discovered_routes"] = ["http://x/a"]
    assert graph_module.should_continue(state) == graph_module.END


# ── verify_alert: XSS confirmation via reflected payload ────────────────────


def test_verify_alert_confirms_xss_when_payload_reflected(monkeypatch):
    payload = "<script>alert(1)</script>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text=f"<html><body>hi {payload} bye</body></html>",
            headers={"content-type": "text/html"},
        )

    real_client_cls = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(tools_module.httpx, "Client", fake_client)

    alert = {
        "name": "Cross Site Scripting (Reflected)",
        "url": "http://target/page?q=test",
        "evidence": payload,
    }

    result = tools_module.verify_alert(alert, "http://target")
    assert result["confirmed"] is True
    assert payload[:5] in result["evidence"]


def test_verify_alert_rejects_xss_when_payload_absent(monkeypatch):
    payload = "<script>alert(1)</script>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>nothing here</body></html>")

    real_client_cls = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(tools_module.httpx, "Client", fake_client)

    alert = {
        "name": "Cross Site Scripting (Reflected)",
        "url": "http://target/page?q=test",
        "evidence": payload,
    }

    result = tools_module.verify_alert(alert, "http://target")
    assert result["confirmed"] is False
    assert "not present" in result["reasoning"].lower()


# ── run_dast_agent: structure with mocked ZAP ───────────────────────────────


@pytest.mark.skipif(
    not graph_module.LANGGRAPH_AVAILABLE, reason="LangGraph not installed"
)
def test_run_dast_agent_returns_expected_structure(monkeypatch):
    monkeypatch.setattr(
        "src.dast_agent.agents.spider_crawl",
        lambda url, **_: {"routes": ["http://target/api/users"], "forms": [], "error": None},
    )
    monkeypatch.setattr(
        "src.dast_agent.agents.active_scan",
        lambda url, **_: {"scan_id": "1", "completed": True, "error": None},
    )
    monkeypatch.setattr(
        "src.dast_agent.agents.get_alerts",
        lambda url, **_: {
            "alerts": [
                {
                    "pluginId": "10038",
                    "name": "Content Security Policy Header Not Set",
                    "risk": "Medium",
                    "url": "http://target/",
                    "description": "CSP missing",
                    "evidence": "",
                    "cweid": "693",
                }
            ],
            "error": None,
        },
    )
    monkeypatch.setattr(
        "src.dast_agent.agents.verify_alert",
        lambda alert, target: {"confirmed": True, "evidence": "header missing", "reasoning": "ok"},
    )
    monkeypatch.setattr("src.dast_agent.agents._llm_invoke", lambda *a, **kw: None)

    import asyncio as _asyncio

    result = _asyncio.run(
        runner_module.run_dast_agent(
            target_url="http://target", max_iterations=1
        )
    )

    assert isinstance(result, dict)
    assert "scan_id" in result
    assert result["status"] in {"done", "error"}
    assert isinstance(result["confirmed_findings"], list)
    assert isinstance(result["false_positives_count"], int)
    assert isinstance(result["iterations_run"], int)
    assert len(result["confirmed_findings"]) == 1
    assert result["confirmed_findings"][0]["tool"] == "zap+langgraph"


# ── Endpoint: 400 on invalid URL ────────────────────────────────────────────


@pytest.fixture()
def app_client(monkeypatch, tmp_path):
    from src.api import main as app_module

    monkeypatch.setattr(app_module, "create_db_and_tables", lambda: None)
    monkeypatch.setattr(app_module, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(app_module, "WORKSPACE_ROOT", tmp_path / "workspace" / "uploads")
    return TestClient(app_module.app)


def test_endpoint_rejects_invalid_url(app_client):
    response = app_client.post(
        "/api/dast/agent/scan", json={"target_url": "ftp://example.com"}
    )
    assert response.status_code == 400


def test_endpoint_returns_503_when_langgraph_missing(app_client, monkeypatch):
    """When LANGGRAPH_AVAILABLE is False, endpoint must return 503 with clear detail."""
    import src.dast_agent as _agent_pkg

    monkeypatch.setattr(_agent_pkg, "LANGGRAPH_AVAILABLE", False)

    response = app_client.post(
        "/api/dast/agent/scan", json={"target_url": "http://target.example.com"}
    )
    assert response.status_code == 503
    assert "langgraph" in response.json().get("detail", "").lower()


def test_endpoint_status_returns_404_for_unknown_scan(app_client):
    response = app_client.get("/api/dast/agent/scan/does-not-exist/status")
    assert response.status_code == 404
