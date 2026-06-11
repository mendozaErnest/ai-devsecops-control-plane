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


# ── active_scan: ZAP error payload propagation ──────────────────────────────


def test_active_scan_propagates_zap_error_code(monkeypatch):
    """When ZAP returns {"code": ..., "message": ...} instead of {"scan": ...},
    the error string must contain both the code and message."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": "url_not_found", "message": "Provided URL is not in the Sites tree"},
            headers={"content-type": "application/json"},
        )

    real_client_cls = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(tools_module.httpx, "Client", fake_client)

    result = tools_module.active_scan("http://target/api")
    assert result["error"] is not None
    assert "url_not_found" in result["error"]
    assert result["scan_id"] is None
    assert result["completed"] is False


# ── target_reachable: connectivity pre-check ────────────────────────────────


def test_target_reachable_returns_false_on_connect_error(monkeypatch):
    """When ZAP cannot connect to the target, reachable=False with an informative error."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    real_client_cls = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(tools_module.httpx, "Client", fake_client)

    result = tools_module.target_reachable("http://127.0.0.1:9999/")
    assert result["reachable"] is False
    assert result["error"] is not None
    assert "host.docker.internal" in result["error"]


def test_target_reachable_returns_true_on_success(monkeypatch):
    """When ZAP returns Result, reachable=True."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"Result": "OK"},
            headers={"content-type": "application/json"},
        )

    real_client_cls = httpx.Client

    def fake_client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client_cls(*args, **kwargs)

    monkeypatch.setattr(tools_module.httpx, "Client", fake_client)

    result = tools_module.target_reachable("http://target/")
    assert result["reachable"] is True
    assert result["error"] is None


# ── explorer_agent: fail-fast on unreachable target ──────────────────────────


def test_explorer_agent_terminates_on_unreachable_target(monkeypatch):
    """Explorer must set status=error and skip spider when target is not reachable."""
    from src.dast_agent import agents as agents_module

    monkeypatch.setattr(
        agents_module,
        "target_reachable",
        lambda url: {"reachable": False, "error": "ZAP cannot reach http://target — use host.docker.internal"},
    )
    # spider_crawl must NOT be called; monkeypatch it to raise if called
    def should_not_be_called(*args, **kwargs):
        raise AssertionError("spider_crawl was called despite unreachable target")

    monkeypatch.setattr(agents_module, "spider_crawl", should_not_be_called)

    state = empty_state("http://target", max_iterations=2)
    out = agents_module.explorer_agent(state)

    assert out["status"] == "error"
    assert out["error"] is not None
    assert "host.docker.internal" in out["error"]
    # should_continue will terminate on error — verify
    assert graph_module.should_continue(out) == graph_module.END
