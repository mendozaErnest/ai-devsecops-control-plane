"""Entry point for the agentic DAST loop.

`run_dast_agent` is the only async function the API endpoint calls.
A module-level dict tracks per-scan progress so a polling endpoint can
report Exploring → Attacking → Verifying → done without streaming.
"""
from __future__ import annotations

import asyncio
import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from .agents import attacker_agent, explorer_agent, verifier_agent
from .graph import LANGGRAPH_AVAILABLE, build_dast_graph, should_continue
from .state import DastAgentState, empty_state


LOGGER = logging.getLogger(__name__)

_active_scans: dict[str, dict] = {}
_active_scans_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _set_scan_status(scan_id: str, **fields) -> None:
    with _active_scans_lock:
        snapshot = _active_scans.setdefault(scan_id, {})
        snapshot.update(fields)
        snapshot["updated_at"] = _now()


def get_scan_status(scan_id: str) -> Optional[dict]:
    with _active_scans_lock:
        return dict(_active_scans[scan_id]) if scan_id in _active_scans else None


def list_active_scans() -> list[dict]:
    with _active_scans_lock:
        return [
            {"scan_id": sid, **snapshot} for sid, snapshot in _active_scans.items()
        ]


def _wrap_node(node_fn, scan_id: str, label: str):
    def wrapped(state: DastAgentState) -> DastAgentState:
        _set_scan_status(
            scan_id,
            status=label,
            iteration=state.get("iteration", 0),
        )
        out = node_fn(state)
        _set_scan_status(
            scan_id,
            status=out.get("status", label),
            iteration=out.get("iteration", 0),
            confirmed_count=len(out.get("confirmed_findings", []) or []),
            false_positives_count=len(out.get("false_positives", []) or []),
            error=out.get("error"),
        )
        return out

    return wrapped


def _build_graph_with_tracking(scan_id: str):
    """Build the LangGraph compiled graph wiring each node with status callbacks."""
    if not LANGGRAPH_AVAILABLE:
        raise ImportError("langgraph not available")

    from langgraph.graph import END, StateGraph  # type: ignore

    graph = StateGraph(DastAgentState)
    graph.add_node("explorer", _wrap_node(explorer_agent, scan_id, "exploring"))
    graph.add_node("attacker", _wrap_node(attacker_agent, scan_id, "attacking"))
    graph.add_node("verifier", _wrap_node(verifier_agent, scan_id, "verifying"))

    graph.set_entry_point("explorer")
    graph.add_edge("explorer", "attacker")
    graph.add_edge("attacker", "verifier")
    graph.add_conditional_edges(
        "verifier",
        should_continue,
        {"attacker": "attacker", END: END},
    )

    return graph.compile()


async def run_dast_agent(
    target_url: str,
    project_id: Optional[str] = None,
    max_iterations: int = 3,
    scan_id: Optional[str] = None,
) -> dict:
    """Run the explorer → attacker → verifier loop.

    Returns a dict with `scan_id`, `confirmed_findings`, `false_positives_count`,
    `iterations_run`, `status`. Never raises — propagates errors via `status="error"`.
    """
    scan_id = scan_id or str(uuid.uuid4())
    _set_scan_status(
        scan_id,
        status="queued",
        target_url=target_url,
        project_id=project_id,
        started_at=_now(),
    )

    if not LANGGRAPH_AVAILABLE:
        _set_scan_status(scan_id, status="error", error="langgraph not installed")
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": "LangGraph is not installed. Install langgraph and langchain_ollama.",
            "confirmed_findings": [],
            "false_positives_count": 0,
            "iterations_run": 0,
        }

    initial = empty_state(
        target_url=target_url,
        project_id=project_id,
        max_iterations=max_iterations,
        scan_id=scan_id,
    )

    try:
        compiled = await asyncio.to_thread(_build_graph_with_tracking, scan_id)
        final_state: DastAgentState = await asyncio.to_thread(compiled.invoke, initial)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Agentic DAST run failed")
        _set_scan_status(scan_id, status="error", error=str(exc))
        return {
            "scan_id": scan_id,
            "status": "error",
            "error": str(exc),
            "confirmed_findings": [],
            "false_positives_count": 0,
            "iterations_run": 0,
        }

    confirmed = list(final_state.get("confirmed_findings", []) or [])
    false_positives = list(final_state.get("false_positives", []) or [])
    iterations_run = int(final_state.get("iteration", 0) or 0)
    status = "error" if final_state.get("error") else "done"

    _set_scan_status(
        scan_id,
        status=status,
        confirmed_count=len(confirmed),
        false_positives_count=len(false_positives),
        iteration=iterations_run,
        completed_at=_now(),
        error=final_state.get("error"),
    )

    return {
        "scan_id": scan_id,
        "status": status,
        "error": final_state.get("error"),
        "confirmed_findings": confirmed,
        "false_positives_count": len(false_positives),
        "false_positives": false_positives,
        "iterations_run": iterations_run,
        "discovered_routes": list(final_state.get("discovered_routes", []) or []),
    }
