"""Shared state for the agentic DAST graph.

The state is a TypedDict so it can be passed directly to LangGraph.
All collections default to empty lists; the runner initialises them
before the first node executes.
"""
from typing import Optional, TypedDict


class DastAgentState(TypedDict, total=False):
    target_url: str
    project_id: Optional[str]

    # Explorer output
    discovered_routes: list[str]
    discovered_forms: list[dict]
    discovered_auth_boundaries: list[str]

    # Attacker output
    attack_payloads: list[dict]
    raw_alerts: list[dict]

    # Verifier output
    confirmed_findings: list[dict]
    false_positives: list[dict]

    # Control flow
    iteration: int
    max_iterations: int
    status: str  # exploring | attacking | verifying | done | error
    error: Optional[str]
    scan_id: Optional[str]
    warnings: list[str]  # non-fatal issues (e.g. ascan failed but passive alerts retrieved)


def empty_state(
    target_url: str,
    project_id: Optional[str] = None,
    max_iterations: int = 3,
    scan_id: Optional[str] = None,
) -> DastAgentState:
    return {
        "target_url": target_url,
        "project_id": project_id,
        "discovered_routes": [],
        "discovered_forms": [],
        "discovered_auth_boundaries": [],
        "attack_payloads": [],
        "raw_alerts": [],
        "confirmed_findings": [],
        "false_positives": [],
        "iteration": 0,
        "max_iterations": max_iterations,
        "status": "exploring",
        "error": None,
        "scan_id": scan_id,
        "warnings": [],
    }
