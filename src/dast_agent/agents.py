"""Explorer, Attacker, and Verifier agents for the agentic DAST loop.

Each agent receives and returns a `DastAgentState` (TypedDict).
Ollama is consulted optionally to enrich the deterministic ZAP-driven logic;
if Ollama is unreachable the agent degrades to the deterministic path silently.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Optional

from .state import DastAgentState
from .tools import active_scan, get_alerts, spider_crawl, target_reachable, verify_alert


LOGGER = logging.getLogger(__name__)


# ── Ollama LLM wrapper ──────────────────────────────────────────────────────


def _try_ollama_llm():
    """Return a langchain LLM client, or None when Ollama / langchain_ollama is unavailable."""
    try:
        from langchain_ollama import OllamaLLM  # type: ignore
    except ImportError:
        try:
            from langchain_community.llms import Ollama as OllamaLLM  # type: ignore
        except ImportError:
            LOGGER.info("langchain_ollama not installed — agents will skip LLM enrichment")
            return None

    base_url = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:14b")
    try:
        return OllamaLLM(model=model, base_url=base_url, temperature=0.1)
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Could not instantiate OllamaLLM: %s", exc)
        return None


def _llm_invoke(prompt: str, max_chars: int = 4000) -> Optional[str]:
    """Best-effort LLM call. Returns string output or None on failure."""
    llm = _try_ollama_llm()
    if llm is None:
        return None
    try:
        response = llm.invoke(prompt[:max_chars])
        if isinstance(response, str):
            return response
        text = getattr(response, "content", None)
        if isinstance(text, str):
            return text
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("Ollama invocation failed: %s", exc)
    return None


# ── Explorer Agent ──────────────────────────────────────────────────────────


def explorer_agent(state: DastAgentState) -> DastAgentState:
    """Discover attack surface via ZAP spider, then optionally rank routes with the LLM."""
    new_state: DastAgentState = {**state, "status": "exploring"}

    reachability = target_reachable(state["target_url"])
    if not reachability["reachable"]:
        new_state["status"] = "error"
        new_state["error"] = reachability["error"] or f"Target {state['target_url']} is not reachable from ZAP"
        LOGGER.warning("Explorer: target not reachable: %s", new_state["error"])
        return new_state

    crawl = spider_crawl(state["target_url"])
    routes = crawl.get("routes", []) or []
    forms = crawl.get("forms", []) or []

    new_state["discovered_routes"] = list(routes)
    new_state["discovered_forms"] = list(forms)
    new_state["discovered_auth_boundaries"] = _detect_auth_boundaries(routes)

    if crawl.get("error"):
        new_state["error"] = crawl["error"]
        LOGGER.warning("Explorer: ZAP spider reported %s", crawl["error"])

    if routes:
        prompt = (
            "You are an AppSec analyst reviewing a crawled application. "
            "From these discovered routes, identify the top high-risk attack surfaces. "
            "Return ONLY a short bullet list — one URL per line, no commentary.\n\n"
            f"Target: {state['target_url']}\n"
            f"Routes ({len(routes)}):\n" + "\n".join(routes[:40])
        )
        llm_response = _llm_invoke(prompt)
        if llm_response:
            ranked = _parse_url_lines(llm_response, fallback=routes)
            new_state["discovered_routes"] = ranked[:40] or list(routes)

    return new_state


def _detect_auth_boundaries(routes: list) -> list[str]:
    keywords = ("login", "signin", "auth", "logout", "register", "token", "session")
    return [r for r in routes if any(k in str(r).lower() for k in keywords)]


def _parse_url_lines(text: str, fallback: list) -> list[str]:
    lines = [
        line.lstrip("-*•0123456789. ").strip()
        for line in text.splitlines()
        if line.strip()
    ]
    urls = [line for line in lines if line.startswith(("http://", "https://"))]
    return urls or list(fallback)


# ── Attacker Agent ──────────────────────────────────────────────────────────


def attacker_agent(state: DastAgentState) -> DastAgentState:
    """Trigger ZAP active scan on the target then read the raw alerts.

    If the active scan fails (e.g. URL_NOT_FOUND), the error is recorded as a
    warning and the flow continues: the spider already populated passive alerts
    (missing security headers, cookies, etc.) that the verifier can confirm.
    Cutting the flow on ascan failure would silently discard those findings.
    """
    warnings = list(state.get("warnings") or [])
    new_state: DastAgentState = {
        **state,
        "status": "attacking",
        "iteration": state.get("iteration", 0) + 1,
        "warnings": warnings,
    }

    scan_result = active_scan(state["target_url"])
    if scan_result.get("error"):
        warning_msg = f"Active scan failed (passive alerts still collected): {scan_result['error']}"
        warnings.append(warning_msg)
        new_state["warnings"] = warnings
        # Do NOT set new_state["error"] — the flow continues to get_alerts
        LOGGER.warning("Attacker: %s", scan_result["error"])

    alerts_result = get_alerts(state["target_url"])
    raw_alerts = alerts_result.get("alerts", []) or []
    new_state["raw_alerts"] = list(raw_alerts)
    LOGGER.info("Attacker: ZAP returned %d raw alerts for verifier", len(raw_alerts))

    forms = state.get("discovered_forms", [])
    payloads: list[dict] = []
    for form in forms[:10]:
        for param in form.get("params", []) or []:
            payloads.append(
                {
                    "url": form.get("url"),
                    "param": param,
                    "payload": "<script>alert(1)</script>",
                    "attack_type": "xss-reflected",
                }
            )
            payloads.append(
                {
                    "url": form.get("url"),
                    "param": param,
                    "payload": "' OR 1=1 --",
                    "attack_type": "sqli-classic",
                }
            )
    new_state["attack_payloads"] = payloads

    if forms:
        prompt = (
            "Given these discovered input forms and their parameters, list 3-5 "
            "additional OWASP Top 10 payloads to try (XSS, SQLi, path traversal, "
            "auth bypass). Return ONLY a JSON-like list of objects with keys "
            "{url, param, payload, attack_type}.\n\n"
            f"Forms: {forms[:5]}"
        )
        _llm_invoke(prompt)  # advisory only — we keep deterministic payload list

    return new_state


# ── Verifier Agent ──────────────────────────────────────────────────────────


def verifier_agent(state: DastAgentState) -> DastAgentState:
    """Confirm or reject each ZAP alert via re-request + LLM reasoning."""
    new_state: DastAgentState = {**state, "status": "verifying", "warnings": list(state.get("warnings") or [])}

    confirmed: list[dict] = []
    false_positives: list[dict] = []

    for alert in state.get("raw_alerts", []) or []:
        verification = verify_alert(alert, state["target_url"])
        if verification.get("confirmed"):
            confirmed.append(_normalize_alert(alert, verification))
        else:
            false_positives.append(
                {
                    "rule_id": alert.get("pluginId", ""),
                    "name": alert.get("name", ""),
                    "url": alert.get("url", ""),
                    "reasoning": verification.get("reasoning", ""),
                }
            )

    new_state["confirmed_findings"] = confirmed
    new_state["false_positives"] = false_positives

    if new_state["iteration"] >= state.get("max_iterations", 3) or not new_state["raw_alerts"]:
        new_state["status"] = "done"

    return new_state


_RISK_MAP = {
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Informational": "INFO",
}


def _normalize_alert(alert: dict, verification: dict) -> dict:
    rule_id = str(alert.get("pluginId") or alert.get("alertRef") or "ZAP-UNKNOWN")
    title = str(alert.get("name") or "")
    description = str(alert.get("description") or "")
    url = str(alert.get("url") or "")
    snippet = str(alert.get("evidence") or "")[:500]
    severity = _RISK_MAP.get(str(alert.get("risk", "Low")), "LOW")
    fingerprint_source = "|".join(
        [rule_id, url, title, description, snippet, "zap+langgraph"]
    )

    return {
        "rule_id": rule_id,
        "tool": "zap+langgraph",
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": str(alert.get("confidence") or "MEDIUM"),
        "file_path": url,
        "line_start": 0,
        "line_end": 0,
        "code_snippet": snippet,
        "cwe": str(alert.get("cweid") or ""),
        "status": "open",
        "verification_evidence": verification.get("evidence", ""),
        "verification_reasoning": verification.get("reasoning", ""),
        "fingerprint": hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest(),
    }
