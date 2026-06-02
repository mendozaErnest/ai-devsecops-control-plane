"""LangGraph-driven agentic DAST loop: Explorer → Attacker → Verifier.

The runtime degrades gracefully when LangGraph or Ollama are unavailable:
- LangGraph missing → `LANGGRAPH_AVAILABLE = False` so the API endpoint can return 503.
- Ollama missing → agents fall back to deterministic logic (no LLM enrichment).
- ZAP missing → tool wrappers return empty results; agent finishes with 0 findings.
"""
from .runner import (
    LANGGRAPH_AVAILABLE,
    get_scan_status,
    list_active_scans,
    run_dast_agent,
)

__all__ = [
    "LANGGRAPH_AVAILABLE",
    "get_scan_status",
    "list_active_scans",
    "run_dast_agent",
]
