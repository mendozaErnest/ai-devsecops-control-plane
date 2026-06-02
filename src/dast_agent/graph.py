"""StateGraph assembly for the agentic DAST loop.

Explorer → Attacker → Verifier ─┐
            ↑___________________↓
                      (loop until iteration >= max OR status=done)
"""
from __future__ import annotations

import logging

from .agents import attacker_agent, explorer_agent, verifier_agent
from .state import DastAgentState


LOGGER = logging.getLogger(__name__)

try:
    from langgraph.graph import END, StateGraph  # type: ignore
    LANGGRAPH_AVAILABLE = True
except ImportError:
    END = "__end__"  # sentinel for unit tests when langgraph absent
    StateGraph = None  # type: ignore
    LANGGRAPH_AVAILABLE = False


def should_continue(state: DastAgentState) -> str:
    """Decide whether to loop back to Attacker or terminate."""
    iteration = state.get("iteration", 0)
    max_iterations = state.get("max_iterations", 3)

    if state.get("error"):
        return END
    if state.get("status") == "done":
        return END
    if iteration >= max_iterations:
        return END
    if state.get("discovered_routes"):
        return "attacker"
    return END


def build_dast_graph():
    """Compile the agentic graph. Raises ImportError if LangGraph is unavailable."""
    if not LANGGRAPH_AVAILABLE or StateGraph is None:
        raise ImportError(
            "langgraph is not installed. Install with: pip install langgraph"
        )

    graph = StateGraph(DastAgentState)
    graph.add_node("explorer", explorer_agent)
    graph.add_node("attacker", attacker_agent)
    graph.add_node("verifier", verifier_agent)

    graph.set_entry_point("explorer")
    graph.add_edge("explorer", "attacker")
    graph.add_edge("attacker", "verifier")
    graph.add_conditional_edges(
        "verifier",
        should_continue,
        {"attacker": "attacker", END: END},
    )

    return graph.compile()
