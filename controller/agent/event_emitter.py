"""Live Event Streaming Interface for Autonomous Testing Controller.

Emits structured telemetry events across testing phases:
- Phase transitions (Reconnaissance, Planning, Probing, Analysis, Complete)
- Proposed actions and policy decisions
- Tool execution results and timing
- Finding recordings and verifications
- Budget tracking and early termination notices

These structured events prepare the agent for consumption by the Phase 6 Windows Dashboard.
"""

import time
from typing import Any, Callable, Dict, List, Optional


class ControllerEventType:
    PHASE_CHANGE = "PHASE_CHANGE"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    POLICY_DECISION = "POLICY_DECISION"
    TOOL_EXECUTED = "TOOL_EXECUTED"
    FINDING_RECORDED = "FINDING_RECORDED"
    BUDGET_UPDATE = "BUDGET_UPDATE"
    EARLY_STOP_TRIGGERED = "EARLY_STOP_TRIGGERED"
    ASSESSMENT_COMPLETED = "ASSESSMENT_COMPLETED"


class AgentEventEmitter:
    """Publish-subscribe live event dispatcher for controller operations."""

    def __init__(self):
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._event_history: List[Dict[str, Any]] = []

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a callback listener function for live events."""
        if callback not in self._subscribers:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Unregister a listener function."""
        if callback in self._subscribers:
            self._subscribers.remove(callback)

    def emit(self, event_type: str, session_id: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Emit a structured live event to all registered subscribers."""
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "session_id": session_id,
            "data": data or {},
        }
        self._event_history.append(event)
        for sub in list(self._subscribers):
            try:
                sub(event)
            except Exception:
                pass
        return event

    def get_events(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve historical events, optionally filtered by session ID."""
        if not session_id:
            return list(self._event_history)
        return [e for e in self._event_history if e.get("session_id") == session_id]

    def clear(self) -> None:
        """Clear recorded events and subscribers."""
        self._event_history.clear()
        self._subscribers.clear()

