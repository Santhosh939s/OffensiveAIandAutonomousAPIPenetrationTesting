"""Session state tracking for Autonomous API Penetration Testing.

Maintains execution state across turns, cumulative request counts, observations,
and termination conditions.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SessionState:
    """Encapsulates the runtime state of a single penetration testing session."""

    target: str
    session_id: str = field(default_factory=lambda: f"session_{uuid.uuid4().hex[:12]}")
    created_at: float = field(default_factory=time.time)
    current_turn: int = 1
    request_count: int = 0
    active_plan: Optional[Dict[str, Any]] = None
    observations: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    is_finished: bool = False
    termination_reason: Optional[str] = None

    def can_continue(self, max_turns: int, max_requests: int) -> bool:
        """Evaluate whether execution should proceed."""
        if self.is_finished:
            return False
        if self.current_turn > max_turns:
            self.is_finished = True
            self.termination_reason = f"Max turn limit reached ({max_turns})"
            return False
        if self.request_count >= max_requests:
            self.is_finished = True
            self.termination_reason = f"Cumulative request limit reached ({max_requests})"
            return False
        return True

    def increment_turn(self) -> None:
        """Advance the turn counter."""
        self.current_turn += 1

    def increment_requests(self, count: int = 1) -> None:
        """Increment cumulative requests counter."""
        self.request_count += count

    def add_observation(self, observation: Dict[str, Any]) -> None:
        """Record a tool execution observation."""
        self.observations.append(observation)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Record a security finding."""
        self.findings.append(finding)

    def mark_completed(self, reason: str = "Assessment completed successfully") -> None:
        """Mark session as completed."""
        self.is_finished = True
        self.termination_reason = reason

