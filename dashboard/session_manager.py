"""Dashboard Session Manager for Autonomous API Penetration Testing Agent.

Coordinates background execution of AutonomousController sessions, dispatches
Server-Sent Events (SSE) from AgentEventEmitter to browser clients, retrieves
and sanitizes traffic logs with sensitive token masking, and manages cancellation.
"""

import json
import logging
import os
import queue
import re
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from controller.agent.autonomous_controller import AutonomousController
from controller.agent.event_emitter import AgentEventEmitter, ControllerEventType
from controller.brain.model_gateway import get_model_brain
from controller.config import AgentConfig, DEFAULT_CONFIG
from controller.guardrails.scope_validator import ScopeValidator
from controller.storage.evidence_store import EvidenceStore

logger = logging.getLogger("autonomous_pentest.dashboard")

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
    re.compile(r'"(password|api_token|token|secret|key|authorization)"\s*:\s*"[^"]+"', re.IGNORECASE),
    re.compile(r'session=[a-zA-Z0-9_\-]+', re.IGNORECASE),
]


def mask_sensitive_traffic_data(data: Any) -> Any:
    """Mask credentials, tokens, session cookies, and API keys from strings, dicts, or lists."""
    if data is None:
        return ""
    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in ("password", "token", "secret", "key", "auth", "cookie")):
                masked_dict[k] = "***MASKED***"
            elif isinstance(v, (dict, list, str)):
                masked_dict[k] = mask_sensitive_traffic_data(v)
            else:
                masked_dict[k] = v
        return masked_dict
    elif isinstance(data, list):
        return [mask_sensitive_traffic_data(item) for item in data]

    masked = str(data)
    # Mask Authorization header tokens
    masked = re.sub(
        r"(Bearer\s+)[a-zA-Z0-9_\-\.]+",
        r"\1***",
        masked,
        flags=re.IGNORECASE,
    )
    # Mask sensitive JSON fields
    masked = re.sub(
        r'("(password|api_token|token|secret|key|authorization)"\s*:\s*)"[^"]+"',
        r'\1"***"',
        masked,
        flags=re.IGNORECASE,
    )
    # Mask cookie session identifiers
    masked = re.sub(
        r"(session=)[a-zA-Z0-9_\-]+",
        r"\1***",
        masked,
        flags=re.IGNORECASE,
    )
    return masked


class DashboardSessionManager:
    """Manages active and historical penetration testing sessions for the dashboard."""

    def __init__(self, db_path: str = "offensive_ai_evidence.db", store: Optional[EvidenceStore] = None):
        self.db_path = db_path
        self.store = store or EvidenceStore(db_path=db_path)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.event_queues: Dict[str, List[queue.Queue]] = {}
        self._lock = threading.RLock()

    def start_assessment(
        self,
        target_url: str,
        assessment_name: str = "Live Web Assessment",
        max_turns: int = 10,
        max_requests: int = 25,
        max_model_calls: int = 25,
        allowed_hosts: Optional[List[str]] = None,
        brain_mode: str = "mock",
        remote_endpoint: Optional[str] = None,
        zap_enabled: bool = False,
        zap_active_scan: bool = False,
        spec_source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate parameters and launch an autonomous assessment in a background worker."""

        # 1. Scope & Input Validation
        hosts_set = set(allowed_hosts) if allowed_hosts else {"127.0.0.1", "localhost", "::1"}
        temp_config = AgentConfig(allowed_hosts=hosts_set)
        scope_validator = ScopeValidator(temp_config)
        scope_res = scope_validator.validate_url(target_url)

        if not scope_res.is_valid:
            return {
                "success": False,
                "error": f"Target scope validation failed: {scope_res.reason}",
                "target_url": target_url,
            }

        normalized_target = scope_res.normalized_url or target_url

        # 2. Build Session Configuration
        config = AgentConfig(
            max_turns=max(1, min(max_turns, 30)),
            max_requests_per_session=max(1, min(max_requests, 50)),
            max_model_calls=max(1, min(max_model_calls, 50)),
            allowed_hosts=hosts_set,
            zap_active_scan_enabled=zap_active_scan,
            db_path=self.db_path,
        )

        # 3. Model Brain Selection
        try:
            brain = get_model_brain(
                mode=brain_mode,
                endpoint_url=remote_endpoint,
            )
        except Exception as exc:
            return {"success": False, "error": f"Failed to initialize model brain: {str(exc)}"}

        # 4. Event Dispatcher & Queue Wiring
        event_emitter = AgentEventEmitter()
        controller = AutonomousController(
            config=config,
            model_brain=brain,
            evidence_store=self.store,
            event_emitter=event_emitter,
        )

        session_id = f"sess_{int(time.time())}_{os.urandom(3).hex()}"
        q: queue.Queue = queue.Queue(maxsize=1000)

        with self._lock:
            self.event_queues[session_id] = [q]

        def on_event(ev: Dict[str, Any]):
            with self._lock:
                listeners = self.event_queues.get(session_id, [])
                for listener in listeners:
                    try:
                        listener.put_nowait(ev)
                    except queue.Full:
                        pass

        event_emitter.subscribe(on_event)

        cancel_event = threading.Event()
        session_record = {
            "session_id": session_id,
            "target_url": normalized_target,
            "assessment_name": assessment_name,
            "brain_mode": brain_mode,
            "status": "RUNNING",
            "start_time": time.time(),
            "end_time": None,
            "controller": controller,
            "event_emitter": event_emitter,
            "config": config,
            "cancellation_requested": False,
            "cancel_event": cancel_event,
            "result": None,
        }

        with self._lock:
            self.active_sessions[session_id] = session_record

        # 5. Execute in Daemon Thread
        def run_worker():
            try:
                auto_spec = spec_source or f"{normalized_target}/openapi.json"
                res = controller.run_assessment(
                    target_url=normalized_target,
                    spec_source=auto_spec,
                    session_notes=assessment_name,
                    session_id=session_id,
                    cancel_check=cancel_event.is_set,
                )
                session_record["result"] = res
                if session_record.get("cancellation_requested"):
                    session_record["status"] = "CANCELLED"
                else:
                    session_record["status"] = "COMPLETED"
            except Exception as exc:
                logger.exception("Assessment worker error: %s", exc)
                session_record["status"] = "ERROR"
                session_record["error"] = str(exc)
            finally:
                session_record["end_time"] = time.time()
                # Release temporary worker memory
                import gc
                gc.collect()
                # Emit termination marker into queue
                on_event({
                    "timestamp": time.time(),
                    "event_type": ControllerEventType.ASSESSMENT_COMPLETED,
                    "session_id": session_id,
                    "data": {"status": session_record["status"]},
                })

        thread = threading.Thread(target=run_worker, daemon=True)
        session_record["thread"] = thread
        thread.start()

        return {
            "success": True,
            "session_id": session_id,
            "target_url": normalized_target,
            "brain_mode": brain_mode,
            "status": "RUNNING",
            "max_turns": config.max_turns,
            "max_requests": config.max_requests_per_session,
        }

    def cancel_assessment(self, session_id: str) -> Dict[str, Any]:
        """Request cooperative cancellation of a running assessment."""
        emitter = None
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                return {"success": False, "error": f"Session '{session_id}' not found"}

            if session["status"] != "RUNNING":
                return {"success": True, "message": f"Session already in state '{session['status']}'"}

            session["cancellation_requested"] = True
            session["status"] = "CANCELLED"
            session["end_time"] = time.time()
            if "cancel_event" in session and session["cancel_event"]:
                session["cancel_event"].set()

            emitter = session.get("event_emitter")

        # Signal through event emitter
        if emitter:
            emitter.emit(
                ControllerEventType.EARLY_STOP_TRIGGERED,
                session_id=session_id,
                data={"reason": "User requested assessment cancellation from dashboard"},
            )

        return {"success": True, "session_id": session_id, "status": "CANCELLED"}

    def get_sse_stream(self, session_id: str) -> Iterator[str]:
        """Generate Server-Sent Events for a browser client."""
        q: queue.Queue = queue.Queue(maxsize=1000)
        with self._lock:
            if session_id not in self.event_queues:
                self.event_queues[session_id] = []
            self.event_queues[session_id].append(q)

        # Initial keepalive ping
        yield f"data: {json.dumps({'event_type': 'STREAM_CONNECTED', 'session_id': session_id, 'timestamp': time.time()})}\n\n"

        # Stream historical events first if available
        with self._lock:
            session = self.active_sessions.get(session_id)
            if session:
                emitter = session.get("event_emitter")
                if emitter:
                    for ev in emitter.get_events(session_id):
                        yield f"data: {json.dumps(ev)}\n\n"

        try:
            while True:
                try:
                    ev = q.get(timeout=1.0)
                    yield f"data: {json.dumps(ev)}\n\n"
                    if ev.get("event_type") == ControllerEventType.ASSESSMENT_COMPLETED:
                        break
                except queue.Empty:
                    with self._lock:
                        sess = self.active_sessions.get(session_id)
                        if sess and sess.get("status") in ("COMPLETED", "ERROR", "CANCELLED"):
                            break
                    # Keepalive heartbeat
                    yield ": ping\n\n"
        finally:
            with self._lock:
                if session_id in self.event_queues and q in self.event_queues[session_id]:
                    self.event_queues[session_id].remove(q)

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Retrieve live status and progress statistics for a session."""
        with self._lock:
            active = self.active_sessions.get(session_id)

        if active:
            start_t = active["start_time"]
            end_t = active["end_time"] or time.time()
            findings = self.store.get_findings(session_id)
            db_session = self.store.get_session(session_id)
            turns_taken = db_session["turns_taken"] if db_session else 0
            requests_sent = db_session["requests_sent"] if db_session else 0

            return {
                "session_id": session_id,
                "target": active["target_url"],
                "target_url": active["target_url"],
                "assessment_name": active["assessment_name"],
                "brain_mode": active["brain_mode"],
                "status": active["status"],
                "elapsed_seconds": round(end_t - start_t, 2),
                "turns_taken": turns_taken,
                "max_turns": active["config"].max_turns,
                "requests_sent": requests_sent,
                "max_requests": active["config"].max_requests_per_session,
                "findings_count": len(findings),
                "cancellation_requested": active.get("cancellation_requested", False),
            }

        # Check database for historical session
        db_sess = self.store.get_session(session_id)
        if not db_sess:
            return {"error": f"Session '{session_id}' not found"}

        findings = self.store.get_findings(session_id)
        return {
            "session_id": session_id,
            "target": db_sess["target"],
            "target_url": db_sess["target"],
            "assessment_name": db_sess.get("notes", "Historical Session"),
            "brain_mode": "stored",
            "status": db_sess["status"],
            "elapsed_seconds": round(db_sess["updated_at"] - db_sess["created_at"], 2),
            "turns_taken": db_sess["turns_taken"],
            "max_turns": DEFAULT_CONFIG.max_turns,
            "requests_sent": db_sess["requests_sent"],
            "max_requests": DEFAULT_CONFIG.max_requests_per_session,
            "findings_count": len(findings),
            "cancellation_requested": False,
        }

    def get_traffic_logs_sanitized(
        self,
        session_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve traffic logs with credentials and authorization headers masked (with pagination)."""
        raw_traffic = self.store.get_traffic_logs(session_id, limit=limit, offset=offset)
        sanitized = []
        for r in raw_traffic:
            sanitized.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "method": r["method"],
                "url": r["url"],
                "headers": {
                    k: (
                        "Bearer ***"
                        if k.lower() == "authorization"
                        else ("***" if "cookie" in k.lower() or "key" in k.lower() else v)
                    )
                    for k, v in r.get("headers", {}).items()
                },
                "request_body": mask_sensitive_traffic_data(r.get("request_body")),
                "response_status": r["response_status"],
                "response_headers": r.get("response_headers", {}),
                "response_body": mask_sensitive_traffic_data(r.get("response_body")),
                "elapsed_ms": r["elapsed_ms"],
            })
        return sanitized

    def get_findings(
        self,
        session_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve security findings recorded for a session (with pagination)."""
        return self.store.get_findings(session_id, limit=limit, offset=offset)

    def get_report_markdown(self, session_id: str) -> str:
        """Retrieve final generated report markdown for a session."""
        from controller.reporting.report_generator import ReportGenerator

        gen = ReportGenerator(evidence_store=self.store)
        return gen.generate_report(session_id)
