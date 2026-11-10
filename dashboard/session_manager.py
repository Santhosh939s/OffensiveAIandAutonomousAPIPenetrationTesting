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
import urllib.parse
from typing import Any, Dict, Iterator, List, Optional

from controller.agent.autonomous_controller import AutonomousController
from controller.agent.event_emitter import AgentEventEmitter, ControllerEventType
from controller.brain.model_gateway import get_model_brain
from controller.config import AgentConfig, DEFAULT_CONFIG
from controller.guardrails.scope_validator import ScopeValidator, set_external_domains_allowed, add_authorized_external_host
from controller.guardrails.policy_service import PolicyService
from controller.storage.evidence_store import EvidenceStore

logger = logging.getLogger("autonomous_pentest.dashboard")

from controller.guardrails.sanitizer import mask_sensitive_traffic_data, SENSITIVE_KEY_PATTERNS


class DashboardSessionManager:
    """Manages active and historical penetration testing sessions for the dashboard."""

    DEFAULT_MAX_CONCURRENT_ASSESSMENTS: int = 4
    MIN_AVAILABLE_RAM_MB: float = 150.0

    def __init__(
        self,
        db_path: str = "offensive_ai_evidence.db",
        store: Optional[EvidenceStore] = None,
        max_concurrent_assessments: int = DEFAULT_MAX_CONCURRENT_ASSESSMENTS,
        min_available_ram_mb: float = MIN_AVAILABLE_RAM_MB,
        policy_service: Optional[Any] = None,
    ):
        self.db_path = db_path
        self.store = store or EvidenceStore(db_path=db_path)
        self.policy_service = policy_service or PolicyService(store=self.store)
        self.max_concurrent_assessments = max_concurrent_assessments
        self.min_available_ram_mb = min_available_ram_mb
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.event_queues: Dict[str, List[queue.Queue]] = {}
        self._report_cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._recover_interrupted_sessions()

    def _recover_interrupted_sessions(self) -> int:
        """Identify and recover any sessions left in RUNNING or ACTIVE status from previous interrupted process runs."""
        recovered = 0
        try:
            with self.store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT session_id, notes FROM sessions WHERE status IN ('RUNNING', 'ACTIVE')")
                stale_sessions = cursor.fetchall()
                for row in stale_sessions:
                    s_id = row["session_id"]
                    old_notes = row["notes"] or ""
                    new_notes = (old_notes + " [Recovered: Marked INTERRUPTED on daemon restart]").strip()
                    cursor.execute(
                        "UPDATE sessions SET status = 'INTERRUPTED', notes = ?, updated_at = ? WHERE session_id = ?",
                        (new_notes, time.time(), s_id),
                    )
                    recovered += 1
                conn.commit()
            if recovered > 0:
                logger.info("Recovered %d interrupted session(s) on startup.", recovered)
        except Exception as exc:
            logger.warning("Failed to recover interrupted sessions on startup: %s", exc)
        return recovered

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
        auth_context: Optional[Any] = None,
        assessment_type: str = "auto",
        selected_categories: Optional[List[str]] = None,
        assessment_depth: str = "standard",
        timeout_seconds: Optional[int] = None,
        auth_type: str = "none",
        auth_credentials: Optional[Dict[str, Any]] = None,
        brain_client: Optional[Any] = None,
        policy_id: Optional[int] = None,
        operator_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Validate parameters and launch an autonomous assessment in a background worker."""

        # 0. Concurrency & Resource Protection Guards
        with self._lock:
            active_running = [
                sid for sid, rec in self.active_sessions.items()
                if rec.get("status") == "RUNNING"
            ]
            if len(active_running) >= self.max_concurrent_assessments:
                logger.warning(
                    "Assessment launch rejected: max concurrency limit reached (%d running)",
                    len(active_running),
                )
                return {
                    "success": False,
                    "error": (
                        f"Maximum concurrent assessments ({self.max_concurrent_assessments}) reached. "
                        "Please wait for an active assessment to finish or cancel one before starting a new assessment."
                    ),
                    "code": "RESOURCE_BUSY_MAX_CONCURRENCY",
                    "active_sessions": active_running,
                }

        # Policy Pre-Validation check
        matching_target_id = None
        target_pol_id = policy_id
        if self.policy_service is not None:
            active_count = len(active_running)
            if target_pol_id is None:
                active_pols = self.policy_service.list_policies(active_only=True)
                if active_pols:
                    target_pol_id = active_pols[0]["id"]
            if target_pol_id is not None:
                permitted, reason, pol_info = self.policy_service.check_assessment_permitted(
                    policy_id=target_pol_id,
                    target_url=target_url,
                    requested_categories=selected_categories,
                    auth_type=auth_type,
                    current_concurrency=active_count,
                )
                if not permitted:
                    return {
                        "success": False,
                        "error": f"Pre-assessment policy rejection: {reason}",
                        "target_url": target_url,
                    }
                if pol_info:
                    matching_target_id = pol_info.get("matching_target_id")
                    pol_cfg = pol_info.get("config", {})
                    if "max_turns" in pol_cfg:
                        max_turns = min(max_turns, int(pol_cfg["max_turns"]))
                    if "max_requests" in pol_cfg:
                        max_requests = min(max_requests, int(pol_cfg["max_requests"]))

        from controller.brain.resource_profile import get_system_memory_info
        sys_mem = get_system_memory_info()
        avail_mb = sys_mem.get("available_ram_mb", 9999.0)
        if avail_mb < self.min_available_ram_mb:
            logger.error(
                "Assessment launch rejected: low system memory (%.1f MB available < %.1f MB limit)",
                avail_mb,
                self.min_available_ram_mb,
            )
            return {
                "success": False,
                "error": (
                    f"Insufficient system memory ({avail_mb:.1f} MB available, {self.min_available_ram_mb:.1f} MB required). "
                    "Aborting launch to prevent system instability."
                ),
                "code": "RESOURCE_EXHAUSTED_MEMORY",
                "available_ram_mb": avail_mb,
            }

        # 1. Scope & Input Validation
        hosts_set = set(allowed_hosts) if allowed_hosts else {"127.0.0.1", "localhost", "::1"}
        pol_targets = pol_info.get("targets", []) if pol_info else None
        allow_ext = bool(pol_info.get("config", {}).get("allow_external_domains", False)) if pol_info else False

        # If wildcard or specific domain authorized, ensure target host can be included in allowed_hosts
        parsed_target = urllib.parse.urlsplit(target_url.strip())
        target_hostname = parsed_target.hostname
        if target_hostname:
            if allow_ext:
                hosts_set.add(target_hostname)
                set_external_domains_allowed(True)
                add_authorized_external_host(target_hostname)
            elif pol_targets:
                for pt in pol_targets:
                    hp = str(pt.get("host_pattern", "")).strip()
                    if hp == "*" or hp == target_hostname or (hp.startswith("*.") and target_hostname.endswith(hp[1:])):
                        hosts_set.add(target_hostname)
                        add_authorized_external_host(target_hostname)
                        break

        temp_config = AgentConfig(allowed_hosts=hosts_set, allow_external_domains=allow_ext)
        scope_validator = ScopeValidator(temp_config)
        scope_res = scope_validator.validate_url(
            target_url,
            target_authorizations=pol_targets,
            allow_external_domains=allow_ext,
        )

        if not scope_res.is_valid:
            return {
                "success": False,
                "error": f"Target scope validation failed: {scope_res.reason}",
                "target_url": target_url,
            }

        normalized_target = scope_res.normalized_url or target_url
        if target_hostname:
            hosts_set.add(target_hostname)

        # 2. Build Session Configuration
        effective_auth_context = auth_context
        if not effective_auth_context and auth_credentials and auth_type != "none":
            if auth_type == "bearer" and auth_credentials.get("token"):
                tok = str(auth_credentials["token"]).strip()
                effective_auth_context = {"Authorization": f"Bearer {tok}"}
            elif auth_type == "api_key" and auth_credentials.get("api_key"):
                h_name = str(auth_credentials.get("header_name") or "X-API-Key").strip()
                effective_auth_context = {h_name: str(auth_credentials["api_key"]).strip()}
            elif auth_type == "basic" and auth_credentials.get("username"):
                import base64
                u = str(auth_credentials.get("username", ""))
                p = str(auth_credentials.get("password", ""))
                b64_up = base64.b64encode(f"{u}:{p}".encode()).decode()
                effective_auth_context = {"Authorization": f"Basic {b64_up}"}
            elif auth_type == "custom" and auth_credentials.get("headers"):
                effective_auth_context = auth_credentials["headers"]

        config = AgentConfig(
            max_turns=max(1, min(max_turns, 30)),
            max_requests_per_session=max(1, min(max_requests, 50)),
            max_model_calls=max(1, min(max_model_calls, 50)),
            allowed_hosts=hosts_set,
            allow_external_domains=allow_ext,
            zap_active_scan_enabled=zap_active_scan,
            db_path=self.db_path,
        )

        # 3. Model Brain Selection
        try:
            brain = brain_client or get_model_brain(
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
            policy_service=self.policy_service,
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
            "operator_id": operator_id,
            "policy_id": target_pol_id,
            "target_authorization_id": matching_target_id,
        }

        with self._lock:
            self.active_sessions[session_id] = session_record

        # 5. Execute in Daemon Thread
        def should_cancel():
            if cancel_event.is_set():
                return "Cancelled by operator"
            if timeout_seconds and (time.time() - session_record["start_time"]) > timeout_seconds:
                session_record["cancellation_requested"] = True
                return f"Session timeout ceiling reached ({timeout_seconds}s limit)"
            return False

        def run_worker():
            try:
                auto_spec = spec_source or f"{normalized_target}/openapi.json"
                res = controller.run_assessment(
                    target_url=normalized_target,
                    spec_source=auto_spec,
                    session_notes=assessment_name,
                    session_id=session_id,
                    cancel_check=should_cancel,
                    auth_context=effective_auth_context,
                    selected_categories=selected_categories,
                    assessment_type=assessment_type,
                    assessment_depth=assessment_depth,
                    policy_id=policy_id,
                    operator_id=operator_id,
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
                try:
                    self.store.update_session_status(
                        session_id=session_id,
                        status="ERROR",
                        notes=f"Worker exception: {str(exc)}",
                    )
                except Exception:
                    pass
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

    def cancel_assessment(
        self,
        session_id: str,
        actor_id: Optional[int] = None,
        actor_role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Request cooperative cancellation of a running assessment with ownership validation."""
        emitter = None
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                return {"success": False, "error": f"Session '{session_id}' not found"}

            # Authorization & ownership enforcement
            if actor_role:
                role_clean = actor_role.strip().lower()
                if role_clean == "auditor":
                    return {"success": False, "error": "Insufficient privileges: Auditor role is strictly read-only"}
                if role_clean == "operator":
                    owner = session.get("operator_id")
                    if owner is not None and actor_id is not None and owner != actor_id:
                        return {
                            "success": False,
                            "error": f"Permission denied: Operator {actor_id} cannot cancel an assessment owned by Operator {owner}",
                        }

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
                    if not self.event_queues[session_id]:
                        del self.event_queues[session_id]

    def cleanup_session(self, session_id: str) -> None:
        """Explicitly release event queues and reclaim memory for a completed session."""
        with self._lock:
            if session_id in self.event_queues:
                del self.event_queues[session_id]
        import gc
        gc.collect()

    def list_sessions(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List all historical and active sessions."""
        return self.store.list_sessions(limit=limit, offset=offset)

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Retrieve live status and progress statistics for a session with fast SQL aggregation."""
        with self._lock:
            active = self.active_sessions.get(session_id)

        summary = self.store.get_finding_summary(session_id)
        by_status = summary.get("by_status", {})
        findings_count = summary.get("total", 0)
        confirmed_count = by_status.get("CONFIRMED", 0)
        suspected_count = by_status.get("SUSPECTED", 0)
        safe_count = by_status.get("NOT_DEMONSTRATED", 0)

        if active:
            start_t = active["start_time"]
            end_t = active["end_time"] or time.time()
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
                "findings_count": findings_count,
                "confirmed_count": confirmed_count,
                "suspected_count": suspected_count,
                "safe_count": safe_count,
                "by_status": by_status,
                "by_severity": summary.get("by_severity", {}),
                "cancellation_requested": active.get("cancellation_requested", False),
            }

        # Check database for historical session
        db_sess = self.store.get_session(session_id)
        if not db_sess:
            return {"error": f"Session '{session_id}' not found"}

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
            "findings_count": findings_count,
            "confirmed_count": confirmed_count,
            "suspected_count": suspected_count,
            "safe_count": safe_count,
            "by_status": by_status,
            "by_severity": summary.get("by_severity", {}),
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
        """Retrieve security findings recorded for a session (with pagination and reproduction steps)."""
        findings = self.store.get_findings(session_id, limit=limit, offset=offset)
        try:
            from controller.reporting.risk_engine import RiskAssessmentEngine
            for f in findings:
                if not f.get("reproduction_steps") or not f.get("technical_impact"):
                    prof = RiskAssessmentEngine.get_finding_risk_profile(
                        category=f.get("category", ""),
                        status=f.get("status", "CONFIRMED"),
                        evidence_notes=f.get("evidence_notes", ""),
                        endpoint=f.get("endpoint", "/"),
                    )
                    f["technical_impact"] = prof.technical_impact
                    f["reproduction_steps"] = prof.reproduction_steps
        except Exception:
            pass
        return findings

    def get_report_markdown(self, session_id: str) -> str:
        """Retrieve final generated report markdown for a session (with memoization for completed runs)."""
        with self._lock:
            cached = self._report_cache.get(session_id, {}).get("markdown")
            if cached is not None:
                return cached

        from controller.reporting.report_generator import ReportGenerator

        gen = ReportGenerator(evidence_store=self.store)
        md = gen.generate_report(session_id)

        sess = self.store.get_session(session_id)
        if sess and sess.get("status") in ("COMPLETED", "ERROR", "CANCELLED", "INTERRUPTED"):
            with self._lock:
                if session_id not in self._report_cache:
                    self._report_cache[session_id] = {}
                self._report_cache[session_id]["markdown"] = md

        return md

    def get_report_json(self, session_id: str) -> Dict[str, Any]:
        """Retrieve final structured report JSON for a session (with memoization for completed runs)."""
        with self._lock:
            cached = self._report_cache.get(session_id, {}).get("json")
            if cached is not None:
                return cached

        from controller.reporting.report_generator import ReportGenerator

        gen = ReportGenerator(evidence_store=self.store)
        data = gen.generate_json_report(session_id)

        sess = self.store.get_session(session_id)
        if sess and sess.get("status") in ("COMPLETED", "ERROR", "CANCELLED", "INTERRUPTED"):
            with self._lock:
                if session_id not in self._report_cache:
                    self._report_cache[session_id] = {}
                self._report_cache[session_id]["json"] = data

        return data

    def get_report_html(self, session_id: str) -> str:
        """Retrieve standalone styled HTML report for a session (with memoization for completed runs)."""
        with self._lock:
            cached = self._report_cache.get(session_id, {}).get("html")
            if cached is not None:
                return cached

        from controller.reporting.report_generator import ReportGenerator

        gen = ReportGenerator(evidence_store=self.store)
        html = gen.generate_html_report(session_id)

        sess = self.store.get_session(session_id)
        if sess and sess.get("status") in ("COMPLETED", "ERROR", "CANCELLED", "INTERRUPTED"):
            with self._lock:
                if session_id not in self._report_cache:
                    self._report_cache[session_id] = {}
                self._report_cache[session_id]["html"] = html

        return html

    def invalidate_report_cache(self, session_id: Optional[str] = None) -> None:
        """Invalidate memoized reports for a specific session or all sessions."""
        with self._lock:
            if session_id:
                self._report_cache.pop(session_id, None)
            else:
                self._report_cache.clear()

    def get_risk_summary(self, session_id: str) -> Dict[str, Any]:
        """Retrieve aggregated risk metrics and severity counts for a session."""
        from controller.reporting.risk_engine import RiskAssessmentEngine

        findings = self.get_findings(session_id)
        summary = RiskAssessmentEngine.calculate_session_risk_summary(findings)
        return summary.to_dict()

    def get_discovered_endpoints(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve discovered endpoints for a session from specifications and plans."""
        discovered: List[Dict[str, Any]] = []
        seen = set()

        specs = self.store.get_specifications(session_id)
        for s in specs:
            spec_data = s.get("spec_data") or {}
            paths = spec_data.get("paths") or {}
            for path, path_obj in paths.items():
                if isinstance(path_obj, dict):
                    for m, details in path_obj.items():
                        if m.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
                            key = f"{m.upper()} {path}"
                            if key not in seen:
                                seen.add(key)
                                summary = details.get("summary") or details.get("description") or "" if isinstance(details, dict) else ""
                                discovered.append({
                                    "method": m.upper(),
                                    "path": path,
                                    "source": s.get("spec_source", "OpenAPI"),
                                    "summary": summary,
                                })

        plans = self.store.get_plans(session_id)
        for p in plans:
            plan = p.get("plan") or {}
            for step in plan.get("steps", []):
                params = step.get("parameters") or {}
                url = params.get("url") or params.get("target_url") or ""
                method = params.get("method") or ("POST" if "graphql" in url else "GET")
                if url:
                    import urllib.parse
                    parsed_path = urllib.parse.urlparse(url).path or url
                    key = f"{str(method).upper()} {parsed_path}"
                    if key not in seen:
                        seen.add(key)
                        discovered.append({
                            "method": str(method).upper(),
                            "path": parsed_path,
                            "source": "Model Test Plan",
                            "summary": step.get("purpose", ""),
                        })

        return discovered

    def get_session_details(self, session_id: str) -> Dict[str, Any]:
        """Return comprehensive session metadata, risk scorecard, and overview for UI reopening."""
        status = self.get_session_status(session_id)
        if "error" in status:
            return status

        risk = self.get_risk_summary(session_id)
        findings = self.get_findings(session_id)
        endpoints = self.get_discovered_endpoints(session_id)
        tool_execs = self.store.get_tool_executions(session_id)

        return {
            "session_id": session_id,
            "status": status,
            "risk_summary": risk,
            "findings_count": len(findings),
            "endpoints_count": len(endpoints),
            "tool_executions_count": len(tool_execs),
            "latest_findings": findings[:5],
        }

    def compare_sessions(self, session_a: str, session_b: str) -> Dict[str, Any]:
        """Compare security findings between two assessment sessions (regression analysis)."""
        sess_a = self.store.get_session(session_a)
        sess_b = self.store.get_session(session_b)
        if not sess_a:
            return {"error": f"Session A '{session_a}' not found"}
        if not sess_b:
            return {"error": f"Session B '{session_b}' not found"}

        findings_a = self.store.get_findings(session_a)
        findings_b = self.store.get_findings(session_b)

        summary_a = self.get_risk_summary(session_a)
        summary_b = self.get_risk_summary(session_b)

        # Normalize finding identity key: (category.lower(), endpoint.lower())
        def finding_key(f: Dict[str, Any]) -> str:
            return f"{str(f.get('category', '')).lower().strip()}::{str(f.get('endpoint', '')).lower().strip()}"

        keys_a = {finding_key(f): f for f in findings_a}
        keys_b = {finding_key(f): f for f in findings_b}

        new_keys = set(keys_b.keys()) - set(keys_a.keys())
        resolved_keys = set(keys_a.keys()) - set(keys_b.keys())
        persistent_keys = set(keys_a.keys()) & set(keys_b.keys())

        new_findings = [keys_b[k] for k in new_keys]
        resolved_findings = [keys_a[k] for k in resolved_keys]
        persistent_findings = [keys_b[k] for k in persistent_keys]

        score_a = summary_a.get("overall_risk_score", 0.0)
        score_b = summary_b.get("overall_risk_score", 0.0)
        risk_delta = round(score_b - score_a, 2)

        return {
            "session_a": {
                "session_id": session_a,
                "target": sess_a.get("target"),
                "status": sess_a.get("status"),
                "created_at": sess_a.get("created_at"),
                "risk_score": score_a,
                "findings_count": len(findings_a),
            },
            "session_b": {
                "session_id": session_b,
                "target": sess_b.get("target"),
                "status": sess_b.get("status"),
                "created_at": sess_b.get("created_at"),
                "risk_score": score_b,
                "findings_count": len(findings_b),
            },
            "risk_delta": risk_delta,
            "status_change": "INCREASED_RISK" if risk_delta > 0 else ("REDUCED_RISK" if risk_delta < 0 else "UNCHANGED"),
            "summary_counts": {
                "new": len(new_findings),
                "resolved": len(resolved_findings),
                "persistent": len(persistent_findings),
            },
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "persistent_findings": persistent_findings,
        }
