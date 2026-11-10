"""Autonomous Controller for API Penetration Testing.

Orchestrates the feedback loop between the Model Brain (decision-maker),
deterministic Guardrails / Policy Engine (permission check), Tool Registry
(safe execution), Evidence Store (SQLite persistence), and Reporting.
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.policy_engine import PolicyEngine
from controller.guardrails.scope_validator import ScopeValidator
from controller.brain.model_gateway import ModelBrainClient, get_model_brain
from controller.tools import ToolRegistry, build_default_tool_registry
from controller.storage.evidence_store import EvidenceStore
from controller.agent.session_state import SessionState
from controller.agent.event_emitter import AgentEventEmitter, ControllerEventType
from controller.agent.context_manager import CompactContextManager
from controller.agent.adaptive_engine import AdaptiveTestSelector
from controller.guardrails.sanitizer import mask_sensitive_traffic_data

logger = logging.getLogger(__name__)


class AutonomousController:
    """Deterministic orchestrator managing model-driven autonomous API security testing."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        model_brain: Optional[ModelBrainClient] = None,
        tool_registry: Optional[ToolRegistry] = None,
        evidence_store: Optional[EvidenceStore] = None,
        policy_engine: Optional[PolicyEngine] = None,
        event_emitter: Optional[AgentEventEmitter] = None,
        policy_service: Optional[Any] = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.brain = model_brain or get_model_brain(mode="mock")
        self.tools = tool_registry or build_default_tool_registry()
        self.store = evidence_store or EvidenceStore(self.config.db_path)
        self.scope_validator = ScopeValidator(self.config)
        self.events = event_emitter or AgentEventEmitter()
        self.policy_service = policy_service

        # Initialize policy engine with registered tool names
        self.policy = policy_engine or PolicyEngine(
            config=self.config,
            registered_tools=set(self.tools.list_tool_names()),
            scope_validator=self.scope_validator,
            policy_service=self.policy_service,
        )
        if self.policy_service and hasattr(self.policy, "set_policy_service"):
            self.policy.set_policy_service(self.policy_service)
        # Wire defense-in-depth policy enforcement directly into ToolRegistry
        if hasattr(self.tools, "set_policy_engine"):
            self.tools.set_policy_engine(self.policy, require_policy=True)

    def run_assessment(
        self,
        target_url: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        spec_source: Optional[str] = None,
        session_notes: str = "",
        session_id: Optional[str] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
        auth_context: Optional[Any] = None,
        selected_categories: Optional[List[str]] = None,
        assessment_type: str = "auto",
        assessment_depth: str = "standard",
        policy_id: Optional[int] = None,
        policy_service: Optional[Any] = None,
        operator_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Execute a complete autonomous API security assessment workflow."""

        # 0. Policy & Target Authorization Resolution
        p_svc = policy_service or self.policy_service
        resolved_policy = None
        if p_svc is not None:
            if policy_id is not None:
                resolved_policy = p_svc.get_policy(policy_id)
                if not resolved_policy:
                    return {
                        "success": False,
                        "error": f"Pre-assessment policy rejection: Policy with ID {policy_id} does not exist",
                        "target": target_url,
                        "session_id": None,
                    }
            else:
                active_policies = p_svc.list_policies(active_only=True)
                if active_policies:
                    resolved_policy = active_policies[0]

        if resolved_policy:
            auth_type = auth_context.get("type") if isinstance(auth_context, dict) else None
            active_concurrency = self.store.get_active_session_count() if hasattr(self.store, "get_active_session_count") else 0
            permitted, reason, _ = p_svc.check_assessment_permitted(
                policy_id=resolved_policy["id"],
                target_url=target_url,
                requested_categories=selected_categories,
                auth_type=auth_type,
                current_concurrency=active_concurrency,
            )
            if not permitted:
                logger.error("Target rejected by PolicyService: %s", reason)
                return {
                    "success": False,
                    "error": f"Pre-assessment policy rejection: {reason}",
                    "target": target_url,
                    "session_id": None,
                }

        # 1. Scope and target authorization check
        target_auths = resolved_policy.get("targets") if resolved_policy else None
        scope_res = self.scope_validator.validate_url(target_url, target_authorizations=target_auths)
        if not scope_res.is_valid:
            logger.error("Target rejected by scope validator: %s", scope_res.reason)
            return {
                "success": False,
                "error": f"Target scope violation: {scope_res.reason}",
                "target": target_url,
                "session_id": None,
            }

        normalized_target = scope_res.normalized_url or target_url

        # 2. Initialize Session and Persistence
        state = (
            SessionState(target=normalized_target, session_id=session_id)
            if session_id
            else SessionState(target=normalized_target)
        )
        matching_tgt_id = None
        if resolved_policy:
            matching_tgt_id = resolved_policy.get("matching_target_id")

        self.store.create_session(
            session_id=state.session_id,
            target=normalized_target,
            notes=session_notes or f"Autonomous assessment of {normalized_target}",
            operator_id=operator_id,
            policy_id=resolved_policy["id"] if resolved_policy else None,
            policy_version=resolved_policy.get("current_version") if resolved_policy else None,
            target_authorization_id=matching_tgt_id,
        )

        # 3. Create Assessment Policy Snapshot and Bind to Policy Engine
        if p_svc and resolved_policy:
            try:
                if hasattr(self.policy, "set_policy_service"):
                    self.policy.set_policy_service(p_svc)
                snapshot = p_svc.create_assessment_snapshot(
                    session_id=state.session_id,
                    policy_id=resolved_policy["id"],
                    applied_by_user_id=operator_id,
                )
                self.policy.bind_policy_snapshot(snapshot)
            except Exception as snap_exc:
                logger.warning("Failed to create policy snapshot: %s", snap_exc)

        try:
            return self._run_assessment_workflow(
                state=state,
                normalized_target=normalized_target,
                endpoints=endpoints,
                spec_source=spec_source,
                session_notes=session_notes,
                cancel_check=cancel_check,
                auth_context=auth_context,
                selected_categories=selected_categories,
                assessment_type=assessment_type,
                assessment_depth=assessment_depth,
            )
        except Exception as exc:
            safe_err = str(mask_sensitive_traffic_data(str(exc)))
            logger.exception("Assessment execution failed for session %s: %s", state.session_id, safe_err)
            self.store.update_session_status(
                session_id=state.session_id,
                status="ERROR",
                turns_taken=max(0, state.current_turn - 1),
                requests_sent=state.request_count,
                notes=f"Execution error: {safe_err}",
            )
            self.events.emit(
                ControllerEventType.ASSESSMENT_FAILED,
                session_id=state.session_id,
                data={"error": safe_err},
            )
            return {
                "success": False,
                "session_id": state.session_id,
                "target": state.target,
                "error": safe_err,
                "turns_taken": max(0, state.current_turn - 1),
                "requests_sent": state.request_count,
                "findings": state.findings,
                "termination_reason": f"Execution error: {safe_err}",
            }

    def _run_assessment_workflow(
        self,
        state: SessionState,
        normalized_target: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        spec_source: Optional[str] = None,
        session_notes: str = "",
        cancel_check: Optional[Callable[[], bool]] = None,
        auth_context: Optional[Any] = None,
        selected_categories: Optional[List[str]] = None,
        assessment_type: str = "auto",
        assessment_depth: str = "standard",
    ) -> Dict[str, Any]:
        """Internal execution loop of the autonomous security assessment."""
        logger.info("Started session %s for target %s", state.session_id, normalized_target)
        self.events.emit(
            ControllerEventType.PHASE_CHANGE,
            session_id=state.session_id,
            data={"phase": "RECONNAISSANCE", "target": normalized_target},
        )

        # 3. OpenAPI Discovery (if spec_source provided or discoverable)
        endpoints_to_test = endpoints or []
        if spec_source:
            logger.info("Discovering API specification from: %s", spec_source)
            spec_decision = self.policy.evaluate_action("openapi_parser", {"spec_source": spec_source})
            if spec_decision.approved:
                spec_res = self.tools.execute("openapi_parser", spec_decision.sanitized_arguments or {"spec_source": spec_source})
                self.store.log_tool_execution(
                    session_id=state.session_id,
                    tool_name="openapi_parser",
                    arguments={"spec_source": spec_source},
                    approved=True,
                    policy_reason="Authorized OpenAPI discovery",
                    result=spec_res,
                )
                if spec_res.get("success"):
                    self.store.record_specification(
                        session_id=state.session_id,
                        spec_source=spec_source,
                        title=spec_res.get("title", "Discovered API"),
                        spec_version=spec_res.get("spec_version"),
                        base_url=(spec_res.get("base_urls") or [normalized_target])[0],
                        endpoints_count=spec_res.get("endpoints_count", 0),
                        spec_data=spec_res,
                    )
                    discovered_planning = spec_res.get("planning_endpoints", [])
                    if discovered_planning:
                        endpoints_to_test = discovered_planning
                        state.add_observation({
                            "turn": 0,
                            "tool_name": "openapi_parser",
                            "status": "DISCOVERY_COMPLETED",
                            "endpoints_count": len(discovered_planning),
                            "security_schemes": spec_res.get("security_schemes"),
                        })

        # Check if GraphQL endpoint candidate should be probed/added
        has_graphql = any("graphql" in str(ep.get("path", "")).lower() for ep in endpoints_to_test)
        if not has_graphql and self.tools.has_tool("graphql_probe"):
            endpoints_to_test.append({"path": "/graphql", "method": "POST"})

        if not endpoints_to_test:
            endpoints_to_test = [{"path": "/", "method": "GET"}]

        # 4. Context Management & Adaptive Prioritization Setup
        context_mgr = CompactContextManager(
            target_url=normalized_target,
            max_turns=self.config.max_turns,
            max_requests=self.config.max_requests_per_session,
            max_probes_per_endpoint=self.config.max_probes_per_endpoint,
        )
        context_mgr.register_discovered_endpoints(endpoints_to_test)
        adaptive_selector = AdaptiveTestSelector(
            context_mgr,
            selected_categories=selected_categories,
            assessment_type=assessment_type,
            assessment_depth=assessment_depth,
        )

        self.events.emit(
            ControllerEventType.PHASE_CHANGE,
            session_id=state.session_id,
            data={"phase": "PLANNING", "endpoints_count": len(endpoints_to_test)},
        )

        # 5. Model generates test plan
        import inspect
        safe_auth = mask_sensitive_traffic_data(auth_context) if auth_context else None

        available_tools_schema = self.tools.get_tool_descriptions()

        sig_plan = inspect.signature(self.brain.create_test_plan)
        has_varkw_plan = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig_plan.parameters.values())
        plan_kwargs = {}
        if has_varkw_plan or "authorized_scope" in sig_plan.parameters:
            plan_kwargs["authorized_scope"] = list(self.config.allowed_hosts)
        if has_varkw_plan or "auth_context" in sig_plan.parameters:
            plan_kwargs["auth_context"] = safe_auth
        if has_varkw_plan or "budget" in sig_plan.parameters:
            plan_kwargs["budget"] = {
                "max_turns": self.config.max_turns,
                "max_requests": self.config.max_requests_per_session,
            }
        if has_varkw_plan or "current_objective" in sig_plan.parameters:
            plan_kwargs["current_objective"] = session_notes or f"Autonomous assessment of {normalized_target}"

        plan_data = self.brain.create_test_plan(
            target_url=normalized_target,
            endpoints=endpoints_to_test,
            available_tools=available_tools_schema,
            **plan_kwargs,
        )
        state.active_plan = plan_data
        self.store.record_plan(state.session_id, plan_data, status="ACTIVE")

        plan_steps = plan_data.get("steps", [])

        self.events.emit(
            ControllerEventType.PHASE_CHANGE,
            session_id=state.session_id,
            data={"phase": "EXECUTION", "plan_title": plan_data.get("plan_title")},
        )

        # 6. Autonomous Execution Loop
        policy_cfg = getattr(self.policy, "policy_snapshot", {}).get("config", {}) if getattr(self.policy, "policy_snapshot", None) else {}
        effective_max_turns = min(self.config.max_turns, policy_cfg.get("max_turns", self.config.max_turns))
        effective_max_requests = min(self.config.max_requests_per_session, policy_cfg.get("max_requests", self.config.max_requests_per_session), 100)
        effective_max_duration = min(float(policy_cfg.get("max_assessment_duration_seconds", getattr(self.config, "max_assessment_duration_seconds", 3600.0) or 3600.0)), 3600.0)
        effective_max_rps = float(policy_cfg.get("max_requests_per_second", getattr(self.config, "max_requests_per_second", 5.0) or 5.0))

        assessment_start_time = time.time()
        last_request_time = 0.0

        while state.can_continue(effective_max_turns, effective_max_requests):
            # Check assessment duration budget
            elapsed_seconds = time.time() - assessment_start_time
            if elapsed_seconds >= effective_max_duration:
                logger.info("Session %s reached duration limit (%.1fs >= %.1fs). Terminating.", state.session_id, elapsed_seconds, effective_max_duration)
                state.mark_completed(f"Assessment duration budget exhausted ({round(elapsed_seconds, 1)}s >= {effective_max_duration}s)")
                break
            if cancel_check:
                cancel_status = cancel_check()
                if cancel_status:
                    cancel_reason = cancel_status if isinstance(cancel_status, str) else "Cancelled by operator"
                    logger.info("Session %s received termination signal: %s. Aborting loop.", state.session_id, cancel_reason)
                    if hasattr(self.policy, "cancel"):
                        self.policy.cancel()
                    state.mark_completed(cancel_reason)
                    break

            # Live policy active status check
            active_pol_id = getattr(self.policy, "active_policy_id", None)
            if self.policy_service and active_pol_id:
                if hasattr(self.policy_service, "is_policy_active") and not self.policy_service.is_policy_active(active_pol_id):
                    logger.info("Session %s detected policy %d was deactivated. Aborting loop safely.", state.session_id, active_pol_id)
                    state.mark_completed(f"Policy ID {active_pol_id} was deactivated by administrator during assessment")
                    break
            turn = state.current_turn
            logger.info("Executing Turn %d/%d for session %s", turn, self.config.max_turns, state.session_id)
            context_mgr.turns_used = turn
            context_mgr.requests_sent = state.request_count

            # Adaptive check & early stopping evaluation
            if self.config.adaptive_selection_enabled:
                candidates = adaptive_selector.evaluate_and_rank_candidates(
                    target_base_url=normalized_target,
                    recent_observations=state.observations,
                )
                if self.config.early_stopping_enabled and turn > 1:
                    should_stop, stop_reason = adaptive_selector.should_abstain_or_stop(candidates)
                    if should_stop:
                        logger.info("Adaptive test selection triggered early stop: %s", stop_reason)
                        self.events.emit(
                            ControllerEventType.EARLY_STOP_TRIGGERED,
                            session_id=state.session_id,
                            data={"turn": turn, "reason": stop_reason},
                        )
                        state.mark_completed(stop_reason)
                        break

            # Live budget update event
            self.events.emit(
                ControllerEventType.BUDGET_UPDATE,
                session_id=state.session_id,
                data={
                    "turn": turn,
                    "requests_sent": state.request_count,
                    "requests_remaining": max(0, self.config.max_requests_per_session - state.request_count),
                },
            )

            # A. Model selects next action
            sig_act = inspect.signature(self.brain.select_next_action)
            has_varkw_act = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig_act.parameters.values())
            act_kwargs = {}
            if has_varkw_act or "target_url" in sig_act.parameters:
                act_kwargs["target_url"] = normalized_target
            if has_varkw_act or "authorized_scope" in sig_act.parameters:
                act_kwargs["authorized_scope"] = list(self.config.allowed_hosts)
            if has_varkw_act or "auth_context" in sig_act.parameters:
                act_kwargs["auth_context"] = safe_auth
            if has_varkw_act or "budget" in sig_act.parameters:
                act_kwargs["budget"] = {
                    "turns_remaining": max(0, self.config.max_turns - turn),
                    "requests_remaining": max(0, self.config.max_requests_per_session - state.request_count),
                }
            if has_varkw_act or "current_objective" in sig_act.parameters:
                act_kwargs["current_objective"] = session_notes or f"Assess {normalized_target} endpoints for OWASP API vulnerabilities"
            if has_varkw_act or "discovered_endpoints" in sig_act.parameters:
                act_kwargs["discovered_endpoints"] = endpoints_to_test

            action_proposal = self.brain.select_next_action(
                current_turn=turn,
                max_turns=self.config.max_turns,
                plan_steps=plan_steps,
                recent_observations=state.observations,
                available_tools=available_tools_schema,
                **act_kwargs,
            )
            self.events.emit(
                ControllerEventType.ACTION_PROPOSED,
                session_id=state.session_id,
                data={"turn": turn, "action_proposal": action_proposal},
            )

            if not isinstance(action_proposal, dict):
                logger.warning("Model returned non-dict action proposal; aborting turn safely.")
                state.mark_completed("Model produced non-dict action proposal")
                break

            action_type = action_proposal.get("action_type", "execute_tool")
            if action_type in {"complete", "no_action"}:
                reason = action_proposal.get("reasoning") or action_proposal.get("error") or "Model signaled testing completion"
                state.mark_completed(reason)
                break

            tool_name = action_proposal.get("tool_name", "")
            raw_arguments = action_proposal.get("arguments")
            if not isinstance(raw_arguments, dict):
                raw_arguments = {}
            else:
                raw_arguments = dict(raw_arguments)

            # Pull arguments declared at action_proposal top level if missing from arguments dict
            for k in ("url", "target", "endpoint", "uri", "method", "headers", "body", "params", "token", "payload", "action", "parameters", "json_body"):
                if k not in raw_arguments and k in action_proposal:
                    raw_arguments[k] = action_proposal[k]

            # Normalize alternate key names for target URL
            if not raw_arguments.get("url"):
                for alt in ("target", "endpoint", "uri"):
                    if raw_arguments.get(alt):
                        raw_arguments["url"] = raw_arguments[alt]
                        break

            # If still missing url for HTTP/probe tools, fallback to normalized_target
            if not raw_arguments.get("url") and tool_name in ("httpx_request", "http_request", "parameter_fuzzer", "zap_scanner", "inventory_scanner", "graphql_probe"):
                raw_arguments["url"] = normalized_target

            # Clean URL: strip leading HTTP method if model prefixed it (e.g. "GET http://...")
            url_str = str(raw_arguments.get("url") or "").strip()
            for prefix in ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "):
                if url_str.upper().startswith(prefix):
                    if not raw_arguments.get("method"):
                        raw_arguments["method"] = prefix.strip()
                    url_str = url_str[len(prefix):].strip()
                    raw_arguments["url"] = url_str
                    break

            # Resolve relative endpoints (e.g. "/api/search") against normalized target
            if url_str and not url_str.startswith(("http://", "https://")):
                if not url_str.startswith("/"):
                    url_str = "/" + url_str
                raw_arguments["url"] = normalized_target.rstrip("/") + url_str

            # Sync normalized arguments back to action_proposal
            action_proposal["arguments"] = raw_arguments

            # B. Deterministic Guardrail / Policy Validation
            target_url_arg = str(raw_arguments.get("url") or normalized_target)
            method_arg = str(raw_arguments.get("method") or "GET").upper()
            endpoint_key = f"{method_arg} {target_url_arg}"

            # Exact duplicate probe protection under identical security & auth context
            import hashlib, json as _json
            probe_sig = hashlib.sha256(
                f"{tool_name}:{method_arg}:{target_url_arg}:{_json.dumps(raw_arguments, sort_keys=True)}:{_json.dumps(safe_auth, sort_keys=True)}".encode()
            ).hexdigest()

            if probe_sig in state.probe_signatures:
                logger.info("Probe deduplication: %s %s already tested with identical parameters in this session", method_arg, target_url_arg)
                state.add_observation({
                    "turn": turn,
                    "tool_name": tool_name,
                    "target_endpoint": endpoint_key,
                    "status": "DEDUPLICATED",
                    "reason": f"Endpoint '{endpoint_key}' was already tested with identical parameters and authentication in this session.",
                })
                state.increment_turn()
                continue
            state.probe_signatures.add(probe_sig)

            if context_mgr.is_endpoint_exhausted(endpoint_key):
                from controller.guardrails.policy_engine import PolicyDecision
                decision = PolicyDecision(
                    approved=False,
                    reason=f"Endpoint '{endpoint_key}' has reached its per-endpoint testing limit ({self.config.max_probes_per_endpoint} probes). Re-probe rejected to preserve budget.",
                    tool_name=tool_name,
                )
            else:
                decision = self.policy.evaluate_action(
                    tool_name=tool_name,
                    arguments=raw_arguments,
                    current_request_count=state.request_count,
                    current_duration_seconds=(time.time() - assessment_start_time),
                    reserve_budget=False,
                    auth_context=safe_auth,
                    current_turn=turn,
                )

            self.events.emit(
                ControllerEventType.POLICY_DECISION,
                session_id=state.session_id,
                data={"turn": turn, "approved": decision.approved, "reason": decision.reason},
            )

            if not decision.approved:
                # Log policy denial
                self.store.log_tool_execution(
                    session_id=state.session_id,
                    tool_name=tool_name,
                    arguments=raw_arguments,
                    approved=False,
                    policy_reason=decision.reason,
                    result={"error": f"Policy rejection: {decision.reason}"},
                    duration_ms=0.0,
                )
                context_mgr.record_probe(
                    endpoint_key=endpoint_key,
                    tool_name=tool_name,
                    arguments=raw_arguments,
                    status_code=None,
                    success=False,
                    policy_denial=decision.reason,
                )

                # Feed policy feedback back to model memory
                state.add_observation({
                    "turn": turn,
                    "tool_name": tool_name,
                    "status": "POLICY_DENIED",
                    "reason": decision.reason,
                })
                state.increment_turn()
                continue

            # C. Tool Execution
            if effective_max_rps and effective_max_rps > 0:
                min_interval = 1.0 / effective_max_rps
                since_last = time.time() - last_request_time
                if since_last < min_interval:
                    time.sleep(min_interval - since_last)
                last_request_time = time.time()

            exec_start = time.time()
            sanitized_args = decision.sanitized_arguments or raw_arguments
            tool_result = self.tools.execute(tool_name, sanitized_args)
            duration_ms = round((time.time() - exec_start) * 1000, 2)

            self.events.emit(
                ControllerEventType.TOOL_EXECUTED,
                session_id=state.session_id,
                data={
                    "turn": turn,
                    "tool_name": tool_name,
                    "status_code": tool_result.get("status_code"),
                    "duration_ms": duration_ms,
                    "success": tool_result.get("success", False),
                },
            )

            # D. Store Execution Receipt and Traffic Logs
            self.store.log_tool_execution(
                session_id=state.session_id,
                tool_name=tool_name,
                arguments=sanitized_args,
                approved=True,
                policy_reason=decision.reason,
                result=tool_result,
                duration_ms=duration_ms,
            )

            traffic_id = None
            if tool_name in {"http_request", "httpx_request"}:
                state.increment_requests(1)
                traffic_id = self.store.log_traffic(
                    session_id=state.session_id,
                    method=sanitized_args.get("method", "GET"),
                    url=sanitized_args.get("url", normalized_target),
                    headers=sanitized_args.get("headers"),
                    request_body=sanitized_args.get("body"),
                    response_status=tool_result.get("status_code"),
                    response_headers=tool_result.get("headers"),
                    response_body=tool_result.get("body"),
                    elapsed_ms=tool_result.get("elapsed_ms"),
                )
            elif tool_name == "parameter_fuzzer":
                probes_count = tool_result.get("probes_executed", 1)
                state.increment_requests(probes_count)
                # Record parameter probe summary in traffic log
                import json as _json
                traffic_id = self.store.log_traffic(
                    session_id=state.session_id,
                    method=sanitized_args.get("method", "GET"),
                    url=sanitized_args.get("url", normalized_target),
                    headers=sanitized_args.get("headers"),
                    request_body=_json.dumps(sanitized_args.get("parameters") or sanitized_args.get("json_body") or {}),
                    response_status=tool_result.get("baseline_status"),
                    response_headers={},
                    response_body=_json.dumps(tool_result.get("results") or []),
                    elapsed_ms=sum(r.get("elapsed_ms") or 0.0 for r in tool_result.get("results", [])),
                )
            elif tool_name == "graphql_probe":
                probes_count = max(1, tool_result.get("tested_endpoints_count", 1))
                state.increment_requests(probes_count)
                import json as _json
                interactions = tool_result.get("traffic_interactions", [])
                if interactions:
                    for item in interactions:
                        traffic_id = self.store.log_traffic(
                            session_id=state.session_id,
                            method=item.get("method", "POST"),
                            url=item.get("url", normalized_target),
                            headers=item.get("headers"),
                            request_body=item.get("request_body"),
                            response_status=item.get("response_status"),
                            response_headers=item.get("response_headers"),
                            response_body=item.get("response_body"),
                            elapsed_ms=item.get("elapsed_ms"),
                        )
                else:
                    traffic_id = self.store.log_traffic(
                        session_id=state.session_id,
                        method="POST",
                        url=sanitized_args.get("target_url", normalized_target),
                        headers={"Content-Type": "application/json"},
                        request_body="query { __schema }",
                        response_status=tool_result.get("status_code", 200),
                        response_headers={},
                        response_body=_json.dumps(tool_result.get("introspection_results") or []),
                        elapsed_ms=tool_result.get("elapsed_ms", 10.0),
                    )
            elif tool_name == "inventory_scanner":
                interactions = tool_result.get("traffic_interactions", [])
                state.increment_requests(len(interactions) if interactions else 1)
                if interactions:
                    for item in interactions:
                        traffic_id = self.store.log_traffic(
                            session_id=state.session_id,
                            method=item.get("method", "GET"),
                            url=item.get("url", normalized_target),
                            headers=item.get("headers"),
                            request_body=item.get("request_body"),
                            response_status=item.get("response_status"),
                            response_headers=item.get("response_headers"),
                            response_body=item.get("response_body"),
                            elapsed_ms=item.get("elapsed_ms"),
                        )
            elif tool_name == "business_flow_probe":
                interactions = tool_result.get("traffic_interactions", [])
                state.increment_requests(len(interactions) if interactions else 1)
                if interactions:
                    for item in interactions:
                        traffic_id = self.store.log_traffic(
                            session_id=state.session_id,
                            method=item.get("method", "POST"),
                            url=item.get("url", normalized_target),
                            headers=item.get("headers"),
                            request_body=item.get("request_body"),
                            response_status=item.get("response_status"),
                            response_headers=item.get("response_headers"),
                            response_body=item.get("response_body"),
                            elapsed_ms=item.get("elapsed_ms"),
                        )
            elif tool_name == "zap_scanner":
                scan_action = sanitized_args.get("action", "unknown")
                scan_id = str(tool_result.get("scan_id") or "0")
                target = sanitized_args.get("url") or normalized_target
                alert_list = tool_result.get("alerts", [])
                self.store.record_zap_scan(
                    session_id=state.session_id,
                    scan_id=scan_id,
                    scan_type=scan_action,
                    target_url=target,
                    status="COMPLETED" if tool_result.get("success") else "FAILED",
                    alert_count=len(alert_list),
                    raw_alerts=alert_list,
                )
                # Correlate alerts into findings
                for alert in alert_list:
                    fid, fstatus, is_new = self.store.correlate_and_record_zap_finding(
                        session_id=state.session_id,
                        alert=alert,
                        zap_scan_id=scan_id,
                    )
                    if is_new:
                        state.add_finding({
                            "id": fid,
                            "endpoint": alert.get("url", target),
                            "category": alert.get("name") or alert.get("alert") or "ZAP Alert",
                            "status": fstatus,
                            "notes": alert.get("description", ""),
                            "verification_rule": "ZAP Automated Signature",
                        })

            # E. Model Analyzes Evidence
            analysis = self.brain.analyze_evidence(
                tool_name=tool_name,
                arguments=sanitized_args,
                tool_result=tool_result,
            )

            recorded_finding_dict = None
            status_prop = analysis.get("status", "NOT_DEMONSTRATED")
            if status_prop in {"SUSPECTED", "CONFIRMED"}:
                finding_endpoint = sanitized_args.get("url") or sanitized_args.get("target_url") or normalized_target
                finding_id, recorded_status = self.store.record_finding(
                    session_id=state.session_id,
                    endpoint=finding_endpoint,
                    category=analysis.get("category", "Security Finding"),
                    status=status_prop,
                    evidence_notes=analysis.get("analysis", ""),
                    verification_rule=analysis.get("verification_rule"),
                    traffic_log_id=traffic_id,
                    raw_evidence={"tool": tool_name, "result": tool_result},
                )
                recorded_finding_dict = {
                    "id": finding_id,
                    "endpoint": finding_endpoint,
                    "category": analysis.get("category"),
                    "status": recorded_status,
                    "notes": analysis.get("analysis"),
                    "verification_rule": analysis.get("verification_rule"),
                }
                state.add_finding(recorded_finding_dict)
                self.events.emit(
                    ControllerEventType.FINDING_RECORDED,
                    session_id=state.session_id,
                    data={"turn": turn, "finding": recorded_finding_dict},
                )

            # Record in context manager
            context_mgr.record_probe(
                endpoint_key=endpoint_key,
                tool_name=tool_name,
                arguments=sanitized_args,
                status_code=tool_result.get("status_code"),
                success=tool_result.get("success", False),
                finding=recorded_finding_dict,
                policy_denial=None,
            )

            # F. Record Observation & Advance Turn
            state.add_observation({
                "turn": turn,
                "tool_name": tool_name,
                "target_endpoint": endpoint_key,
                "arguments": sanitized_args,
                "result_status": tool_result.get("status_code"),
                "success": tool_result.get("success", False),
                "finding": recorded_finding_dict,
                "analysis": analysis,
            })
            state.increment_turn()

        # 7. Finalize Session in Database
        final_status = "COMPLETED" if state.is_finished else "TIMEOUT"
        self.store.update_session_status(
            session_id=state.session_id,
            status=final_status,
            turns_taken=state.current_turn - 1,
            requests_sent=state.request_count,
            notes=state.termination_reason or "Finished execution loop",
        )

        self.events.emit(
            ControllerEventType.PHASE_CHANGE,
            session_id=state.session_id,
            data={"phase": "REPORTING"},
        )

        # 8. Generate Report
        session_summary = {
            "session_id": state.session_id,
            "target": state.target,
            "turns_taken": state.current_turn - 1,
            "requests_sent": state.request_count,
            "termination_reason": state.termination_reason,
            "findings": state.findings,
            "observations_count": len(state.observations),
        }
        report_md = self.brain.generate_report(session_summary)

        self.events.emit(
            ControllerEventType.ASSESSMENT_COMPLETED,
            session_id=state.session_id,
            data={
                "turns_taken": state.current_turn - 1,
                "requests_sent": state.request_count,
                "findings_count": len(state.findings),
                "termination_reason": state.termination_reason,
            },
        )

        return {
            "success": True,
            "session_id": state.session_id,
            "target": state.target,
            "turns_taken": state.current_turn - 1,
            "requests_sent": state.request_count,
            "findings": state.findings,
            "report_markdown": report_md,
            "termination_reason": state.termination_reason,
        }

