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
    ):
        self.config = config or DEFAULT_CONFIG
        self.brain = model_brain or get_model_brain(mode="mock")
        self.tools = tool_registry or build_default_tool_registry()
        self.store = evidence_store or EvidenceStore(self.config.db_path)
        self.scope_validator = ScopeValidator(self.config)
        self.events = event_emitter or AgentEventEmitter()

        # Initialize policy engine with registered tool names
        self.policy = policy_engine or PolicyEngine(
            config=self.config,
            registered_tools=set(self.tools.list_tool_names()),
            scope_validator=self.scope_validator,
        )

    def run_assessment(
        self,
        target_url: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        spec_source: Optional[str] = None,
        session_notes: str = "",
        session_id: Optional[str] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Execute a complete autonomous API security assessment workflow."""

        # 1. Scope and target authorization check
        scope_res = self.scope_validator.validate_url(target_url)
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
        self.store.create_session(
            session_id=state.session_id,
            target=normalized_target,
            notes=session_notes or f"Autonomous assessment of {normalized_target}",
        )

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
        adaptive_selector = AdaptiveTestSelector(context_mgr)

        self.events.emit(
            ControllerEventType.PHASE_CHANGE,
            session_id=state.session_id,
            data={"phase": "PLANNING", "endpoints_count": len(endpoints_to_test)},
        )

        # 5. Model generates test plan
        available_tools_schema = self.tools.get_tool_descriptions()
        plan_data = self.brain.create_test_plan(
            target_url=normalized_target,
            endpoints=endpoints_to_test,
            available_tools=available_tools_schema,
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
        while state.can_continue(self.config.max_turns, self.config.max_requests_per_session):
            if cancel_check and cancel_check():
                logger.info("Session %s received cancellation signal. Aborting loop.", state.session_id)
                state.mark_completed("Cancelled by operator")
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
            action_proposal = self.brain.select_next_action(
                current_turn=turn,
                max_turns=self.config.max_turns,
                plan_steps=plan_steps,
                recent_observations=state.observations,
                available_tools=available_tools_schema,
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
            raw_arguments = action_proposal.get("arguments", {})

            # B. Deterministic Guardrail / Policy Validation
            target_url_arg = str(raw_arguments.get("url") or normalized_target)
            method_arg = str(raw_arguments.get("method") or "GET").upper()
            endpoint_key = f"{method_arg} {target_url_arg}"

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
                finding_id, recorded_status = self.store.record_finding(
                    session_id=state.session_id,
                    endpoint=sanitized_args.get("url", normalized_target),
                    category=analysis.get("category", "Security Finding"),
                    status=status_prop,
                    evidence_notes=analysis.get("analysis", ""),
                    verification_rule=analysis.get("verification_rule"),
                    traffic_log_id=traffic_id,
                    raw_evidence={"tool": tool_name, "result": tool_result},
                )
                recorded_finding_dict = {
                    "id": finding_id,
                    "endpoint": sanitized_args.get("url", normalized_target),
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
                "arguments": sanitized_args,
                "result_status": tool_result.get("status_code"),
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

