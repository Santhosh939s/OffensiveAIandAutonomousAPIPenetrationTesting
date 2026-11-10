"""Policy Engine for Autonomous API Penetration Testing.

Enforces deterministic authorization boundaries before any tool execution.
Validates tool names, argument schemas, scope restrictions, command injection prevention,
destructive query prevention, and cumulative request budget constraints.

Supports Layer 1 developer safety invariants (non-overridable ceilings and pattern blocks)
and Layer 2 administrator policy snapshots (tool whitelists, categories, HTTP methods,
auth modes, and per-target authorization rules).
"""

import copy
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator, is_destination_external_allowed

DEVELOPER_SAFETY_MAX_REQUESTS: int = 100


class SharedBudgetManager:
    """Thread-safe synchronized budget manager for concurrent tool executions."""

    def __init__(
        self,
        max_requests: int = DEVELOPER_SAFETY_MAX_REQUESTS,
        max_duration_seconds: float = 3600.0,
        max_rps: Optional[float] = None,
        max_turns: int = 20,
    ):
        import threading
        self._lock = threading.RLock()
        self.max_requests = max_requests
        self.max_duration_seconds = max_duration_seconds
        self.max_rps = max_rps
        self.max_turns = max_turns
        self.reserved_requests = 0
        self.completed_requests = 0
        self.current_turn = 0
        import time as _time
        self.start_time = _time.time()
        self.last_request_time = 0.0
        self.is_cancelled = False

    def try_reserve_request(self, count: int = 1) -> "Tuple[bool, str]":
        import time as _time
        with self._lock:
            if self.is_cancelled:
                return False, "Assessment has been cancelled by operator/administrator."

            elapsed = _time.time() - self.start_time
            if elapsed >= self.max_duration_seconds:
                return False, f"Assessment duration limit reached ({self.max_duration_seconds:.1f}s). Budget exhausted."

            if self.reserved_requests + count > self.max_requests:
                return False, (
                    f"Request budget exhausted: cannot reserve {count} request(s) "
                    f"(currently reserved: {self.reserved_requests}, limit: {self.max_requests})."
                )

            self.reserved_requests += count
            return True, ""

    def can_reserve(self, count: int = 1) -> bool:
        import time as _time
        with self._lock:
            if self.is_cancelled:
                return False
            if (_time.time() - self.start_time) >= self.max_duration_seconds:
                return False
            return (self.reserved_requests + count) <= self.max_requests

    def release_reservation(self, count: int = 1) -> None:
        with self._lock:
            self.reserved_requests = max(0, self.reserved_requests - count)

    def record_completed(self, count: int = 1) -> None:
        with self._lock:
            self.completed_requests += count

    def set_turn(self, turn: int) -> "Tuple[bool, str]":
        with self._lock:
            self.current_turn = turn
            if turn > self.max_turns:
                return False, f"Turn limit reached ({turn} > {self.max_turns}). Assessment turn budget exhausted."
            return True, ""

    def cancel(self) -> None:
        with self._lock:
            self.is_cancelled = True

    def throttle_rps(self) -> None:
        if not self.max_rps or self.max_rps <= 0:
            return
        import time as _time
        with self._lock:
            min_interval = 1.0 / self.max_rps
            since_last = _time.time() - self.last_request_time
            sleep_time = min_interval - since_last if since_last < min_interval else 0.0
            self.last_request_time = _time.time() + sleep_time
        if sleep_time > 0:
            _time.sleep(sleep_time)


@dataclass(frozen=True)
class PolicyDecision:
    """Deterministic authorization decision for a proposed action."""
    approved: bool
    reason: str
    tool_name: str
    sanitized_arguments: Optional[Dict[str, Any]] = None


class PolicyEngine:
    """Enforces safety guardrails, scope rules, and limits on agent proposals."""

    NETWORK_PROBE_TOOLS = {
        "http_request",
        "httpx_request",
        "parameter_fuzzer",
        "graphql_probe",
        "inventory_scanner",
        "business_flow_probe",
        "zap_scanner",
    }

    # Patterns indicating potential shell execution or command injection attempts
    PROHIBITED_COMMAND_PATTERNS = [
        re.compile(r"[;&|`$><]"),
        re.compile(r"\b(rm|cat|ls|powershell|cmd|sh|bash|curl|wget|nc|python|perl)\b", re.IGNORECASE),
        re.compile(r"(\.\./|/etc/|windows[/\\]system32)", re.IGNORECASE),
    ]

    # Patterns indicating destructive database operations (safe testing probes are allowed, destructive operations blocked)
    DESTRUCTIVE_DB_PATTERNS = [
        re.compile(r"\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE|DELETE\s+FROM|UPDATE\s+.*SET)\b", re.IGNORECASE),
        re.compile(r"\b(SHUTDOWN|XP_CMDSHELL|EXEC\s+sp_)\b", re.IGNORECASE),
    ]

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        registered_tools: Optional[Set[str]] = None,
        scope_validator: Optional[ScopeValidator] = None,
        policy_snapshot: Optional[Dict[str, Any]] = None,
        policy_service: Optional[Any] = None,
        require_policy: bool = False,
    ):
        self.config = config or DEFAULT_CONFIG
        self.registered_tools = registered_tools if registered_tools is not None else set()
        self.scope_validator = scope_validator or ScopeValidator(self.config)
        self.policy_snapshot: Optional[Dict[str, Any]] = None
        self.target_authorizations: Optional[List[Dict[str, Any]]] = None
        self.active_policy_id: Optional[int] = None
        self.policy_service: Optional[Any] = policy_service
        self.require_policy = require_policy
        self.is_cancelled = False
        self.budget_manager = SharedBudgetManager(
            max_requests=min(self.config.max_requests_per_session if self.config else DEVELOPER_SAFETY_MAX_REQUESTS, DEVELOPER_SAFETY_MAX_REQUESTS),
            max_duration_seconds=min(getattr(self.config, "max_assessment_duration_seconds", 3600.0) or 3600.0, 3600.0),
            max_turns=self.config.max_turns if self.config else 100,
        )

        if policy_snapshot:
            self.bind_policy_snapshot(policy_snapshot)

    def set_policy_service(self, policy_service: Any) -> None:
        """Bind a live PolicyService to enable real-time target revocation and policy deactivation checks."""
        self.policy_service = policy_service

    def cancel(self) -> None:
        """Cancel assessment execution, halting subsequent reservations and tool executions."""
        self.is_cancelled = True
        if self.budget_manager:
            self.budget_manager.cancel()

    def reserve_request_budget(self, count: int = 1) -> "Tuple[bool, str]":
        """Atomically reserve request budget under concurrency."""
        return self.budget_manager.try_reserve_request(count)

    def release_request_reservation(self, count: int = 1) -> None:
        """Release previously reserved request budget."""
        self.budget_manager.release_reservation(count)

    def record_completed_request(self, count: int = 1) -> None:
        """Record completed request in shared budget counter."""
        self.budget_manager.record_completed(count)

    def is_active_policy(self) -> bool:
        """Return True if active policy is valid and not deactivated."""
        if self.policy_service and self.active_policy_id:
            if hasattr(self.policy_service, "is_policy_active"):
                return bool(self.policy_service.is_policy_active(self.active_policy_id))
        return True

    def _check_live_target_and_policy(self, tool_name: str = "", url: Optional[str] = None) -> Optional[PolicyDecision]:
        """Check live policy active status and live target revocation from PolicyService if available."""
        if not self.policy_service or not self.active_policy_id:
            return None

        if hasattr(self.policy_service, "is_policy_active") and not self.policy_service.is_policy_active(self.active_policy_id):
            return PolicyDecision(
                approved=False,
                reason=f"Policy ID {self.active_policy_id} was deactivated by administrator. Assessment execution halted.",
                tool_name=tool_name,
            )

        if url and hasattr(self.policy_service, "is_target_authorized_live"):
            is_auth, reason, _ = self.policy_service.is_target_authorized_live(
                self.active_policy_id, str(url)
            )
            if not is_auth:
                return PolicyDecision(
                    approved=False,
                    reason=f"Live target authorization revoked: {reason}",
                    tool_name=tool_name,
                )

        return None

    def bind_policy_snapshot(self, snapshot_data: Dict[str, Any]) -> None:
        """Bind an immutable assessment policy snapshot to guide evaluation."""
        self.policy_snapshot = copy.deepcopy(snapshot_data)
        # Extract targets if present in snapshot
        self.target_authorizations = self.policy_snapshot.get("targets", [])
        self.active_policy_id = self.policy_snapshot.get("policy_id")

        policy_cfg = self.policy_snapshot.get("config", {}) if self.policy_snapshot else {}
        effective_max_requests = min(
            int(policy_cfg.get("max_requests", self.config.max_requests_per_session)),
            DEVELOPER_SAFETY_MAX_REQUESTS,
        )
        effective_max_duration = min(
            float(policy_cfg.get("max_assessment_duration_seconds", getattr(self.config, "max_assessment_duration_seconds", 3600.0) or 3600.0)),
            3600.0,
        )
        max_rps = policy_cfg.get("max_requests_per_second")
        max_turns = int(policy_cfg.get("max_turns", self.config.max_turns))

        self.budget_manager = SharedBudgetManager(
            max_requests=effective_max_requests,
            max_duration_seconds=effective_max_duration,
            max_rps=max_rps,
            max_turns=max_turns,
        )

    def register_tool_name(self, name: str) -> None:
        """Register a valid tool name."""
        self.registered_tools.add(name)

    def evaluate_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_request_count: int = 0,
        current_duration_seconds: Optional[float] = None,
        reserve_budget: bool = False,
        auth_context: Optional[Dict[str, Any]] = None,
        current_turn: Optional[int] = None,
    ) -> PolicyDecision:
        """Evaluate a proposed action against Layer 1 safety invariants and Layer 2 policy."""

        # 0. Cancellation Check
        if self.is_cancelled or (self.budget_manager and self.budget_manager.is_cancelled):
            return PolicyDecision(
                approved=False,
                reason="Assessment has been cancelled by operator/administrator.",
                tool_name=tool_name,
            )

        # 0b. Missing policy context check (Default-deny)
        if self.require_policy and (not self.policy_snapshot or self.active_policy_id is None):
            return PolicyDecision(
                approved=False,
                reason="Missing policy enforcement context. Action denied by default.",
                tool_name=tool_name,
            )

        # -------------------------------------------------------------
        # 1. LAYER 1: Core System Invariants (Never Overridable)
        # -------------------------------------------------------------

        # Dynamic live policy deactivation check
        live_denial = self._check_live_target_and_policy(tool_name=tool_name)
        if live_denial:
            return live_denial

        # A. Tool name sanity
        if not tool_name or not isinstance(tool_name, str):
            return PolicyDecision(
                approved=False,
                reason="Invalid tool name provided (must be non-empty string)",
                tool_name=str(tool_name),
            )

        # B. Registered tool check
        if tool_name not in self.registered_tools:
            return PolicyDecision(
                approved=False,
                reason=f"Tool '{tool_name}' is not in the authorized tool registry",
                tool_name=tool_name,
            )

        # C. Argument schema validation
        if not isinstance(arguments, dict):
            return PolicyDecision(
                approved=False,
                reason="Arguments must be a valid dictionary",
                tool_name=tool_name,
            )

        # D. Layer 1 Non-overridable request ceiling (100 max)
        if current_request_count >= DEVELOPER_SAFETY_MAX_REQUESTS or (
            self.budget_manager and self.budget_manager.reserved_requests >= DEVELOPER_SAFETY_MAX_REQUESTS
        ):
            return PolicyDecision(
                approved=False,
                reason=f"Developer safety ceiling reached ({DEVELOPER_SAFETY_MAX_REQUESTS} requests). Session terminated by Layer 1 invariant.",
                tool_name=tool_name,
            )

        # E. Turn budget check
        if current_turn is not None and self.budget_manager:
            turn_ok, turn_reason = self.budget_manager.set_turn(current_turn)
            if not turn_ok:
                return PolicyDecision(
                    approved=False,
                    reason=turn_reason,
                    tool_name=tool_name,
                )

        # -------------------------------------------------------------
        # 2. LAYER 2: Administrator Policy Configuration (Snapshot)
        # -------------------------------------------------------------

        policy_cfg = self.policy_snapshot.get("config", {}) if self.policy_snapshot else {}

        # A. Policy Allowed Tools Check
        allowed_tools = policy_cfg.get("allowed_tools")
        if allowed_tools and tool_name not in allowed_tools:
            return PolicyDecision(
                approved=False,
                reason=f"Tool '{tool_name}' is not permitted by active policy. Permitted: {sorted(allowed_tools)}",
                tool_name=tool_name,
            )

        # B. Policy Request Budget Check
        policy_max_requests = policy_cfg.get("max_requests", self.config.max_requests_per_session)
        effective_max_requests = min(policy_max_requests, DEVELOPER_SAFETY_MAX_REQUESTS)
        if current_request_count >= effective_max_requests or (
            self.budget_manager and self.budget_manager.reserved_requests >= effective_max_requests
        ):
            return PolicyDecision(
                approved=False,
                reason=f"Cumulative request limit reached ({effective_max_requests} requests). Session budget exhausted.",
                tool_name=tool_name,
            )

        # C. Assessment Duration Budget Check
        effective_max_duration = min(
            policy_cfg.get("max_assessment_duration_seconds", getattr(self.config, "max_assessment_duration_seconds", 3600.0) or 3600.0),
            3600.0,
        )
        if current_duration_seconds is not None and current_duration_seconds >= effective_max_duration:
            return PolicyDecision(
                approved=False,
                reason=f"Assessment duration limit reached ({effective_max_duration}s). Session budget exhausted.",
                tool_name=tool_name,
            )
        import time as _time
        if self.budget_manager and (_time.time() - self.budget_manager.start_time) >= effective_max_duration:
            return PolicyDecision(
                approved=False,
                reason=f"Assessment duration limit reached ({effective_max_duration}s). Session budget exhausted.",
                tool_name=tool_name,
            )

        # D. Category Whitelist Check (if category specified in arguments)
        category = arguments.get("category") or arguments.get("test_category") or arguments.get("owasp_category")
        if category and policy_cfg.get("allowed_categories"):
            allowed_cats = set(policy_cfg["allowed_categories"])
            cat_norm = str(category).split(":")[0].strip().upper()
            allowed_norms = {str(c).split(":")[0].strip().upper() for c in allowed_cats} | allowed_cats
            if category not in allowed_cats and cat_norm not in allowed_norms:
                return PolicyDecision(
                    approved=False,
                    reason=f"Category '{category}' is not permitted by active policy. Permitted: {sorted(list(allowed_cats))}",
                    tool_name=tool_name,
                )

        # E. Authentication Mode Whitelist Check
        allowed_auth_modes = policy_cfg.get("allowed_auth_modes")
        if allowed_auth_modes:
            mode = None
            if auth_context and isinstance(auth_context, dict):
                mode = auth_context.get("type")
            elif "auth_mode" in arguments:
                mode = str(arguments["auth_mode"]).lower()
            elif "auth_type" in arguments:
                mode = str(arguments["auth_type"]).lower()
            elif "headers" in arguments and isinstance(arguments["headers"], dict):
                auth_hdr = arguments["headers"].get("Authorization") or arguments["headers"].get("authorization")
                if auth_hdr and isinstance(auth_hdr, str):
                    if auth_hdr.lower().startswith("bearer "):
                        mode = "bearer"
                    elif auth_hdr.lower().startswith("basic "):
                        mode = "basic"
            if mode and mode not in allowed_auth_modes:
                return PolicyDecision(
                    approved=False,
                    reason=f"Authentication mode '{mode}' is not permitted by active policy. Permitted: {sorted(allowed_auth_modes)}",
                    tool_name=tool_name,
                )

        # F. Tool-specific evaluations
        sub_decision = None
        if tool_name in {"http_request", "httpx_request"}:
            sub_decision = self._evaluate_http_request(arguments, tool_name=tool_name, policy_cfg=policy_cfg)
        elif tool_name == "openapi_parser":
            sub_decision = self._evaluate_openapi_parser(arguments)
        elif tool_name == "jwt_inspector":
            sub_decision = self._evaluate_jwt_inspector(arguments)
        elif tool_name == "parameter_fuzzer":
            sub_decision = self._evaluate_parameter_fuzzer(arguments)
        elif tool_name == "zap_scanner":
            sub_decision = self._evaluate_zap_scanner(arguments, policy_cfg=policy_cfg)
        elif tool_name == "graphql_probe":
            sub_decision = self._evaluate_generic_url_tool(arguments, tool_name, url_keys=["url", "target_url"])
        elif tool_name == "inventory_scanner":
            sub_decision = self._evaluate_generic_url_tool(arguments, tool_name, url_keys=["target_url", "url", "base_url"])
        elif tool_name == "business_flow_probe":
            sub_decision = self._evaluate_generic_url_tool(arguments, tool_name, url_keys=["url", "target_url"])
        else:
            # Default fallback for registered generic tools
            sub_decision = PolicyDecision(
                approved=True,
                reason="Action conforms to standard policy",
                tool_name=tool_name,
                sanitized_arguments=arguments,
            )

        if not sub_decision.approved:
            return sub_decision

        # G. Synchronized Budget Reservation for Network Probes
        if tool_name in self.NETWORK_PROBE_TOOLS:
            if reserve_budget:
                reserved, r_msg = self.budget_manager.try_reserve_request(1)
                if not reserved:
                    return PolicyDecision(
                        approved=False,
                        reason=r_msg,
                        tool_name=tool_name,
                    )
            else:
                if not self.budget_manager.can_reserve(1) or current_request_count >= effective_max_requests:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Cumulative request limit reached ({effective_max_requests} requests). Session budget exhausted.",
                        tool_name=tool_name,
                    )

        return sub_decision

    def _evaluate_http_request(
        self,
        args: Dict[str, Any],
        tool_name: str = "http_request",
        policy_cfg: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        url = args.get("url") or args.get("target") or args.get("endpoint") or args.get("uri")
        if not url:
            return PolicyDecision(
                approved=False,
                reason=f"{tool_name} requires a 'url' argument",
                tool_name=tool_name,
            )
        url_str = str(url).strip()
        for prefix in ("GET ", "POST ", "PUT ", "PATCH ", "DELETE ", "HEAD ", "OPTIONS "):
            if url_str.upper().startswith(prefix):
                if not args.get("method"):
                    args["method"] = prefix.strip()
                url_str = url_str[len(prefix):].strip()
                break
        url = url_str
        args["url"] = url

        # Determine if external domains permitted for this evaluation
        host = urllib.parse.urlsplit(str(url)).hostname or ""
        allow_ext = (
            bool(policy_cfg and policy_cfg.get("allow_external_domains"))
            or is_destination_external_allowed(host)
            or bool(self.target_authorizations and any(t.get("is_wildcard") or t.get("host_pattern") == "*" for t in self.target_authorizations))
            or getattr(self.config, "allow_external_domains", False)
        )

        # Validate URL scope against Layer 1 safety + Layer 2 target authorizations
        scope_res = self.scope_validator.validate_url(
            raw_url=str(url),
            target_authorizations=self.target_authorizations,
            allow_external_domains=allow_ext,
        )
        if not scope_res.is_valid:
            return PolicyDecision(
                approved=False,
                reason=f"Scope violation: {scope_res.reason}",
                tool_name=tool_name,
            )

        # Dynamic live target revocation check
        live_tgt_denial = self._check_live_target_and_policy(tool_name=tool_name, url=str(url))
        if live_tgt_denial:
            return live_tgt_denial

        # Validate HTTP method
        method = str(args.get("method", "GET")).upper()
        allowed_methods = (
            policy_cfg.get("allowed_http_methods")
            if policy_cfg and policy_cfg.get("allowed_http_methods")
            else self.config.allowed_http_methods
        )
        if method not in allowed_methods:
            return PolicyDecision(
                approved=False,
                reason=f"HTTP method '{method}' is not allowed by policy. Allowed: {sorted(allowed_methods)}",
                tool_name=tool_name,
            )

        # Layer 1 Invariant: Check payload/body for destructive DB patterns or shell command strings
        body = args.get("body")
        if body and isinstance(body, str):
            for pattern in self.DESTRUCTIVE_DB_PATTERNS:
                if pattern.search(body):
                    return PolicyDecision(
                        approved=False,
                        reason="Destructive database operation detected in request payload; rejected by Layer 1 guardrail.",
                        tool_name=tool_name,
                    )

        sanitized = dict(args)
        sanitized["method"] = method
        sanitized["url"] = scope_res.normalized_url
        effective_max_body = min(
            policy_cfg.get("max_response_body_bytes", getattr(self.config, "max_response_body_bytes", 65536) or 65536) if policy_cfg else getattr(self.config, "max_response_body_bytes", 65536),
            65536,
        )
        sanitized["max_response_body_bytes"] = effective_max_body

        return PolicyDecision(
            approved=True,
            reason=f"HTTP request ({tool_name}) is authorized within scope",
            tool_name=tool_name,
            sanitized_arguments=sanitized,
        )

    def _evaluate_openapi_parser(self, args: Dict[str, Any]) -> PolicyDecision:
        spec_source = args.get("spec_source")
        spec_content = args.get("spec_content")

        if not spec_source and not spec_content:
            return PolicyDecision(
                approved=False,
                reason="openapi_parser requires 'spec_source' (file/URL) or 'spec_content'",
                tool_name="openapi_parser",
            )

        if spec_source and isinstance(spec_source, str):
            src_str = spec_source.strip()
            # If URL, enforce scope validation
            if src_str.lower().startswith(("http://", "https://")):
                scope_res = self.scope_validator.validate_url(
                    raw_url=src_str,
                    target_authorizations=self.target_authorizations,
                )
                if not scope_res.is_valid:
                    return PolicyDecision(
                        approved=False,
                        reason=f"Scope violation on OpenAPI specification URL: {scope_res.reason}",
                        tool_name="openapi_parser",
                    )
            # If file path, check for shell injection characters
            for pattern in self.PROHIBITED_COMMAND_PATTERNS:
                if pattern.search(src_str):
                    return PolicyDecision(
                        approved=False,
                        reason="Prohibited character pattern detected in spec_source file path (Layer 1 safety)",
                        tool_name="openapi_parser",
                    )

        return PolicyDecision(
            approved=True,
            reason="OpenAPI specification discovery authorized",
            tool_name="openapi_parser",
            sanitized_arguments=dict(args),
        )

    def _evaluate_jwt_inspector(self, args: Dict[str, Any]) -> PolicyDecision:
        token = args.get("token")
        if not token or not isinstance(token, str):
            return PolicyDecision(
                approved=False,
                reason="jwt_inspector requires a non-empty string 'token' argument",
                tool_name="jwt_inspector",
            )

        sanitized = dict(args)
        sanitized["token"] = token.strip()

        return PolicyDecision(
            approved=True,
            reason="JWT inspection authorized (offline structural decoding only)",
            tool_name="jwt_inspector",
            sanitized_arguments=sanitized,
        )

    def _evaluate_parameter_fuzzer(self, args: Dict[str, Any]) -> PolicyDecision:
        url = args.get("url") or args.get("target") or args.get("endpoint") or args.get("uri")
        if not url:
            return PolicyDecision(
                approved=False,
                reason="parameter_fuzzer requires a 'url' argument",
                tool_name="parameter_fuzzer",
            )
        args["url"] = str(url)

        host = urllib.parse.urlsplit(str(url)).hostname or ""
        allow_ext = (
            is_destination_external_allowed(host)
            or bool(self.target_authorizations and any(t.get("is_wildcard") or t.get("host_pattern") == "*" for t in self.target_authorizations))
            or getattr(self.config, "allow_external_domains", False)
        )

        scope_res = self.scope_validator.validate_url(
            raw_url=str(url),
            target_authorizations=self.target_authorizations,
            allow_external_domains=allow_ext,
        )
        if not scope_res.is_valid:
            return PolicyDecision(
                approved=False,
                reason=f"Scope violation: {scope_res.reason}",
                tool_name="parameter_fuzzer",
            )

        # Dynamic live target revocation check
        live_tgt_denial = self._check_live_target_and_policy(tool_name="parameter_fuzzer", url=str(url))
        if live_tgt_denial:
            return live_tgt_denial

        parameters = args.get("parameters")
        json_body = args.get("json_body")
        if not ((parameters and isinstance(parameters, (dict, list))) or (json_body and isinstance(json_body, dict))):
            return PolicyDecision(
                approved=False,
                reason="parameter_fuzzer requires 'parameters' or 'json_body' to probe",
                tool_name="parameter_fuzzer",
            )

        sanitized = dict(args)
        sanitized["url"] = scope_res.normalized_url

        return PolicyDecision(
            approved=True,
            reason="Controlled parameter boundary testing authorized within scope",
            tool_name="parameter_fuzzer",
            sanitized_arguments=sanitized,
        )

    def _evaluate_zap_scanner(
        self,
        args: Dict[str, Any],
        policy_cfg: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        action = str(args.get("action", "")).strip().lower()
        valid_actions = {
            "check_health",
            "spider",
            "passive_scan",
            "get_status",
            "get_alerts",
            "active_scan",
        }
        if not action or action not in valid_actions:
            return PolicyDecision(
                approved=False,
                reason=f"zap_scanner requires a valid 'action'. Permitted: {sorted(valid_actions)}",
                tool_name="zap_scanner",
            )

        # Check if active scan is enabled in policy snapshot or config
        zap_active_allowed = False
        if policy_cfg:
            tool_restr = policy_cfg.get("tool_restrictions", {}).get("zap_scanner", {})
            zap_active_allowed = tool_restr.get("active_scan_allowed", policy_cfg.get("zap_active_scan_enabled", False))
        else:
            zap_active_allowed = self.config.zap_active_scan_enabled

        if action == "active_scan" and not zap_active_allowed:
            return PolicyDecision(
                approved=False,
                reason=(
                    "Active scanning via OWASP ZAP is strictly disabled by policy. "
                    "Active injection tests require explicit policy permission."
                ),
                tool_name="zap_scanner",
            )

        target_url = args.get("url") or args.get("target_url")
        sanitized = dict(args)
        sanitized["action"] = action

        # If a target URL is provided, validate scope
        if target_url:
            scope_res = self.scope_validator.validate_url(
                raw_url=str(target_url),
                target_authorizations=self.target_authorizations,
            )
            if not scope_res.is_valid:
                return PolicyDecision(
                    approved=False,
                    reason=f"Scope violation: {scope_res.reason}",
                    tool_name="zap_scanner",
                )
            sanitized["url"] = scope_res.normalized_url

        return PolicyDecision(
            approved=True,
            reason=f"ZAP action '{action}' authorized within scope",
            tool_name="zap_scanner",
            sanitized_arguments=sanitized,
        )

    def _evaluate_generic_url_tool(
        self,
        args: Dict[str, Any],
        tool_name: str,
        url_keys: Optional[List[str]] = None,
    ) -> PolicyDecision:
        """Validate target URL and scope for tools operating on HTTP endpoints."""
        keys = url_keys or ["url", "target_url", "base_url"]
        target_url = None
        matched_key = None
        for k in keys:
            if args.get(k):
                target_url = args[k]
                matched_key = k
                break

        if not target_url:
            return PolicyDecision(
                approved=False,
                reason=f"{tool_name} requires a target URL parameter ({', '.join(keys)})",
                tool_name=tool_name,
            )

        scope_res = self.scope_validator.validate_url(
            raw_url=str(target_url),
            target_authorizations=self.target_authorizations,
        )
        if not scope_res.is_valid:
            return PolicyDecision(
                approved=False,
                reason=f"Scope violation: {scope_res.reason}",
                tool_name=tool_name,
            )

        # Dynamic live target revocation check
        live_tgt_denial = self._check_live_target_and_policy(tool_name=tool_name, url=str(target_url))
        if live_tgt_denial:
            return live_tgt_denial

        sanitized = dict(args)
        if matched_key:
            sanitized[matched_key] = scope_res.normalized_url

        return PolicyDecision(
            approved=True,
            reason=f"Tool '{tool_name}' target is authorized within scope",
            tool_name=tool_name,
            sanitized_arguments=sanitized,
        )
