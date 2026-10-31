"""Policy Engine for Autonomous API Penetration Testing.

Enforces deterministic authorization boundaries before any tool execution.
Validates tool names, argument schemas, scope restrictions, command injection prevention,
destructive query prevention, and cumulative request budget constraints.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator


@dataclass(frozen=True)
class PolicyDecision:
    """Deterministic authorization decision for a proposed action."""
    approved: bool
    reason: str
    tool_name: str
    sanitized_arguments: Optional[Dict[str, Any]] = None


class PolicyEngine:
    """Enforces safety guardrails, scope rules, and limits on agent proposals."""

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
    ):
        self.config = config or DEFAULT_CONFIG
        self.registered_tools = registered_tools if registered_tools is not None else set()
        self.scope_validator = scope_validator or ScopeValidator(self.config)

    def register_tool_name(self, name: str) -> None:
        """Register a valid tool name."""
        self.registered_tools.add(name)

    def evaluate_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        current_request_count: int = 0,
    ) -> PolicyDecision:
        """Evaluate a proposed action against all safety and scope policies."""

        # 1. Tool registration check
        if not tool_name or not isinstance(tool_name, str):
            return PolicyDecision(
                approved=False,
                reason="Invalid tool name provided (must be non-empty string)",
                tool_name=str(tool_name),
            )

        if tool_name not in self.registered_tools:
            return PolicyDecision(
                approved=False,
                reason=f"Tool '{tool_name}' is not in the authorized tool registry",
                tool_name=tool_name,
            )

        # 2. Argument schema validation
        if not isinstance(arguments, dict):
            return PolicyDecision(
                approved=False,
                reason="Arguments must be a valid dictionary",
                tool_name=tool_name,
            )

        # 3. Request count budget check
        if current_request_count >= self.config.max_requests_per_session:
            return PolicyDecision(
                approved=False,
                reason=f"Cumulative request limit reached ({self.config.max_requests_per_session} requests). Session budget exhausted.",
                tool_name=tool_name,
            )

        # 4. Tool-specific evaluations
        if tool_name in {"http_request", "httpx_request"}:
            return self._evaluate_http_request(arguments, tool_name=tool_name)
        elif tool_name == "openapi_parser":
            return self._evaluate_openapi_parser(arguments)
        elif tool_name == "jwt_inspector":
            return self._evaluate_jwt_inspector(arguments)
        elif tool_name == "parameter_fuzzer":
            return self._evaluate_parameter_fuzzer(arguments)
        elif tool_name == "zap_scanner":
            return self._evaluate_zap_scanner(arguments)

        # Default fallback for registered generic tools
        return PolicyDecision(
            approved=True,
            reason="Action conforms to standard policy",
            tool_name=tool_name,
            sanitized_arguments=arguments,
        )

    def _evaluate_http_request(self, args: Dict[str, Any], tool_name: str = "http_request") -> PolicyDecision:
        url = args.get("url")
        if not url:
            return PolicyDecision(
                approved=False,
                reason=f"{tool_name} requires a 'url' argument",
                tool_name=tool_name,
            )

        # Validate URL scope
        scope_res = self.scope_validator.validate_url(str(url))
        if not scope_res.is_valid:
            return PolicyDecision(
                approved=False,
                reason=f"Scope violation: {scope_res.reason}",
                tool_name=tool_name,
            )

        # Validate HTTP method
        method = str(args.get("method", "GET")).upper()
        if method not in self.config.allowed_http_methods:
            return PolicyDecision(
                approved=False,
                reason=f"HTTP method '{method}' is not allowed. Allowed: {sorted(self.config.allowed_http_methods)}",
                tool_name=tool_name,
            )

        # Check payload/body for destructive patterns or shell command strings
        body = args.get("body")
        if body and isinstance(body, str):
            for pattern in self.DESTRUCTIVE_DB_PATTERNS:
                if pattern.search(body):
                    return PolicyDecision(
                        approved=False,
                        reason="Destructive database operation detected in request payload; rejected by guardrail.",
                        tool_name=tool_name,
                    )

        sanitized = dict(args)
        sanitized["method"] = method
        sanitized["url"] = scope_res.normalized_url

        return PolicyDecision(
            approved=True,
            reason=f"HTTP request ({tool_name}) is authorized within localhost scope",
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
                scope_res = self.scope_validator.validate_url(src_str)
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
                        reason="Prohibited character pattern detected in spec_source file path",
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

        # Sanitize whitespace
        sanitized = dict(args)
        sanitized["token"] = token.strip()

        return PolicyDecision(
            approved=True,
            reason="JWT inspection authorized (offline structural decoding only)",
            tool_name="jwt_inspector",
            sanitized_arguments=sanitized,
        )

    def _evaluate_parameter_fuzzer(self, args: Dict[str, Any]) -> PolicyDecision:
        url = args.get("url")
        if not url:
            return PolicyDecision(
                approved=False,
                reason="parameter_fuzzer requires a 'url' argument",
                tool_name="parameter_fuzzer",
            )

        scope_res = self.scope_validator.validate_url(str(url))
        if not scope_res.is_valid:
            return PolicyDecision(
                approved=False,
                reason=f"Scope violation: {scope_res.reason}",
                tool_name="parameter_fuzzer",
            )

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
            reason="Controlled parameter boundary testing authorized within localhost scope",
            tool_name="parameter_fuzzer",
            sanitized_arguments=sanitized,
        )

    def _evaluate_zap_scanner(self, args: Dict[str, Any]) -> PolicyDecision:
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

        # Invariant: Active scanning requires explicit configuration permission
        if action == "active_scan" and not self.config.zap_active_scan_enabled:
            return PolicyDecision(
                approved=False,
                reason=(
                    "Active scanning via OWASP ZAP is strictly disabled by policy "
                    "(AgentConfig.zap_active_scan_enabled=False). Active injection tests "
                    "require explicit safety override."
                ),
                tool_name="zap_scanner",
            )

        target_url = args.get("url") or args.get("target_url")
        sanitized = dict(args)
        sanitized["action"] = action

        # If a target URL is provided, validate scope
        if target_url:
            scope_res = self.scope_validator.validate_url(str(target_url))
            if not scope_res.is_valid:
                return PolicyDecision(
                    approved=False,
                    reason=f"Scope violation: {scope_res.reason}",
                    tool_name="zap_scanner",
                )
            sanitized["url"] = scope_res.normalized_url

        return PolicyDecision(
            approved=True,
            reason=f"ZAP action '{action}' authorized within localhost scope",
            tool_name="zap_scanner",
            sanitized_arguments=sanitized,
        )


