"""Prompt templates for Qwen2.5-1.5B-Instruct API Security Model.

Formats structured inputs using Qwen's ChatML template format (<|im_start|>...<|im_end|>)
for request classification, autonomous test planning, action selection,
evidence analysis, and report generation.
"""

import json
from typing import Any, Dict, List, Optional


SYSTEM_PROMPT = """You are the core intelligence brain for an Autonomous API Security Testing Agent.
Your responsibility is to analyze API architectures, formulate structured testing plans, select appropriate testing tools, analyze HTTP and scanner evidence, and assess potential vulnerabilities.
Always respond with precise, valid JSON enclosed in ```json ... ``` code blocks.
Do not propose destructive attacks, arbitrary command execution, or out-of-scope targets.
Localhost testing only (127.0.0.1 / localhost).
When evidence or context is insufficient to draw conclusions, abstain safely by choosing 'no_action' or status 'NOT_DEMONSTRATED'."""


def format_qwen_chat(system_prompt: str, user_prompt: str) -> str:
    """Format prompt according to standard Qwen2.5 ChatML template."""
    return (
        f"<|im_start|>system\n{system_prompt}<|im_end|>\n"
        f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
        f"<|im_start|>assistant\n"
    )


def format_classification_prompt(request_dict: Dict[str, Any]) -> str:
    """Format request classification prompt matching RebuiltV4 fine-tuned scheme."""
    user_content = (
        "Classify the following HTTP request into exactly one of these 8 categories:\n"
        "Benign, SQL Injection, XSS, Directory Traversal, RCE, Cookie Injection, Log Forging, LOG4J.\n\n"
        f"HTTP Request:\n{json.dumps(request_dict, indent=2)}\n\n"
        "Return ONLY a JSON object formatted as:\n"
        "```json\n"
        "{\n"
        '  "category": "<Category>",\n'
        '  "confidence": 1.0,\n'
        '  "reasoning": "<explanation>"\n'
        "}\n"
        "```"
    )
    return format_qwen_chat(SYSTEM_PROMPT, user_content)


def _compact_tools_summary(tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format tools concisely to stay well within 1.5B token limits."""
    compact = []
    for t in tools:
        compact.append({
            "name": t.get("name"),
            "category": t.get("category", "active_probe"),
            "description": str(t.get("description", ""))[:100],
        })
    return compact


def _compact_endpoints_summary(endpoints: List[Dict[str, Any]], max_items: int = 15) -> List[Dict[str, Any]]:
    """Format endpoints concisely to prevent prompt explosion."""
    compact = []
    for ep in endpoints[:max_items]:
        compact.append({
            "method": str(ep.get("method") or "GET").upper(),
            "path": str(ep.get("path") or ep.get("url") or "/"),
            "summary": str(ep.get("summary") or "")[:80],
        })
    return compact


def format_test_planning_prompt(
    target_url: str,
    endpoints: List[Dict[str, Any]],
    available_tools: List[Dict[str, Any]],
    authorized_scope: Optional[List[str]] = None,
    auth_context: Optional[Any] = None,
    budget: Optional[Dict[str, Any]] = None,
    current_objective: Optional[str] = None,
) -> str:
    """Format test plan generation prompt with OpenAPI discovered routes."""
    scope_str = f"Authorized Scope Hosts: {', '.join(authorized_scope)}\n" if authorized_scope else ""
    auth_str = f"Authentication Context (masked): {json.dumps(auth_context)}\n" if auth_context else "Authentication Context: None provided (unauthenticated reconnaissance & public endpoints)\n"
    budget_str = f"Execution Budget: {json.dumps(budget)}\n" if budget else ""
    obj_str = f"Current Objective: {current_objective}\n" if current_objective else ""

    compact_eps = _compact_endpoints_summary(endpoints)
    compact_tls = _compact_tools_summary(available_tools)

    user_content = (
        f"Create an autonomous security test plan for target: {target_url}\n"
        f"{scope_str}{auth_str}{budget_str}{obj_str}\n"
        f"Discovered Endpoints:\n{json.dumps(compact_eps, indent=1)}\n\n"
        f"Available Registered Testing Tools:\n{json.dumps(compact_tls, indent=1)}\n\n"
        "Instructions:\n"
        "1. Plan structured, non-destructive API boundary probes for authentication, authorization, and input validation.\n"
        "2. Select appropriate tools from available registered tools (e.g., httpx_request, parameter_fuzzer, jwt_inspector, zap_scanner, graphql_probe, inventory_scanner, business_flow_probe).\n"
        "3. Keep parameter paths concrete.\n\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "```json\n"
        "{\n"
        '  "plan_title": "<Concise Plan Title>",\n'
        '  "steps": [\n'
        '    {"step_number": 1, "tool": "<tool_name>", "purpose": "<test rationale>", "parameters": { ... }}\n'
        "  ],\n"
        '  "rationale": "<Overall testing methodology>"\n'
        "}\n"
        "```"
    )
    return format_qwen_chat(SYSTEM_PROMPT, user_content)


def format_action_selection_prompt(
    current_turn: int,
    max_turns: int,
    plan_steps: List[Dict[str, Any]],
    recent_observations: List[Dict[str, Any]],
    available_tools: List[Dict[str, Any]],
    target_url: Optional[str] = None,
    authorized_scope: Optional[List[str]] = None,
    auth_context: Optional[Any] = None,
    budget: Optional[Dict[str, Any]] = None,
    current_objective: Optional[str] = None,
    discovered_endpoints: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Format action selection prompt for the agent's turn."""
    context_lines = [f"Execution Turn {current_turn} of {max_turns}."]
    if target_url:
        context_lines.append(f"Target: {target_url}")
    if authorized_scope:
        context_lines.append(f"Authorized Scope: {', '.join(authorized_scope)}")
    if auth_context:
        context_lines.append(f"Authentication Context (masked): {json.dumps(auth_context)}")
    if budget:
        context_lines.append(f"Remaining Budget: {json.dumps(budget)}")
    if current_objective:
        context_lines.append(f"Current Objective: {current_objective}")

    context_header = "\n".join(context_lines)

    compact_tls = _compact_tools_summary(available_tools)
    compact_obs = []
    for obs in recent_observations[-4:]:
        compact_obs.append({
            "turn": obs.get("turn"),
            "tool": obs.get("tool_name"),
            "target": obs.get("target_endpoint") or obs.get("arguments", {}).get("url"),
            "status": obs.get("status") or (f"HTTP {obs.get('status_code')}" if obs.get("status_code") else None),
            "finding": obs.get("finding", {}).get("category") if obs.get("finding") else None,
            "note": obs.get("reason") or obs.get("error"),
        })

    compact_plan = []
    for s in plan_steps[:6]:
        compact_plan.append({
            "step": s.get("step_number"),
            "tool": s.get("tool"),
            "endpoint": s.get("endpoint") or (s.get("parameters", {}).get("url") if isinstance(s.get("parameters"), dict) else None),
            "purpose": str(s.get("purpose", ""))[:80],
        })

    endpoints_str = ""
    if discovered_endpoints:
        compact_eps = _compact_endpoints_summary(discovered_endpoints[:10])
        endpoints_str = f"Discovered Target Endpoints:\n{json.dumps(compact_eps, indent=1)}\n\n"

    user_content = (
        f"{context_header}\n\n"
        f"{endpoints_str}"
        f"Active Test Plan Summary:\n{json.dumps(compact_plan, indent=1)}\n\n"
        f"Recent Observations & Evidence:\n{json.dumps(compact_obs, indent=1)}\n\n"
        f"Available Registered Tools:\n{json.dumps(compact_tls, indent=1)}\n\n"
        "Instructions:\n"
        "1. Propose the NEXT authorized action to perform, or signal completion if testing is done.\n"
        "2. Do NOT repeat an endpoint or payload that already returned 404 or DEDUPLICATED in Recent Observations. Pivot to the next discovered endpoint or attack vector.\n"
        "3. Ensure the 'url' argument is a clean URL (e.g., 'http://127.0.0.1:5050/api/search') without HTTP method prefixes like 'GET '.\n\n"
        "Return ONLY a JSON object with this exact structure:\n"
        "```json\n"
        "{\n"
        '  "action_type": "execute_tool" | "complete" | "no_action",\n'
        '  "tool_name": "<registered_tool_name or empty string>",\n'
        '  "arguments": { ... },\n'
        '  "reasoning": "<concise explanation of decision>"\n'
        "}\n"
        "```"
    )
    return format_qwen_chat(SYSTEM_PROMPT, user_content)


def _compact_tool_result(result: Dict[str, Any], max_body_chars: int = 1200) -> Dict[str, Any]:
    """Compact tool result to preserve key vulnerability indicators without blowing up context."""
    if not isinstance(result, dict):
        return {"raw": str(result)[:max_body_chars]}
    compact: Dict[str, Any] = {}
    for k, v in result.items():
        if k == "body" and isinstance(v, str):
            compact[k] = v[:max_body_chars] if len(v) > max_body_chars else v
        elif k in {"findings", "alerts", "introspection_results"} and isinstance(v, list):
            compact[k] = v[:5]
        elif isinstance(v, (str, int, float, bool)) or v is None:
            compact[k] = v
        else:
            compact[k] = str(v)[:300]
    return compact


def format_evidence_analysis_prompt(
    tool_name: str,
    arguments: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> str:
    """Format prompt for analyzing HTTPX and OWASP ZAP evidence."""
    compact_res = _compact_tool_result(tool_result)
    user_content = (
        f"Analyze the following tool execution evidence:\n"
        f"Tool Used: {tool_name}\n"
        f"Arguments: {json.dumps(arguments, indent=2)}\n"
        f"Result / Response Data: {json.dumps(compact_res, indent=2)}\n\n"
        "Evaluate whether this evidence proves or suggests a security vulnerability.\n"
        "Allowed Finding Statuses:\n"
        "- 'CONFIRMED': Conclusive server proof (e.g. database SQL syntax error, unauthorized private data disclosure).\n"
        "- 'SUSPECTED': Heuristic anomaly or automated scanner alert without full exploit proof.\n"
        "- 'NOT_DEMONSTRATED': Normal application behavior (e.g. standard 200 OK or 404 response).\n"
        "- 'UNTESTED': Insufficient evidence to evaluate.\n\n"
        "Return ONLY a JSON object with this structure:\n"
        "```json\n"
        "{\n"
        '  "status": "CONFIRMED" | "SUSPECTED" | "NOT_DEMONSTRATED" | "UNTESTED",\n'
        '  "category": "<Vulnerability Category, e.g. SQL Injection, BOLA / IDOR, Mass Assignment, Insecure Authentication>",\n'
        '  "analysis": "<detailed rationale citing concrete response body, status code, or header evidence>",\n'
        '  "verification_rule": "<Approved Rule ID or null>"\n'
        "}\n"
        "```"
    )
    return format_qwen_chat(SYSTEM_PROMPT, user_content)


def format_reporting_prompt(session_summary: Dict[str, Any]) -> str:
    """Format prompt for generating final assessment report."""
    user_content = (
        f"Generate a comprehensive API Security Assessment Report in GitHub-flavored Markdown based on this session audit data:\n"
        f"{json.dumps(session_summary, indent=2)}\n\n"
        "Include:\n"
        "1. Executive Summary and Scope Verification.\n"
        "2. Discovered Endpoints and Testing Methodology.\n"
        "3. Security Findings Table (ID, Endpoint, Category, Status, Verification Rule).\n"
        "4. Detailed Evidence Breakdown with Technical Analysis.\n"
        "5. Remediation Recommendations.\n"
    )
    return format_qwen_chat(SYSTEM_PROMPT, user_content)
