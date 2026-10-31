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


def format_test_planning_prompt(
    target_url: str,
    endpoints: List[Dict[str, Any]],
    available_tools: List[Dict[str, Any]],
) -> str:
    """Format test plan generation prompt with OpenAPI discovered routes."""
    user_content = (
        f"Create an autonomous security test plan for target: {target_url}\n"
        f"Discovered Endpoints (OpenAPI / Reconnaissance):\n{json.dumps(endpoints, indent=2)}\n\n"
        f"Available Registered Testing Tools:\n{json.dumps(available_tools, indent=2)}\n\n"
        "Instructions:\n"
        "1. Plan structured, non-destructive API boundary probes for authentication, authorization, and input validation.\n"
        "2. Select appropriate tools from available registered tools (e.g., httpx_request, parameter_fuzzer, jwt_inspector, zap_scanner).\n"
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
) -> str:
    """Format action selection prompt for the agent's turn."""
    user_content = (
        f"Execution Turn {current_turn} of {max_turns}.\n\n"
        f"Active Test Plan:\n{json.dumps(plan_steps, indent=2)}\n\n"
        f"Recent Observations & Evidence:\n{json.dumps(recent_observations[-4:], indent=2)}\n\n"
        f"Available Registered Tools:\n{json.dumps(available_tools, indent=2)}\n\n"
        "Propose the NEXT authorized action to perform, or signal completion if testing is done.\n"
        "If you do not have sufficient context, or if the target is out of scope, select action_type 'no_action'.\n\n"
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


def format_evidence_analysis_prompt(
    tool_name: str,
    arguments: Dict[str, Any],
    tool_result: Dict[str, Any],
) -> str:
    """Format prompt for analyzing HTTPX and OWASP ZAP evidence."""
    user_content = (
        f"Analyze the following tool execution evidence:\n"
        f"Tool Used: {tool_name}\n"
        f"Arguments: {json.dumps(arguments, indent=2)}\n"
        f"Result / Response Data: {json.dumps(tool_result, indent=2)[:3000]}\n\n"
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
