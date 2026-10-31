"""Parameter Testing Tool for Autonomous API Penetration Testing.

Implements controlled, harmless parameter boundary testing against local APIs.
Uses a strictly bounded set of non-destructive boundary probes (e.g., empty string,
integer bounds, harmless character probes) to observe input validation responses.
Supports testing both query string parameters and JSON request body parameters.
Does NOT execute destructive payloads, OS commands, or unrestricted fuzzing.
"""

import copy
import json
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.tools.http_request import execute_http_request
from controller.tools.registry import BaseTool

# Predefined, strictly harmless test values for parameter boundary observation
HARMLESS_PROBES = [
    {"label": "empty_string", "value": ""},
    {"label": "null_literal", "value": "null"},
    {"label": "integer_zero", "value": "0"},
    {"label": "integer_negative", "value": "-1"},
    {"label": "integer_max32", "value": "2147483647"},
    {"label": "single_quote_test", "value": "'"},
    {"label": "double_quote_test", "value": '"'},
    {"label": "angle_bracket_test", "value": "<test>"},
    {"label": "safe_length_100", "value": "A" * 100},
]

# Prevent pytest from treating functions in this module as unit test cases
__test__ = False

# Common signatures indicating server error leaks or unhandled exceptions
ERROR_SIGNATURES = [
    ("sql_syntax_error", ["syntax error", "sqlite3.operationalerror", "ora-00933", "pg::syntaxerror", "mysql server version for the right syntax"]),
    ("stack_trace_leak", ["traceback (most recent call last)", "at org.apache.", "nullpointerexception", "stack trace:"]),
    ("path_disclosure", ["c:\\users\\", "/home/", "/var/www/", "/etc/passwd"]),
]


def _detect_error_signatures(body: str) -> List[str]:
    """Scan response body for unhandled error signatures or database error messages."""
    detected = []
    if not body:
        return detected
    lowered = body.lower()
    for label, patterns in ERROR_SIGNATURES:
        for p in patterns:
            if p in lowered:
                detected.append(f"{label}: found '{p}'")
                break
    return detected


def _check_reflection(probe_val: Any, body: str) -> bool:
    """Check if the probe value appears unescaped in the response body."""
    if not probe_val or not body or not isinstance(probe_val, str):
        return False
    return probe_val in body


def probe_api_parameters(
    url: str,
    method: str = "GET",
    parameters: Optional[Dict[str, Any]] = None,
    json_body: Optional[Dict[str, Any]] = None,
    headers: Optional[Dict[str, str]] = None,
    probes_to_run: Optional[List[str]] = None,
    config: Optional[AgentConfig] = None,
) -> Dict[str, Any]:
    """Execute bounded parameter boundary tests against an authorized local endpoint."""
    cfg = config or DEFAULT_CONFIG
    base_params = dict(parameters or {})
    method_upper = method.strip().upper()

    is_json_mode = json_body is not None and isinstance(json_body, dict)
    target_params = dict(json_body) if is_json_mode else base_params

    if not target_params:
        return {
            "success": False,
            "error": "No parameters or json_body fields specified for testing",
            "probes_executed": 0,
            "results": [],
            "sub_requests": [],
        }

    # Filter probes if specific labels requested, else use first 4 harmless probes
    selected_probes = []
    if probes_to_run:
        selected_probes = [p for p in HARMLESS_PROBES if p["label"] in probes_to_run]
    if not selected_probes:
        selected_probes = HARMLESS_PROBES[:4]

    results = []
    sub_requests = []
    baseline_status = None

    # Step 1: Execute baseline request
    baseline_headers = dict(headers or {})
    baseline_body = None
    baseline_params = None

    if is_json_mode:
        baseline_body = json.dumps(json_body)
        baseline_headers["Content-Type"] = "application/json"
    elif method_upper in {"POST", "PUT", "PATCH"}:
        baseline_body = urllib.parse.urlencode(base_params)
        baseline_headers["Content-Type"] = "application/x-www-form-urlencoded"
    else:
        baseline_params = base_params

    baseline_resp = execute_http_request(
        url=url,
        method=method_upper,
        headers=baseline_headers,
        params=baseline_params,
        body=baseline_body,
        config=cfg,
    )
    baseline_status = baseline_resp.get("status_code")
    sub_requests.append({
        "type": "baseline",
        "method": method_upper,
        "url": url,
        "status_code": baseline_status,
        "elapsed_ms": baseline_resp.get("elapsed_ms"),
    })

    # Step 2: Iterate over each parameter with selected harmless probes
    for param_name in target_params.keys():
        for probe in selected_probes:
            req_headers = dict(headers or {})
            probe_body = None
            probe_params = None

            if is_json_mode:
                test_body = copy.deepcopy(json_body)
                test_body[param_name] = probe["value"]
                probe_body = json.dumps(test_body)
                req_headers["Content-Type"] = "application/json"
            elif method_upper in {"POST", "PUT", "PATCH"}:
                test_params = dict(base_params)
                test_params[param_name] = probe["value"]
                probe_body = urllib.parse.urlencode(test_params)
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                test_params = dict(base_params)
                test_params[param_name] = probe["value"]
                probe_params = test_params

            probe_resp = execute_http_request(
                url=url,
                method=method_upper,
                headers=req_headers,
                params=probe_params,
                body=probe_body,
                config=cfg,
            )

            status = probe_resp.get("status_code")
            body_text = probe_resp.get("body") or ""
            body_sample = body_text[:200]

            sub_requests.append({
                "type": "probe",
                "parameter": param_name,
                "probe_label": probe["label"],
                "status_code": status,
                "elapsed_ms": probe_resp.get("elapsed_ms"),
            })

            # Security Anomaly Detection
            anomalies = []
            if baseline_status and status != baseline_status:
                anomalies.append(f"Status changed from baseline {baseline_status} to {status}")
            if status and status >= 500:
                anomalies.append(f"Server returned internal error {status}")

            error_sigs = _detect_error_signatures(body_text)
            if error_sigs:
                anomalies.extend(error_sigs)

            is_reflected = _check_reflection(probe["value"], body_text)
            if is_reflected and probe["label"] in {"single_quote_test", "double_quote_test", "angle_bracket_test"}:
                anomalies.append(f"Harmless probe '{probe['value']}' reflected unescaped in response")

            anomaly_detected = len(anomalies) > 0
            notes = "; ".join(anomalies) if anomalies else "Standard response matching baseline"

            results.append({
                "parameter": param_name,
                "probe_label": probe["label"],
                "probe_value": probe["value"],
                "status_code": status,
                "elapsed_ms": probe_resp.get("elapsed_ms"),
                "anomaly_detected": anomaly_detected,
                "anomalies": anomalies,
                "observation_notes": notes,
                "reflected": is_reflected,
                "response_sample": body_sample,
            })

    return {
        "success": True,
        "endpoint": url,
        "method": method_upper,
        "mode": "json" if is_json_mode else "query/form",
        "baseline_status": baseline_status,
        "probes_executed": len(results),
        "results": results,
        "sub_requests": sub_requests,
    }


class ParameterFuzzerTool(BaseTool):
    """Standard ParameterFuzzerTool implementing the BaseTool interface."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        super().__init__(
            name="parameter_fuzzer",
            description="Executes controlled, harmless boundary probes against local API parameters or JSON body fields to observe validation handling.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The localhost target API endpoint"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH"], "default": "GET"},
                    "parameters": {"type": "object", "description": "Optional dictionary of URL/form parameters to probe"},
                    "json_body": {"type": "object", "description": "Optional dictionary of JSON body fields to probe"},
                    "headers": {"type": "object", "description": "Optional HTTP request headers"},
                    "probes_to_run": {"type": "array", "items": {"type": "string"}, "description": "Optional list of probe labels to execute"},
                },
                "required": ["url"],
            },
            category="active_probe",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        return probe_api_parameters(config=self.config, **kwargs)
