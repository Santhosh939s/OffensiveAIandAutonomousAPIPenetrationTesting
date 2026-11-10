"""HTTP Request Tool for Autonomous API Penetration Testing.

Executes bounded, deterministic HTTP requests against local authorized targets.
Enforces connect and read timeouts, response size capping, and disabled redirects.
Captures comprehensive request/response evidence and security header analysis.
"""

import json
import socket
import threading
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests
import requests.adapters
import urllib3.util.connection as urllib3_conn

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.tools.registry import BaseTool
from controller.guardrails.scope_validator import ScopeValidator, canonicalize_ip_str, validate_destination_address, is_destination_external_allowed

# Install socket-level Layer 1 safety invariant and DNS rebinding prevention hook
_orig_create_connection = urllib3_conn.create_connection

def _secure_create_connection(address, *args, **kwargs):
    host, port = address
    is_ext = is_destination_external_allowed(host)
    ok, reason = validate_destination_address(host, port, allow_external=is_ext, allow_private=is_ext)
    if not ok:
        raise requests.exceptions.ConnectionError(
            f"Layer 1 Safety Violation: Connection to prohibited destination '{host}' ({host}:{port}) blocked: {reason}"
        )
    return _orig_create_connection(address, *args, **kwargs)

urllib3_conn.create_connection = _secure_create_connection

_local_sessions = threading.local()


def _get_thread_local_session(cfg: AgentConfig) -> requests.Session:
    """Retrieve or create a thread-local persistent connection-pooled requests.Session."""
    session = getattr(_local_sessions, "session", None)
    if session is None:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
            max_retries=1,
            pool_block=False,
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _local_sessions.session = session
    return session


STANDARD_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
]


def _analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Inspect presence and values of common security headers."""
    lowered = {k.lower(): v for k, v in headers.items()}
    present = {}
    missing = []
    for h in STANDARD_SECURITY_HEADERS:
        if h in lowered:
            present[h] = lowered[h]
        else:
            missing.append(h)
    return {
        "present": present,
        "missing": missing,
        "has_content_type_options": "x-content-type-options" in lowered,
        "has_csp": "content-security-policy" in lowered,
        "has_cors_wildcard": lowered.get("access-control-allow-origin") == "*",
    }


def execute_http_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    config: Optional[AgentConfig] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute a single bounded HTTP request against an authorized target."""
    cfg = config or DEFAULT_CONFIG
    method_upper = method.strip().upper()

    if method_upper not in cfg.allowed_http_methods:
        return {
            "success": False,
            "error": f"Method '{method_upper}' not permitted. Allowed: {sorted(cfg.allowed_http_methods)}",
            "status_code": None,
            "url": url,
            "method": method_upper,
        }

    # Layer 1 safety invariant: Block destructive SQL operations in request body
    if body and isinstance(body, str):
        from controller.guardrails.policy_engine import PolicyEngine
        for pattern in PolicyEngine.DESTRUCTIVE_DB_PATTERNS:
            if pattern.search(body):
                return {
                    "success": False,
                    "error": "Destructive database operation detected in request payload; rejected by Layer 1 guardrail.",
                    "status_code": None,
                    "url": url,
                    "method": method_upper,
                    "policy_denied": True,
                }

    req_headers = dict(headers or {})
    if "User-Agent" not in req_headers:
        req_headers["User-Agent"] = "AutonomousAPISecurityAgent/1.0"

    # Normalize body data
    data_payload = None
    if body is not None:
        if isinstance(body, (str, bytes)):
            data_payload = body
        elif isinstance(body, (dict, list)):
            data_payload = json.dumps(body)
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"

    request_metadata = {
        "method": method_upper,
        "url": url,
        "headers": req_headers,
        "params": params or {},
        "body_length": len(data_payload) if data_payload else 0,
    }

    start_time = time.time()
    session = _get_thread_local_session(cfg)
    try:
        session.cookies.clear()
        response = session.request(
            method=method_upper,
            url=url,
            headers=req_headers,
            data=data_payload,
            params=params,
            timeout=cfg.http_timeout,
            allow_redirects=False,
            stream=True,
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # Read up to max_response_body_bytes + 1 to detect truncation safely
        content_chunks = []
        bytes_read = 0
        truncated = False

        effective_max_body = min(int(kwargs.get("max_response_body_bytes", cfg.max_response_body_bytes)), 65536)
        for chunk in response.iter_content(chunk_size=4096):
            if chunk:
                bytes_read += len(chunk)
                if bytes_read > effective_max_body:
                    excess = bytes_read - effective_max_body
                    keep_len = len(chunk) - excess
                    if keep_len > 0:
                        content_chunks.append(chunk[:keep_len])
                    truncated = True
                    break
                content_chunks.append(chunk)

        raw_bytes = b"".join(content_chunks)
        try:
            body_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_text = str(raw_bytes)

        resp_headers = dict(response.headers)
        content_type = resp_headers.get("Content-Type", "")

        # Attempt to parse json body if applicable
        json_body = None
        if "application/json" in content_type.lower() and body_text:
            try:
                json_body = json.loads(body_text)
            except Exception:
                json_body = None

        security_headers_eval = _analyze_security_headers(resp_headers)

        # Check redirect target scope if redirect returned
        redirect_url = resp_headers.get("Location") or resp_headers.get("location")
        redirect_in_scope = None
        if redirect_url:
            from controller.guardrails.scope_validator import ScopeValidator
            resolved_redirect = urllib.parse.urljoin(url, redirect_url)
            scope_val = ScopeValidator(cfg)
            redirect_in_scope = scope_val.validate_url(resolved_redirect).is_valid

        # Clean session cookies to maintain strict request isolation
        session.cookies.clear()

        return {
            "success": True,
            "status_code": response.status_code,
            "status_reason": response.reason,
            "elapsed_ms": elapsed_ms,
            "url": response.url,
            "method": method_upper,
            "request_metadata": request_metadata,
            "headers": resp_headers,
            "content_type": content_type,
            "body": body_text,
            "json_body": json_body,
            "security_headers": security_headers_eval,
            "bytes_received": bytes_read,
            "truncated": truncated,
            "redirect_url": redirect_url,
            "redirect_in_scope": redirect_in_scope,
            "error": None,
        }

    except requests.exceptions.Timeout as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "status_reason": "Timeout",
            "elapsed_ms": elapsed_ms,
            "url": url,
            "method": method_upper,
            "request_metadata": request_metadata,
            "headers": {},
            "content_type": None,
            "body": None,
            "json_body": None,
            "security_headers": None,
            "bytes_received": 0,
            "truncated": False,
            "error": f"Request timed out: {exc}",
        }
    except requests.exceptions.RequestException as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "status_reason": "NetworkError",
            "elapsed_ms": elapsed_ms,
            "url": url,
            "method": method_upper,
            "request_metadata": request_metadata,
            "headers": {},
            "content_type": None,
            "body": None,
            "json_body": None,
            "security_headers": None,
            "bytes_received": 0,
            "truncated": False,
            "error": f"Network error: {exc}",
        }


class HttpRequestTool(BaseTool):
    """Standard HttpRequestTool implementing the BaseTool interface."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        super().__init__(
            name="http_request",
            description="Executes a bounded, safe HTTP request (GET/POST/PUT/PATCH/DELETE) against an authorized localhost target.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The localhost target URL"},
                    "method": {
                        "type": "string",
                        "enum": list(self.config.allowed_http_methods),
                        "default": "GET",
                    },
                    "headers": {"type": "object", "description": "Optional HTTP request headers"},
                    "body": {"type": "string", "description": "Optional request body string or JSON"},
                    "params": {"type": "object", "description": "Optional URL query parameters"},
                },
                "required": ["url"],
            },
            category="active_probe",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        policy_ok, pol_err, clean_kwargs = self._check_execution_policy(kwargs)
        if not policy_ok:
            return {
                "success": False,
                "error": pol_err,
                "tool_name": self.name,
                "policy_denied": True,
            }
        return execute_http_request(config=self.config, **clean_kwargs)
