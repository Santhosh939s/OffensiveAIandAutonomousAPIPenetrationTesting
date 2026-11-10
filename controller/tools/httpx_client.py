"""HTTPX Adapter Tool for Autonomous API Penetration Testing.

Provides synchronous and controlled asynchronous HTTP communication using HTTPX.
Enforces connect and read timeouts, response body size capping, disabled redirects,
and strict localhost scope validation.
Captures comprehensive request/response evidence, timing metrics, and security headers.
"""

import asyncio
import json
import socket
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator, validate_destination_address, is_destination_external_allowed
from controller.tools.http_request import STANDARD_SECURITY_HEADERS, _analyze_security_headers
from controller.tools.registry import BaseTool

# Install socket-level Layer 1 safety invariant and DNS rebinding hook for HTTPX / httpcore
_orig_socket_create_connection = socket.create_connection

def _secure_socket_create_connection(address, *args, **kwargs):
    host, port = address
    is_ext = is_destination_external_allowed(host)
    ok, reason = validate_destination_address(host, port, allow_external=is_ext, allow_private=is_ext)
    if not ok:
        raise ConnectionError(
            f"Layer 1 Safety Violation: Connection to prohibited destination '{host}' ({host}:{port}) blocked: {reason}"
        )
    return _orig_socket_create_connection(address, *args, **kwargs)

socket.create_connection = _secure_socket_create_connection


class SecureHttpxTransport(httpx.HTTPTransport):
    """Secure HTTPX transport validating destination IP boundaries immediately prior to dispatch."""

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        is_ext = is_destination_external_allowed(host)
        ok, reason = validate_destination_address(host, port, allow_external=is_ext, allow_private=is_ext)
        if not ok:
            raise httpx.ConnectError(f"Layer 1 Safety Violation: Connection to '{host}' ({host}:{port}) blocked: {reason}")
        return super().handle_request(request)


class SecureAsyncHttpxTransport(httpx.AsyncHTTPTransport):
    """Secure async HTTPX transport validating destination IP boundaries immediately prior to dispatch."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        is_ext = is_destination_external_allowed(host)
        ok, reason = validate_destination_address(host, port, allow_external=is_ext, allow_private=is_ext)
        if not ok:
            raise httpx.ConnectError(f"Layer 1 Safety Violation: Connection to '{host}' ({host}:{port}) blocked: {reason}")
        return await super().handle_async_request(request)


_local_httpx = threading.local()


def _get_thread_local_httpx_client(cfg: AgentConfig) -> httpx.Client:
    """Retrieve or create a thread-local persistent connection-pooled httpx.Client."""
    client = getattr(_local_httpx, "client", None)
    cached_timeout = getattr(_local_httpx, "read_timeout", None)
    if client is None or client.is_closed or cached_timeout != cfg.http_read_timeout:
        if client and not client.is_closed:
            try:
                client.close()
            except Exception:
                pass
        timeout_config = httpx.Timeout(
            timeout=cfg.http_read_timeout,
            connect=cfg.http_connect_timeout,
            read=cfg.http_read_timeout,
            write=cfg.http_read_timeout,
            pool=cfg.http_connect_timeout,
        )
        limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=40,
            keepalive_expiry=30.0,
        )
        transport = SecureHttpxTransport(
            limits=limits,
            retries=0,
        )
        client = httpx.Client(
            timeout=timeout_config,
            limits=limits,
            transport=transport,
            follow_redirects=False,
        )
        _local_httpx.client = client
        _local_httpx.read_timeout = cfg.http_read_timeout
    return client


def execute_httpx_request(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    body: Optional[Union[str, bytes, Dict[str, Any]]] = None,
    params: Optional[Dict[str, Any]] = None,
    config: Optional[AgentConfig] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Execute a single bounded HTTP request using HTTPX against an authorized target."""
    cfg = config or DEFAULT_CONFIG
    method_upper = method.strip().upper()

    # Pre-dispatch Layer 1 safety & Scope validation
    host = urllib.parse.urlsplit(url).hostname or ""
    is_ext = is_destination_external_allowed(host) or getattr(cfg, "allow_external_domains", False)
    scope_val = ScopeValidator(cfg)
    scope_res = scope_val.validate_url(url, allow_external_domains=is_ext)
    if not scope_res.is_valid:
        return {
            "success": False,
            "error": f"Scope violation: {scope_res.reason}",
            "status_code": None,
            "url": url,
            "method": method_upper,
            "policy_denied": True,
            "client": "httpx",
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
                    "client": "httpx",
                }

    if method_upper not in cfg.allowed_http_methods:
        return {
            "success": False,
            "error": f"Method '{method_upper}' not permitted. Allowed: {sorted(cfg.allowed_http_methods)}",
            "status_code": None,
            "url": url,
            "method": method_upper,
        }

    req_headers = dict(headers or {})
    if "User-Agent" not in req_headers:
        req_headers["User-Agent"] = "AutonomousAPISecurityAgent/HTTPX-1.0"

    # Prepare body payload
    data_payload = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data_payload = json.dumps(body)
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/json"
        elif isinstance(body, (str, bytes)):
            data_payload = body

    request_metadata = {
        "method": method_upper,
        "url": url,
        "headers": req_headers,
        "params": params or {},
        "body_length": len(data_payload) if data_payload else 0,
        "client": "httpx",
    }

    timeout_config = httpx.Timeout(
        timeout=cfg.http_read_timeout,
        connect=cfg.http_connect_timeout,
        read=cfg.http_read_timeout,
        write=cfg.http_read_timeout,
        pool=cfg.http_connect_timeout,
    )

    start_time = time.time()
    client = _get_thread_local_httpx_client(cfg)
    try:
        # Clear cookies to ensure strict request isolation
        client.cookies.clear()
        response = client.request(
            method=method_upper,
            url=url,
            headers=req_headers,
            content=data_payload,
            params=params,
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        # Enforce body size limit
        raw_bytes = response.content
        bytes_received = len(raw_bytes)
        effective_max_body = min(int(kwargs.get("max_response_body_bytes", cfg.max_response_body_bytes)), 65536)
        truncated = False
        if bytes_received > effective_max_body:
            raw_bytes = raw_bytes[: effective_max_body]
            truncated = True

        try:
            body_text = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_text = str(raw_bytes)

        resp_headers = dict(response.headers)
        content_type = resp_headers.get("content-type", "")

        # Attempt JSON parse
        json_body = None
        if "application/json" in content_type.lower() and body_text:
            try:
                json_body = json.loads(body_text)
            except Exception:
                json_body = None

        security_headers_eval = _analyze_security_headers(resp_headers)

        # Check redirect target scope if redirect returned
        redirect_url = resp_headers.get("location") or resp_headers.get("Location")
        redirect_in_scope = None
        if redirect_url:
            scope_val = ScopeValidator(cfg)
            try:
                resolved_redirect = str(response.url.join(redirect_url))
                redirect_in_scope = scope_val.validate_url(resolved_redirect).is_valid
            except Exception:
                redirect_in_scope = False

        # Clean cookies to preserve strict isolation
        client.cookies.clear()

        return {
            "success": True,
            "status_code": response.status_code,
            "status_reason": response.reason_phrase,
            "elapsed_ms": elapsed_ms,
            "url": str(response.url),
            "method": method_upper,
            "request_metadata": request_metadata,
            "headers": resp_headers,
            "content_type": content_type,
            "body": body_text,
            "json_body": json_body,
            "security_headers": security_headers_eval,
            "bytes_received": bytes_received,
            "truncated": truncated,
            "redirect_url": redirect_url,
            "redirect_in_scope": redirect_in_scope,
            "error": None,
            "client": "httpx",
        }

    except httpx.TimeoutException as exc:
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
            "error": f"HTTPX request timed out: {exc}",
            "client": "httpx",
        }
    except httpx.ConnectError as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "status_reason": "ConnectionError",
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
            "error": f"HTTPX connection error: {exc}",
            "client": "httpx",
        }
    except httpx.RequestError as exc:
        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": False,
            "status_code": None,
            "status_reason": "RequestError",
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
            "error": f"HTTPX request failed: {exc}",
            "client": "httpx",
        }


async def _probe_single_async(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    cfg: Optional[AgentConfig] = None,
) -> Dict[str, Any]:
    """Execute a single async probe bounded by a semaphore."""
    agent_cfg = cfg or DEFAULT_CONFIG
    async with semaphore:
        start_time = time.time()
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers or {},
            )
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            raw = resp.content
            truncated = len(raw) > agent_cfg.max_response_body_bytes
            body_text = raw[: agent_cfg.max_response_body_bytes].decode("utf-8", errors="replace")

            return {
                "success": True,
                "url": str(resp.url),
                "method": method,
                "status_code": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "body": body_text,
                "truncated": truncated,
                "error": None,
            }
        except Exception as exc:
            elapsed_ms = round((time.time() - start_time) * 1000, 2)
            return {
                "success": False,
                "url": url,
                "method": method,
                "status_code": None,
                "elapsed_ms": elapsed_ms,
                "body": None,
                "truncated": False,
                "error": str(exc),
            }


async def _run_batch_probes_async(
    endpoints_to_probe: List[Dict[str, Any]],
    base_url: str,
    concurrency_limit: int = 3,
    config: Optional[AgentConfig] = None,
) -> List[Dict[str, Any]]:
    """Internal runner executing concurrent probes with bounded concurrency."""
    cfg = config or DEFAULT_CONFIG
    scope_val = ScopeValidator(cfg)
    semaphore = asyncio.Semaphore(min(max(1, concurrency_limit), 5))  # Hard ceiling at 5

    timeout_config = httpx.Timeout(
        timeout=cfg.http_read_timeout,
        connect=cfg.http_connect_timeout,
        read=cfg.http_read_timeout,
        write=cfg.http_read_timeout,
        pool=cfg.http_connect_timeout,
    )

    transport = SecureAsyncHttpxTransport()
    async with httpx.AsyncClient(timeout=timeout_config, transport=transport, follow_redirects=False) as client:
        tasks = []
        for item in endpoints_to_probe:
            path = item.get("path", "")
            method = item.get("method", "GET").upper()
            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"

            # Strict scope check on every URL in batch
            scope_res = scope_val.validate_url(full_url)
            if not scope_res.is_valid:
                # Add rejected result immediately without network dispatch
                tasks.append(asyncio.sleep(0, result={
                    "success": False,
                    "url": full_url,
                    "method": method,
                    "status_code": None,
                    "elapsed_ms": 0.0,
                    "error": f"Scope violation: {scope_res.reason}",
                }))
                continue

            tasks.append(_probe_single_async(
                client=client,
                semaphore=semaphore,
                url=full_url,
                method=method,
                headers=item.get("headers"),
                cfg=cfg,
            ))

        return await asyncio.gather(*tasks)


def probe_multiple_endpoints_httpx(
    endpoints_to_probe: List[Dict[str, Any]],
    base_url: str,
    concurrency_limit: int = 3,
    config: Optional[AgentConfig] = None,
) -> Dict[str, Any]:
    """Execute controlled asynchronous reconnaissance against a list of in-scope endpoints.
    
    Applies strict concurrency limits (default 3, max 5) and validates scope
    for each endpoint prior to dispatch.
    """
    cfg = config or DEFAULT_CONFIG
    start_time = time.time()

    # Run event loop safely across sync/async callers
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # In an already running loop (e.g. jupyter), run in thread or separate loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                results = pool.submit(
                    asyncio.run,
                    _run_batch_probes_async(endpoints_to_probe, base_url, concurrency_limit, cfg)
                ).result()
        else:
            results = loop.run_until_complete(
                _run_batch_probes_async(endpoints_to_probe, base_url, concurrency_limit, cfg)
            )
    except RuntimeError:
        results = asyncio.run(
            _run_batch_probes_async(endpoints_to_probe, base_url, concurrency_limit, cfg)
        )

    total_elapsed_ms = round((time.time() - start_time) * 1000, 2)
    successful_count = sum(1 for r in results if r.get("success"))

    return {
        "success": True,
        "base_url": base_url,
        "total_probed": len(results),
        "successful_count": successful_count,
        "concurrency_limit": concurrency_limit,
        "total_elapsed_ms": total_elapsed_ms,
        "results": results,
    }


class HttpxRequestTool(BaseTool):
    """Standard HttpxRequestTool implementing the BaseTool interface."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        super().__init__(
            name="httpx_request",
            description="Executes a high-performance HTTP request (GET/POST/PUT/PATCH/DELETE) using HTTPX against an authorized localhost target.",
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
        return execute_httpx_request(config=self.config, **clean_kwargs)
