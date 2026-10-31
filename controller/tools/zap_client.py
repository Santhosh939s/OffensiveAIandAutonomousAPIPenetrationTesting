"""OWASP ZAP Integration Tool for Autonomous API Penetration Testing.

Integrates a locally running OWASP ZAP daemon through its standard REST API.
Enforces strict localhost scope validation, connectivity checks, API key masking,
controlled spidering, passive scan record inspection, and safe active scanning gates.

Safety Invariants:
1. Local daemon only: ZAP must be hosted on 127.0.0.1 / localhost.
2. Scope constraint: Scans are strictly confined to authorized localhost targets.
3. Active scanning disabled by default: Active scanning requires explicit policy override.
4. Credential masking: API keys are masked ('***') in all receipts, logs, and representations.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import httpx

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.registry import BaseTool

logger = logging.getLogger("autonomous_pentest.zap")

VALID_ZAP_ACTIONS = {
    "check_health",
    "spider",
    "passive_scan",
    "get_status",
    "get_alerts",
    "active_scan",
}


def mask_zap_api_key(value: Optional[str]) -> str:
    """Safely mask API key for logging and receipts."""
    if not value:
        return "None"
    return "***"


class ZapClientError(Exception):
    """Exception raised for unrecoverable ZAP daemon communication errors."""
    pass


class ZapSecurityScanTool(BaseTool):
    """BaseTool implementation for the OWASP ZAP REST API."""

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.scope_validator = ScopeValidator(self.config)
        self.base_url = self.config.zap_base_url.rstrip("/")
        self.api_key = self.config.zap_api_key

        super().__init__(
            name="zap_scanner",
            description=(
                "Interact with OWASP ZAP REST API for vulnerability discovery. "
                "Supported actions: 'check_health' (daemon status), 'spider' (crawl endpoints), "
                "'passive_scan' (check passive queue), 'get_status' (poll scan progress), "
                "'get_alerts' (retrieve findings), 'active_scan' (active scan, disabled by default)."
            ),
            parameters_schema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": list(VALID_ZAP_ACTIONS),
                        "description": "ZAP operation to execute",
                    },
                    "url": {
                        "type": "string",
                        "description": "Target URL to scan or retrieve alerts for (must be within scope)",
                    },
                    "scan_id": {
                        "type": "string",
                        "description": "Scan ID for polling spider or active scan progress",
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["spider", "ascan"],
                        "description": "Type of scan for status checks (default: 'spider')",
                    },
                    "max_children": {
                        "type": "integer",
                        "description": "Maximum children/depth for spider crawl",
                    },
                    "poll_until_complete": {
                        "type": "boolean",
                        "description": "If True, poll synchronously until scan finishes or timeout occurs",
                    },
                    "poll_timeout": {
                        "type": "number",
                        "description": "Maximum polling timeout in seconds",
                    },
                    "api_key": {
                        "type": "string",
                        "description": "Optional ZAP API key override",
                    },
                },
                "required": ["action"],
            },
            category="scanner",
            is_destructive=False,
        )

    def _get_api_headers(self, key_override: Optional[str] = None) -> Dict[str, str]:
        """Build request headers with ZAP API key if configured."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "AutonomousAPISecurityAgent/ZAP-1.0",
        }
        effective_key = key_override or self.api_key
        if effective_key:
            headers["X-ZAP-API-Key"] = effective_key
        return headers

    def _request_zap(
        self,
        endpoint_path: str,
        params: Optional[Dict[str, Any]] = None,
        key_override: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Execute a GET request against the ZAP REST API.
        
        Returns:
            Tuple[bool, Dict[str, Any], Optional[str]]: (success, response_dict, error_message)
        """
        target_path = endpoint_path if endpoint_path.startswith("/") else f"/{endpoint_path}"
        full_url = f"{self.base_url}{target_path}"
        headers = self._get_api_headers(key_override)
        req_params = dict(params or {})

        effective_key = key_override or self.api_key
        if effective_key and "apikey" not in req_params:
            req_params["apikey"] = effective_key

        effective_timeout = timeout or self.config.http_connect_timeout

        try:
            with httpx.Client(
                timeout=httpx.Timeout(
                    timeout=effective_timeout,
                    connect=self.config.http_connect_timeout,
                    read=self.config.http_read_timeout,
                    write=self.config.http_connect_timeout,
                    pool=self.config.http_connect_timeout,
                ),
                follow_redirects=False,
            ) as client:
                resp = client.get(full_url, headers=headers, params=req_params)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        return True, data, None
                    except Exception:
                        return True, {"raw_text": resp.text[:2000]}, None
                elif resp.status_code in {401, 403}:
                    return False, {}, f"ZAP Authentication failed ({resp.status_code}): Invalid or missing API key"
                else:
                    return False, {}, f"ZAP API returned HTTP status {resp.status_code}: {resp.text[:500]}"
        except httpx.ConnectError:
            return False, {}, f"Unable to connect to OWASP ZAP daemon at '{self.base_url}'. Is ZAP running?"
        except httpx.TimeoutException:
            return False, {}, f"Request to ZAP daemon timed out after {effective_timeout}s"
        except Exception as exc:
            return False, {}, f"ZAP communication error: {type(exc).__name__}: {str(exc)}"

    def check_health(self, key_override: Optional[str] = None) -> Dict[str, Any]:
        """Check if ZAP daemon is running, responding, and healthy."""
        ok, data, err = self._request_zap("/JSON/core/view/version/", key_override=key_override)
        if ok:
            version = data.get("version", "unknown")
            return {
                "success": True,
                "action": "check_health",
                "connected": True,
                "version": version,
                "zap_base_url": self.base_url,
                "api_key_configured": bool(key_override or self.api_key),
            }
        return {
            "success": False,
            "action": "check_health",
            "connected": False,
            "error": err,
            "zap_base_url": self.base_url,
            "api_key_configured": bool(key_override or self.api_key),
        }

    def start_spider(
        self,
        target_url: str,
        max_children: Optional[int] = None,
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start a spider crawl for a target URL within scope."""
        scope_res = self.scope_validator.validate_url(target_url)
        if not scope_res.is_valid:
            return {
                "success": False,
                "action": "spider",
                "error": f"Target URL out of scope: {scope_res.reason}",
                "target_url": target_url,
            }

        depth = max_children if max_children is not None else self.config.zap_max_spider_depth
        params = {
            "url": scope_res.normalized_url,
            "maxChildren": str(depth),
            "recurse": "true",
        }
        ok, data, err = self._request_zap("/JSON/spider/action/scan/", params=params, key_override=key_override)
        if ok:
            scan_id = str(data.get("scan", "0"))
            return {
                "success": True,
                "action": "spider",
                "scan_id": scan_id,
                "target_url": scope_res.normalized_url,
                "max_children": depth,
                "status": "STARTED",
            }
        return {
            "success": False,
            "action": "spider",
            "target_url": target_url,
            "error": err,
        }

    def get_scan_status(
        self,
        scan_id: str,
        scan_type: str = "spider",
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Poll scan progress percentage (0-100)."""
        scan_type_norm = "ascan" if scan_type.lower() in {"ascan", "active"} else "spider"
        endpoint = f"/JSON/{scan_type_norm}/view/status/"
        params = {"scanId": str(scan_id)}
        ok, data, err = self._request_zap(endpoint, params=params, key_override=key_override)
        if ok:
            progress_str = str(data.get("status", "0"))
            try:
                progress_int = int(progress_str)
            except ValueError:
                progress_int = 0
            is_complete = progress_int >= 100
            return {
                "success": True,
                "action": "get_status",
                "scan_id": str(scan_id),
                "scan_type": scan_type_norm,
                "progress_percent": progress_int,
                "is_complete": is_complete,
            }
        return {
            "success": False,
            "action": "get_status",
            "scan_id": str(scan_id),
            "scan_type": scan_type_norm,
            "error": err,
        }

    def get_spider_results(
        self,
        scan_id: str,
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve list of discovered URLs from a spider scan."""
        params = {"scanId": str(scan_id)}
        ok, data, err = self._request_zap("/JSON/spider/view/results/", params=params, key_override=key_override)
        if ok:
            results = data.get("results", [])
            return {
                "success": True,
                "action": "get_spider_results",
                "scan_id": str(scan_id),
                "urls_count": len(results),
                "discovered_urls": results,
            }
        return {
            "success": False,
            "action": "get_spider_results",
            "scan_id": str(scan_id),
            "error": err,
        }

    def check_passive_scan(self, key_override: Optional[str] = None) -> Dict[str, Any]:
        """Check passive scan queue records remaining to scan."""
        ok, data, err = self._request_zap("/JSON/pscan/view/recordsToScan/", key_override=key_override)
        if ok:
            records_str = str(data.get("recordsToScan", "0"))
            try:
                records_int = int(records_str)
            except ValueError:
                records_int = 0
            return {
                "success": True,
                "action": "passive_scan",
                "records_remaining": records_int,
                "is_drained": records_int == 0,
            }
        return {
            "success": False,
            "action": "passive_scan",
            "error": err,
        }

    def get_alerts(
        self,
        base_url: Optional[str] = None,
        start: int = 0,
        count: int = 100,
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve security alerts detected by ZAP."""
        params: Dict[str, Any] = {"start": str(start), "count": str(count)}
        if base_url:
            scope_res = self.scope_validator.validate_url(base_url)
            if scope_res.is_valid:
                params["baseurl"] = scope_res.normalized_url

        ok, data, err = self._request_zap("/JSON/core/view/alerts/", params=params, key_override=key_override)
        if ok:
            raw_alerts = data.get("alerts", [])
            normalized_alerts = []
            for item in raw_alerts:
                normalized_alerts.append({
                    "id": str(item.get("id", "")),
                    "name": item.get("alert") or item.get("name") or "Unknown Alert",
                    "risk": item.get("risk", "Low"),
                    "confidence": item.get("confidence", "Medium"),
                    "url": item.get("url", ""),
                    "method": item.get("method", "GET"),
                    "param": item.get("param", ""),
                    "attack": item.get("attack", ""),
                    "evidence": item.get("evidence", ""),
                    "description": item.get("description", ""),
                    "solution": item.get("solution", ""),
                    "cweid": str(item.get("cweid", "")),
                    "wascid": str(item.get("wascid", "")),
                })
            return {
                "success": True,
                "action": "get_alerts",
                "count": len(normalized_alerts),
                "alerts": normalized_alerts,
                "base_url": base_url,
            }
        return {
            "success": False,
            "action": "get_alerts",
            "base_url": base_url,
            "error": err,
            "alerts": [],
        }

    def start_active_scan(
        self,
        target_url: str,
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start an active vulnerability scan.
        
        Strict Guardrail: Denied if zap_active_scan_enabled is False in config.
        """
        if not self.config.zap_active_scan_enabled:
            return {
                "success": False,
                "action": "active_scan",
                "error": "Active scanning is disabled by safety configuration (zap_active_scan_enabled=False).",
                "target_url": target_url,
                "policy_blocked": True,
            }

        scope_res = self.scope_validator.validate_url(target_url)
        if not scope_res.is_valid:
            return {
                "success": False,
                "action": "active_scan",
                "error": f"Target URL out of scope: {scope_res.reason}",
                "target_url": target_url,
            }

        params = {
            "url": scope_res.normalized_url,
            "recurse": "true",
        }
        ok, data, err = self._request_zap("/JSON/ascan/action/scan/", params=params, key_override=key_override)
        if ok:
            scan_id = str(data.get("scan", "0"))
            return {
                "success": True,
                "action": "active_scan",
                "scan_id": scan_id,
                "target_url": scope_res.normalized_url,
                "status": "STARTED",
            }
        return {
            "success": False,
            "action": "active_scan",
            "target_url": target_url,
            "error": err,
        }

    def poll_scan_until_done(
        self,
        scan_id: str,
        scan_type: str = "spider",
        timeout: Optional[float] = None,
        key_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Poll scan status until 100% or timeout."""
        max_wait = timeout or self.config.zap_max_poll_seconds
        start_time = time.time()
        poll_interval = self.config.zap_poll_interval

        while (time.time() - start_time) < max_wait:
            status_res = self.get_scan_status(scan_id=scan_id, scan_type=scan_type, key_override=key_override)
            if not status_res.get("success"):
                return status_res
            if status_res.get("is_complete"):
                return status_res
            time.sleep(poll_interval)

        # Timed out waiting
        last_status = self.get_scan_status(scan_id=scan_id, scan_type=scan_type, key_override=key_override)
        last_status["timed_out"] = True
        last_status["waited_seconds"] = round(time.time() - start_time, 2)
        return last_status

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Standard tool execution dispatcher."""
        valid, err = self.validate_arguments(kwargs)
        if not valid:
            return {"success": False, "error": err}

        action = str(kwargs.get("action", "")).strip().lower()
        if action not in VALID_ZAP_ACTIONS:
            return {
                "success": False,
                "error": f"Invalid action '{action}'. Permitted: {sorted(VALID_ZAP_ACTIONS)}",
            }

        target_url = kwargs.get("url") or kwargs.get("target_url")
        scan_id = kwargs.get("scan_id")
        scan_type = kwargs.get("scan_type", "spider")
        max_children = kwargs.get("max_children")
        poll_until_complete = bool(kwargs.get("poll_until_complete", False))
        poll_timeout = kwargs.get("poll_timeout")
        key_override = kwargs.get("api_key")

        # Mask API key in all internal receipt generation
        receipt_meta = {
            "tool_name": "zap_scanner",
            "action": action,
            "zap_base_url": self.base_url,
            "api_key_masked": mask_zap_api_key(key_override or self.api_key),
        }

        if action == "check_health":
            res = self.check_health(key_override=key_override)
        elif action == "spider":
            if not target_url:
                return {"success": False, "error": "Action 'spider' requires a 'url' parameter"}
            res = self.start_spider(target_url=target_url, max_children=max_children, key_override=key_override)
            if res.get("success") and poll_until_complete and res.get("scan_id"):
                poll_res = self.poll_scan_until_done(
                    scan_id=res["scan_id"],
                    scan_type="spider",
                    timeout=poll_timeout,
                    key_override=key_override,
                )
                res["poll_result"] = poll_res
                # Also collect spider results if completed
                results_res = self.get_spider_results(scan_id=res["scan_id"], key_override=key_override)
                if results_res.get("success"):
                    res["discovered_urls"] = results_res.get("discovered_urls", [])
                    res["urls_count"] = results_res.get("urls_count", 0)
        elif action == "get_status":
            if not scan_id:
                return {"success": False, "error": "Action 'get_status' requires a 'scan_id' parameter"}
            res = self.get_scan_status(scan_id=scan_id, scan_type=scan_type, key_override=key_override)
        elif action == "passive_scan":
            res = self.check_passive_scan(key_override=key_override)
        elif action == "get_alerts":
            res = self.get_alerts(base_url=target_url, key_override=key_override)
        elif action == "active_scan":
            if not target_url:
                return {"success": False, "error": "Action 'active_scan' requires a 'url' parameter"}
            res = self.start_active_scan(target_url=target_url, key_override=key_override)
            if res.get("success") and poll_until_complete and res.get("scan_id"):
                poll_res = self.poll_scan_until_done(
                    scan_id=res["scan_id"],
                    scan_type="ascan",
                    timeout=poll_timeout,
                    key_override=key_override,
                )
                res["poll_result"] = poll_res
        else:
            return {"success": False, "error": f"Unhandled action '{action}'"}

        res.update(receipt_meta)
        return res

