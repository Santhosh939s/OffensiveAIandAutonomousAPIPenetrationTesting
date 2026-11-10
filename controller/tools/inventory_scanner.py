"""API Inventory Scanner Tool for Autonomous Penetration Testing.

Discovers undocumented, shadow, legacy (e.g. /v1/, /beta/), and debug API endpoints
that remain reachable on the target system without inventory tracking or documentation.
Demonstrates OWASP API9:2023 (Improper Inventory Management).
"""

import logging
import time
from typing import Any, Dict, List, Optional

import requests

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.registry import BaseTool

logger = logging.getLogger(__name__)

CANDIDATE_SHADOW_PATHS = [
    "/api/v1/users/export",
    "/api/v1/debug/dump",
    "/api/v1/users",
    "/api/v1/items",
    "/api/v1/config",
    "/api/beta/features",
    "/api/debug/dump",
    "/api/legacy/orders",
]


class ApiInventoryScannerTool(BaseTool):
    """Tool for detecting shadow, deprecated, and unadvertised API endpoints."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        scope_validator: Optional[ScopeValidator] = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.scope_validator = scope_validator or ScopeValidator(self.config)
        super().__init__(
            name="inventory_scanner",
            description="Probes target for undocumented, shadow, legacy (v1), and debug API endpoints not listed in published specifications.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "target_url": {
                        "type": "string",
                        "description": "Base target URL to probe for shadow endpoints (e.g. http://127.0.0.1:5000)",
                    },
                    "candidate_paths": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional custom candidate path list to probe",
                    },
                    "known_endpoints": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of paths already known from OpenAPI spec to identify unadvertised shadow endpoints",
                    },
                },
                "required": ["target_url"],
            },
            category="recon",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute shadow endpoint probe against candidate paths."""
        policy_ok, pol_err, clean_kwargs = self._check_execution_policy(kwargs)
        if not policy_ok:
            return {
                "success": False,
                "error": pol_err,
                "tool_name": self.name,
                "policy_denied": True,
            }

        target_url = str(clean_kwargs.get("target_url") or "").rstrip("/")
        if not target_url:
            return {"success": False, "error": "target_url is required"}

        # Scope validation
        scope_res = self.scope_validator.validate_url(target_url)
        if not scope_res.is_valid:
            return {
                "success": False,
                "error": f"Target '{target_url}' rejected by scope policy: {scope_res.reason}",
                "shadow_endpoints_found": [],
                "findings": [],
                "policy_denied": True,
            }

        custom_paths = clean_kwargs.get("candidate_paths")
        paths_to_test = custom_paths if isinstance(custom_paths, list) and custom_paths else CANDIDATE_SHADOW_PATHS
        known_endpoints = set(clean_kwargs.get("known_endpoints") or [])

        shadow_endpoints_found: List[Dict[str, Any]] = []
        traffic_interactions: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []

        headers = {
            "User-Agent": "Autonomous-API-Pentester-InventoryScanner/1.0",
            "Accept": "application/json",
        }

        import concurrent.futures

        def _probe_path(path: str):
            norm_path = "/" + path.lstrip("/")
            full_url = f"{target_url}{norm_path}"
            scope_check = self.scope_validator.validate_url(full_url)
            if not scope_check.is_valid:
                return norm_path, full_url, None, 0.0, None, Exception(f"Scope violation: {scope_check.reason}")

            start_t = time.time()
            try:
                resp = requests.get(full_url, headers=headers, timeout=self.config.http_read_timeout)
                elapsed_ms = round((time.time() - start_t) * 1000, 2)
                traffic_record = {
                    "method": "GET",
                    "url": full_url,
                    "headers": headers,
                    "request_body": None,
                    "response_status": resp.status_code,
                    "response_headers": dict(resp.headers),
                    "response_body": resp.text[:1000],
                    "elapsed_ms": elapsed_ms,
                }
                return norm_path, full_url, resp, elapsed_ms, traffic_record, None
            except requests.RequestException as exc:
                return norm_path, full_url, None, 0.0, None, exc

        max_workers = min(4, max(1, len(paths_to_test)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            probe_results = list(executor.map(_probe_path, paths_to_test))

        for norm_path, full_url, resp, elapsed_ms, traffic_record, exc in probe_results:
            if exc or resp is None:
                logger.debug("Inventory probe to %s failed or timed out: %s", full_url, exc)
                continue

            traffic_interactions.append(traffic_record)

            if resp.status_code == 200:
                body_lower = resp.text.lower()
                is_shadow = (
                    "shadow" in body_lower
                    or "deprecated" in body_lower
                    or "v1" in norm_path
                    or norm_path not in known_endpoints
                )

                shadow_info = {
                    "path": norm_path,
                    "url": full_url,
                    "status_code": resp.status_code,
                    "elapsed_ms": elapsed_ms,
                    "response_preview": resp.text[:200],
                    "is_undocumented": norm_path not in known_endpoints,
                }
                shadow_endpoints_found.append(shadow_info)

                if is_shadow:
                    findings.append({
                        "type": "SHADOW_OR_DEPRECATED_API_EXPOSED",
                        "endpoint": full_url,
                        "category": "Improper Inventory Management (Shadow API)",
                        "status": "CONFIRMED",
                        "verification_rule": "SHADOW_OR_DEPRECATED_API_EXPOSED",
                        "evidence_notes": f"Undocumented/shadow API endpoint '{norm_path}' responded with HTTP 200 and leaked internal/legacy data.",
                        "traffic_record": traffic_record,
                    })

        return {
            "success": True,
            "target_url": target_url,
            "paths_tested": len(paths_to_test),
            "shadow_endpoints_found": shadow_endpoints_found,
            "shadow_count": len(shadow_endpoints_found),
            "findings": findings,
            "traffic_interactions": traffic_interactions,
        }

