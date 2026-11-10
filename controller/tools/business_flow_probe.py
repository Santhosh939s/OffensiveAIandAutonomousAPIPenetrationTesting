"""Business Flow Probe Tool for Autonomous Penetration Testing.

Evaluates sensitive business processes (discount redemptions, coupon claims, bulk checkouts)
for absence of rate-limiting, anti-automation controls, and velocity protections.
Demonstrates OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows).
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.registry import BaseTool

logger = logging.getLogger(__name__)


class BusinessFlowProbeTool(BaseTool):
    """Tool for probing sensitive business flows for lack of anti-automation and rate-limits."""

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        scope_validator: Optional[ScopeValidator] = None,
    ):
        self.config = config or DEFAULT_CONFIG
        self.scope_validator = scope_validator or ScopeValidator(self.config)
        super().__init__(
            name="business_flow_probe",
            description="Tests sensitive business logic flows (e.g. coupon redemption, checkout) with sequential rapid operations to verify absence of rate limits and anti-automation controls.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Endpoint URL implementing a business flow (e.g. http://127.0.0.1:5000/api/coupons/apply)",
                    },
                    "method": {
                        "type": "string",
                        "default": "POST",
                        "description": "HTTP method to use",
                    },
                    "payload": {
                        "type": "object",
                        "description": "JSON payload to send with each probe request",
                    },
                    "iterations": {
                        "type": "integer",
                        "default": 3,
                        "description": "Number of rapid sequential iterations to dispatch (non-destructive; limited to 3-5)",
                    },
                },
                "required": ["url"],
            },
            category="assessment",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute non-destructive automated sequence against target business flow."""
        policy_ok, pol_err, clean_kwargs = self._check_execution_policy(kwargs)
        if not policy_ok:
            return {
                "success": False,
                "error": pol_err,
                "tool_name": self.name,
                "iterations_completed": 0,
                "findings": [],
                "policy_denied": True,
            }

        target_url = str(clean_kwargs.get("url") or clean_kwargs.get("target_url") or "").strip()
        if not target_url:
            return {"success": False, "error": "url is required"}

        # Scope validation
        scope_res = self.scope_validator.validate_url(target_url)
        if not scope_res.is_valid:
            return {
                "success": False,
                "error": f"Target '{target_url}' rejected by scope policy: {scope_res.reason}",
                "iterations_completed": 0,
                "findings": [],
                "policy_denied": True,
            }

        method = str(clean_kwargs.get("method") or "POST").upper()
        payload = clean_kwargs.get("payload") or {"coupon_code": "SAVE50", "order_id": 101}
        # Strictly limit iterations between 2 and 5 to prevent denial-of-service
        raw_iterations = int(clean_kwargs.get("iterations") or 3)
        iterations = max(2, min(5, raw_iterations))

        traffic_interactions: List[Dict[str, Any]] = []
        statuses: List[int] = []
        responses: List[str] = []
        findings: List[Dict[str, Any]] = []

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Autonomous-API-Pentester-BusinessFlow/1.0",
        }

        with requests.Session() as session:
            adapter = requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=2, max_retries=0)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            for i in range(iterations):
                start_t = time.time()
                try:
                    if method == "POST":
                        resp = session.post(
                            target_url,
                            json=payload,
                            headers=headers,
                            timeout=self.config.http_read_timeout,
                            allow_redirects=False,
                        )
                    else:
                        resp = session.get(
                            target_url,
                            headers=headers,
                            timeout=self.config.http_read_timeout,
                            allow_redirects=False,
                        )
                    elapsed_ms = round((time.time() - start_t) * 1000, 2)
                    statuses.append(resp.status_code)
                    responses.append(resp.text[:500])

                    traffic_record = {
                        "method": method,
                        "url": target_url,
                        "headers": headers,
                        "request_body": json.dumps(payload),
                        "response_status": resp.status_code,
                        "response_headers": dict(resp.headers),
                        "response_body": resp.text[:1000],
                        "elapsed_ms": elapsed_ms,
                    }
                    traffic_interactions.append(traffic_record)

                except requests.RequestException as exc:
                    logger.debug("Business flow probe iteration %d failed: %s", i + 1, exc)
                    break

        # Check if all iterations succeeded with 200 and showed signs of unrestricted repetition
        all_succeeded = len(statuses) >= 2 and all(s == 200 for s in statuses)
        has_business_indicators = any(
            "abuse" in r.lower() or "times_applied" in r.lower() or "applied" in r.lower() or "discount" in r.lower()
            for r in responses
        )

        if all_succeeded and has_business_indicators:
            findings.append({
                "type": "BUSINESS_FLOW_UNRESTRICTED_ACCESS",
                "endpoint": target_url,
                "category": "Unrestricted Access to Sensitive Business Flows",
                "status": "CONFIRMED",
                "verification_rule": "BUSINESS_FLOW_UNRESTRICTED_ACCESS",
                "evidence_notes": (
                    f"Sensitive business transaction at '{target_url}' was successfully executed "
                    f"{len(statuses)} consecutive times without rate limiting (429), CAPTCHA, or quota restrictions."
                ),
                "traffic_record": traffic_interactions[-1] if traffic_interactions else None,
            })

        return {
            "success": True,
            "target_url": target_url,
            "iterations_executed": len(statuses),
            "status_codes": statuses,
            "all_succeeded": all_succeeded,
            "findings": findings,
            "traffic_interactions": traffic_interactions,
        }

