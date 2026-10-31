"""Compact Context Management and Assessment Memory for Qwen Model Brain.

Preserves structured, high-signal security assessment context without overloading
the 1.5B model's limited context window. Tracks tested routes, probe counts,
anomalous observations, verified findings, failed approaches, and remaining budgets.
"""

from typing import Any, Dict, List, Optional, Set


class CompactContextManager:
    """Manages compact assessment memory and token-optimized context synthesis."""

    def __init__(
        self,
        target_url: str,
        max_turns: int = 10,
        max_requests: int = 30,
        max_probes_per_endpoint: int = 3,
    ):
        self.target_url = target_url
        self.max_turns = max_turns
        self.max_requests = max_requests
        self.max_probes_per_endpoint = max_probes_per_endpoint

        # Endpoints registry: endpoint_path -> metadata
        self.endpoints_meta: Dict[str, Dict[str, Any]] = {}
        self.endpoint_probe_counts: Dict[str, int] = {}

        # Findings & Evidence
        self.confirmed_findings: List[Dict[str, Any]] = []
        self.suspected_findings: List[Dict[str, Any]] = []

        # Action history & Failures
        self.executed_actions: List[Dict[str, Any]] = []
        self.failed_approaches: List[Dict[str, Any]] = []

        # Dynamic budget
        self.turns_used: int = 0
        self.requests_sent: int = 0
        self.model_calls: int = 0

    def register_discovered_endpoints(self, endpoints: List[Dict[str, Any]]) -> None:
        """Ingest discovered endpoints from OpenAPI or initial target configuration."""
        for ep in endpoints:
            path = ep.get("path") or ep.get("url") or "/"
            method = (ep.get("method") or "GET").upper()
            key = f"{method} {path}"
            if key not in self.endpoints_meta:
                self.endpoints_meta[key] = {
                    "path": path,
                    "method": method,
                    "status": "UNTESTED",
                    "parameters": ep.get("parameters", []),
                    "summary": ep.get("summary", ""),
                    "has_auth": bool(ep.get("security") or "login" in path or "auth" in path),
                }
                self.endpoint_probe_counts[key] = 0

    def record_probe(
        self,
        endpoint_key: str,
        tool_name: str,
        arguments: Dict[str, Any],
        status_code: Optional[int],
        success: bool,
        finding: Optional[Dict[str, Any]] = None,
        policy_denial: Optional[str] = None,
    ) -> None:
        """Record the outcome of a tool execution turn."""
        self.endpoint_probe_counts[endpoint_key] = self.endpoint_probe_counts.get(endpoint_key, 0) + 1
        meta = self.endpoints_meta.get(endpoint_key)

        action_summary = {
            "endpoint": endpoint_key,
            "tool": tool_name,
            "status_code": status_code,
            "success": success,
        }
        self.executed_actions.append(action_summary)

        if policy_denial:
            self.failed_approaches.append({
                "endpoint": endpoint_key,
                "tool": tool_name,
                "reason": f"Policy rejection: {policy_denial}",
            })
            return

        if not success:
            self.failed_approaches.append({
                "endpoint": endpoint_key,
                "tool": tool_name,
                "reason": f"Tool execution error or timeout (status: {status_code})",
            })
            return

        if finding:
            f_status = finding.get("status", "SUSPECTED")
            if f_status == "CONFIRMED":
                self.confirmed_findings.append(finding)
                if meta:
                    meta["status"] = "VULNERABLE"
            else:
                self.suspected_findings.append(finding)
                if meta and meta["status"] != "VULNERABLE":
                    meta["status"] = "SUSPECTED"
        else:
            if meta and meta["status"] == "UNTESTED":
                meta["status"] = "CLEAN"

    def is_endpoint_exhausted(self, endpoint_key: str) -> bool:
        """Check if an endpoint has reached its maximum probe budget."""
        return self.endpoint_probe_counts.get(endpoint_key, 0) >= self.max_probes_per_endpoint

    def get_remaining_untested_endpoints(self) -> List[str]:
        """Return list of endpoints that have not yet been probed."""
        return [
            k for k, v in self.endpoints_meta.items()
            if v["status"] == "UNTESTED" and not self.is_endpoint_exhausted(k)
        ]

    def has_high_value_targets_remaining(self) -> bool:
        """Determine whether worthwhile targets remain to probe."""
        for k, v in self.endpoints_meta.items():
            if not self.is_endpoint_exhausted(k):
                if v["status"] in {"UNTESTED", "SUSPECTED"}:
                    return True
        return False

    def build_compact_memory_for_prompt(self, max_observations: int = 4) -> Dict[str, Any]:
        """Synthesize a compact, structured representation under 400 tokens for Qwen prompting."""
        untested = self.get_remaining_untested_endpoints()
        exhausted = [k for k in self.endpoints_meta if self.is_endpoint_exhausted(k)]

        findings_summary = [
            f"[{f.get('status')}] {f.get('category')} at {f.get('endpoint')} ({f.get('verification_rule') or 'Heuristic'})"
            for f in (self.confirmed_findings + self.suspected_findings)[-5:]
        ]

        recent_actions = self.executed_actions[-max_observations:]
        recent_failures = self.failed_approaches[-3:]

        return {
            "target": self.target_url,
            "budget": {
                "turns_remaining": max(0, self.max_turns - self.turns_used),
                "requests_remaining": max(0, self.max_requests - self.requests_sent),
            },
            "untested_endpoints_count": len(untested),
            "untested_candidates": untested[:4],
            "exhausted_endpoints": exhausted[:3],
            "confirmed_findings_count": len(self.confirmed_findings),
            "suspected_findings_count": len(self.suspected_findings),
            "recent_findings": findings_summary,
            "recent_actions": recent_actions,
            "avoid_failed_approaches": recent_failures,
        }

