"""Adaptive Decision Engine for Evidence-Driven API Security Test Selection.

Implements mathematical and heuristic prioritization to compute the most informative
next API testing operations based on:
1. OpenAPI specification properties (methods, auth schemes, query/path parameters).
2. Historical request/response evidence (HTTP status codes, errors, anomaly flags).
3. Previous testing attempts and exhausted probe budgets.
4. Existing ZAP alerts and vulnerability verification states.

Invariant: Deterministic calculations provide ranked candidate recommendations,
while the Qwen model brain retains final authority for selecting the next action.
When no high-value tests remain, safe abstention ('no_action' / 'complete') is recommended.
"""

from typing import Any, Dict, List, Optional, Tuple

from controller.agent.context_manager import CompactContextManager


class PrioritizedCandidate:
    """A prioritized testing operation candidate recommended to the model."""

    def __init__(
        self,
        endpoint_key: str,
        path: str,
        method: str,
        recommended_tool: str,
        parameters: Dict[str, Any],
        priority_score: float,
        rationale: str,
    ):
        self.endpoint_key = endpoint_key
        self.path = path
        self.method = method
        self.recommended_tool = recommended_tool
        self.parameters = parameters
        self.priority_score = priority_score
        self.rationale = rationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint_key,
            "path": self.path,
            "method": self.method,
            "recommended_tool": self.recommended_tool,
            "parameters": self.parameters,
            "priority_score": round(self.priority_score, 2),
            "rationale": self.rationale,
        }


class AdaptiveTestSelector:
    """Computes evidence-driven test prioritization to minimize testing steps."""

    def __init__(self, context_manager: CompactContextManager):
        self.context = context_manager

    def evaluate_and_rank_candidates(
        self,
        target_base_url: str,
        recent_observations: List[Dict[str, Any]],
    ) -> List[PrioritizedCandidate]:
        """Rank candidate endpoints and tools by expected information gain."""
        candidates: List[PrioritizedCandidate] = []

        for key, meta in self.context.endpoints_meta.items():
            if self.context.is_endpoint_exhausted(key):
                continue

            path = meta["path"]
            method = meta["method"]
            status = meta["status"]
            probes_done = self.context.endpoint_probe_counts.get(key, 0)

            score = 5.0
            reasons = []

            # 1. Base architectural relevance
            path_lower = path.lower()
            if any(term in path_lower for term in ["login", "auth", "token", "session"]):
                score += 4.0
                reasons.append("High-value authentication/session surface")
            elif any(term in path_lower for term in ["user", "account", "profile", "admin"]):
                score += 3.5
                reasons.append("High-value authorization/privilege boundary")
            elif any(term in path_lower for term in ["search", "query", "find", "filter"]):
                score += 3.0
                reasons.append("High-value parameterized search surface")

            # 2. Parameterization indicators
            if "{" in path or "?" in path or meta.get("parameters"):
                score += 2.5
                reasons.append("Parameterized endpoint (BOLA / Injection potential)")

            # 3. Status and historical evidence
            if status == "UNTESTED":
                score += 3.0
                reasons.append("Unexplored endpoint surface")
            elif status == "SUSPECTED":
                score += 4.5
                reasons.append("Prior evidence suggests vulnerability (requires verification probe)")
            elif status == "VULNERABLE":
                score -= 3.0
                reasons.append("Vulnerability already confirmed on this endpoint")
            elif status == "CLEAN":
                score -= 2.0
                reasons.append("Previous probe returned clean baseline")

            # 4. Check recent anomalies or 500 errors in observations
            for obs in recent_observations[-3:]:
                obs_url = str(obs.get("arguments", {}).get("url", ""))
                obs_status = obs.get("result_status")
                if path in obs_url:
                    if obs_status == 500:
                        score += 3.5
                        reasons.append("Server returned 500 Internal Error (investigate SQLi / unhandled crash)")
                    elif obs.get("status") == "POLICY_DENIED":
                        score -= 4.0
                        reasons.append("Previous probe blocked by policy")

            # 5. Penalize repeated probes on same route
            score -= probes_done * 2.5

            # 6. Tool Recommendation
            full_url = f"{target_base_url.rstrip('/')}/{path.lstrip('/')}"
            rec_tool = "httpx_request"
            test_params: Dict[str, Any] = {"url": full_url, "method": method}

            if "search" in path_lower or "q=" in path_lower:
                if probes_done > 0:
                    rec_tool = "parameter_fuzzer"
                    test_params = {
                        "url": full_url.split("?")[0],
                        "parameters": {"q": "'"},
                    }
            elif "login" in path_lower:
                if method == "POST":
                    test_params["body"] = {"username": "admin", "password": ""}
            elif "{" in path:
                # Concrete ID substitution
                concrete_path = path.replace("{id}", "2").replace("{userId}", "2")
                full_url = f"{target_base_url.rstrip('/')}/{concrete_path.lstrip('/')}"
                test_params["url"] = full_url
                if method == "PUT":
                    test_params["body"] = {"role": "admin", "is_admin": 1}

            rationale_text = "; ".join(reasons)
            candidates.append(
                PrioritizedCandidate(
                    endpoint_key=key,
                    path=path,
                    method=method,
                    recommended_tool=rec_tool,
                    parameters=test_params,
                    priority_score=score,
                    rationale=rationale_text,
                )
            )

        # Sort descending by priority score
        candidates.sort(key=lambda c: c.priority_score, reverse=True)
        return candidates

    def should_abstain_or_stop(
        self,
        candidates: List[PrioritizedCandidate],
        min_priority_threshold: float = 3.0,
    ) -> Tuple[bool, str]:
        """Determine whether testing should conclude early."""
        if not candidates:
            return True, "All discovered endpoints have reached their probe budget limits."

        top_candidate = candidates[0]
        if top_candidate.priority_score < min_priority_threshold:
            return (
                True,
                f"Remaining test candidates have low expected information gain (top score: {top_candidate.priority_score}).",
            )

        if not self.context.has_high_value_targets_remaining():
            return True, "All high-value targets evaluated; no remaining unexplored surfaces."

        return False, ""

