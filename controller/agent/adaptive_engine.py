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

    def __init__(
        self,
        context_manager: CompactContextManager,
        selected_categories: Optional[List[str]] = None,
        assessment_type: str = "auto",
        assessment_depth: str = "standard",
    ):
        self.context = context_manager
        self.selected_categories = [c.upper() for c in (selected_categories or [])]
        self.assessment_type = assessment_type.lower()
        self.assessment_depth = assessment_depth.lower()

    def evaluate_and_rank_candidates(
        self,
        target_base_url: str,
        recent_observations: List[Dict[str, Any]],
    ) -> List[PrioritizedCandidate]:
        """Rank candidate endpoints and tools by expected information gain."""
        candidates: List[PrioritizedCandidate] = []

        # Category booster mapping
        cat_keywords = {
            "API1": ["user", "account", "profile", "order", "item", "id", "{id}", "record"],
            "API2": ["login", "auth", "token", "session", "jwt", "password"],
            "API3": ["user", "profile", "update", "role", "patch", "put"],
            "API4": ["search", "query", "filter", "list", "items", "limit", "pagination"],
            "API5": ["admin", "manage", "config", "internal", "dashboard", "super"],
            "API6": ["checkout", "cart", "pay", "coupon", "promo", "transfer", "redeem", "order"],
            "API7": ["url", "fetch", "proxy", "webhook", "callback", "redirect", "import"],
            "API8": ["graphql", "debug", "test", "swagger", "openapi", "error"],
            "API9": ["v1", "v2", "beta", "old", "legacy", "internal", "metrics"],
            "API10": ["webhook", "partner", "external", "thirdparty", "integration"],
        }

        for key, meta in self.context.endpoints_meta.items():
            if self.context.is_endpoint_exhausted(key):
                continue

            path = meta["path"]
            method = meta["method"]
            status = meta["status"]
            probes_done = self.context.endpoint_probe_counts.get(key, 0)

            score = 5.0
            reasons = []
            path_lower = path.lower()

            # Assessment type constraints
            if self.assessment_type == "graphql" and "graphql" not in path_lower:
                score -= 10.0
                reasons.append("Filtered: Non-GraphQL endpoint in GraphQL-only assessment")
            elif self.assessment_type == "rest" and "graphql" in path_lower:
                score -= 10.0
                reasons.append("Filtered: GraphQL endpoint in REST-only assessment")

            # 1. Base architectural relevance
            if "graphql" in path_lower:
                score += 4.5
                reasons.append("GraphQL interface surface (API8/API4 potential)")
            elif any(term in path_lower for term in ["login", "auth", "token", "session"]):
                score += 4.0
                reasons.append("High-value authentication/session boundary (API2)")
            elif any(term in path_lower for term in ["admin", "manage", "role", "internal"]):
                score += 4.0
                reasons.append("Privilege / function authorization boundary (API5)")
            elif any(term in path_lower for term in ["checkout", "pay", "promo", "coupon", "transfer"]):
                score += 3.8
                reasons.append("Sensitive business transaction flow (API6)")
            elif any(term in path_lower for term in ["user", "account", "profile", "order"]):
                score += 3.5
                reasons.append("Object authorization boundary (API1/API3)")
            elif any(term in path_lower for term in ["search", "query", "find", "filter"]):
                score += 3.0
                reasons.append("Parameterized search query surface (API8/API4)")
            elif any(term in path_lower for term in ["v1", "v2", "beta", "old", "test"]):
                score += 3.0
                reasons.append("Inventory versioning / deprecated route (API9)")

            # 2. Selected Category Filtering and Boosting
            if self.selected_categories:
                matched_sel_cat = False
                for cat in self.selected_categories:
                    cat_key = cat.split(":")[0].strip()
                    relevant_terms = cat_keywords.get(cat_key, [])
                    if any(t in path_lower for t in relevant_terms):
                        matched_sel_cat = True
                        score += 5.0
                        reasons.append(f"Explicitly prioritized by selected category {cat_key}")
                        break
                if not matched_sel_cat:
                    score -= 4.0
                    reasons.append("Not matching selected OWASP categories")

            # 3. Parameterization indicators
            if "{" in path or "?" in path or meta.get("parameters"):
                score += 2.5
                reasons.append("Parameterized endpoint (BOLA / Injection potential)")

            # 4. Status and historical evidence
            if status == "UNTESTED":
                score += 3.0
                reasons.append("Unexplored endpoint surface")
            elif status == "SUSPECTED":
                score += 5.0
                reasons.append("Prior evidence suggests vulnerability (requires verification probe)")
            elif status == "VULNERABLE":
                score -= 4.0
                reasons.append("Vulnerability already confirmed on this endpoint")
            elif status == "CLEAN":
                score -= 3.0
                reasons.append("Previous probe returned clean baseline")

            # 5. Check recent anomalies or 500 errors in observations
            for obs in recent_observations[-3:]:
                obs_url = str(obs.get("arguments", {}).get("url", ""))
                obs_status = obs.get("result_status")
                if path in obs_url:
                    if obs_status == 500:
                        score += 4.0
                        reasons.append("Server returned 500 Internal Error (investigate SQLi / unhandled crash)")
                    elif obs_status in (401, 403) and "admin" in path_lower:
                        score += 2.0
                        reasons.append("Protected administrative boundary; probe for BFLA bypass")
                    elif obs.get("status") == "POLICY_DENIED":
                        score -= 5.0
                        reasons.append("Previous probe blocked by policy")

            # 6. Penalize redundant / repeated probes on same route
            score -= probes_done * 2.5

            # 7. Tool Recommendation
            full_url = f"{target_base_url.rstrip('/')}/{path.lstrip('/')}"
            rec_tool = "httpx_request"
            test_params: Dict[str, Any] = {"url": full_url, "method": method}

            if "graphql" in path_lower:
                rec_tool = "graphql_probe"
                test_params = {
                    "target_url": full_url,
                    "probe_types": ["introspection", "field_suggestion"] if probes_done == 0 else ["deep_query"],
                }
            elif any(term in path_lower for term in ["checkout", "promo", "coupon", "order", "transfer"]):
                if probes_done > 0:
                    rec_tool = "business_flow_probe"
                    test_params = {
                        "target_url": full_url,
                        "method": method,
                        "probe_count": 5,
                    }
            elif "search" in path_lower or "q=" in path_lower:
                if probes_done > 0:
                    rec_tool = "parameter_fuzzer"
                    test_params = {
                        "target_url": full_url.split("?")[0],
                        "parameter_name": "q",
                        "attack_type": "sqli",
                        "method": method,
                    }
            elif any(term in path_lower for term in ["url", "fetch", "webhook", "proxy", "redirect"]):
                if probes_done > 0:
                    rec_tool = "parameter_fuzzer"
                    test_params = {
                        "target_url": full_url.split("?")[0],
                        "parameter_name": "url",
                        "attack_type": "ssrf",
                        "method": method,
                    }
            elif "login" in path_lower:
                if method == "POST":
                    test_params["body"] = {"username": "admin", "password": ""}
            elif "{" in path:
                # Concrete ID substitution for BOLA testing
                sub_id = "2" if probes_done == 0 else "999"
                concrete_path = path.replace("{id}", sub_id).replace("{userId}", sub_id)
                full_url = f"{target_base_url.rstrip('/')}/{concrete_path.lstrip('/')}"
                test_params["url"] = full_url
                if method in ("PUT", "PATCH"):
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

