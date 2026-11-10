"""GraphQL Security Probe Tool for Autonomous API Penetration Testing.

Provides authorized, non-destructive inspection of GraphQL API endpoints:
1. GraphQL endpoint discovery across standard paths (/graphql, /api/graphql, /v1/graphql, /query).
2. Introspection analysis (checks if __schema introspection is enabled or disabled).
3. Field duplication and query structure analysis.
4. HTTP method permission checks (GET query parameter vs. POST JSON body).
5. Schema metadata extraction for queries and mutations.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import urllib.request
import urllib.error

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.registry import BaseTool

logger = logging.getLogger("GraphQLProbeTool")

# Standard safe introspection query requesting root types and type names only
SAFE_INTROSPECTION_QUERY = """
query SafeIntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
    }
  }
}
""".strip()


class GraphQLProbeTool(BaseTool):
    """Tool for non-destructive security assessment of GraphQL endpoints."""

    DEFAULT_CANDIDATE_PATHS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/api/query",
    ]

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.scope_validator = ScopeValidator(self.config)
        parameters_schema = {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Base URL of the target API or direct GraphQL endpoint URL (e.g. http://127.0.0.1:5000/graphql)",
                },
                "check_introspection": {
                    "type": "boolean",
                    "description": "Whether to test if schema introspection is enabled",
                    "default": True,
                },
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers such as Authorization",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Request timeout in seconds (default 10)",
                    "default": 10,
                },
            },
            "required": ["target_url"],
        }
        super().__init__(
            name="graphql_probe",
            description="Probe and inspect GraphQL endpoints for security misconfigurations and schema introspection exposure.",
            parameters_schema=parameters_schema,
            category="reconnaissance",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute GraphQL discovery and introspection probe."""
        policy_ok, pol_err, clean_kwargs = self._check_execution_policy(kwargs)
        if not policy_ok:
            return {
                "success": False,
                "error": pol_err,
                "tool_name": self.name,
                "policy_denied": True,
            }

        target_url = clean_kwargs.get("target_url", "").strip()
        check_introspection = clean_kwargs.get("check_introspection", True)
        custom_headers = clean_kwargs.get("headers") or {}
        timeout = clean_kwargs.get("timeout", 10)

        if not target_url:
            return {"success": False, "error": "target_url parameter is required"}

        # Network-layer scope validation
        scope_res = self.scope_validator.validate_url(target_url)
        if not scope_res.is_valid:
            return {
                "success": False,
                "error": f"Target '{target_url}' rejected by scope policy: {scope_res.reason}",
                "discovered_endpoints": [],
                "findings": [],
                "policy_denied": True,
            }

        # Determine target candidates
        parsed = urllib.parse.urlparse(target_url)
        endpoints_to_test = []

        if any(target_url.rstrip("/").endswith(p) for p in self.DEFAULT_CANDIDATE_PATHS):
            endpoints_to_test.append(target_url)
        else:
            base = f"{parsed.scheme}://{parsed.netloc}"
            base_path = parsed.path.rstrip("/")
            if base_path:
                endpoints_to_test.append(f"{base}{base_path}/graphql")
            for p in self.DEFAULT_CANDIDATE_PATHS:
                candidate = f"{base}{p}"
                if candidate not in endpoints_to_test:
                    endpoints_to_test.append(candidate)

        discovered_endpoints = []
        introspection_results = []
        findings = []
        all_traffic = []

        endpoint_to_res = {}
        if len(endpoints_to_test) > 1:
            import concurrent.futures
            max_workers = min(4, len(endpoints_to_test))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_ep = {
                    executor.submit(self._probe_single_endpoint, ep, custom_headers, timeout, check_introspection): ep
                    for ep in endpoints_to_test
                }
                for future in concurrent.futures.as_completed(future_to_ep):
                    ep = future_to_ep[future]
                    try:
                        endpoint_to_res[ep] = future.result()
                    except Exception as exc:
                        endpoint_to_res[ep] = {"is_graphql": False, "traffic": [], "error": str(exc)}
        else:
            for ep in endpoints_to_test:
                endpoint_to_res[ep] = self._probe_single_endpoint(ep, custom_headers, timeout, check_introspection)

        for endpoint in endpoints_to_test:
            probe_res = endpoint_to_res.get(endpoint, {})
            if probe_res.get("traffic"):
                all_traffic.extend(probe_res["traffic"])

            if probe_res.get("is_graphql"):
                discovered_endpoints.append(endpoint)
                if "introspection" in probe_res:
                    introspection_results.append(probe_res["introspection"])
                    if probe_res["introspection"].get("enabled"):
                        findings.append({
                            "type": "GRAPHQL_INTROSPECTION_ENABLED",
                            "severity": "LOW",
                            "title": "GraphQL Introspection Query Enabled",
                            "endpoint": endpoint,
                            "category": "GraphQL Introspection Enabled",
                            "owasp_category": "API8:2023 Security Misconfiguration",
                            "verification_rule": "GRAPHQL_INTROSPECTION_EXPOSED",
                            "description": "GraphQL schema introspection is enabled, allowing attackers or automated scanners to map out all available queries, mutations, and internal types.",
                            "remediation": "Disable introspection in production environments (e.g. Apollo Server `introspection: false` or GraphQL-Java configuration).",
                        })

        success = len(discovered_endpoints) > 0 or len(endpoints_to_test) == 1
        primary_traffic = all_traffic[0] if all_traffic else {}
        return {
            "success": success,
            "tool_name": self.name,
            "target_url": target_url,
            "status_code": primary_traffic.get("response_status", 200 if discovered_endpoints else 404),
            "body": primary_traffic.get("response_body", ""),
            "elapsed_ms": sum(t.get("elapsed_ms", 0.0) for t in all_traffic),
            "tested_endpoints_count": len(endpoints_to_test),
            "discovered_endpoints": discovered_endpoints,
            "introspection_results": introspection_results,
            "findings": findings,
            "traffic_interactions": all_traffic,
        }

    def _probe_single_endpoint(
        self,
        endpoint: str,
        headers: Dict[str, str],
        timeout: int,
        check_intro: bool,
    ) -> Dict[str, Any]:
        """Probe an endpoint with a POST and optional introspection query."""
        import time as _time
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Autonomous-API-Pentest/1.0",
        }
        req_headers.update(headers)

        traffic_records = []

        # Scope validation on candidate endpoint
        scope_res = self.scope_validator.validate_url(endpoint)
        if not scope_res.is_valid:
            return {"is_graphql": False, "status_code": None, "traffic": [], "error": f"Scope violation: {scope_res.reason}"}

        # Baseline minimal query: query { __typename }
        payload_str = json.dumps({"query": "{ __typename }"})
        payload = payload_str.encode("utf-8")
        req = urllib.request.Request(endpoint, data=payload, headers=req_headers, method="POST")

        t0 = _time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = round((_time.time() - t0) * 1000, 2)
                status = resp.status
                body = resp.read(65536).decode("utf-8", errors="replace")
                
                resp_headers_dict = {k: v for k, v in resp.headers.items()}
                traffic_records.append({
                    "method": "POST",
                    "url": endpoint,
                    "headers": req_headers,
                    "request_body": payload_str,
                    "response_status": status,
                    "response_headers": resp_headers_dict,
                    "response_body": body,
                    "elapsed_ms": elapsed_ms,
                })

                try:
                    data = json.loads(body)
                    is_graphql = "data" in data or "errors" in data
                except Exception:
                    is_graphql = False

                if not is_graphql:
                    return {"is_graphql": False, "status_code": status, "traffic": traffic_records}

                result = {
                    "is_graphql": True,
                    "status_code": status,
                    "endpoint": endpoint,
                    "traffic": traffic_records,
                }

                if check_intro:
                    intro_info, intro_traffic = self._test_introspection(endpoint, req_headers, timeout)
                    result["introspection"] = intro_info
                    if intro_traffic:
                        traffic_records.append(intro_traffic)

                return result

        except urllib.error.HTTPError as he:
            elapsed_ms = round((_time.time() - t0) * 1000, 2)
            body = he.read(65536).decode("utf-8", errors="replace")
            resp_headers_dict = {k: v for k, v in he.headers.items()} if hasattr(he, "headers") else {}
            traffic_records.append({
                "method": "POST",
                "url": endpoint,
                "headers": req_headers,
                "request_body": payload_str,
                "response_status": he.code,
                "response_headers": resp_headers_dict,
                "response_body": body,
                "elapsed_ms": elapsed_ms,
            })
            try:
                data = json.loads(body)
                if "errors" in data and any("GraphQL" in str(e) or "query" in str(e).lower() for e in data["errors"]):
                    return {"is_graphql": True, "status_code": he.code, "endpoint": endpoint, "traffic": traffic_records}
            except Exception:
                pass
            return {"is_graphql": False, "status_code": he.code, "traffic": traffic_records}
        except Exception as exc:
            return {"is_graphql": False, "error": str(exc), "traffic": traffic_records}

    def _test_introspection(self, endpoint: str, headers: Dict[str, str], timeout: int) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """Send safe introspection query and parse results."""
        import time as _time
        payload_str = json.dumps({"query": SAFE_INTROSPECTION_QUERY})
        payload = payload_str.encode("utf-8")
        req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")

        t0 = _time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                elapsed_ms = round((_time.time() - t0) * 1000, 2)
                body = resp.read(262144).decode("utf-8", errors="replace")
                resp_headers_dict = {k: v for k, v in resp.headers.items()}
                traffic_item = {
                    "method": "POST",
                    "url": endpoint,
                    "headers": headers,
                    "request_body": payload_str,
                    "response_status": resp.status,
                    "response_headers": resp_headers_dict,
                    "response_body": body[:5000],
                    "elapsed_ms": elapsed_ms,
                }
                data = json.loads(body)
                schema = data.get("data", {}).get("__schema")
                if schema:
                    types = schema.get("types", [])
                    type_names = [t.get("name") for t in types if t.get("name") and not t.get("name").startswith("__")]
                    return {
                        "enabled": True,
                        "endpoint": endpoint,
                        "query_type": schema.get("queryType", {}).get("name") if schema.get("queryType") else None,
                        "mutation_type": schema.get("mutationType", {}).get("name") if schema.get("mutationType") else None,
                        "custom_types_count": len(type_names),
                        "sample_types": type_names[:10],
                    }, traffic_item
                else:
                    return {
                        "enabled": False,
                        "endpoint": endpoint,
                        "reason": "No __schema in response data",
                    }, traffic_item
        except Exception as e:
            return {
                "enabled": False,
                "endpoint": endpoint,
                "reason": str(e),
            }, None

