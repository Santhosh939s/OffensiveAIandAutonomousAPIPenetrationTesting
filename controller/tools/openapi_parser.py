"""OpenAPI Discovery Tool for Autonomous API Penetration Testing.

Parses OpenAPI 3.x and Swagger 2.0 specifications in JSON or YAML formats from
local files or authorized localhost URLs. Extracts routes, HTTP methods,
parameters, request bodies, authentication schemes, and responses, converting
them into structured inputs for the Qwen model brain's test planning.
"""

import json
import os
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
import yaml

from controller.config import DEFAULT_CONFIG, AgentConfig
from controller.guardrails.scope_validator import ScopeValidator
from controller.tools.registry import BaseTool


class OpenApiParserTool(BaseTool):
    """Tool for discovering and parsing OpenAPI/Swagger specifications."""

    def __init__(self, config: Optional[AgentConfig] = None, scope_validator: Optional[ScopeValidator] = None):
        self.config = config or DEFAULT_CONFIG
        self.scope_validator = scope_validator or ScopeValidator(self.config)
        super().__init__(
            name="openapi_parser",
            description="Parses OpenAPI 3.x or Swagger 2.0 JSON/YAML specifications from a local file path or authorized localhost URL, extracting endpoints, parameters, and authentication schemes.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "spec_source": {
                        "type": "string",
                        "description": "Local file path (e.g. lab_spec.json, spec.yaml) or authorized localhost URL (e.g. http://127.0.0.1:5000/openapi.json)",
                    },
                    "spec_content": {
                        "type": "string",
                        "description": "Optional raw JSON or YAML text content of the specification",
                    },
                },
            },
            category="recon",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute OpenAPI specification discovery and parsing."""
        spec_source = kwargs.get("spec_source")
        spec_content = kwargs.get("spec_content")

        if not spec_source and not spec_content:
            return {
                "success": False,
                "error": "Either 'spec_source' (file/URL) or 'spec_content' (raw text) must be provided",
                "endpoints_count": 0,
                "endpoints": [],
            }

        # Step 1: Load raw specification content
        raw_text, load_error = self._load_spec_content(spec_source, spec_content)
        if load_error:
            return {
                "success": False,
                "error": load_error,
                "endpoints_count": 0,
                "endpoints": [],
            }

        # Step 2: Parse raw text into dictionary (JSON or YAML)
        spec_dict, parse_error = self._parse_to_dict(raw_text)
        if parse_error:
            return {
                "success": False,
                "error": parse_error,
                "endpoints_count": 0,
                "endpoints": [],
            }

        # Step 3: Extract specification metadata and endpoints
        return self._extract_specification_data(spec_dict, source=spec_source or "raw_content")

    def _load_spec_content(
        self, spec_source: Optional[str], spec_content: Optional[str]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Load text content from raw string, localhost URL, or local file."""
        if spec_content and isinstance(spec_content, str) and spec_content.strip():
            return spec_content.strip(), None

        source = str(spec_source).strip()

        # Check if URL
        if source.lower().startswith(("http://", "https://")):
            # Validate target scope
            scope_res = self.scope_validator.validate_url(source)
            if not scope_res.is_valid:
                return None, f"Scope violation for specification URL: {scope_res.reason}"

            try:
                resp = requests.get(
                    source,
                    timeout=self.config.http_timeout,
                    headers={"User-Agent": "AutonomousAPISecurityAgent/OpenAPI-Discovery"},
                    allow_redirects=False,
                )
                if resp.status_code != 200:
                    return None, f"Failed to retrieve specification from URL (HTTP {resp.status_code})"
                if len(resp.content) > self.config.max_response_body_bytes * 5:  # 250KB cap
                    return None, f"Specification exceeds maximum allowed size ({len(resp.content)} bytes)"
                return resp.text, None
            except Exception as exc:
                return None, f"Network error retrieving specification URL: {exc}"

        # Otherwise treat as local file path
        if not os.path.exists(source):
            return None, f"Specification file not found at path: {source}"

        try:
            with open(source, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            return content, None
        except Exception as exc:
            return None, f"Failed to read specification file: {exc}"

    def _parse_to_dict(self, raw_text: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Parse raw text into a Python dictionary supporting JSON and YAML."""
        if not raw_text or not raw_text.strip():
            return None, "Empty specification content provided"

        # Try JSON first
        try:
            data = json.loads(raw_text)
            if isinstance(data, dict):
                return data, None
        except json.JSONDecodeError:
            pass

        # Try YAML
        try:
            data = yaml.safe_load(raw_text)
            if isinstance(data, dict):
                return data, None
            return None, "Parsed YAML did not produce an object/dictionary"
        except yaml.YAMLError as yerr:
            return None, f"Failed to parse specification as JSON or YAML: {yerr}"

    def _extract_specification_data(self, spec: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Extract structured information from OpenAPI 3.x or Swagger 2.0 definition."""
        is_openapi_3 = "openapi" in spec
        is_swagger_2 = "swagger" in spec and str(spec.get("swagger", "")).startswith("2.")

        if not (is_openapi_3 or is_swagger_2):
            return {
                "success": False,
                "error": "Unsupported specification format. Must be OpenAPI 3.x ('openapi' key) or Swagger 2.0 ('swagger': '2.0')",
                "endpoints_count": 0,
                "endpoints": [],
            }

        spec_version = spec.get("openapi") or spec.get("swagger", "2.0")
        info = spec.get("info", {})
        title = info.get("title", "Discovered API")
        version = info.get("version", "1.0.0")
        description = info.get("description", "")

        # Base URLs / Servers
        base_urls: List[str] = []
        if is_openapi_3:
            servers = spec.get("servers", [])
            for s in servers:
                if isinstance(s, dict) and "url" in s:
                    base_urls.append(s["url"])
        else:
            host = spec.get("host", "")
            base_path = spec.get("basePath", "/")
            schemes = spec.get("schemes", ["http"])
            if host:
                for scheme in schemes:
                    base_urls.append(f"{scheme}://{host}{base_path}".rstrip("/"))

        # Security Schemes
        security_schemes = self._extract_security_schemes(spec, is_openapi_3)

        # Endpoints
        paths = spec.get("paths", {})
        discovered_endpoints = []
        planning_endpoints = []

        valid_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

        for path_str, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            path_params = path_item.get("parameters", [])

            for method_key, operation in path_item.items():
                method_lower = method_key.lower()
                if method_lower not in valid_methods or not isinstance(operation, dict):
                    continue

                method_upper = method_lower.upper()
                combined_params = list(path_params) + operation.get("parameters", [])

                extracted_path_params = []
                extracted_query_params = []
                extracted_header_params = []
                body_schema = None

                for p in combined_params:
                    if not isinstance(p, dict):
                        continue
                    p_in = p.get("in", "")
                    p_name = p.get("name", "")
                    p_type = p.get("type") or (p.get("schema", {}).get("type") if isinstance(p.get("schema"), dict) else "string")
                    p_req = bool(p.get("required", False))

                    param_info = {
                        "name": p_name,
                        "type": p_type,
                        "required": p_req,
                        "description": p.get("description", ""),
                    }

                    if p_in == "path":
                        extracted_path_params.append(param_info)
                    elif p_in == "query":
                        extracted_query_params.append(param_info)
                    elif p_in == "header":
                        extracted_header_params.append(param_info)
                    elif p_in == "body" and not is_openapi_3:
                        # Swagger 2.0 body parameter
                        body_schema = p.get("schema", {})

                # OpenAPI 3 requestBody extraction
                if is_openapi_3 and "requestBody" in operation:
                    rb = operation["requestBody"]
                    if isinstance(rb, dict):
                        content = rb.get("content", {})
                        for mime, mime_def in content.items():
                            if isinstance(mime_def, dict) and "schema" in mime_def:
                                body_schema = {
                                    "content_type": mime,
                                    "schema": mime_def["schema"],
                                    "required": rb.get("required", False),
                                }
                                break

                # Extract response definitions
                responses = {}
                for status_code, resp_obj in operation.get("responses", {}).items():
                    if isinstance(resp_obj, dict):
                        responses[str(status_code)] = resp_obj.get("description", "")

                # Heuristic testing focus
                focus_tags = []
                if extracted_path_params:
                    focus_tags.append("BOLA/IDOR")
                if extracted_query_params:
                    focus_tags.append("Parameter Injection")
                if body_schema:
                    focus_tags.append("Mass Assignment & Input Validation")
                if operation.get("security") or spec.get("security"):
                    focus_tags.append("Auth Verification")

                endpoint_record = {
                    "path": path_str,
                    "method": method_upper,
                    "operation_id": operation.get("operationId", f"{method_lower}_{path_str}"),
                    "summary": operation.get("summary", ""),
                    "description": operation.get("description", ""),
                    "path_parameters": extracted_path_params,
                    "query_parameters": extracted_query_params,
                    "header_parameters": extracted_header_params,
                    "request_body_schema": body_schema,
                    "responses": responses,
                    "security": operation.get("security", []),
                    "suggested_test_focus": focus_tags or ["Baseline Assessment"],
                }
                discovered_endpoints.append(endpoint_record)

                # Format compatible with AutonomousController / Qwen Brain planning
                param_names = [p["name"] for p in (extracted_query_params + extracted_path_params)]
                planning_endpoints.append({
                    "path": path_str,
                    "method": method_upper,
                    "parameters": param_names,
                    "body_schema": body_schema,
                    "has_auth": bool(operation.get("security") or spec.get("security")),
                    "focus": focus_tags,
                })

        return {
            "success": True,
            "spec_source": source,
            "spec_version": str(spec_version),
            "title": title,
            "version": version,
            "description": description,
            "base_urls": base_urls,
            "security_schemes": security_schemes,
            "endpoints_count": len(discovered_endpoints),
            "endpoints": discovered_endpoints,
            "planning_endpoints": planning_endpoints,
            "error": None,
        }

    def _extract_security_schemes(self, spec: Dict[str, Any], is_openapi_3: bool) -> Dict[str, Any]:
        """Extract declared authentication / security schemes."""
        schemes = {}
        if is_openapi_3:
            raw_schemes = spec.get("components", {}).get("securitySchemes", {})
        else:
            raw_schemes = spec.get("securityDefinitions", {})

        if isinstance(raw_schemes, dict):
            for name, scheme_def in raw_schemes.items():
                if isinstance(scheme_def, dict):
                    schemes[name] = {
                        "type": scheme_def.get("type", "unknown"),
                        "scheme": scheme_def.get("scheme", ""),
                        "bearer_format": scheme_def.get("bearerFormat", ""),
                        "in": scheme_def.get("in", ""),
                        "name": scheme_def.get("name", ""),
                    }
        return schemes

