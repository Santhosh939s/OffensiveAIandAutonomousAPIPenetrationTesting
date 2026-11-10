# API Security Testing Tools Status Report

**Package:** `controller/tools/`  
**Tool Registry:** `ToolRegistry` (`controller/tools/registry.py`)  
**Registered Tools:** 7 Tools  
**Date:** November 3, 2026  

---

## 1. Tool Suite Inventory & Verification Status

| Tool Name | Class | Category | Destructive? | Implementation Status | Test Coverage |
| :--- | :--- | :--- | :---: | :---: | :---: |
| `http_request` | `HttpRequestTool` | Active Probe | No | Fully Implemented | 100% Passed (`test_tools.py`) |
| `httpx_request` | `HttpxRequestTool` | Active Probe | No | Fully Implemented | 100% Passed (`test_httpx_client.py`) |
| `openapi_parser` | `OpenApiParserTool` | Reconnaissance | No | Fully Implemented | 100% Passed (`test_openapi_parser.py`) |
| `jwt_inspector` | `JwtInspectorTool` | Passive Analysis | No | Fully Implemented | 100% Passed (`test_tools.py`) |
| `parameter_fuzzer`| `ParameterFuzzerTool` | Active Probe | No | Fully Implemented | 100% Passed (`test_tools.py`) |
| `graphql_probe` | `GraphQLProbeTool` | Reconnaissance | No | **Newly Implemented & Verified** | 100% Passed (`test_graphql_client.py`) |
| `zap_security_scan`| `ZapSecurityScanTool`| Active/Passive | Configurable| Fully Implemented | 100% Passed (`test_zap_client.py`) |

---

## 2. Tool Details & Verification Constraints

### A. GraphQL Probe Tool (`controller/tools/graphql_client.py`)
- **Capability:** Discovers GraphQL endpoints across common paths (`/graphql`, `/api/graphql`, `/query`).
- **Safety Guarantee:** Dispatches safe, read-only introspection queries (`query { __schema { ... } }`) without executing any mutations.
- **Reporting:** Automatically records `GRAPHQL_INTROSPECTION_ENABLED` findings mapped to OWASP API8:2023 Security Misconfiguration.

### B. OpenAPI / Swagger Parser (`controller/tools/openapi_parser.py`)
- **Capability:** Ingests local files (`.json`, `.yaml`) or live remote documentation endpoints (`/openapi.json`, `/swagger.json`).
- **Security Check:** Validates specification URLs against `ScopeValidator` before fetching, preventing SSRF via malicious documentation URLs.

### C. JWT Inspector Tool (`controller/tools/jwt_inspector.py`)
- **Capability:** Decodes header, payload, and signature segments offline without remote dependencies.
- **Vulnerability Checks:** Identifies `alg: "none"` bypass attempts, expired timestamps, excessive lifespans, and sensitive claim exposure.

### D. OWASP ZAP Integration (`controller/tools/zap_client.py`)
- **Live vs. Offline Daemon Detection:** The ZAP client actively probes the local ZAP API endpoint (`http://localhost:8080/JSON/core/view/version/`).
- **Zero Mock Claims:** If the ZAP daemon is not running locally, the tool returns an explicit `service_unavailable` diagnostic instead of faking scan results.
- **Guardrail Enforcement:** Active scans (`ascan`) are blocked by default unless explicitly approved in the session configuration.

