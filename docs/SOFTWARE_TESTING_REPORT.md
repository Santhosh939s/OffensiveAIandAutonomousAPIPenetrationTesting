# Comprehensive Software Testing & Quality Assurance Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Milestone:** Comprehensive Software Testing and Quality Assurance  
**Date:** November 4, 2026  
**Test Suite Status:** **213 Passed / 0 Failed (100% Pass Rate)**  
**Environment:** Windows 10 (AMD64), Python 3.8.10, Localhost (127.0.0.1)  
**Model Under Test:** Fine-Tuned `Qwen2.5-1.5B-Instruct` Q4_K_M GGUF (`models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`)  
**Inference Engine:** Authentic `llama-cli.exe` (Local CPU, strictly non-mock)  

---

## 1. Executive Summary

A comprehensive, multi-phase software testing and quality assurance milestone was conducted across the entire architecture of the Offensive AI and Autonomous API Penetration Testing system. All testing was executed strictly against the controlled localhost API laboratory (`lab/app.py` bound to 127.0.0.1) and internal component boundaries, ensuring zero destructive operations, zero denial-of-service, and zero arbitrary shell execution.

The total automated test suite grew from 172 tests to **213 automated passing tests**, verifying real model inference, full OWASP API Top 10 (2023) coverage, all 5 authentication modes, session isolation, credential masking, concurrency, cooperative cancellation, fault tolerance, dashboard APIs, and deterministic security guardrails.

| Test Phase | Test Suite File | Test Count | Execution Time | Status |
| :--- | :--- | :---: | :---: | :---: |
| **Phase 1: Real Model Inference** | `tests/test_qa_phase1_real_gguf.py` | 1 | 179.10s | **PASSED** |
| **Phase 2: OWASP Top 10 & Baseline** | `tests/test_qa_phase2_owasp_top10.py` | 13 | 1.51s | **PASSED** |
| **Phase 3: Auth & Secret Masking** | `tests/test_qa_phase3_auth_and_config.py` | 10 | 4.33s | **PASSED** |
| **Phase 4: Lifecycle & Diffing** | `tests/test_qa_phase4_lifecycle.py` | 5 | 3.01s | **PASSED** |
| **Phase 5: Dashboard & Reports** | `tests/test_qa_phase5_dashboard_reports.py` | 5 | 4.15s | **PASSED** |
| **Phase 6: Guardrails & Robustness** | `tests/test_qa_phase6_security_robustness.py` | 7 | 2.00s | **PASSED** |
| **Regression Base Suite (Modules 1–8)** | `tests/test_*.py` (21 test files) | 172 | 144.22s | **PASSED** |
| **Total Test Suite** | **27 test files** | **213** | **~5.6 mins** | **100% PASSED** |

---

## 2. Phase 1: Real End-to-End Model Testing

The full autonomous pentesting pipeline was executed against the authentic Local API Security Lab using strictly the quantized local GGUF model (`qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`, 940.37 MB) driven by the native Windows `llama-cli.exe` executable with `allow_mock_fallback=False`.

### Pipeline Steps Verified:
1. **Target Ingestion:** Local lab started on random free localhost port; OpenAPI 3.0 specification discovered at `/openapi.json`.
2. **Session Initialization:** Session registered in SQLite with active status.
3. **Model Inference:** Real GGUF model loaded into memory, ingested compacted API context, and autonomously generated tool proposals.
4. **Guardrail Check:** PolicyEngine deterministically validated model action proposals against scope and budget.
5. **Tool Execution:** `http_request` probe executed against `/api/admin/export`.
6. **Observation Feedback:** HTTP response returned to the model memory.
7. **Evidence Gate:** Deterministic verification rule `BFLA_ADMIN_FUNCTION_BYPASS` validated traffic and confirmed finding.
8. **Report Generation:** Multi-format reports (Markdown, JSON, HTML) synthesized.

### Measured Performance & Memory Metrics:
- **Inference Engine:** Native Windows `llama-cli.exe` (AVX2/CPU)
- **Model Size on Disk:** 940.37 MB (Q4_K_M quantization)
- **Peak Process RAM:** ~1,120 MB (Process-tree working set including controller and llama-cli)
- **Inference Latency:** 2.8s - 5.4s per turn on 4 CPU threads
- **Token Budget:** Ingested context held under 400 tokens via compact endpoint schemas

---

## 3. Phase 2: OWASP API Security Top 10 (2023) Validation

All 10 vulnerability categories defined in the OWASP API Security Top 10 (2023) standard were verified against dedicated local lab endpoints, confirming accurate CVSS v3.1 scoring, CWE identifiers, technical impact assessments, and safe reproduction steps.

| Category | Endpoint Tested | Vulnerability Type | CWE | CVSS Base | Severity | Approved Verification Rule |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **API1:2023** | `/api/users/{id}`, `/api/orders/{id}` | BOLA / IDOR | CWE-639 | 8.6 | HIGH | `BOLA_CROSS_ACCOUNT_LEAK` |
| **API2:2023** | `/api/login` | Weak Auth & 'none' JWT | CWE-347 | 8.8 | HIGH | `TOKEN_ALGORITHM_NONE_ACCEPTED` |
| **API3:2023** | `/api/users/{id}` (PUT) | BOPLA / Mass Assignment | CWE-915 | 7.5 | HIGH | `ROLE_ELEVATION_VERIFIED` |
| **API4:2023** | `/api/items/batch` | Unrestricted Resource Consumption | CWE-770 | 6.5 | MEDIUM | `UNRESTRICTED_RESOURCE_CONSUMPTION` |
| **API5:2023** | `/api/admin/export` | Broken Function Level Auth (BFLA) | CWE-285 | 8.5 | HIGH | `BFLA_ADMIN_FUNCTION_BYPASS` |
| **API6:2023** | `/api/coupons/apply` | Business Flow Abuse | CWE-799 | 6.5 | MEDIUM | `BUSINESS_FLOW_UNRESTRICTED_ACCESS` |
| **API7:2023** | `/api/integrations/fetch` | Server-Side Request Forgery (SSRF) | CWE-918 | 8.6 | HIGH | `SSRF_INTERNAL_ENDPOINT_LEAK` |
| **API8:2023** | `/api/search` & `/graphql` | SQL Injection & Introspection | CWE-89 / CWE-16 | 9.8 / 5.3 | CRITICAL / LOW | `SQL_SYNTAX_ERROR_MATCH` / `GRAPHQL_INTROSPECTION_EXPOSED` |
| **API9:2023** | `/api/v1/users/export` | Shadow / Deprecated API | CWE-1059 | 6.5 | MEDIUM | `SHADOW_OR_DEPRECATED_API_EXPOSED` |
| **API10:2023** | `/api/integrations/webhook` | Unsafe Downstream API Consumption | CWE-20 | 7.5 | HIGH | `UNSAFE_DOWNSTREAM_API_CONSUMPTION` |

### Baseline & False-Positive Demotion Gates:
- **Clean Baselines:** `/health` and `/api/items` returned clean 200 responses and were recorded as `NOT_DEMONSTRATED`, preventing false positives.
- **Verification Gates:** An asserted `CONFIRMED` status without an approved verification rule or without documented traffic evidence was automatically demoted to `SUSPECTED` with audit notice `[AUTO-DEMOTED FROM CONFIRMED]`.

---

## 4. Phase 3: Authentication Robustness and Secret Masking

Verified the complete authentication lifecycle across all 5 operational authentication modes, invalid credentials handling, and end-to-end secret masking.

### Supported Authentication Modes Tested:
1. `none`: Public reconnaissance and unauthenticated probes.
2. `bearer`: Construction and injection of `Authorization: Bearer <token>` headers.
3. `api_key`: Custom API key headers (e.g. `X-API-Key: <key>`).
4. `basic`: Base64 encoded credentials (`Authorization: Basic <base64>`).
5. `custom`: Custom header dictionaries (e.g. `X-Tenant-ID`, `X-Client-Signature`).

### Secret Masking Across Architectural Layers:
- **Traffic Inspector:** Tokens, passwords, cookies, and keys masked (`***` or `Bearer ***`) via `mask_sensitive_traffic_data`.
- **Model Prompts:** Injected `auth_context` masked before inclusion in LLM prompt context to eliminate prompt leaking.
- **Evidence Database:** Sanitized traffic responses strip cleartext secrets.
- **Security Reports:** Markdown, JSON, and HTML reports verify that canary secrets (`report_leak_canary_token_999`) never appear in report output.

---

## 5. Phase 4: Lifecycle Management, Concurrency, and Regression Diffing

Verified the stability and recovery mechanics of long-running and concurrent penetration testing sessions.

### Lifecycle Capabilities Verified:
- **Multi-Session Concurrency:** 3 concurrent assessment threads executed simultaneously against localhost without SQLite locking or database contention.
- **Cooperative Cancellation:** Tested `cancel_assessment(session_id)`; `threading.Event` cooperatively stopped execution within one turn, cleanly setting status to `CANCELLED`.
- **Fault Tolerance:** Injected unhandled model client exceptions (`RuntimeError`); controller caught exception, recorded failure details, updated session to `ERROR`, and released database locks safely.
- **Historical Session Restoration:** Re-opened past assessment sessions across new manager instances; verified full recovery of status, findings count, traffic records, and report generation.
- **Cross-Session Regression Diffing:** Executed baseline and regression scans; verified precise calculation of:
  - `new_findings`: 1 (Unrestricted Resource Consumption)
  - `resolved_findings`: 1 (SQL Injection)
  - `persistent_findings`: 1 (BOLA / IDOR)
  - `risk_delta`: Calculated accurately between session risk scores.

---

## 6. Phase 5: Dashboard and Multi-Format Reporting

Verified all 17 REST and HTML routes in `dashboard/app.py` and the full reporting engine.

### Verified Endpoints:
- `GET /`: Serves complete dark-themed Single Page Application with all navigation tabs.
- `GET /api/system/status` & `GET /api/system/resources`: Returns host RAM, process working set, and model availability.
- `POST /api/assessments/start`: Validates target URL, scheme, timeouts, and auth settings.
- `GET /api/assessments`: Lists historical and active sessions.
- `GET /api/assessments/<id>/status`: Returns progress percentage, turns taken, and active phase.
- `GET /api/assessments/<id>/findings`: Returns findings with category, CVSS, and verification rules.
- `GET /api/assessments/<id>/traffic`: Returns sanitized traffic logs with credentials masked.
- `GET /api/assessments/<id>/risk`: Returns risk scorecard and severity counts.
- `GET /api/assessments/compare`: Returns regression diffing results.
- `GET /api/assessments/<id>/report`: Synthesizes Markdown assessment report.
- `GET /api/assessments/<id>/report/json`: Exports structured JSON report.
- `GET /api/assessments/<id>/report/html`: Renders standalone, styled HTML report.
- `GET /api/assessments/<id>/report/download`: Returns report file with `Content-Disposition: attachment`.

---

## 7. Phase 6: Security Guardrails & Operational Robustness

Verified that the application enforces strict boundaries preventing out-of-scope traffic and unauthorized actions.

### Verified Guardrails:
- **Out-of-Scope Target Blocking:** ScopeValidator blocked `https://google.com`, `http://malicious-external-target.com`, and `http://192.168.1.100` before dispatching any network packets.
- **Illegal Schemes Rejected:** `file://`, `ftp://`, `gopher://`, `javascript:`, and malformed strings rejected with HTTP 400.
- **Destructive Commands Blocked:** `bash_exec`, `cmd_exec`, `rm -rf`, and destructive SQL (`DROP TABLE`, `DELETE FROM`) blocked by PolicyEngine.
- **Per-Endpoint Probe Ceiling:** Maximum probes per endpoint (e.g. 2 probes) enforced; further probes against the same endpoint rejected to prevent denial of service.
- **Cumulative Request & Turn Limits:** Reaching `max_requests_per_session` or `max_turns` terminates assessment cleanly with structured termination reason.

---

## 8. Defects Discovered and Resolved During Testing

| # | Component | Defect Discovered | Root Cause | Fix Implemented |
| :---: | :--- | :--- | :--- | :--- |
| **1** | `controller/reporting/risk_engine.py` | "Unrestricted Resource Consumption" mapped to CWE-94 (RCE) instead of CWE-770 | Substring match `if key in cat_lower` matched `"rce"` inside `"resou[rce]"` | Added `_find_best_match` with exact matching, descending key length sort, and whole-word boundary `\b` for short acronyms. |
| **2** | `controller/agent/autonomous_controller.py` | Unhandled brain exception left session permanently in `ACTIVE` state | `run_assessment` lacked top-level `try...except` block | Wrapped core workflow in `_run_assessment_workflow` with `try...except`; updates status to `ERROR` and returns structured failure. |
| **3** | `controller/storage/evidence_store.py` | Missing `list_sessions()` method required by session manager | Historical session list relied on raw queries | Added `list_sessions(limit, offset)` in EvidenceStore and delegated in DashboardSessionManager. |
| **4** | `lab/app.py` | Local lab lacked explicit endpoints for API4 and API7 | Only 8 of 10 OWASP categories had dedicated lab routes | Added `/api/items/batch` (API4 Resource Limits) and `/api/integrations/fetch` (API7 SSRF) to `lab/app.py` and OpenAPI spec. |
| **5** | `controller/brain/local_cpu_client.py` | `llama-cli.exe` continued generating past `<|im_end|>` stop token | Missing `-r "<|im_end|>"` parameter in command invocation | Added `-r "<|im_end|>"` to `cmd` arguments, preventing runaway generation and token overflow. |

---

## 9. Current Operational Boundaries & Limitations

1. **Hardware Viability on 8 GB Laptops:**
   - Real GGUF model execution via CPU consumes ~1.1 GB process RAM and runs smoothly on 4 CPU threads.
   - For rapid automated regression testing across 200+ unit tests, `DeterministicMockBrainClient` is used to complete the entire suite in ~2.5 minutes, while `test_qa_phase1_real_gguf.py` verifies the authentic GGUF model.
2. **Authorized Scope:**
   - All tests run strictly against `127.0.0.1` and `localhost`. External internet access is disabled during testing.
3. **Preservation of Artifacts:**
   - No models were retrained, no checkpoints modified, and zero git commits or pushes were performed.

