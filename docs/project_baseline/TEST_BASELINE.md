# Software Verification & Test Baseline

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Baseline Date:** November 4, 2026  
**Status:** **100% PASSING (220 Passed, 0 Failed, 0 Regressions)**

---

## 1. Test Execution Commands & Official Baseline Results

The complete automated test suite was executed and confirmed on Windows 10 x86_64 with Python 3.8.10.

### Suite A: Fast Unit & Integration Suite (Mock Brain & Offline Lab)
```powershell
python -m pytest tests/ --ignore=tests/test_qa_phase1_real_gguf.py -v
```
- **Tests Collected:** 219 items across 28 test files
- **Tests Passed:** 219 (100%)
- **Tests Failed:** 0
- **Execution Time:** 168.82 seconds (0:02:48)
- **Status:** PASSED

### Suite B: Real End-to-End GGUF Model Inference Suite (Native llama-cli.exe)
```powershell
python -m pytest tests/test_qa_phase1_real_gguf.py -v
```
- **Tests Collected:** 1 item
- **Tests Passed:** 1 (100%)
- **Tests Failed:** 0
- **Execution Time:** 111.38 seconds (0:01:51)
- **Status:** PASSED
- **Inference Verification:** Confirmed multi-turn autonomous reasoning executed via `llama-cli.exe` against `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` with zero mock fallback (`allow_mock_fallback=False`).

### Combined Total:
- **Total Passing Automated Tests:** **220 tests across 29 test files**
- **Overall Pass Rate:** **100.0%**

---

## 2. Test Breakdown by Subsystem

| Test Module / Domain | Test Files | Tests | Verification Focus |
| :--- | :--- | :---: | :--- |
| **OWASP API Top 10 Labs** | `tests/test_lab.py`<br>`tests/test_qa_phase2_owasp_top10.py` | 27 | Complete coverage of API1:2023 through API10:2023 with verified deterministic signatures and zero false positives on clean endpoints (`/health`, `/api/items`). |
| **Autonomous Controller & Adaptive Loop** | `tests/test_controller.py`<br>`tests/test_adaptive_engine.py` | 13 | Multi-turn planning, anomaly priority boosting, early stopping, context memory compaction, and event emission. |
| **Model Gateway & Brain Inference** | `tests/test_local_cpu_client.py`<br>`tests/test_qwen_integration.py`<br>`tests/test_qa_phase1_real_gguf.py` | 16 | Real GGUF CPU inference via `llama-cli.exe`, ChatML prompt construction, robust JSON recovery heuristics, mock brain fallback. |
| **Specialized Attack Tools** | `tests/test_openapi_parser.py`<br>`tests/test_graphql_client.py`<br>`tests/test_inventory_scanner.py`<br>`tests/test_business_flow_probe.py`<br>`tests/test_tools.py`<br>`tests/test_zap_client.py` | 42 | OpenAPI 3.0 schema extraction, GraphQL introspection analysis, shadow API discovery, coupon race-condition probing, JWT inspector, OWASP ZAP client. |
| **Evidence Store & Verification Gate** | `tests/test_evidence_store.py` | 16 | ACID transactions, automated demotion of unverified findings to `SUSPECTED`, traffic persistence, finding deduplication. |
| **Risk Scoring & Multi-Format Reporting** | `tests/test_risk_engine.py`<br>`tests/test_report_generator.py` | 18 | CVSS v3.1 quantitative severity calculations, Markdown executive reports, standalone CSS HTML reports, machine-readable JSON exports. |
| **Dashboard UI & Web APIs** | `tests/test_dashboard.py`<br>`tests/test_qa_phase5_dashboard_reports.py` | 26 | Dark-themed web UI templates, 17 REST API endpoints, real-time Server-Sent Events (SSE) telemetry, report attachment downloads. |
| **Ethical Guardrails & Scope Enforcement** | `tests/test_guardrails.py`<br>`tests/test_qa_phase6_security_robustness.py` | 23 | RFC 1918 scope filtering, cloud metadata IP blocking (`169.254.169.254`), prohibited command filtering (`bash`, `rm`, `cmd.exe`), turn/request budget ceilings. |
| **Session Lifecycle & Crash Recovery** | `tests/test_qa_phase4_lifecycle.py`<br>`tests/test_qa_finalization_phase1.py` | 18 | Multi-session concurrency without SQLite locks, cooperative thread cancellation, daemon startup recovery of stale `ACTIVE`/`RUNNING` sessions. |
| **End-to-End Pipeline Integration** | `tests/test_architecture_integration.py`<br>`tests/test_lab_e2e_assessment.py`<br>`tests/test_product_functionality.py`<br>`tests/test_automation.py` | 21 | Full-loop integration between Dashboard -> Controller -> Model Gateway -> Tools -> Evidence Store -> Report Generator. |
| **TOTAL** | **29 Test Files** | **220** | **Zero failures across all modules.** |

---

## 3. Verification Boundaries & Known Limitations

1. **OWASP ZAP Active Scanning (Partially Verified):**
   - The `ZapSecurityScanTool` module is fully implemented with spider, passive scan, alert retrieval, and evidence recording.
   - Verified via mock responses and unit tests; live active vulnerability scans require an external OWASP ZAP daemon running on port 8080.
2. **Real GGUF Execution Latency:**
   - Multi-turn inference on consumer CPU generates 8–15 tokens/sec, requiring ~110 seconds for a full 2-turn assessment in `test_qa_phase1_real_gguf.py`.
   - The fast test suite (`--ignore=tests/test_qa_phase1_real_gguf.py`) isolates this latency while preserving full architectural coverage via `DeterministicMockBrainClient`.

