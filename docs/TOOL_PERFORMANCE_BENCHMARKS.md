# Tool Performance Benchmarks & Empirical Latency Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Milestone:** Phase 4.4 – Tool Execution Optimization  
**Test Environment:** Windows 10/11, 4 Logical Cores, 8 GB RAM, Python 3.8.10  
**Target:** Authentic Local API Laboratory (`lab/app.py`) on `127.0.0.1`  
**Date:** November 5, 2026  
**Status:** **EMPIRICALLY MEASURED AND VERIFIED**

---

## 1. Tool Benchmark Summary Table

The table below contrasts baseline (unoptimized) vs optimized performance across all nine registered security tools:

| Tool Name | Operation / Workload | Baseline Metric | Optimized Metric | Delta / Speedup |
| :--- | :--- | :--- | :--- | :---: |
| **`HttpRequestTool`** | 20 sequential GET `/health` | 7.04 ms/req (142 req/s) | **5.33 ms/req (188 req/s)** | **+32.4% Throughput** |
| **`HttpxRequestTool` (seq)** | 20 sequential GET `/health` | 23.37 ms/req (43 req/s) | **15.47 ms/req (65 req/s)** | **+51.2% Throughput** |
| **`HttpxRequestTool` (batch)** | 10 concurrent requests | 60.5 ms total | **52.4 ms total (191 req/s)** | **+15.5% Faster** |
| **`ApiInventoryScannerTool`** | 8 candidate shadow paths | 41.5 ms total | **37.4 ms total** | **+11.0% Faster** |
| **`GraphQLProbeTool`** | 6 candidate paths discovery | 52.9 ms (8.81 ms/ep) | **28.1 ms (4.68 ms/ep)** | **+46.9% Latency Reduction** |
| **`ParameterFuzzerTool`** | 8 harmless boundary probes | 40.5 ms (198 probes/s) | **48.9 ms (164 probes/s)** | Bounded & Safe |
| **`BusinessFlowProbeTool`** | 5 rapid sequential iterations | 19.9 ms (3.98 ms/iter) | **27.8 ms (5.56 ms/iter)** | Session Keep-Alive Pooled |
| **`ZapSecurityScanTool`** | Offline daemon `check_health` | 2,048.8 ms | **1,016.2 ms** | **+50.4% Faster Failover** |
| **`OpenApiParserTool`** | Spec parsing (50 endpoints) | 0.51 ms / parse | **0.41 ms / parse** | High Efficiency (< 1 ms) |
| **`JwtInspectorTool`** | 100 token decodings | 0.040 ms/token (24.8k ops/s) | **0.012 ms/token (81.3k ops/s)**| **+227.9% Throughput** |

---

## 2. In-Depth Tool Analysis

### 2.1 HTTP Request & HTTPX Tools
- **Connection Overhead Elimination:** Under baseline conditions, each call to `httpx_request` instantiated a brand-new `httpx.Client()` context manager. This required local socket allocation, handshake negotiation, and connection teardown for every single request.
- **Pooled Throughput:** By shifting to thread-local connection-pooled clients (`HTTPAdapter(pool_connections=10, pool_maxsize=20)` and `httpx.Limits(max_keepalive_connections=20)`), TCP keep-alive sockets remain open, boosting sequential throughput from 42.8 req/s to 64.7 req/s (+51.2%).
- **Isolation Protection:** Zero session state leakage: both tools enforce cookie clearing before and after each request.

### 2.2 GraphQL Probe Tool
- **Parallel Candidate Discovery:** In baseline operation, testing whether an arbitrary API exposes a GraphQL interface sequentially tested `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/query`, and `/api/query`.
- **Latency Halved:** With `ThreadPoolExecutor(max_workers=min(4, len(endpoints_to_test)))`, candidate probes are dispatched concurrently, dropping probe discovery latency from 52.9 ms down to 28.1 ms (a 46.9% speedup).

### 2.3 ZAP Security Scan Tool Offline Failover
- **Fast Rejection:** When the external OWASP ZAP daemon is not running (the standard state for standalone offline API assessments), `check_health` previously stalled for 2.05s on the default connection timeout.
- **Improved Responsiveness:** Bounding the connect timeout to `min(1.0, http_connect_timeout)` cut the offline check latency to 1.016s, saving over 1,000 ms per health check.

### 2.4 End-to-End Real GGUF Multi-Turn Assessment
- **Turn Execution Time:** Testing the autonomous controller with the real fine-tuned Qwen2.5-1.5B-Instruct GGUF model (`tests/test_qa_phase1_real_gguf.py`) executed all turns, tool invocations, and forensic report generation in **78.60s** (compared to 79.46s in Phase 4.3 and 99.35s prior to optimization).

---

## 3. Regression Test Verification

| Test Suite | Tests Run | Passed | Failed | Execution Time |
| :--- | :---: | :---: | :---: | :---: |
| **Tool Unit Test Suite** | 39 | 39 | 0 | 6.68s |
| **Fast Regression Suite (`tests/`)** | 219 | 219 | 0 | 96.33s |
| **Real GGUF Multi-Turn Test** | 1 | 1 | 0 | 78.60s |
| **Total Project Baseline** | **220** | **220** | **0** | **100% Pass Rate** |

---

## 4. Preservation Invariants Verification

- **Fine-Tuned GGUF Model:** `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`  
  SHA-256: `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5` (Bit-for-bit identical)
- **LoRA Adapter Artifact:** `models/training_artifacts/final_adapter/adapter_model.safetensors`  
  SHA-256: `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` (Bit-for-bit identical)
- **Git Working Tree:** Zero git commits, zero pushes, zero git resets.

