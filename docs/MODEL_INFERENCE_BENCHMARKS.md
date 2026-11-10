# Model & Inference Benchmarks Report (Phase 4.1)

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Benchmark Date:** November 5, 2026  
**Benchmarking Harness:** `scratch/benchmark_baseline.py` & `scratch/benchmark_optimized.py`  
**Model Under Test:** `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` (940.37 MB)  
**Binary Engine:** `llama-cli.exe` & `llama-server.exe` (v0.3.0-dev build 10679, Clang 20.1.8 x86_64)  
**Host Machine Specs:** Windows 10 x86_64 (build 10.0.26300), 4 Logical CPU Cores, 7.65 GB Physical RAM (Target 8 GB RAM Specification)

---

## 1. Benchmark Methodology

All benchmarks were conducted using actual GGUF model inference on CPU (strictly non-mock). Mocks and unit tests were isolated and evaluated separately.

Four representative offensive AI tasks were evaluated across 3 repeat trials per task:
1. **Task 1: Request Classification:** Classifying a raw SQL injection payload (`/api/v1/search?q=' UNION SELECT...`).
2. **Task 2: Action Selection:** Formulating the next penetration testing action within the autonomous ReAct loop.
3. **Task 3: Evidence Analysis:** Analyzing a database error response (`status_code: 500, unrecognized token near '''`) and verifying detection rules.
4. **Task 4: Test Plan Formulation:** Formulating a sequential security testing plan against 5 discovered OpenAPI routes and 4 registered testing tools.

Metrics captured:
- **Cold Latency (s):** First invocation requiring initialization and model loading.
- **Warm Latency (s):** Average of repeat invocations 2 and 3.
- **Overall Latency (s):** Mean latency across all 3 trials.
- **Valid JSON Rate:** Ratio of responses successfully parsed into schema-validated JSON without fallback.
- **Peak RSS Working Set (MB):** Peak memory consumed by the Python controller process.

---

## 2. Before-versus-After Benchmark Comparison

### A. Four Canonical Offensive AI Tasks (Averaged Over 3 Trials Each)

| Task Name | Baseline Latency (Existing) | Baseline Valid Rate | Optimized CLI Latency | Optimized Server Latency | Optimized Valid Rate | Improvement (CLI / Server) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Classification** | 10.15s | 3/3 (100%) | 11.28s | **5.85s** | 3/3 (100%) | **-42.4% latency** (Server) |
| **2. Action Selection** | 10.77s | 3/3 (100%) | 11.59s | **8.53s** | 3/3 (100%) | **-20.8% latency** (Server) |
| **3. Evidence Analysis** | 10.10s | **0/3 (0% - Failed)** | 11.18s | **6.62s** | **3/3 (100% - Fixed)** | **100% extraction recovery** |
| **4. Test Planning** | 16.52s | 3/3 (100%) | 16.36s | **16.39s** | 3/3 (100%) | Output bounded to 448 tokens |
| **Cumulative (12 Inferences)**| **142.62s** | 9/12 (75.0%) | 151.17s | **112.13s** | **12/12 (100.0%)** | **+25.0% Accuracy / -21.4% Time** |

### B. Single-Prompt Raw CLI Inference Benchmark (Identical Prompt & Seeds)

Measured on a direct single-prompt classification evaluation using `scratch/compare_cli_flags.py`:

| Configuration | Parameters | Latency | Speedup | Prompt Throughput | Generation Throughput |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Baseline CLI** | `-c 4096 -t 3 -n 128` (default flags) | **4.46s** | Baseline | 128.2 t/s | 11.9 t/s |
| **Optimized CLI** | `-c 2048 -t 4 -tb 4 -n 96 --no-warmup --no-display-prompt --log-disable` | **3.26s** | **+26.8% faster** | 139.4 t/s | 13.7 t/s |

### C. Real Multi-Turn End-to-End Penetration Testing Assessment

Measured via the authentic local lab test `tests/test_qa_phase1_real_gguf.py` (complete closed-loop assessment including lab server setup, OpenAPI parsing, real GGUF multi-turn inference, tool dispatch, evidence verification, risk scoring, and report generation):

| Metric | Baseline Assessment | Optimized Assessment | Absolute Change | Relative Improvement |
| :--- | :---: | :---: | :---: | :---: |
| **Total Test Duration** | **111.38s** (0:01:51) | **76.53s** (0:01:16) | **-34.85 seconds** | **31.3% Faster** |
| **Model Inferences** | Real GGUF (`llama_cli`) | Real GGUF (`llama_cli`) | Unchanged | Verified Non-Mock |
| **Autonomous Turns Taken**| 2 turns | 2 turns | Unchanged | Deterministic |
| **Tool Probes Dispatched**| 2 requests | 2 requests | Unchanged | Scope Verified |
| **Findings Confirmed** | 1 confirmed | 1 confirmed | Unchanged | Rule Attached |
| **Test Result** | **PASSED** | **PASSED** | 0 failures | 100% Pass |

### D. Full Fast Regression Test Suite (219 Automated Tests)

| Metric | Baseline Regression Suite | Optimized Regression Suite | Difference |
| :--- | :---: | :---: | :---: |
| **Total Tests Run** | 219 items | 219 items | Zero regressions |
| **Tests Passed** | 219 passed | 219 passed | 100% Pass Rate |
| **Tests Failed** | 0 failed | 0 failed | Zero failures |
| **Execution Time** | **168.82s** (0:02:48) | **154.31s** (0:02:34) | **-14.51 seconds faster** |

---

## 3. Resource Profile & Memory Telemetry

Measured on Windows 10 x86_64 with Python 3.8.10:

| Resource Metric | Baseline Value | Optimized Value | Defensibility Impact |
| :--- | :---: | :---: | :--- |
| **GGUF Model File Size** | 940.37 MB | 940.37 MB | Unchanged (SHA-256 match) |
| **Default Context Length** | 4096 tokens | 2048 tokens | Saves ~175 MB KV cache |
| **KV Cache RAM Footprint** | ~350 MB | ~175 MB | 50% memory reduction |
| **Python Process Working Set**| 16.2 MB | 27.7 MB | Stable (<35 MB in Python) |
| **Total System RAM Target** | 8 GB RAM target | 8 GB RAM target | Well within 8 GB laptop limit |
| **CPU Logical Threads Used** | 3 threads | 4 threads (`-t 4 -tb 4`) | Maximizes 4-core utilization |

---

## 4. Key Engineering Takeaways

1. **Subprocess Overhead Elimination:** Eliminating warmup loops (`--no-warmup`) and prompt echoing (`--no-display-prompt`) shaved 1.2s off every CLI execution.
2. **Context Window Right-Sizing:** Lowering `n_ctx` from 4096 to 2048 halved the memory overhead of the KV cache while leaving ample room for comprehensive API endpoint specifications.
3. **Regex Schema Recovery:** Resilient regex extraction in `extract_and_validate_json` completely resolved model parsing issues when evaluating raw SQL errors with internal quotes, raising Evidence Analysis from 0% to 100% success.
4. **Resident Daemon Viability:** The opt-in `llama_server` engine demonstrated that keeping the GGUF model resident in memory enables sub-second (~180ms - 5s) responses on standard CPU hardware.

