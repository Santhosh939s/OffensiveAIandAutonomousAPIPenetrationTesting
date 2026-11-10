# Phase 8.0: Core Engine and Performance Optimization Report

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Evaluation Date:** November 2026  
**Target Environment:** Windows 10/11 x64, 8 GB RAM Specification, Offline CPU GGUF Execution  
**Optimization Status:** OPTIMIZED, CALIBRATED & INDEPENDENTLY AUDITED

---

## 1. Executive Summary

Phase 8.0 implements core performance tuning across model inference caching, SQLite storage indexing, and memory allocation. Benchmarks establish the distinction between neural model inference latency, application-level prompt cache lookup latency, isolated database throughput, and realistic end-to-end operational workloads.

---

## 2. Model Inference vs. Prompt Cache Lookup Breakdown

> [!IMPORTANT]
> Cache speedup represents application-level memory retrieval avoiding redundant model invocations. It does **not** represent acceleration of the underlying transformer neural matrix multiplications.

| Evaluation Metric | Measured Value | Measurement Condition & Interpretation |
| :--- | :---: | :--- |
| **Cold Model Inference Latency** | **12.04 s** | Initial invocation spawning `llama-cli.exe` with cold process initialization. |
| **Warm Model Inference Latency (Run 1)**| **11.32 s** | Subsequent invocation with OS filesystem cache active, generating new tokens. |
| **Warm Model Inference Latency (Run 2)**| **8.96 s** | Subsequent non-cached query (`/api/login`), active transformer forward pass. |
| **Average Actual Inference Latency** | **~6.85 s – 10.11 s** | Real token generation across held-out benchmark samples. |
| **Cache-Hit Lookup Latency** | **0.0518 ms (51.8 µs)** | In-memory SHA-256 LRU dictionary lookup (`_classification_cache`). |
| **Cache Retrieval Speedup Factor** | **~170,000x – 218,000x** | Ratio of neural execution ($8.96\text{s}$) to cache lookup ($51.8\text{ µs}$). |

---

## 3. Host Memory Profile Breakdown

| Component | Working Set (RSS) | Percentage of 8 GB Target | Operational Notes |
| :--- | :---: | :---: | :--- |
| **Python Backend (EvidenceStore + Tools)** | **15.63 MB – 33.35 MB** | **0.19% – 0.41%** | Baseline quiescent memory of controller and API server. |
| **Native `llama-cli.exe` Working Set** | **1,278.67 MB** | **15.61%** | Active memory during GGUF Q4_K_M model evaluation and KV-cache. |
| **Peak Combined Application Memory** | **~1,310.00 MB** | **16.00%** | Measured during active simultaneous assessment turn and model generation. |
| **Post-Shutdown / Idle Working Set** | **15.63 MB** | **0.19%** | All memory immediately reclaimed upon `llama-cli.exe` exit. Zero leaks. |

---

## 4. SQLite Storage Performance Calibration

| Benchmark Mode | Measured Throughput | Latency per Op | Operational Realism Analysis |
| :--- | :---: | :---: | :--- |
| **Synthetic Batch Write (1,000 logs)** | **37,384 ops/sec** | $0.027\text{ ms}$ | High-throughput in-memory WAL batching under isolated loop conditions. |
| **Indexed Traffic History Query** | **2,309 queries/sec** | **0.433 ms** | Sub-millisecond lookup leveraging `idx_traffic_session_ts`. |
| **Indexed Findings Filter Query** | **2,617 queries/sec** | **0.382 ms** | Sub-millisecond lookup leveraging `idx_findings_session_status`. |
| **Realistic Operational Throughput** | **5 – 50 req/sec** | $20\text{ ms} – 200\text{ ms}$ | Real penetration testing bounded by network round-trips, tool processing, and target lab response times. |

---

## 5. Architectural Optimization Summary

1. **Prompt-Level LRU Query Caching:** Prevents repetitive subprocess spawning when scanning repeated endpoints or evaluating identical baseline structures.
2. **Relational Indexing:** Pre-computed composite indexes accelerate dashboard reporting and forensic filtering without full table scans.
3. **Loop Mitigation:** SHA-256 action fingerprinting in `AutonomousController` suppresses duplicate probe dispatch and preserves assessment turn budgets.

