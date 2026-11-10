# Phase 4.2 – System Resource Benchmarks and Telemetry Report

## Test Environment Profile

- **Operating System:** Windows 10 x86_64
- **CPU Cores:** 4 Logical Cores
- **Installed System RAM:** 7,834.63 MB (~7.65 GB)
- **Baseline Available RAM:** 1,032 – 1,364 MB (Host Memory Load: 82% – 86%)
- **AI Model Under Test:** `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`
- **Model Checksum (SHA-256):** `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5`
- **Inference Runtime:** Standalone `llama-cli.exe` (AVX2 optimized)

---

## Complete Resource Benchmark Across 6 Target Scenarios

| Scenario | Duration | Working Set (RSS) | Peak Working Set | CPU % (Total Process) | Active Threads | Status / Health |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Application Startup** (Dashboard + Lab server) | 0.031s | 43.16 MB (Delta: +2.7 MB) | 43.16 MB | 12.65% | 2 | HEALTHY |
| **2. Idle Operation** (5-second quiescent period) | 5.000s | 43.16 MB | 43.16 MB | **0.00%** (Target: < 2%) | 2 | HEALTHY |
| **3. Real GGUF Model Inference** (Single Turn) | 14.116s | 18.04 MB | 43.26 MB | 0.06% (Process) | 2 | HEALTHY (Valid Action) |
| **4. One Autonomous Assessment** (Complete loop) | 0.426s | 46.12 MB | 55.75 MB | 16.49% | 2 | COMPLETED |
| **5. Two Concurrent Assessments** (Parallel load) | 0.184s | 46.92 MB | **58.46 MB** | 29.72% | 2 | BOTH COMPLETED (0 collisions) |
| **6. Repeated Assessments & Post-GC Cleanup** | 3 Runs | [47.31, 47.55, 47.49] MB | 58.46 MB | Quiescent | 2 | 0 Thread Leak, Stable RSS |

---

## Analysis & Evaluation Against Targets

### 1. Working Set Memory Constraint (< 350 MB Target)
- Target: `< 350 MB`
- Measured Peak: **58.46 MB**
- **Margin:** 291.54 MB below ceiling (**83.3% lower than target limit**).
- Result: **PASSED (Substantial Safety Margin)**

### 2. Idle CPU Utilization (< 2% Target)
- Target: `< 2.0%`
- Measured: **0.00%**
- Result: **PASSED (Zero Idle Waste)**

### 3. Thread Leakage (Zero Leak Target)
- Initial Threads at Startup: 2
- Post-Cleanup Threads after 3 Runs: 2
- Result: **PASSED (Zero Orphan Threads)**

### 4. Database Concurrency & Deadlock Prevention
- Pre-Optimization: Concurrent threads raised `sqlite3.OperationalError: cannot commit - no transaction is active` and `cannot start a transaction within a transaction`.
- Post-Optimization (`_SafeConnectionProxy` + WAL mode): Parallel sessions completed simultaneously with 0 errors and zero write aborts.
- Result: **PASSED (100% Concurrent Integrity)**

### 5. Multi-Session Protection
- Verified `MAX_CONCURRENT_ASSESSMENTS = 4` guard: Rejects requests exceeding threshold with `RESOURCE_BUSY_MAX_CONCURRENCY`.
- Verified `MIN_AVAILABLE_RAM_MB = 150.0` guard: Rejects requests during acute memory pressure with `RESOURCE_EXHAUSTED_MEMORY`.
- Result: **PASSED**

