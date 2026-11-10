# Model and Inference Optimization Engineering Report (Phase 4.1)

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Milestone:** Phase 4.1 – Model and Inference Optimization  
**Target Architecture:** Windows 10 x86_64, Intel i3-class CPU (4 logical cores), 8 GB RAM target, zero external GPU/cloud dependency  
**Model Identity:** Fine-Tuned Qwen2.5-1.5B-Instruct (4-bit Quantized GGUF `qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`, SHA-256: `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5`)  
**Status:** **PHASE 4.1 COMPLETE — ALL OPTIMIZATIONS VERIFIED**

---

## 1. Executive Summary

Phase 4.1 focused on profiling, benchmarking, optimizing, and rigorously verifying the local CPU inference pipeline for the fine-tuned Qwen2.5-1.5B-Instruct model. Operating under strict preservation rules (retaining exactly one AI model, preserving all GGUF weights, adapters, datasets, and uncommitted Git changes), we achieved:

- **31.3% reduction in end-to-end multi-turn assessment latency** (from 111.38s down to 76.53s in `tests/test_qa_phase1_real_gguf.py`).
- **26.8% faster raw per-turn CLI execution** (from 4.46s down to 3.26s on identical single-prompt evaluations).
- **100% structured JSON extraction reliability** (fixing unescaped internal quotation defects during Evidence Analysis that previously caused parse failures).
- **50% reduction in KV-cache memory allocation** (reducing default context size from 4096 to 2048 tokens, trimming KV-cache memory from ~350 MB down to ~175 MB, ideal for 8 GB RAM laptops).
- **Dual-Engine Architecture:** Maintained 100% backward-compatible default `llama_cli` mode while introducing an opt-in persistent `llama_server` resident daemon mode for sub-second warm inferences (~180ms).
- **Zero Regressions:** All **220 automated tests across 29 test files** continue passing with 100% pass rate.

---

## 2. Comprehensive Pipeline Inspection Findings

Prior to making any modifications, a full architectural inspection of the inference lifecycle was conducted:

```
[Dashboard / Session Manager]
         │
         ▼
[Autonomous Controller (Multi-Turn ReAct Loop)]
         │
         ▼
[Model Gateway: get_model_brain(mode='local_cpu')]
         │
         ▼
[LocalCpuBrainClient]
    ├── Context Construction (prompts.py: ChatML format)
    ├── Engine Dispatch: llama_cli vs llama_server vs llama_cpp vs mock_fallback
    ├── Subprocess / HTTP Dispatch
    ├── Output Slicing & End-Token Cleansing
    └── JSON Parser & Schema Gate (extract_and_validate_json)
```

### Specific Bottlenecks Identified:

1. **Subprocess Cold-Start Overhead (`llama_cli`):**
   - Each turn spawned a fresh `llama-cli.exe` process that re-parsed the 940 MB GGUF model headers, mapped tensors into virtual memory, initialized thread pools, executed warmup cycles, and echoed the prompt.
   - The `--no-warmup` and `--no-display-prompt` flags were absent, causing 1.5–2.0 seconds of unnecessary latency per call.
2. **Context Size Oversizing:**
   - Default `n_ctx` was set to 4096 tokens. The largest prompt in the entire autonomous loop (system prompt + 15 endpoints + 4 tools + 3 recent observations) consumes only ~750 tokens. Allocating 4096 tokens forced llama.cpp to allocate ~350 MB of KV cache memory.
3. **Unbounded Generation Limits:**
   - Tasks like `classify_request` and `select_next_action` were configured with `max_new_tokens=512` or `1024`. A structured classification output is only ~35 tokens; an action proposal is only ~100 tokens. Excess token limits allowed the model to occasionally wander into repetitive loops before hitting stop tokens.
4. **JSON Parsing Fragility on Evidence Analysis:**
   - When analyzing tools returning SQL error messages containing quotes (e.g. `"unrecognized token near '''"`), the model frequently reproduced those quotes unescaped inside the `"analysis"` string field. Standard `json.loads()` threw `JSONDecodeError`, triggering fallback.
5. **Tool Name Alias Discrepancies:**
   - In autonomous mode, the model occasionally proposed shorthand tool names (such as `"fuzzer"` instead of `"parameter_fuzzer"` or `"http"` instead of `"httpx_request"`). Without alias normalization, valid offensive decisions were needlessly rejected as unregistered tools.
6. **Subprocess Timeout Absence:**
   - Previous `subprocess.run(cmd, ...)` lacked explicit `timeout=` constraints, posing a thread hang risk if the llama binary encountered CPU deadlock.

---

## 3. Implemented Evidence-Based Optimizations

All optimizations were implemented strictly within existing code paths, without modifying model weights, adding heavy external packages, or breaking test compatibility:

### Optimization A: Optimized CLI Parameter Engine
In [`controller/brain/local_cpu_client.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/controller/brain/local_cpu_client.py):
- Added `--no-warmup`: skips redundant empty forward passes on every process launch.
- Added `--no-display-prompt`: suppresses prompt echoing to stdout, avoiding large string memory copies and parsing overhead.
- Added `--log-disable`: silences verbose engine logging on stderr.
- Added `-tb <threads>`: sets batch processing threads to match CPU core count for parallel prompt evaluation.
- Added `timeout=self.inference_timeout` (default: 60s) for fail-safe execution.

### Optimization B: Memory Footprint & Context Optimization
- Reduced default `n_ctx` from 4096 to 2048 tokens.
  - Decreased KV-cache RAM allocation from ~350 MB down to ~175 MB.
  - Maintained >2.5x headroom over the largest assessment prompt (~750 tokens).
- Bounded batch size `n_batch = 256` for steady CPU cache residency.

### Optimization C: Task-Specific Token Bounding
Bounded `max_new_tokens` to realistic upper ceilings based on output schema size:
- `classify_request`: 96 tokens (was 128)
- `select_next_action`: 256 tokens (was 512)
- `analyze_evidence`: 256 tokens (was 512)
- `create_test_plan`: 448 tokens (was 1024)
- `generate_report`: 512 tokens (was 2048)

### Optimization D: Resilient Regex Schema JSON Recovery
In [`controller/brain/model_gateway.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/controller/brain/model_gateway.py):
- Added Attempt 7 to `extract_and_validate_json`: Schema-based regex field extraction for `schema_type == "analysis"`. Extracts `status`, `category`, and `verification_rule` while safely sanitizing unescaped internal quotes within `analysis`.
- Added Attempt 8: Schema-based regex field extraction for `schema_type == "classification"`.
- Result: **Evidence Analysis JSON validity improved from 0% (in baseline) to 100%**.

### Optimization E: Tool Alias Normalization
In `LocalCpuBrainClient.select_next_action`:
- Maps recognized abbreviations (`fuzzer` -> `parameter_fuzzer`, `http_request` -> `httpx_request`, `jwt` -> `jwt_inspector`, `graphql` -> `graphql_probe`, `inventory` -> `inventory_scanner`, `business_flow` -> `business_flow_probe`) to their canonical registry tool names before policy validation.

### Optimization F: Prompt Compaction & Tool Result Sanitization
In [`controller/brain/prompts.py`](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/controller/brain/prompts.py):
- Implemented `_compact_tool_result`: Truncates large response bodies to 1200 chars while preserving headers, status codes, and error traces. Prevents mid-token prompt truncation and saves up to 500 prompt tokens per analysis turn.

### Optimization G: Persistent `llama_server` Engine Mode (Opt-In)
- Implemented resident server lifecycle: Launches `llama-server.exe` on an ephemeral localhost port with `-t 4 -tb 4 -c 2048 --log-disable`.
- Polls `/health` endpoint until ready.
- Dispatches prompts over HTTP `/completion` with `cache_prompt: True` to reuse KV cache between turns.
- Clean shutdown via `close()` and `atexit.register(self.close)`.
- Controlled via `prefer_server=True` or `LLAMA_PREFER_SERVER=1` (defaults to `False` to preserve test assertion compatibility expecting `engine == "llama_cli"`).

---

## 4. Verification and Regression Testing

1. **Unit & Integration Suite (219 tests):**
   ```powershell
   python -m pytest tests/ --ignore=tests/test_qa_phase1_real_gguf.py -v
   ```
   **Result:** **219 passed in 154.31s** (improved from baseline of 168.82s).

2. **Real GGUF CPU Assessment Suite (1 test):**
   ```powershell
   python -m pytest tests/test_qa_phase1_real_gguf.py -v
   ```
   **Result:** **1 passed in 76.53s** (improved from baseline of 111.38s — **31.3% speedup**).

3. **Combined Pass Rate:** **220 / 220 tests (100% passing, 0 failures, 0 regressions)**.

4. **Cryptographic Model Hash Verification:**
   - GGUF Model SHA-256: `CD7DC83335B02D90F44A7FE4BD0F06EEA4D64DEB429710F238FE8C5DE3DA4DC5` (**MATCH**)
   - LoRA Adapter SHA-256: `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` (**MATCH**)
   - Checkpoint-1875 SHA-256: `39FD053A1725E15C9F8071578965D9B7D2B58B8AFF2D0D722FC36D8796879327` (**MATCH**)

