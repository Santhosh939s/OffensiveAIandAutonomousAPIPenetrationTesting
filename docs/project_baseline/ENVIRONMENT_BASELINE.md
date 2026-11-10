# Environment & Dependency Baseline

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Baseline Date:** November 4, 2026  
**Confidentiality:** Zero secrets, keys, or passwords recorded

---

## 1. Operating System & Runtime Environment

- **Operating System:** Windows 10 Pro / Enterprise (x86_64, build 10.0.26300-SP0)
- **Architecture:** AMD64 / x86_64 CPU (AVX2 support verified)
- **Python Runtime:** Python 3.8.10 (`tags/v3.8.10:3d8993a`, May 3 2021)
- **Python Binary Location:** `C:\Users\santhosh\AppData\Local\Programs\Python\Python38\python.exe`
- **Target Deployment Spec:** Commodity Windows PC / Laptop with Intel Core i3 or equivalent, 8 GB RAM, no dedicated GPU.

---

## 2. Standalone Inference Binary (llama.cpp)

- **Executable:** `llama-cli.exe`
- **Discovered Location:** `C:\Users\santhosh\AppData\Local\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-cli.exe`
- **Version String:** `version: 0.3.0-dev (build 10679, commit 50f068fff)`
- **Compiler:** Clang 20.1.8 for Windows x86_64
- **Runtime Execution Flags:**
  - Context size: `-c 4096`
  - Threads: `-t 4`
  - Memory-mapping: `--mmap`
  - Temperature: `--temp 0.2`
  - Penalty: `--repeat-penalty 1.1`

---

## 3. Installed Python Project Dependencies

| Package Name | Installed Version | Purpose in Codebase |
| :--- | :--- | :--- |
| `flask` | `3.0.3` | Native dark-themed web dashboard and REST API service |
| `werkzeug` | `3.0.6` | WSGI utility layer and test harness server |
| `jinja2` | `3.1.6` | Dashboard HTML and report rendering templates |
| `httpx` | `0.28.1` | High-performance asynchronous and sync HTTP client |
| `requests` | `2.32.4` | Standard HTTP request engine for tool actions |
| `pyyaml` | `6.0.3` | OpenAPI 3.0 YAML specification parsing |
| `pytest` | `8.3.5` | Automated test runner and assertion framework |
| `anyio` | `4.5.2` | Asynchronous concurrency abstraction |
| `pluggy` | `1.5.0` | Plugin management for pytest test collection |

*(Note: Heavy GPU libraries such as `torch`, `transformers`, `peft`, `bitsandbytes`, and `accelerate` are NOT installed locally; the runtime executes strictly on CPU via `llama-cli.exe` and native Python).*

---

## 4. Configuration Environment Variables (Names Only)

The application uses these configuration variables without requiring hardcoded secrets:

| Variable Name | Default Value | Description |
| :--- | :--- | :--- |
| `QWEN_CPU_GGUF_PATH` | `models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` | Path override for the fine-tuned 4-bit quantized GGUF model |
| `MODEL_GATEWAY_URL` | None | Remote GPU model brain HTTP endpoint (optional) |
| `AGENT_MAX_TURNS` | `10` | Hard cap on autonomous decision-making turns per session |
| `AGENT_REQUEST_BUDGET` | `50` | Hard cap on total outgoing HTTP requests per session |
| `PORT` | `5000` | Port for the operational dashboard web application |
| `LAB_PORT` | `5050` | Port for the authentic vulnerable testing lab server |
| `ZAP_PROXY_URL` | `http://127.0.0.1:8080` | Proxy URL for optional OWASP ZAP daemon integration |
| `ZAP_API_KEY` | None | API authentication key for OWASP ZAP (optional) |

---

## 5. Primary Application Entry Points

1. **Operational Web Dashboard:**
   - Command: `python dashboard/app.py`
   - Default URL: `http://127.0.0.1:5000`
   - Features: Assessment configuration, live SSE telemetry, traffic inspector, reports.
2. **Local Vulnerable API Lab:**
   - Command: `python lab/app.py`
   - Default URL: `http://127.0.0.1:5050`
   - Features: Realistic OWASP API Top 10 vulnerable endpoints and OpenAPI spec (`/openapi.json`).
3. **Automated Test Suite (Fast):**
   - Command: `python -m pytest tests/ --ignore=tests/test_qa_phase1_real_gguf.py -v`
   - Features: 219 tests covering all subsystems in ~2.8 minutes.
4. **Real End-to-End GGUF Model Assessment:**
   - Command: `python -m pytest tests/test_qa_phase1_real_gguf.py -v`
   - Features: Verified closed-loop autonomous penetration testing with CPU model inference.

