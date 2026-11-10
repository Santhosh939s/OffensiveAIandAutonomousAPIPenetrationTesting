# Complete Software Dependency Inventory & Classification

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Milestone:** Phase 4.7 – Offline Operation and Dependency Audit  
**Author:** Senior Offline Systems Architect & Software Dependency Auditor  
**Date:** November 5, 2026  
**Status:** **100% INVENTORIED AND CLASSIFIED**

---

## 1. Dependency Classification Framework

Every component, library, binary, and asset within the application is classified into one of five formal categories:
1. **Required Local Dependency:** Essential for the offline execution of the core application.
2. **Optional Local Dependency:** Enhances capabilities when present locally, but gracefully degrades without crashing if unavailable.
3. **External Network Dependency:** Requires an internet connection or remote cloud service (Target count: **0**).
4. **Development / Test-Only Dependency:** Used solely during automated testing, benchmarking, or development.
5. **Unused / Legacy Dependency:** Historical artifacts or documentation references with zero runtime binding.

---

## 2. Complete Dependency Inventory Table

| Component / Library | Version / Source | Classification | Role / Functionality | Offline Guarantee |
| :--- | :--- | :---: | :--- | :--- |
| **Python Core Runtime** | 3.8.10 (64-bit) | **Required Local** | Base Python execution environment | 100% Localhost |
| **Flask** | `>=3.0.0,<3.2.0` | **Required Local** | Web dashboard service & local target API lab | 100% Localhost (`127.0.0.1`) |
| **Werkzeug** | `>=3.0.0,<3.2.0` | **Required Local** | WSGI web server primitives, routing, security | 100% Localhost |
| **httpx** | `>=0.25.0,<0.29.0`| **Required Local** | Connection-pooled HTTP assessment tool | Strict ScopeValidator |
| **requests** | `>=2.31.0` | **Required Local** | Synchronous HTTP probe tool | Strict ScopeValidator |
| **pydantic** | `>=2.0.0` | **Required Local** | Agent configuration & state schema validation | 100% In-memory |
| **PyYAML** | `>=6.0.0` | **Required Local** | OpenAPI 3.0 / Swagger schema parser | Local files only |
| **cryptography** | `>=41.0.0` | **Required Local** | JWT inspection, algorithm evaluation, key math | 100% In-memory |
| **sqlite3** | Built-in (3.35+) | **Required Local** | Local persistence, WAL journaling, evidence | Local file (`.db`) |
| **llama-cli.exe** | Clang 20.1.8 x86_64 | **Required Local** | Offline Qwen GGUF inference executable | Standalone binary, 0 network |
| **Qwen GGUF Model** | Q4_K_M (1.5B) | **Required Local** | Fine-tuned offensive AI core model | Local file (`models/*.gguf`) |
| **LoRA Final Adapter** | Checkpoint-1875 | **Required Local** | Safetensors weights & configuration | Local file (`models/*`) |
| **llama-server.exe** | Clang 20.1.8 x86_64 | **Optional Local** | Opt-in resident inference daemon | Local loopback only |
| **OWASP ZAP Daemon** | Local 8080 (Java) | **Optional Local** | Active/passive vulnerability spidering | Graceful failover if offline |
| **pytest** | `>=8.0.0` | **Dev-Only** | Automated test runner & regression harness | Local execution only |
| **pytest-mock** | `>=3.14.0` | **Dev-Only** | Mocking primitives for isolated testing | In-memory only |
| **anyio** | `>=4.5.0` | **Dev-Only** | Asynchronous test fixture orchestration | In-memory only |
| **Cloud AI SDKs** | None (0) | **External Network** | None (OpenAI, Anthropic, Gemini, HF Hub) | **STRICTLY 0 / NOT USED** |
| **Remote CDN Assets** | None (0) | **External Network** | None (cdnjs, jsdelivr, Google Fonts) | **STRICTLY 0 / NOT USED** |

---

## 3. Native Binary & DLL Verification

- **Executable:** `llama-cli.exe`
  - Location: Verified on host via system PATH.
  - Native architecture: Clang 20.1.8 Windows x86_64.
  - Dynamically linked system libraries: `KERNEL32.dll`, `MSVCP140.dll`, `VCRUNTIME140.dll` (standard Windows C/C++ runtime).
  - External network calls: **None**. Operates purely by reading local GGUF bytes from disk, allocating local RAM buffers, computing tensor operations on CPU SIMD/AVX2 threads, and streaming tokens to stdout.

---

## 4. Frontend Asset Air-Gap Verification

- **Stylesheet:** `dashboard/static/css/dashboard.css` (18.6 KB) - 100% local.
- **JavaScript Controller:** `dashboard/static/js/dashboard.js` (44.4 KB) - 100% local.
- **HTML Markup:** `dashboard/templates/index.html` (41.6 KB) - 100% local.
- **Fonts & Typography:** Utilizes system font stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`.
- **Icons:** Native UTF-8 Unicode emojis (🛡️, 📊, 🎯, ⚡, 🔍, 🚨, 🌐, 📑, ⚙️).
- **External CDN / Font Audit:** **0 external tags**.

