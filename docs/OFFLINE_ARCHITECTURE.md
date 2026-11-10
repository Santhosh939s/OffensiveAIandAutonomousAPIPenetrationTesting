# Offline Architecture & Air-Gap Technical Specification

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Milestone:** Phase 4.7 – Offline Operation and Dependency Audit  
**Author:** Senior Offline Systems Architect  
**Date:** November 5, 2026  
**Status:** **100% AIR-GAPPED & OFFLINE VERIFIED**

---

## 1. Architectural Philosophy & Isolation Guarantee

The Offensive AI platform is intentionally engineered from the ground up for strict, zero-trust, air-gapped environments:
- **No Cloud AI APIs:** The platform utilizes strictly ONE AI model: the local fine-tuned `Qwen2.5-1.5B-Instruct Q4_K_M GGUF` model via local CPU execution. Zero calls to OpenAI, Anthropic, Gemini, or remote inference proxies.
- **No Remote Model Hub Downloads:** Model weights and checkpoints are loaded directly from local filesystem paths (`models/qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf`). No HuggingFace Hub downloads, automatic git pulls, or weight synchronizations are permitted at runtime.
- **No CDN or External Font Dependencies:** The dashboard user interface is entirely self-contained within `dashboard/templates/index.html`, `dashboard/static/css/dashboard.css`, and `dashboard/static/js/dashboard.js`. No Google Fonts, unpkg, cdnjs, or third-party CSS frameworks are loaded.
- **Zero Online Authentication or Licensing Check:** The system does not check online license servers, telemetry daemons, or remote authorization endpoints.
- **Self-Contained Persistence:** Testing state, findings, and traffic history persist exclusively in a local SQLite database (`EvidenceStore`), with WAL journaling and in-memory caches.

---

## 2. Complete Offline Runtime Architecture

```
+---------------------------------------------------------------------------------+
|                     LOCAL AIR-GAPPED HOST (WINDOWS 64-BIT)                     |
|                                                                                 |
|  +--------------------+        HTTP (Localhost)        +---------------------+  |
|  | Modern Web Browser | <----------------------------> | Flask Dashboard App |  |
|  | (100% Offline UI)  |       http://127.0.0.1:8088    | (dashboard/app.py)  |  |
|  +--------------------+                                +----------+----------+  |
|                                                                   |             |
|                                                                   v             |
|  +---------------------------------------------------------------------------+  |
|  |                     DashboardSessionManager                               |  |
|  |                 - Telemetry Event Queue (SSE)                             |  |
|  |                 - Background Worker Lifecycle                             |  |
|  |                 - Interrupted Session Auto-Recovery                       |  |
|  +------------------------------------+--------------------------------------+  |
|                                       |                                         |
|                                       v                                         |
|  +---------------------------------------------------------------------------+  |
|  |                     Autonomous Controller Engine                          |  |
|  |                 - ReAct Loop (Observe, Reason, Act)                      |  |
|  |                 - Scope & Policy Validation Engine                        |  |
|  |                 - Verification Gate (Proof Verification)                  |  |
|  +-------------------+---------------------------------+---------------------+  |
|                      |                                 |                        |
|                      v                                 v                        |
|  +------------------------------------+   +----------------------------------+  |
|  |      Local CPU Model Brain         |   |       Local Security Tools       |  |
|  |  (LocalCpuBrainClient)             |   |   - HttpRequestTool              |  |
|  |  Engine: Standalone llama-cli.exe  |   |   - HttpxRequestTool             |  |
|  |  Model: Qwen2.5-1.5B Q4_K_M GGUF   |   |   - GraphQLProbeTool             |  |
|  |  (Local binary, zero network)      |   |   - ParameterFuzzerTool          |  |
|  +------------------------------------+   |   - ApiInventoryScannerTool      |  |
|                                           |   - OpenApiParserTool            |  |
|                      +--------------------+   - JwtInspectorTool             |  |
|                      |                        - BusinessFlowProbeTool        |  |
|                      v                        - ZapSecurityScanTool (Opt)    |  |
|  +------------------------------------+   +----------------------------------+  |
|  |         Local Persistence          |                     |                   |
|  |     (EvidenceStore SQLite)         |                     v                   |
|  |  - Local File: offensive_ai.db     |           +-------------------+         |
|  |  - SHA-256 Cryptographic Hashes    |           | Local Target Lab  |         |
|  |  - Automated Audit Engine          |           | http://127.0.0.1  |         |
|  +------------------------------------+           +-------------------+         |
+---------------------------------------------------------------------------------+
```

---

## 3. Strict Boundary Rules

1. **Permitted Network Scope:** Only connections explicitly matching loopback addresses (`127.0.0.1`, `localhost`, `0.0.0.0`, `::1`) or authorized private subnets specified in `AgentConfig.allowed_hosts` are allowed.
2. **Firewall Enforcement:** All tool execution passes through `ScopeValidator`. Targets attempting DNS resolution or IP connection to external non-local addresses without explicit authorization are rejected with HTTP 400.
3. **Graceful Failure on Missing Optional Components:** If an optional local daemon (such as OWASP ZAP on port 8080) is not active, the system detects offline status gracefully via `check_health` without hanging or throwing unhandled exceptions.

