# Autonomous Controller Architecture & Implementation Status

**Component:** Autonomous API Penetration Testing Controller  
**Package:** `controller/agent/`, `controller/guardrails/`, `controller/storage/`  
**Current Test Coverage:** 100% Pass across unit & integration test suites  
**Date:** November 3, 2026  

---

## 1. Controller Pipeline Overview

The autonomous controller orchestrates goal-oriented, policy-guarded security assessments against authorized target APIs:

```
[ User Input / Dashboard ]
           │
           ▼
[ Scope & Authorization Validator ]  <-- Rejects out-of-scope & destructive requests
           │
           ▼
[ Autonomous Controller Session ]
    ├── [ Context Manager ]          <-- Manages turn limits, observations, and memory
    ├── [ Adaptive Engine ]          <-- Dynamically prioritizes endpoints based on error patterns
    ├── [ Local Qwen AI Brain ]      <-- Selects tool actions, interprets API responses
    ├── [ Tool Execution Registry ]  <-- Invokes approved testing tools (HTTP, OpenAPI, JWT, GraphQL)
    └── [ Evidence Verification Gate ] <-- Validates findings against strict proof criteria
           │
           ▼
[ SQLite Evidence Store & Report Generator ]
```

---

## 2. Component Implementation Status

### A. Scope & Safety Guardrails (`controller/guardrails/`)
- **`ScopeValidator`:**
  - Enforces explicit IP/hostname allowlists.
  - Automatically rejects cloud metadata addresses (`169.254.169.254`), non-HTTP schemes (`file://`, `ftp://`), and external third-party hosts.
  - Normalizes target URLs to prevent directory traversal or URL encoding bypasses.
- **`PolicyEngine`:**
  - Enforces per-session request budgets and turn limits.
  - Detects and blocks destructive HTTP methods or SQL queries (e.g. `DROP`, `TRUNCATE`, `DELETE *`).
  - Requires explicit authorization flags before permitting active scanner probes.

### B. Adaptive Decision Loop (`controller/agent/adaptive_engine.py`)
- Analyzes HTTP status codes, reflection patterns, and error responses.
- Implements dynamic priority scoring: endpoints exhibiting 500 internal server errors, unhandled exceptions, or missing authorization headers receive priority boosts.
- Enforces probe exhaustion limits (capping maximum requests per individual endpoint) to prevent accidental denial-of-service.

### C. Evidence Verification Gate (`controller/storage/evidence_store.py`)
- **Strict Verification Policy:** An HTTP 200 OK or generic error code is **never** accepted as proof of a vulnerability.
- Confirmed findings require verifiable indicators:
  - SQLi: Exact database syntax error regex match or differential response delay.
  - Auth Bypass / IDOR: Cross-account data leakage verified against session tokens.
  - Misconfiguration: Introspection schema type dump or missing security headers.
- Unverified anomalies are logged as informational observations, preventing false-positive clutter in final reports.

