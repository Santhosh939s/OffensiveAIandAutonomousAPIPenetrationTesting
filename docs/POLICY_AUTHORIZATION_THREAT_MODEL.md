# Policy & Authorization Threat Model & Security Analysis

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Directory:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Role:** Senior Application Security Architect & Threat Modeler  
**Date:** November 5, 2026  
**Document Status:** Complete Threat Analysis (Pre-Implementation)

---

## 1. Threat Modeling Methodology

This threat model uses the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) combined with **CVSS v3.1** severity scoring to systematically evaluate the attack surface of the Policy & Authorization Administration system and the autonomous testing engine.

### System Trust Boundaries:
1. **Trust Boundary 1 (External Web / Operator -> Dashboard API):**
   - Untrusted web browsers, automated API clients, and network traffic entering port 8088.
2. **Trust Boundary 2 (Dashboard Controller -> Administration Data Store):**
   - Administrative endpoints modifying database tables (`policies`, `target_authorizations`, `users`).
3. **Trust Boundary 3 (Autonomous Agent Controller -> AI Brain Model):**
   - Autonomous inference loop interacting with the local Qwen GGUF model via `llama-cli.exe`. Model outputs are strictly untrusted strings.
4. **Trust Boundary 4 (Tool Execution Engine -> Network Targets):**
   - Outbound HTTP requests, probes, and scanner executions interacting with targeted web applications.

---

## 2. In-Depth Threat Analysis & Defense Specifications

```
Threat Summary Matrix:
-----------------------------------------------------------------------------------------------------------------
ID     Threat Scenario                                STRIDE Category        CVSS v3.1    Severity    Mitigation Status
-----------------------------------------------------------------------------------------------------------------
TH-01  Privilege Escalation (Operator to Admin)       Elevation of Privilege 8.8 (High)   HIGH        Designed (RBAC Gate)
TH-02  Authentication Bypass on Admin Endpoints       Spoofing / Bypass      9.8 (Crit)   CRITICAL    Designed (Session Middleware)
TH-03  Cross-Site Request Forgery (CSRF) on Admin    Tampering              8.1 (High)   HIGH        Designed (Double-Submit/Header)
TH-04  Session Fixation & Hijacking                   Spoofing               7.5 (High)   HIGH        Designed (Token Regeneration)
TH-05  Policy Parameter Modification by Operator      Tampering              7.2 (High)   HIGH        Designed (Server-Side Validation)
TH-06  Scope Bypass via IP/DNS Encoding Tricks        Elevation of Privilege 8.6 (High)   HIGH        Designed (Canonical IP Parser)
TH-07  Redirect-Based Scope Escape                    Elevation of Privilege 8.6 (High)   HIGH        Enforced (allow_redirects=False)
TH-08  Model-Generated Unauthorized Tool Invocations  Tampering / Injection  7.8 (High)   HIGH        Enforced (Deterministic PolicyEngine)
TH-09  Direct API Calls Bypassing UI Restrictions     Bypass                 8.2 (High)   HIGH        Designed (Backend Auth Enforcer)
TH-10  Race Conditions During Concurrent Policy Edits Tampering / Concurrency 6.8 (Med)   MEDIUM      Designed (Immutable Snapshots)
-----------------------------------------------------------------------------------------------------------------
```

---

### Threat 01: Privilege Escalation (Operator Attempting Admin Actions)
- **STRIDE:** Elevation of Privilege
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (**8.8 - High**)
- **Attack Scenario:**
  An authenticated operator account attempts to call administrative REST endpoints (e.g., `POST /api/admin/policy/create`, `PUT /api/admin/policy/{id}`, or `DELETE /api/admin/targets/{id}`) to whitelist external targets or grant themselves administrative capabilities.
- **Vulnerability in Existing Codebase:**
  Currently, all dashboard endpoints are unauthenticated and lack role checks. Anyone with network access to port 8088 has full control.
- **Designed Defense:**
  - Role-Based Access Control (RBAC) middleware decorator `@require_role('admin')`.
  - The middleware extracts the session token from the `admin_sessions` table, verifies `is_active == 1`, confirms `role == 'admin'`, and checks `locked_until IS NULL`.
  - Non-admin sessions receive an immediate `403 Forbidden` JSON error, and the attempt is logged to `admin_audit_log` with status `DENIED`.
- **Automated Verification Test:**
  `test_operator_cannot_access_admin_policy_endpoints()`: Creates an operator session, issues `POST /api/admin/policy/create`, asserts HTTP 403, asserts no policy is inserted in the database, and verifies audit entry logged as `DENIED`.

---

### Threat 02: Authentication Bypass on Admin Endpoints
- **STRIDE:** Spoofing / Elevation of Privilege
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (**9.8 - Critical**)
- **Attack Scenario:**
  An attacker sends forged session cookies, empty Authorization headers, or malformed tokens to administrative endpoints, attempting to exploit loose validation logic.
- **Vulnerability in Existing Codebase:**
  Endpoints currently lack session validation entirely.
- **Designed Defense:**
  - Mandatory session verification middleware on all `/api/admin/*` and `/api/auth/me` routes.
  - Session tokens are compared using constant-time string comparison (`hmac.compare_digest`) against active database rows in `admin_sessions`.
  - Sessions past `expires_at` or idle for > 30 minutes are immediately purged and rejected with `401 Unauthorized`.
- **Automated Verification Test:**
  `test_admin_endpoints_reject_unauthenticated_requests()`: Calls all administrative endpoints with (a) no session cookie, (b) invalid cookie `bad_token_123`, (c) expired session token. Asserts HTTP 401 across all calls.

---

### Threat 03: Cross-Site Request Forgery (CSRF) on Administrative Actions
- **STRIDE:** Tampering
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (**8.1 - High**)
- **Attack Scenario:**
  An administrator logged into the dashboard visits a malicious website in another browser tab. The malicious page triggers a background cross-origin `POST http://127.0.0.1:8088/api/admin/policy/create` using the administrator's ambient browser cookies to add an external target to the whitelist.
- **Vulnerability in Existing Codebase:**
  No CSRF tokens or SameSite cookie configurations currently exist.
- **Designed Defense:**
  1. Session cookies are configured with `SameSite=Strict; HttpOnly; Path=/`.
  2. Synchronizer Token Pattern: Every state-changing request (`POST`, `PUT`, `DELETE`) requires a custom header `X-CSRF-Token`. Browsers prevent cross-origin scripts from setting custom headers without CORS preflight approval (and CORS is disabled / restricted to localhost).
  3. Server validates `request.headers.get("X-CSRF-Token") == session.csrf_token`.
- **Automated Verification Test:**
  `test_csrf_token_required_for_admin_state_mutations()`: Establishes a valid admin session, issues `POST /api/admin/policy/create` without the `X-CSRF-Token` header, asserts HTTP 403 `CSRF token missing or invalid`, and confirms no database state changes.

---

### Threat 04: Session Fixation & Hijacking
- **STRIDE:** Spoofing
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (**7.5 - High**)
- **Attack Scenario:**
  An attacker forces an unauthenticated victim to use a known session identifier, which becomes authenticated once the administrator logs in.
- **Vulnerability in Existing Codebase:**
  No web sessions currently exist.
- **Designed Defense:**
  - Session tokens are generated solely server-side using `secrets.token_urlsafe(32)` **after** successful credential verification.
  - Any pre-existing cookies are cleared upon login.
  - Explicit logout (`POST /api/auth/logout`) destroys the session in the database and expires the client cookie.
  - Absolute session expiration (8 hours) and sliding idle expiration (30 minutes).
- **Automated Verification Test:**
  `test_session_regeneration_and_invalidation_on_logout()`: Verifies that session tokens change upon login, old pre-login tokens are invalid, and logout renders the session token immediately unusable.

---

### Threat 05: Policy Modification / Parameter Tampering by Assessment Operators
- **STRIDE:** Tampering
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (**7.2 - High**)
- **Attack Scenario:**
  An assessment operator issues `POST /api/assessments/start` with a body attempting to override policy constraints (e.g., passing `max_requests=500` when the policy permits only `25`, or passing an unapproved `target_url`).
- **Vulnerability in Existing Codebase:**
  `DashboardSessionManager.start_assessment` currently accepts whatever parameters the caller provides.
- **Designed Defense:**
  - Operator must provide a valid `policy_id`.
  - The backend retrieves the active policy and strictly enforces that user-provided arguments cannot exceed policy boundaries:
    - `effective_max_requests = min(user_req, policy.max_requests, LEVEL_A_MAX_REQUESTS)`
    - `target_url` must match an approved entry in `target_authorizations` for that `policy_id`.
  - Any attempt to bypass policy boundaries results in a `400 Bad Request` rejection with a descriptive policy violation receipt.
- **Automated Verification Test:**
  `test_assessment_start_rejects_budget_tampering()`: Starts an assessment requesting 100 requests under a policy capping requests at 20. Asserts the controller is initialized with `max_requests_per_session=20`.

---

### Threat 06: Scope Bypass via IP/DNS Encoding Tricks
- **STRIDE:** Elevation of Privilege
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` (**8.6 - High**)
- **Attack Scenario:**
  An attacker submits obfuscated target URLs designed to bypass string-based hostname checks while resolving to prohibited addresses (e.g., `http://0177.0.0.1` [octal], `http://0x7f000001` [hex], `http://2130706433` [decimal dword], `http://127.0.0.1.nip.io`, or `http://[::ffff:127.0.0.1]`).
- **Vulnerability in Existing Codebase:**
  `ScopeValidator` currently uses `urllib.parse.urlsplit` and string comparisons against `allowed_hosts`.
- **Designed Defense:**
  - URL host strings are parsed and canonicalized using Python's standard `ipaddress.ip_address` parser.
  - Integer, hex, and octal representations are normalized to standard dotted-decimal IPv4 or canonical IPv6 format before comparison.
  - DNS hostnames are validated against an explicit whitelist of approved FQDNs; unapproved domains are rejected before any DNS resolution occurs.
- **Automated Verification Test:**
  `test_scope_validator_rejects_obfuscated_ip_representations()`: Feeds hex, octal, decimal, and non-whitelisted FQDN variants into `ScopeValidator.validate_url()`, confirming all invalid or non-whitelisted formats are blocked.

---

### Threat 07: Scope Escape via HTTP 3xx Redirects
- **STRIDE:** Elevation of Privilege
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (**8.6 - High**)
- **Attack Scenario:**
  A targeted localhost application responds to an authorized probe with an HTTP 302 redirect pointing to an unauthorized external target or cloud metadata endpoint: `Location: http://169.254.169.254/latest/meta-data/`. If the HTTP client follows redirects automatically, the agent inadvertently probes out-of-scope targets.
- **Vulnerability in Existing Codebase:**
  `http_request.py` and `httpx_client.py` currently set `allow_redirects=False` and `follow_redirects=False`. However, if an agent turn proposes probing the URL found in the `Location` header, this proposal must undergo full validation.
- **Designed Defense:**
  - `allow_redirects=False` remains an **Immutable Level A Invariant**.
  - If the agent extracts the `Location` header and attempts to dispatch a subsequent request, the new URL must enter the front of the policy pipeline, where it is evaluated against Level A metadata blocks and Level B authorized target whitelists.
- **Automated Verification Test:**
  `test_http_redirect_never_followed_to_unauthorized_target()`: Configures a local mock server returning `302 Found` with `Location: http://169.254.169.254/latest/meta-data/`. Asserts tool execution returns the 302 response without following, and any subsequent probe proposal is blocked by `PolicyEngine`.

---

### Threat 08: Model-Generated Unauthorized Tool Invocations & Payload Injection
- **STRIDE:** Tampering / Elevation of Privilege
- **CVSS v3.1:** `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (**7.8 - High**)
- **Attack Scenario:**
  During an assessment, an adversarial prompt injection in a target web application's response payload induces the Qwen LLM to output a tool invocation requesting shell execution (`rm -rf /`, `powershell`, or `curl evil.com`) or a destructive SQL command (`DROP TABLE users`).
- **Vulnerability in Existing Codebase:**
  `PolicyEngine` contains regex patterns in `PROHIBITED_COMMAND_PATTERNS` and `DESTRUCTIVE_DB_PATTERNS`, but lacks formal multi-category tool permission gating.
- **Designed Defense:**
  - Deterministic gate: The LLM output is parsed into a structured candidate action and immediately routed to `PolicyEngine.evaluate_action()`.
  - The model has no direct execution privileges.
  - Regex guards reject any shell chaining characters or destructive SQL syntax.
  - Unregistered or policy-disabled tools are rejected with `approved=False`.
- **Automated Verification Test:**
  `test_model_prompt_injection_cannot_bypass_policy_engine()`: Simulates model generating commands containing `; rm -rf`, `DROP TABLE`, and `powershell.exe`. Asserts `PolicyEngine.evaluate_action()` returns `approved=False` for 100% of adversarial proposals.

---

### Threat 09: Direct API Calls Bypassing Dashboard Restrictions
- **STRIDE:** Elevation of Privilege / Security Bypass
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` (**8.2 - High**)
- **Attack Scenario:**
  An attacker avoids the web frontend entirely and sends raw HTTP requests directly to backend endpoints (e.g. `curl -X POST http://127.0.0.1:8088/api/assessments/start -d '{"target_url": "http://evil.com"}'`).
- **Vulnerability in Existing Codebase:**
  `dashboard/app.py` has basic parameter validation, but does not authenticate callers or verify database policies.
- **Designed Defense:**
  - Client-side validation in `dashboard.js` is treated as a user experience convenience only.
  - The server (`app.py` and `session_manager.py`) independently authenticates the request, validates the CSRF token, loads the policy from the database, and enforces scope boundaries via `PolicyEngine`.
- **Automated Verification Test:**
  `test_direct_backend_api_calls_enforce_all_policy_checks()`: Uses Python `requests` or `TestClient` to send raw, malformed, and out-of-scope payloads directly to `/api/assessments/start` without browser context, asserting strict server-side rejection.

---

### Threat 10: Race Conditions During Concurrent Policy Updates
- **STRIDE:** Tampering / Concurrency Conflict
- **CVSS v3.1:** `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:M` (**6.8 - Medium**)
- **Attack Scenario:**
  An administrator edits or deactivates a policy while an autonomous penetration testing session governed by that policy is actively executing turns. A race condition could cause the controller to read partially updated policy state or crash mid-assessment.
- **Vulnerability in Existing Codebase:**
  Currently policies are static. Dynamic policies in SQLite could suffer from phantom reads or state inconsistencies during long-running sessions.
- **Designed Defense:**
  - **Immutable Policy Snapshots:** When an assessment session launches, the governing policy version is serialized into JSON and written to `assessment_policy_snapshots(assessment_session_id, policy_id, policy_version, snapshot_json)`.
  - The active assessment controller reads exclusively from this frozen snapshot for its entire lifecycle.
  - Editing or deleting a policy in `policies` / `policy_versions` does not mutate existing running assessments.
  - If an administrator explicitly revokes/cancels an active assessment, they use the dedicated `/api/assessments/{id}/cancel` endpoint.
- **Automated Verification Test:**
  `test_active_assessment_unaffected_by_concurrent_policy_mutation()`: Launches a mock multi-turn assessment under Policy v1. Concurrently mutates Policy v1 to disable tools and change budgets. Asserts the running session completes its turns adhering strictly to the frozen snapshot.

---

## 3. Threat Model Review & Sign-Off
This threat model covers all ten threat vectors specified in Phase 5.1 requirements. The mitigations established here directly guide the technical implementations in [POLICY_AUTHORIZATION_IMPLEMENTATION_PLAN.md](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/docs/POLICY_AUTHORIZATION_IMPLEMENTATION_PLAN.md) and the test suites in [POLICY_AUTHORIZATION_TEST_PLAN.md](file:///s:/UROP/offensive%20AI%20and%20autonomous%20APi%20penetration%20testing/docs/POLICY_AUTHORIZATION_TEST_PLAN.md).

