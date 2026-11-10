# Policy & Authorization Comprehensive Security Test Plan

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Directory:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Role:** Senior Security QA Architect, Application Security Engineer & Penetration Tester  
**Date:** November 5, 2026  
**Document Status:** Complete Test Plan (Pre-Implementation)

---

## 1. Quality Assurance & Security Verification Objectives

This test plan defines the formal test suites, test cases, attack simulations, and empirical verification procedures required to guarantee that the Policy & Authorization Administration system operates flawlessly and securely under zero-trust conditions.

### Core Testing Invariants:
1. **Level A Non-Bypassability:** Immutable developer safety rules cannot be bypassed by any user role, database entry, or AI model generation.
2. **Zero-Trust Policy Enforcement:** Every proposed tool action must pass through the deterministic `PolicyEngine` before network execution. Missing, expired, invalid, or ambiguous authorizations result in immediate denial.
3. **Model Independence:** The local Qwen GGUF model possesses no execution authority. Adversarial model prompt injections cannot trigger unauthorized actions or bypass safety gates.
4. **Air-Gapped Local Operation:** All cryptographic operations, password verifications, session validations, and audit logs execute strictly on the local machine with 0 external network requests.
5. **Zero Regression:** All existing application capabilities and all 234 existing automated tests across 30 test files must remain 100% passing.

---

## 2. Test Suite Organization & Traceability Matrix

```
Test Suite Traceability Matrix:
-------------------------------------------------------------------------------------------------------------------------
Suite ID    Test Module                                 Coverage Area                                      Target Tests
-------------------------------------------------------------------------------------------------------------------------
TS-01       tests/test_evidence_store_schema_v2.py      Database schema, migrations, foreign keys, indexes 8 tests
TS-02       tests/test_auth_crypto_and_sessions.py      PBKDF2 hashing, session tokens, CSRF, rate limits  12 tests
TS-03       tests/test_policy_service_and_versioning.py Policy CRUD, version increments, snapshots, rollback 10 tests
TS-04       tests/test_policy_scope_enforcement.py      Level A invariants, Level B policies, redirects    15 tests
TS-05       tests/test_dashboard_auth_and_rbac.py       API auth decorators, role gating, CSRF validation  14 tests
TS-06       tests/test_assessment_policy_binding.py     Assessment snapshot immutability & race defense    6 tests
TS-07       tests/test_admin_audit_logging.py           Audit log completeness, immutability, detail JSON  6 tests
TS-08       Full Test Suite Regression                  Complete test suite execution (All 30 test files)  234+ tests
-------------------------------------------------------------------------------------------------------------------------
```

---

## 3. Detailed Test Specifications

### Suite TS-01: Database Schema & Relational Integrity (`test_evidence_store_schema_v2.py`)
- **Test 1.1: `test_v2_schema_creation_and_preservation`**
  - *Objective:* Verify all 7 new tables are created without modifying or dropping existing tables (`sessions`, `plans`, `traffic_log`, `findings`, `tool_executions`, `specifications`, `zap_scans`).
  - *Assertion:* Table list contains exactly 14 tables; existing row counts and column schemas are preserved.
- **Test 1.2: `test_foreign_key_constraints_enforced`**
  - *Objective:* Verify SQLite enforces foreign keys across new tables (`policy_versions.policy_id` -> `policies.id`, `admin_sessions.user_id` -> `users.id`).
  - *Assertion:* Inserting orphaned child row raises `sqlite3.IntegrityError`.
- **Test 1.3: `test_policy_version_uniqueness_constraint`**
  - *Objective:* Verify `(policy_id, version)` tuple is unique in `policy_versions`.
  - *Assertion:* Inserting duplicate version number for the same policy raises `sqlite3.IntegrityError`.
- **Test 1.4: `test_admin_audit_log_persists_without_foreign_key_lockout`**
  - *Objective:* Verify `admin_audit_log` records events with valid user references and system events with `user_id = NULL`.
  - *Assertion:* Both authenticated and unauthenticated actions are recorded successfully.

---

### Suite TS-02: Cryptographic Authentication & Session Management (`test_auth_crypto_and_sessions.py`)
- **Test 2.1: `test_password_hashing_pbkdf2_salted`**
  - *Objective:* Verify password hashing produces unique 32-byte salts and deterministic hash verification.
  - *Assertion:* `hash_password("Pass123!")` returns unique salt each call; `verify_password()` returns `True` for matching password and `False` for incorrect password or empty string.
- **Test 2.2: `test_constant_time_comparison_timing_resistance`**
  - *Objective:* Verify password and token comparisons use `hmac.compare_digest` to prevent timing attacks.
  - *Assertion:* Inspection of verification routine confirms `hmac.compare_digest` usage.
- **Test 2.3: `test_session_token_cryptographic_randomness`**
  - *Objective:* Verify session tokens are generated from `secrets.token_urlsafe(32)`.
  - *Assertion:* Token length is >= 43 base64 characters; 1,000 generated tokens exhibit zero collisions.
- **Test 2.4: `test_session_sliding_expiration`**
  - *Objective:* Verify session expires after 30 minutes of inactivity, but refreshes `last_activity_at` upon valid request.
  - *Assertion:* Simulated time advancement > 30 minutes invalidates session (`validate_session() is None`); activity before 30 minutes extends validity up to the 8-hour hard ceiling.
- **Test 2.5: `test_session_invalidation_on_logout`**
  - *Objective:* Verify `invalidate_session()` destroys server-side session immediately.
  - *Assertion:* Subsequent calls to `validate_session()` with the invalidated token return `None`.
- **Test 2.6: `test_login_rate_limiting_and_lockout`**
  - *Objective:* Verify that 5 consecutive failed login attempts lock the account for 15 minutes.
  - *Assertion:* 5th failure sets `locked_until > time.time()`; 6th attempt is rejected immediately with "Account locked" without evaluating password hash.
- **Test 2.7: `test_csrf_token_generation_and_validation`**
  - *Objective:* Verify synchronizer CSRF token generated per session.
  - *Assertion:* Valid session returns `csrf_token`; validating mismatched or empty token fails.
- **Test 2.8: `test_emergency_cli_bootstrap_and_recovery`**
  - *Objective:* Verify CLI bootstrap tool creates admin account when database is empty.
  - *Assertion:* `bootstrap_admin` succeeds on empty DB; refuses execution if an admin already exists; password reset CLI successfully updates password hash.

---

### Suite TS-03: Policy Service & Versioning Engine (`test_policy_service_and_versioning.py`)
- **Test 3.1: `test_policy_creation_and_version_1_initialization`**
  - *Objective:* Creating a policy creates row in `policies` and version 1 row in `policy_versions`.
  - *Assertion:* `policy.current_version == 1`; `policy_versions` contains configuration JSON matching input.
- **Test 3.2: `test_policy_mutation_creates_immutable_new_version`**
  - *Objective:* Updating policy configuration increments version number without mutating previous version row.
  - *Assertion:* After update, `policies.current_version == 2`; both version 1 and version 2 exist in `policy_versions`.
- **Test 3.3: `test_policy_version_rollback`**
  - *Objective:* Rolling back to version 1 creates version 3 containing exact copy of version 1 configuration.
  - *Assertion:* Version 3 created; `change_summary` notes "Rollback to version 1"; audit entry logged.
- **Test 3.4: `test_policy_activation_and_deactivation`**
  - *Objective:* Deactivating a policy sets `is_active = 0` and removes it from `get_active_policies()`.
  - *Assertion:* Deactivated policy cannot be selected by operators for new assessments.
- **Test 3.5: `test_policy_expiration_boundary`**
  - *Objective:* Policy with past `expires_at` is treated as inactive.
  - *Assertion:* Attempting to launch an assessment with an expired policy raises policy rejection error.

---

### Suite TS-04: Policy & Scope Enforcement Engine (`test_policy_scope_enforcement.py`)
- **Test 4.1: `test_level_a_destructive_db_queries_blocked_unconditionally`**
  - *Objective:* Verify destructive patterns (`DROP TABLE`, `TRUNCATE`, `DELETE FROM`, `SHUTDOWN`) are rejected even if administrator enables all tools and categories.
  - *Assertion:* `PolicyEngine.evaluate_action()` returns `approved=False` for all destructive SQL payloads.
- **Test 4.2: `test_level_a_shell_injection_blocked_unconditionally`**
  - *Objective:* Verify command injection characters and binaries are rejected.
  - *Assertion:* Proposals containing `; cat /etc/passwd`, `| cmd.exe`, or `& powershell` return `approved=False`.
- **Test 4.3: `test_level_a_http_redirect_never_followed`**
  - *Objective:* Verify HTTP tools return 302 responses without following redirects.
  - *Assertion:* Response object has `status_code = 302`; target URL remains initial URL; no request dispatched to `Location`.
- **Test 4.4: `test_level_a_hard_resource_ceiling_enforcement`**
  - *Objective:* Verify hard ceiling of 100 requests per session cannot be overridden by policy configuration.
  - *Assertion:* Policy with `max_requests = 500` is clamped to 100 at runtime.
- **Test 4.5: `test_level_b_target_whitelist_enforcement`**
  - *Objective:* Verify only hosts in the active policy's `target_authorizations` are permitted.
  - *Assertion:* Targets matching authorized host/port return `approved=True`; non-whitelisted targets return `approved=False`.
- **Test 4.6: `test_level_b_port_range_and_path_prefix_matching`**
  - *Objective:* Verify target with port outside authorized range or path outside allowed prefix is rejected.
  - *Assertion:* `http://127.0.0.1:9000/api` rejected when policy allows only ports `5000-5055`.
- **Test 4.7: `test_level_b_http_method_restriction`**
  - *Objective:* Verify methods not in policy `allowed_http_methods` are rejected.
  - *Assertion:* `DELETE` request rejected when policy permits only `GET, POST`.
- **Test 4.8: `test_level_b_tool_whitelist_restriction`**
  - *Objective:* Verify tools not in policy allowed list are rejected.
  - *Assertion:* `zap_scanner` proposal rejected when policy allows only `http_request`.
- **Test 4.9: `test_canonical_ip_normalization_defeats_obfuscation`**
  - *Objective:* Verify hex (`0x7f000001`), octal (`0177.0000.0000.0001`), decimal (`2130706433`), and IPv6-mapped addresses are normalized or rejected.
  - *Assertion:* Obfuscated representations are properly evaluated against normalized whitelist; non-loopback obfuscations blocked.

---

### Suite TS-05: Dashboard Authentication & RBAC API (`test_dashboard_auth_and_rbac.py`)
- **Test 5.1: `test_unauthenticated_requests_to_admin_api_rejected_401`**
  - *Objective:* Calling `/api/admin/policies` without session cookie returns HTTP 401.
  - *Assertion:* Status code 401; response body contains `{"error": "Authentication required"}`.
- **Test 5.2: `test_operator_access_to_admin_api_rejected_403`**
  - *Objective:* Authenticated operator accessing `/api/admin/policies` receives HTTP 403.
  - *Assertion:* Status code 403; response body contains `{"error": "Administrator privilege required"}`.
- **Test 5.3: `test_admin_login_success_sets_http_only_cookie`**
  - *Objective:* `POST /api/auth/login` with valid admin credentials sets `Set-Cookie` with `HttpOnly` and `SameSite=Strict`.
  - *Assertion:* Response header `Set-Cookie` contains `HttpOnly` and `SameSite=Strict`; returns CSRF token in JSON.
- **Test 5.4: `test_admin_csrf_protection_on_mutating_endpoints`**
  - *Objective:* Calling `POST /api/admin/policies` without `X-CSRF-Token` header returns HTTP 403.
  - *Assertion:* Status code 403; response contains `{"error": "CSRF token missing or invalid"}`.
- **Test 5.5: `test_admin_policy_crud_lifecycle_via_api`**
  - *Objective:* Full lifecycle test via REST API: Create -> Read -> Update -> Rollback -> Deactivate.
  - *Assertion:* All operations succeed with valid credentials and CSRF token; version numbers increment properly.
- **Test 5.6: `test_assessment_start_requires_valid_policy_and_authorized_target`**
  - *Objective:* `POST /api/assessments/start` validates `policy_id` and target match.
  - *Assertion:* Missing or inactive `policy_id` returns 400; target outside policy returns 400; valid request launches session.

---

### Suite TS-06: Assessment Policy Snapshot Immutability (`test_assessment_policy_binding.py`)
- **Test 6.1: `test_policy_snapshot_frozen_at_assessment_launch`**
  - *Objective:* Launching an assessment writes frozen copy of policy to `assessment_policy_snapshots`.
  - *Assertion:* Row exists in `assessment_policy_snapshots` for `session_id`; `snapshot_json` matches policy configuration.
- **Test 6.2: `test_running_assessment_immune_to_policy_mutation`**
  - *Objective:* Mutating policy in database while assessment runs does not alter running controller's behavior.
  - *Assertion:* Running controller continues using frozen snapshot configuration for all turns.
- **Test 6.3: `test_running_assessment_immune_to_policy_deletion`**
  - *Objective:* Deleting or deactivating policy while assessment runs does not abort or corrupt active session.
  - *Assertion:* Active session completes successfully using snapshot; subsequent reports correctly link to snapshot.

---

### Suite TS-07: Administrative Audit Logging Completeness (`test_admin_audit_logging.py`)
- **Test 7.1: `test_login_success_and_failure_audited`**
  - *Objective:* Verify both successful and failed login attempts create rows in `admin_audit_log`.
  - *Assertion:* Successful login logs `action = "LOGIN_SUCCESS", status = "SUCCESS"`; failed login logs `action = "LOGIN_FAILURE", status = "FAILED"`.
- **Test 7.2: `test_policy_lifecycle_events_audited`**
  - *Objective:* Creating, editing, activating, and rolling back policies log audit events with detail JSON diffs.
  - *Assertion:* Audit log contains entries for `POLICY_CREATED`, `POLICY_UPDATED`, `POLICY_ACTIVATED`, `POLICY_ROLLBACK` with `details_json` containing parameter diffs.
- **Test 7.3: `test_unauthorized_admin_access_attempt_audited`**
  - *Objective:* Operator attempting to access admin endpoint is logged as `ACCESS_DENIED`.
  - *Assertion:* `admin_audit_log` records `action = "ADMIN_ACCESS_ATTEMPT", status = "DENIED"`, username, and IP.

---

### Suite TS-08: Complete System Regression Test
- **Execution Command:**
  ```powershell
  python -m pytest tests -v
  ```
- **Pass Criteria:**
  - 100% of the original 234 tests across 30 test files must pass.
  - All new test suites (TS-01 through TS-07) must pass.
  - Test suite execution exit code must be `0`.

---

## 4. Test Execution Sign-Off & Phase Transition
This test plan ensures comprehensive test-driven development (TDD) for Phase 5.2. Implementation will proceed with test creation and verification at every stage.

