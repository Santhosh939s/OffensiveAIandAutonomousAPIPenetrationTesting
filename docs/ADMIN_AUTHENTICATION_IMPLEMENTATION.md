# Administrator Authentication Implementation Specification

**Project:** Offensive AI and Autonomous API Penetration Testing  
**Project Directory:** `S:\UROP\offensive AI and autonomous APi penetration testing`  
**Role:** Senior Backend Security Engineer & Authentication Architect  
**Date:** November 5, 2026  
**Status:** Completed & Empirically Verified (Phase 5.2)

---

## 1. Overview & Architectural Boundaries

Phase 5.2 implements an offline-capable, role-segregated **Administrator Authentication System** for the Autonomous API Penetration Testing Platform. The implementation provides cryptographically secure password hashing, single-use administrator bootstrap, token-hashed server-side sessions, sliding inactivity expiration, synchronizer-token CSRF protection, and role-based access control (RBAC).

All authentication and session components execute locally on Windows without external network calls, cloud authentication providers, or third-party identity dependencies.

```mermaid
flowchart TD
    subgraph Client["Web Browser Client"]
        Browser["User Browser"]
        CookieStorage["HttpOnly Cookie Store<br/>(session_token)"]
        MemoryStorage["JavaScript Memory Store<br/>(csrfToken)"]
    end

    subgraph DashboardLayer["Dashboard Service (Flask on 127.0.0.1:8088)"]
        AuthMiddleware["Middleware Decorators<br/>(@require_auth, @require_role, @require_csrf)"]
        LoginEndpoint["POST /api/auth/login"]
        LogoutEndpoint["POST /api/auth/logout"]
        StatusEndpoint["GET /api/auth/status"]
        AdminTestEndpoint["GET /api/admin/test<br/>POST /api/admin/echo"]
    end

    subgraph AuthCore["Controller Auth Engine (Python)"]
        AuthService["AuthenticationService<br/>PBKDF2-HMAC-SHA256 (600k iter, 32B salt)<br/>Brute-Force Counter & Lockout"]
        SessionService["SessionService<br/>32B CSPRNG Token Hashing (SHA-256)<br/>Sliding Expiration (30 min / 8 hr)"]
        RoleService["RoleService<br/>Role & Permission Mapping<br/>(Admin, Operator, Auditor)"]
    end

    subgraph DataStore["Evidence Database (SQLite)"]
        UsersTable["users Table<br/>(salted hashes, lockouts, counters)"]
        SessionsTable["admin_sessions Table<br/>(token_hash, user_id, csrf_token)"]
        AuditTable["admin_audit_log Table<br/>(immutable security event trail)"]
    end

    Browser -->|POST /api/auth/login| LoginEndpoint
    LoginEndpoint --> AuthService
    AuthService --> UsersTable
    AuthService --> AuditTable
    AuthService --> SessionService
    SessionService --> SessionsTable
    SessionService -->|Set-Cookie: session_token (HttpOnly, SameSite=Strict)| CookieStorage
    SessionService -->|Return csrf_token| MemoryStorage

    Browser -->|GET /api/admin/test + Cookie| AuthMiddleware
    Browser -->|POST /api/admin/echo + Cookie + X-CSRF-Token| AuthMiddleware
    AuthMiddleware --> SessionService
    AuthMiddleware --> RoleService
    AuthMiddleware --> AdminTestEndpoint
```

---

## 2. Core Security Services Implementation

### 2.1 Role Service (`controller/auth/role_service.py`)
Defines the platform's initial role hierarchy:
- `Role.ADMIN ("admin")`: Complete control over users, policies, targets, assessment execution, audit logs, and diagnostic endpoints.
- `Role.OPERATOR ("operator")`: Authorized to execute, monitor, and cancel assessments; view findings, traffic, and reports. Forbidden from accessing administrative controls or audit logs.
- `Role.AUDITOR ("auditor")`: Read-only access to assessment findings, reports, and administrative audit logs. Forbidden from launching assessments or editing configurations.

### 2.2 Session Security Service (`controller/auth/session_service.py`)
- **Cryptographic Randomness:** Raw tokens and CSRF tokens are generated via `secrets.token_urlsafe(32)`.
- **Database Token Hashing:** The database stores `session_token_hash = sha256(raw_token)` rather than the plaintext token. Even with read access to the SQLite database, an attacker cannot construct valid session cookies.
- **Sliding Inactivity Expiration:** Every valid request validates `(now - last_activity_at) <= 1800.0` (30 minutes) and advances `last_activity_at` forward. Idle sessions past 30 minutes are deleted.
- **Maximum Lifetime Ceiling:** Sessions are strictly bounded by `now <= expires_at` (8 hours from creation). Even with continuous activity, sessions expire after 8 hours.
- **Session Rotation:** Successful authentication executes `rotate_session()`, purging any previous pre-authentication session identifier to defeat session fixation attacks.
- **CSRF Token Validation:** Validates incoming `X-CSRF-Token` headers against the session's synchronizer token using constant-time `hmac.compare_digest()`.

### 2.3 Authentication Service (`controller/auth/authentication_service.py`)
- **Password Hashing:** Implemented via standard library `hashlib.pbkdf2_hmac("sha256", password, salt, iterations=600_000)`.
- **Salts:** 32-byte cryptographically random salt generated via `secrets.token_bytes(32)`.
- **Constant-Time Verification:** Compares the newly derived PBKDF2 hash against the stored hash digest using `hmac.compare_digest()` to eliminate timing side-channels.
- **Brute-Force & Account Lockout:**
  - Failed login attempts increment `failed_login_attempts`.
  - Reaching 5 consecutive failures sets `locked_until = now + 900.0` (15-minute temporary lockout).
  - During lockout, all login attempts are denied immediately.
  - Successful login resets `failed_login_attempts = 0` and clears `locked_until`.
  - Generic error message `"Invalid credentials"` is returned across all failure scenarios to prevent username enumeration.
- **Password Strength Rules:**
  - Minimum 10 characters length.
  - Requires at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special symbol.
  - Prohibits username substrings and trivial dictionary passwords.

---

## 3. Administrator Bootstrap & Recovery Procedure

### 3.1 Initial Administrator Bootstrap
- Command:
  ```powershell
  python -m controller.auth.bootstrap_admin --username <username>
  ```
- **Security Invariants:**
  1. Prompts for password twice without echo (`getpass.getpass()`).
  2. Queries `users` table for existing accounts with `role == 'admin' AND is_active == 1`.
  3. If an administrator exists, the command terminates with exit code 1 and logs `BOOTSTRAP_REJECTED` with status `DENIED`.
  4. Validates username and password complexity before hashing.
  5. Commits administrator record and writes `BOOTSTRAP_ADMIN_CREATED` to `admin_audit_log`.

### 3.2 Local Credential Recovery Procedure
In the event of forgotten administrator credentials, local shell access allows offline password reset:
- Command:
  ```powershell
  python -m controller.auth.reset_password --username <username>
  ```
- Prompts for new password without echo, validates complexity, updates the PBKDF2 salt and hash, resets failed login counters, clears account locks, and immediately purges all active sessions from `admin_sessions` for that user.

---

## 4. Database Schema Migrations

The database migration was implemented non-destructively in `EvidenceStore._init_db()` in `controller/storage/evidence_store.py`:

```sql
-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'operator', 'auditor')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_login_at REAL,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until REAL
);

-- Admin Sessions Table
CREATE TABLE IF NOT EXISTS admin_sessions (
    session_token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    last_activity_at REAL NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Admin Audit Log Table
CREATE TABLE IF NOT EXISTS admin_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    ip_address TEXT,
    details_json TEXT,
    status TEXT NOT NULL CHECK(status IN ('SUCCESS', 'DENIED', 'FAILED')),
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_timestamp ON admin_audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_user ON admin_audit_log(user_id);
```

Existing assessment tables (`sessions`, `plans`, `traffic_log`, `findings`, `tool_executions`, `specifications`, `zap_scans`) and existing recorded data remain completely intact.

---

## 5. Dashboard Integration & Endpoints

| Route | Method | Access Control | Function |
| :--- | :--- | :--- | :--- |
| `/login` | `GET` | Public | Renders clean dark-themed administrator login page (`login.html`). |
| `/api/auth/login` | `POST` | Public (Rate Limited) | Authenticates user, rotates session, sets `HttpOnly` `SameSite=Strict` cookie, returns CSRF token. |
| `/api/auth/logout` | `POST` | `@require_auth`<br>`@require_csrf` | Invalidates server-side session in database and expires client cookie. |
| `/api/auth/status` | `GET` | Public | Returns current authentication state (`authenticated: bool`, `user`, `csrf_token`). |
| `/api/admin/test` | `GET` | `@require_auth`<br>`@require_role('admin')` | Protected diagnostic endpoint verifying administrator authorization. |
| `/api/admin/echo` | `POST` | `@require_auth`<br>`@require_role('admin')`<br>`@require_csrf` | Protected state-changing diagnostic endpoint verifying CSRF and admin role. |
| `/api/assessments/*` | `ALL` | Public (Preserved) | All existing assessment and reporting APIs remain operational without disruption. |

