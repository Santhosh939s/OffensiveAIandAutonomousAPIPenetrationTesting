# Local API Security Laboratory

An intentionally vulnerable mock REST API service engineered exclusively for controlled, local validation of the Autonomous API Penetration Testing Controller.

> [!IMPORTANT]
> **Strict Localhost Boundary:** This service binds strictly to `127.0.0.1` and uses fictitious dummy records. It has no external network access, cloud dependencies, or persistent production data.

---

## Architecture & Endpoints

| Endpoint | Method | Intended Function | Demonstrable Security Weakness |
|---|---|---|---|
| `/health` | `GET` | Health check & service identification | Baseline: Clean status |
| `/api/users` | `GET` | Public user directory | Baseline: Standard unauthenticated listing |
| `/api/users/<id>` | `GET` | Retrieve user profile by ID | **BOLA / IDOR:** Leaks private attributes (`email`, `api_token`, `password_hash`) across accounts |
| `/api/login` | `POST` | User authentication simulation | **Weak Authentication:** Allows blank-password bypass; issues unsigned JWT with `alg="none"` |
| `/api/users/<id>` | `PUT` | Update profile information | **Mass Assignment:** Permits unauthorized privilege escalation by updating `role` or `is_admin` |
| `/api/search?q=` | `GET` | Item catalog search | **Unsafe Input Handling:** Unsanitized query string triggers unhandled database syntax error (SQLi risk) |
| `/api/items` | `GET` | Catalog item listing | Baseline: Standard product list |

---

## Seeded Dummy Accounts & Credentials

The lab automatically seeds the following in-memory testing dataset:

| ID | Username | Dummy Password | Role | Is Admin | API Token |
|---|---|---|---|---|---|
| `1` | `alice` | `alice123` | `user` | `0` | `tok_alice_live_99182` |
| `2` | `bob` | `bob123` | `user` | `0` | `tok_bob_live_47219` |
| `3` | `admin` | `AdminSuperKey_2026!` | `admin` | `1` | `tok_admin_root_master_88201` |

---

## Demonstration Scenarios

### 1. BOLA / IDOR (Broken Object-Level Authorization)
- **Normal Request:** `GET /api/users/1`
- **Anomalous Request:** `GET /api/users/2` or `GET /api/users/3`
- **Evidence:** Server returns sensitive fields (`password_hash`, `api_token`) belonging to other users without requiring authorization tokens or verifying object ownership.

### 2. Insecure Token & Authentication Bypass
- **Normal Request:** `POST /api/login` with `{"username": "alice", "password": "alice123"}`
- **Bypass Probe:** `POST /api/login` with `{"username": "admin", "password": ""}`
- **Evidence:** Login succeeds without credentials, and the returned JWT token has a header with `"alg": "none"` and no signature.

### 3. Mass Assignment
- **Normal Request:** `PUT /api/users/1` with `{"full_name": "Alice Cooper"}`
- **Privilege Escalation Probe:** `PUT /api/users/1` with `{"role": "admin", "is_admin": 1}`
- **Evidence:** Response confirms the user's role was elevated to `admin` due to missing attribute filtering.

### 4. Unsafe Input Handling / SQL Syntax Anomaly
- **Normal Request:** `GET /api/search?q=laptop` -> HTTP 200 with search results
- **Probe Request:** `GET /api/search?q='` -> HTTP 500
- **Evidence:** Server response body contains `Database error: syntax error in query...`, proving unsanitized string interpolation.

---

## Standalone Execution

To start the local lab independently:
```powershell
python -m lab.app
```
By default, the server listens at `http://127.0.0.1:5000`.

