"""Evidence Database Store for Autonomous API Penetration Testing.

Manages persistent SQLite storage of sessions, test plans, raw traffic logs,
tool execution receipts, and security findings.
Enforces that findings cannot be marked CONFIRMED without documented traffic
evidence and an explicit, valid verification rule.
"""

import json
import logging
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("EvidenceStore")

MAX_STORED_BODY_CHARS = 65536  # 64 KB ceiling for stored HTTP body in evidence database to bound RAM usage


def _bound_body(body_str: Optional[str], limit: int = MAX_STORED_BODY_CHARS) -> Optional[str]:
    """Truncate excessively large HTTP bodies to maintain a bounded memory footprint."""
    if body_str is None or len(body_str) <= limit:
        return body_str
    truncated_count = len(body_str) - limit
    return f"{body_str[:limit]}\n... [TRUNCATED {truncated_count} bytes for memory optimization]"


class _SafeConnectionProxy:
    """Thread-safe proxy for SQLite connections that serializes transactions and manages closing."""

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock, is_shared: bool):
        self._conn = conn
        self._lock = lock
        self._is_shared = is_shared

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        try:
            self._conn.__enter__()
            return self._conn
        except Exception:
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._conn.__exit__(exc_type, exc_val, exc_tb)
        except sqlite3.OperationalError:
            # Catch 'cannot commit - no transaction is active' when committed inside block
            pass
        finally:
            self._lock.release()
            if not self._is_shared:
                try:
                    self._conn.close()
                except Exception:
                    pass

    def commit(self):
        try:
            self._conn.commit()
        except sqlite3.OperationalError:
            pass



VALID_FINDING_STATUSES = {
    "UNTESTED",
    "SUSPECTED",
    "CONFIRMED",
    "NOT_DEMONSTRATED",
}

APPROVED_VERIFICATION_RULES = {
    "SQL_SYNTAX_ERROR_MATCH",          # Server returned explicit SQL error string
    "UNAUTHENTICATED_DATA_ACCESS",     # Protected endpoint returned 200 with data without valid credentials
    "ROLE_ELEVATION_VERIFIED",         # Server response confirmed role elevation beyond status 200 alone
    "PRIVILEGE_ESCALATION_STATUS_200", # Deprecated legacy alias retained for backwards compatibility
    "REFLECTED_PAYLOAD_UNSANITIZED",   # Input probe reflected without sanitization
    "TOKEN_ALGORITHM_NONE_ACCEPTED",   # Server accepted unsigned 'none' algorithm JWT
    "DIRECTORY_TRAVERSAL_FILE_LEAK",   # Server returned known system file content
    "UNHANDLED_EXCEPTION_LEAK",        # Server leaked internal stack trace or unhandled exception
    "GRAPHQL_INTROSPECTION_EXPOSED",   # GraphQL schema introspection exposed types/queries
    "BOLA_CROSS_ACCOUNT_LEAK",         # Horizontal authorization bypass accessing other tenant data
    "SSRF_INTERNAL_ENDPOINT_LEAK",     # Outbound probe reached private internal resource or loopback
    "UNRESTRICTED_RESOURCE_CONSUMPTION", # Endpoint lacks pagination ceiling or rate limiting
    "SECURITY_MISCONFIGURATION_HEADER",# Dangerous CORS wildcard or missing transport security
    "UNAUTHENTICATED_ENDPOINT_ACCESS", # Sensitive administrative functionality accessible without session
    "BFLA_ADMIN_FUNCTION_BYPASS",      # Administrative function invoked without authorization checks (API5:2023)
    "BUSINESS_FLOW_UNRESTRICTED_ACCESS",# Sensitive business flow executed without rate-limits or quotas (API6:2023)
    "SHADOW_OR_DEPRECATED_API_EXPOSED", # Deprecated or unadvertised shadow API surface reachable (API9:2023)
    "UNSAFE_DOWNSTREAM_API_CONSUMPTION",# Downstream API/webhook ingested without validation/signature (API10:2023)
}


class EvidenceStore:
    """Thread-safe SQLite storage for API security testing evidence and audit trail."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._local = threading.local()
        self._shared_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False, timeout=30.0)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> Any:
        if self._shared_conn is not None:
            return _SafeConnectionProxy(self._shared_conn, self._lock, is_shared=True)
        
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.execute("SELECT 1;")
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = None

        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("PRAGMA cache_size = -2000;")
                conn.execute("PRAGMA busy_timeout = 10000;")
                conn.execute("PRAGMA temp_store = MEMORY;")
                conn.execute("PRAGMA mmap_size = 33554432;")
            except Exception:
                pass
            self._local.conn = conn
        return _SafeConnectionProxy(conn, self._lock, is_shared=True)

    def close(self) -> None:
        """Close open SQLite database connections."""
        with self._lock:
            if self._shared_conn is not None:
                try:
                    self._shared_conn.close()
                except Exception:
                    pass
                self._shared_conn = None
            conn = getattr(self._local, "conn", None)
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
                self._local.conn = None

    def _init_db(self) -> None:
        """Create tables if they do not exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    status TEXT NOT NULL,
                    turns_taken INTEGER DEFAULT 0,
                    requests_sent INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)

            # 2. Plans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS plans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    plan_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            # 3. Traffic log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    headers_json TEXT,
                    request_body TEXT,
                    response_status INTEGER,
                    response_headers_json TEXT,
                    response_body TEXT,
                    elapsed_ms REAL,
                    evidence_hash TEXT,
                    raw_body_bytes INTEGER DEFAULT 0,
                    is_truncated INTEGER DEFAULT 0,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            # 4. Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    endpoint TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    evidence_notes TEXT,
                    verification_rule TEXT,
                    traffic_log_id INTEGER,
                    raw_evidence_json TEXT,
                    severity TEXT DEFAULT 'INFORMATIONAL',
                    cvss_score REAL DEFAULT 0.0,
                    cwe_id TEXT DEFAULT 'CWE-699',
                    remediation TEXT DEFAULT '',
                    evidence_hash TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id),
                    FOREIGN KEY(traffic_log_id) REFERENCES traffic_log(id)
                )
            """)

            # Non-destructive schema migration for existing databases
            cursor.execute("PRAGMA table_info(findings)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            if "severity" not in existing_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN severity TEXT DEFAULT 'INFORMATIONAL'")
            if "cvss_score" not in existing_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN cvss_score REAL DEFAULT 0.0")
            if "cwe_id" not in existing_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN cwe_id TEXT DEFAULT 'CWE-699'")
            if "remediation" not in existing_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN remediation TEXT DEFAULT ''")
            if "evidence_hash" not in existing_cols:
                cursor.execute("ALTER TABLE findings ADD COLUMN evidence_hash TEXT")

            cursor.execute("PRAGMA table_info(traffic_log)")
            existing_traffic_cols = {row["name"] for row in cursor.fetchall()}
            if "evidence_hash" not in existing_traffic_cols:
                cursor.execute("ALTER TABLE traffic_log ADD COLUMN evidence_hash TEXT")
            if "raw_body_bytes" not in existing_traffic_cols:
                cursor.execute("ALTER TABLE traffic_log ADD COLUMN raw_body_bytes INTEGER DEFAULT 0")
            if "is_truncated" not in existing_traffic_cols:
                cursor.execute("ALTER TABLE traffic_log ADD COLUMN is_truncated INTEGER DEFAULT 0")

            cursor.execute("PRAGMA table_info(sessions)")
            existing_session_cols = {row["name"] for row in cursor.fetchall()}
            if "operator_id" not in existing_session_cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN operator_id INTEGER")
            if "policy_id" not in existing_session_cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN policy_id INTEGER")
            if "policy_version" not in existing_session_cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN policy_version INTEGER")
            if "target_authorization_id" not in existing_session_cols:
                cursor.execute("ALTER TABLE sessions ADD COLUMN target_authorization_id INTEGER")

            # 5. Tool executions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tool_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT,
                    approved INTEGER NOT NULL,
                    policy_reason TEXT,
                    result_json TEXT,
                    duration_ms REAL,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            # 6. Specifications table (OpenAPI / Swagger discovery records)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS specifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    spec_source TEXT NOT NULL,
                    spec_version TEXT,
                    title TEXT,
                    base_url TEXT,
                    endpoints_count INTEGER DEFAULT 0,
                    spec_json TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            # 7. ZAP Scans table (OWASP ZAP scan executions, alerts, and metadata)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS zap_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    scan_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    alert_count INTEGER DEFAULT 0,
                    scan_summary_json TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
                )
            """)

            # 8. Users Table (Administrator, Operator, Auditor Accounts)
            cursor.execute("""
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
                    locked_until REAL,
                    must_change_password INTEGER DEFAULT 0
                )
            """)

            # Migration: ensure must_change_password column exists on users
            cursor.execute("PRAGMA table_info(users)")
            user_cols = [c[1] for c in cursor.fetchall()]
            if "must_change_password" not in user_cols:
                cursor.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")

            # 9. Admin Sessions Table (Stores SHA-256 hash of session token)
            cursor.execute("""
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
                )
            """)

            # 10. Admin Audit Log Table
            cursor.execute("""
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
                )
            """)

            # 11. Policies Table (Core policy entity & activation status)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_uuid TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_by INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    current_version INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(created_by) REFERENCES users(id)
                )
            """)

            # 12. Policy Versions Table (Immutable historical snapshots)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS policy_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id INTEGER NOT NULL,
                    version INTEGER NOT NULL,
                    config_json TEXT NOT NULL,
                    created_by INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    change_summary TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    expires_at REAL,
                    FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE,
                    FOREIGN KEY(created_by) REFERENCES users(id),
                    UNIQUE(policy_id, version)
                )
            """)

            # 13. Target Authorizations Table (Authorized endpoints per policy)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS target_authorizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id INTEGER NOT NULL,
                    host_pattern TEXT NOT NULL,
                    port_range TEXT NOT NULL DEFAULT '1-65535',
                    allowed_schemes TEXT NOT NULL DEFAULT 'http,https',
                    path_prefix TEXT NOT NULL DEFAULT '/',
                    is_wildcard INTEGER NOT NULL DEFAULT 0,
                    expires_at REAL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(policy_id) REFERENCES policies(id) ON DELETE CASCADE
                )
            """)

            # 14. Assessment Policy Snapshots Table (Frozen policy configuration per assessment session)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessment_policy_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_session_id TEXT NOT NULL UNIQUE,
                    policy_id INTEGER NOT NULL,
                    policy_version INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    applied_by_user_id INTEGER,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(assessment_session_id) REFERENCES sessions(session_id),
                    FOREIGN KEY(policy_id) REFERENCES policies(id),
                    FOREIGN KEY(applied_by_user_id) REFERENCES users(id)
                )
            """)

            # 15. System Settings / Setup State Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

            # Performance indexes for fast relational lookups, pagination, and reporting aggregation
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_plans_session_id ON plans(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_session_id ON traffic_log(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_evidence_hash ON traffic_log(evidence_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_session_id ON findings(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_traffic_id ON findings(traffic_log_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_session_status ON findings(session_id, status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_exec_session_id ON tool_executions(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_specifications_session_id ON specifications(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_zap_scans_session_id ON zap_scans(session_id, id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_log_timestamp ON admin_audit_log(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_admin_audit_log_user ON admin_audit_log(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(is_active)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_versions_lookup ON policy_versions(policy_id, version)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_auth_policy ON target_authorizations(policy_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_target_auth_policy_active ON target_authorizations(policy_id, is_active)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_operator ON sessions(operator_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_assessment_snapshot_session ON assessment_policy_snapshots(assessment_session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_session_ts ON traffic_log(session_id, timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool_exec_tool_name ON tool_executions(tool_name)")

            conn.commit()

    # --- Session Management ---

    def create_session(
        self,
        session_id: str,
        target: str,
        notes: str = "",
        operator_id: Optional[int] = None,
        policy_id: Optional[int] = None,
        policy_version: Optional[int] = None,
        target_authorization_id: Optional[int] = None,
    ) -> None:
        """Initialize a new testing session with full attribution and policy binding."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (
                    session_id, target, created_at, updated_at, status, turns_taken, requests_sent, notes,
                    operator_id, policy_id, policy_version, target_authorization_id
                )
                VALUES (?, ?, ?, ?, 'ACTIVE', 0, 0, ?, ?, ?, ?, ?)
                """,
                (session_id, target, now, now, notes, operator_id, policy_id, policy_version, target_authorization_id),
            )
            conn.commit()

    def update_session_status(
        self,
        session_id: str,
        status: str,
        turns_taken: Optional[int] = None,
        requests_sent: Optional[int] = None,
        notes: Optional[str] = None,
    ) -> None:
        """Update session progress and lifecycle status."""
        now = time.time()
        with self._get_connection() as conn:
            query = "UPDATE sessions SET updated_at = ?, status = ?"
            params: List[Any] = [now, status]

            if turns_taken is not None:
                query += ", turns_taken = ?"
                params.append(turns_taken)
            if requests_sent is not None:
                query += ", requests_sent = ?"
                params.append(requests_sent)
            if notes is not None:
                query += ", notes = ?"
                params.append(notes)

            query += " WHERE session_id = ?"
            params.append(session_id)

            conn.execute(query, params)
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve session details by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_sessions(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List all testing sessions ordered by creation date descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (int(limit), int(offset)),
            )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def get_active_session_count(self) -> int:
        """Return the count of currently active or running assessment sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM sessions WHERE status IN ('ACTIVE', 'RUNNING')")
            row = cursor.fetchone()
            return row["count"] if row else 0

    # --- Plan Management ---

    def record_plan(self, session_id: str, plan_data: Dict[str, Any], status: str = "PROPOSED") -> int:
        """Record an agent test plan."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO plans (session_id, created_at, plan_json, status)
                VALUES (?, ?, ?, ?)
                """,
                (session_id, now, json.dumps(plan_data), status),
            )
            conn.commit()
            return cursor.lastrowid

    def get_plans(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all plans for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM plans WHERE session_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "created_at": r["created_at"],
                    "plan": json.loads(r["plan_json"]),
                    "status": r["status"],
                }
                for r in rows
            ]

    # --- OpenAPI / Specification Storage ---

    def record_specification(
        self,
        session_id: str,
        spec_source: str,
        title: str = "Discovered API",
        spec_version: Optional[str] = None,
        base_url: Optional[str] = None,
        endpoints_count: int = 0,
        spec_data: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Store discovered OpenAPI or Swagger specification metadata and endpoints."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO specifications (
                    session_id, timestamp, spec_source, spec_version, title, base_url, endpoints_count, spec_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    spec_source,
                    spec_version,
                    title,
                    base_url,
                    endpoints_count,
                    json.dumps(spec_data or {}),
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_specifications(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all specification discovery records for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM specifications WHERE session_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "timestamp": r["timestamp"],
                    "spec_source": r["spec_source"],
                    "spec_version": r["spec_version"],
                    "title": r["title"],
                    "base_url": r["base_url"],
                    "endpoints_count": r["endpoints_count"],
                    "spec_data": json.loads(r["spec_json"] or "{}"),
                }
                for r in rows
            ]

    # --- OWASP ZAP Scan Storage ---

    def record_zap_scan(
        self,
        session_id: str,
        scan_id: str,
        scan_type: str,
        target_url: str,
        status: str = "COMPLETED",
        alert_count: int = 0,
        scan_summary: Optional[Dict[str, Any]] = None,
        raw_alerts: Optional[List[Dict[str, Any]]] = None,
    ) -> int:
        """Store OWASP ZAP scan execution metadata and status."""
        now = time.time()
        effective_summary = dict(scan_summary or {})
        if raw_alerts is not None:
            effective_summary["alerts"] = raw_alerts

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO zap_scans (
                    session_id, timestamp, scan_id, scan_type, target_url, status, alert_count, scan_summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    scan_id,
                    scan_type,
                    target_url,
                    status,
                    alert_count,
                    json.dumps(effective_summary),
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_zap_scans(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all ZAP scan execution records for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM zap_scans WHERE session_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "timestamp": r["timestamp"],
                    "scan_id": r["scan_id"],
                    "scan_type": r["scan_type"],
                    "target_url": r["target_url"],
                    "status": r["status"],
                    "alert_count": r["alert_count"],
                    "scan_summary": json.loads(r["scan_summary_json"] or "{}"),
                }
                for r in rows
            ]

    def correlate_and_record_zap_finding(
        self,
        session_id: str,
        alert: Dict[str, Any],
        zap_scan_id: Optional[str] = None,
    ) -> Tuple[int, str, bool]:
        """Correlate a ZAP alert with existing findings to avoid duplicate entries.
        
        Returns:
            Tuple[int, str, bool]: (finding_id, assigned_status, is_new_finding)
        """
        endpoint = alert.get("url") or alert.get("uri") or "/"
        category = alert.get("name") or alert.get("alert") or "ZAP Alert"
        risk = alert.get("risk", "Low")
        evidence_snippet = alert.get("evidence", "")
        param = alert.get("param", "")
        description = alert.get("description", "")
        solution = alert.get("solution", "")

        # Check existing findings for this session to avoid duplicates
        existing_findings = self.get_findings(session_id)
        for f in existing_findings:
            if f["endpoint"] == endpoint and f["category"].lower() == category.lower():
                # Duplicate detected: augment notes without creating a duplicate row
                return f["id"], f["status"], False

        # Invariant: ZAP alerts default to SUSPECTED unless an explicit verification rule matches
        status = "SUSPECTED"
        verification_rule = None

        if "syntax error" in evidence_snippet.lower() or "sql" in category.lower():
            if evidence_snippet:
                status = "CONFIRMED"
                verification_rule = "SQL_SYNTAX_ERROR_MATCH"

        notes = (
            f"[ZAP {risk.upper()} Risk Alert]: {description[:200]} | "
            f"Param: '{param}' | Remediation: {solution[:150]}"
        )

        finding_id, assigned_status = self.record_finding(
            session_id=session_id,
            endpoint=endpoint,
            category=category,
            status=status,
            evidence_notes=notes,
            verification_rule=verification_rule,
            raw_evidence={"zap_scan_id": zap_scan_id, "alert": alert},
        )
        return finding_id, assigned_status, True

    # --- Traffic Logging ---

    def log_traffic(
        self,
        session_id: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        response_status: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[str] = None,
        elapsed_ms: Optional[float] = None,
    ) -> int:
        """Log an HTTP request and response interaction with cryptographic evidence hashing."""
        import hashlib
        now = time.time()
        req_body_str = (
            json.dumps(request_body)
            if isinstance(request_body, (dict, list))
            else (str(request_body) if request_body is not None else None)
        )
        resp_body_str = (
            json.dumps(response_body)
            if isinstance(response_body, (dict, list))
            else (str(response_body) if response_body is not None else None)
        )
        raw_bytes_len = len(resp_body_str.encode("utf-8")) if resp_body_str else 0
        is_truncated = 1 if resp_body_str and len(resp_body_str) > MAX_STORED_BODY_CHARS else 0
        raw_repr = f"{session_id}|{now:.4f}|{method}|{url}|{response_status}|{resp_body_str or ''}"
        evidence_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

        req_body_str = _bound_body(req_body_str)
        resp_body_str = _bound_body(resp_body_str)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO traffic_log (
                    session_id, timestamp, method, url, headers_json, request_body,
                    response_status, response_headers_json, response_body, elapsed_ms,
                    evidence_hash, raw_body_bytes, is_truncated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    method,
                    url,
                    json.dumps(headers or {}),
                    req_body_str,
                    response_status,
                    json.dumps(response_headers or {}),
                    resp_body_str,
                    elapsed_ms,
                    evidence_hash,
                    raw_bytes_len,
                    is_truncated,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def log_traffic_batch(
        self,
        session_id: str,
        records: List[Dict[str, Any]],
    ) -> List[int]:
        """Log multiple HTTP request and response interactions in a single atomic transaction."""
        if not records:
            return []
        import hashlib
        now = time.time()
        inserted_ids = []
        with self._get_connection() as conn:
            cursor = conn.cursor()
            for rec in records:
                method = rec.get("method", "GET")
                url = rec.get("url", "")
                headers = rec.get("headers") or {}
                request_body = rec.get("request_body")
                response_status = rec.get("response_status")
                response_headers = rec.get("response_headers") or {}
                response_body = rec.get("response_body")
                elapsed_ms = rec.get("elapsed_ms")

                req_body_str = (
                    json.dumps(request_body)
                    if isinstance(request_body, (dict, list))
                    else (str(request_body) if request_body is not None else None)
                )
                resp_body_str = (
                    json.dumps(response_body)
                    if isinstance(response_body, (dict, list))
                    else (str(response_body) if response_body is not None else None)
                )
                raw_bytes_len = len(resp_body_str.encode("utf-8")) if resp_body_str else 0
                is_truncated = 1 if resp_body_str and len(resp_body_str) > MAX_STORED_BODY_CHARS else 0
                raw_repr = f"{session_id}|{now:.4f}|{method}|{url}|{response_status}|{resp_body_str or ''}"
                evidence_hash = hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()

                req_body_str = _bound_body(req_body_str)
                resp_body_str = _bound_body(resp_body_str)

                cursor.execute(
                    """
                    INSERT INTO traffic_log (
                        session_id, timestamp, method, url, headers_json, request_body,
                        response_status, response_headers_json, response_body, elapsed_ms,
                        evidence_hash, raw_body_bytes, is_truncated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        now,
                        method,
                        url,
                        json.dumps(headers),
                        req_body_str,
                        response_status,
                        json.dumps(response_headers),
                        resp_body_str,
                        elapsed_ms,
                        evidence_hash,
                        raw_bytes_len,
                        is_truncated,
                    ),
                )
                inserted_ids.append(cursor.lastrowid)
            conn.commit()
        return inserted_ids

    def get_traffic_logs(
        self,
        session_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve traffic logs for a session with optional pagination."""
        query = "SELECT * FROM traffic_log WHERE session_id = ? ORDER BY id ASC"
        params = [session_id]
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([int(limit), int(offset)])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "timestamp": r["timestamp"],
                    "method": r["method"],
                    "url": r["url"],
                    "headers": json.loads(r["headers_json"] or "{}"),
                    "request_body": r["request_body"],
                    "response_status": r["response_status"],
                    "response_headers": json.loads(r["response_headers_json"] or "{}"),
                    "response_body": r["response_body"],
                    "elapsed_ms": r["elapsed_ms"],
                    "evidence_hash": r["evidence_hash"] if "evidence_hash" in r.keys() else None,
                    "raw_body_bytes": r["raw_body_bytes"] if "raw_body_bytes" in r.keys() else 0,
                    "is_truncated": bool(r["is_truncated"]) if "is_truncated" in r.keys() else False,
                }
                for r in rows
            ]

    def get_traffic_by_id(self, traffic_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific traffic log entry by primary key ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM traffic_log WHERE id = ?", (traffic_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "session_id": row["session_id"],
                "timestamp": row["timestamp"],
                "method": row["method"],
                "url": row["url"],
                "headers": json.loads(row["headers_json"] or "{}"),
                "request_body": row["request_body"],
                "response_status": row["response_status"],
                "response_headers": json.loads(row["response_headers_json"] or "{}"),
                "response_body": row["response_body"],
                "elapsed_ms": row["elapsed_ms"],
                "evidence_hash": row["evidence_hash"] if "evidence_hash" in row.keys() else None,
                "raw_body_bytes": row["raw_body_bytes"] if "raw_body_bytes" in row.keys() else 0,
                "is_truncated": bool(row["is_truncated"]) if "is_truncated" in row.keys() else False,
            }

    # --- Tool Execution Receipts ---

    def log_tool_execution(
        self,
        session_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        approved: bool,
        policy_reason: str,
        result: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
    ) -> int:
        """Record a tool execution attempt, policy check, and output."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO tool_executions (
                    session_id, timestamp, tool_name, arguments_json, approved, policy_reason, result_json, duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    tool_name,
                    json.dumps(arguments),
                    1 if approved else 0,
                    policy_reason,
                    json.dumps(result or {}),
                    duration_ms,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get_tool_executions(self, session_id: str) -> List[Dict[str, Any]]:
        """Retrieve all tool execution records for a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM tool_executions WHERE session_id = ? ORDER BY id ASC", (session_id,))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "timestamp": r["timestamp"],
                    "tool_name": r["tool_name"],
                    "arguments": json.loads(r["arguments_json"] or "{}"),
                    "approved": bool(r["approved"]),
                    "policy_reason": r["policy_reason"],
                    "result": json.loads(r["result_json"] or "{}"),
                    "duration_ms": r["duration_ms"],
                }
                for r in rows
            ]

    # --- Finding Verification & Storage ---

    def record_finding(
        self,
        session_id: str,
        endpoint: str,
        category: str,
        status: str,
        evidence_notes: str,
        verification_rule: Optional[str] = None,
        traffic_log_id: Optional[int] = None,
        raw_evidence: Optional[Dict[str, Any]] = None,
        severity: Optional[str] = None,
        cvss_score: Optional[float] = None,
        cwe_id: Optional[str] = None,
        remediation: Optional[str] = None,
    ) -> Tuple[int, str]:
        """Record a security finding with strict verification gate enforcement.
        
        Returns:
            Tuple[int, str]: (finding_id, assigned_status)
        """
        status_norm = status.strip().upper()
        if status_norm not in VALID_FINDING_STATUSES:
            status_norm = "UNTESTED"

        # INVARIANT: A vulnerability must NOT become CONFIRMED merely because the model asserts it.
        # Confirmation strictly requires documented traffic evidence and an explicit verification rule.
        if status_norm == "CONFIRMED":
            valid_rule = verification_rule in APPROVED_VERIFICATION_RULES
            valid_evidence = traffic_log_id is not None or (raw_evidence and len(raw_evidence) > 0)
            if not (valid_rule and valid_evidence):
                # Demote to SUSPECTED due to lack of verifiable proof
                status_norm = "SUSPECTED"
                evidence_notes = (
                    f"[AUTO-DEMOTED FROM CONFIRMED]: Missing documented traffic evidence "
                    f"or approved verification rule. Original rule='{verification_rule}'. "
                    f"Notes: {evidence_notes}"
                )

        # Resolve risk metadata via RiskAssessmentEngine
        try:
            from controller.reporting.risk_engine import RiskAssessmentEngine
            risk_prof = RiskAssessmentEngine.get_finding_risk_profile(category, status_norm, evidence_notes, endpoint=endpoint)
            sev_val = severity or risk_prof.severity.value
            cvss_val = cvss_score if cvss_score is not None else risk_prof.cvss_score
            cwe_val = cwe_id or risk_prof.cwe_id
            rem_val = remediation or risk_prof.remediation_guidance
        except Exception:
            sev_val = severity or "INFORMATIONAL"
            cvss_val = cvss_score if cvss_score is not None else 0.0
            cwe_val = cwe_id or "CWE-699"
            rem_val = remediation or ""

        now = time.time()

        # Resolve cryptographic evidence integrity hash
        import hashlib
        finding_hash = None
        if traffic_log_id:
            with self._get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT evidence_hash FROM traffic_log WHERE id = ?", (traffic_log_id,))
                row = cur.fetchone()
                if row and "evidence_hash" in row.keys() and row["evidence_hash"]:
                    finding_hash = row["evidence_hash"]

        if not finding_hash:
            raw_data_str = json.dumps(raw_evidence or {}, sort_keys=True)
            finding_repr = f"{session_id}|{endpoint}|{category}|{status_norm}|{verification_rule or ''}|{raw_data_str}"
            finding_hash = hashlib.sha256(finding_repr.encode("utf-8")).hexdigest()

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO findings (
                    session_id, timestamp, endpoint, category, status,
                    evidence_notes, verification_rule, traffic_log_id, raw_evidence_json,
                    severity, cvss_score, cwe_id, remediation, evidence_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    now,
                    endpoint,
                    category,
                    status_norm,
                    evidence_notes,
                    verification_rule,
                    traffic_log_id,
                    json.dumps(raw_evidence or {}),
                    sev_val,
                    cvss_val,
                    cwe_val,
                    rem_val,
                    finding_hash,
                ),
            )
            conn.commit()
            return cursor.lastrowid, status_norm

    def get_findings(
        self,
        session_id: str,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Retrieve security findings for a session with optional pagination."""
        query = "SELECT * FROM findings WHERE session_id = ? ORDER BY id ASC"
        params = [session_id]
        if limit is not None:
            query += " LIMIT ? OFFSET ?"
            params.extend([int(limit), int(offset)])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            rows = cursor.fetchall()
            return [
                {
                    "id": r["id"],
                    "session_id": r["session_id"],
                    "timestamp": r["timestamp"],
                    "endpoint": r["endpoint"],
                    "category": r["category"],
                    "status": r["status"],
                    "evidence_notes": r["evidence_notes"],
                    "verification_rule": r["verification_rule"],
                    "traffic_log_id": r["traffic_log_id"],
                    "raw_evidence": json.loads(r["raw_evidence_json"] or "{}"),
                    "severity": r["severity"] if "severity" in r.keys() else "INFORMATIONAL",
                    "cvss_score": r["cvss_score"] if "cvss_score" in r.keys() else 0.0,
                    "cwe_id": r["cwe_id"] if "cwe_id" in r.keys() else "CWE-699",
                    "remediation": r["remediation"] if "remediation" in r.keys() else "",
                    "evidence_hash": r["evidence_hash"] if "evidence_hash" in r.keys() else None,
                }
                for r in rows
            ]

    def get_finding_summary(self, session_id: str) -> Dict[str, Any]:
        """Aggregate finding counts by status and category for executive review using direct SQL aggregation."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as total FROM findings WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            total = row["total"] if row else 0

            summary = {
                "total": total,
                "by_status": {s: 0 for s in VALID_FINDING_STATUSES},
                "by_category": {},
            }
            if total == 0:
                return summary

            cursor.execute(
                "SELECT status, COUNT(*) as cnt FROM findings WHERE session_id = ? GROUP BY status",
                (session_id,),
            )
            for r in cursor.fetchall():
                st = r["status"]
                summary["by_status"][st] = r["cnt"]

            cursor.execute(
                "SELECT category, COUNT(*) as cnt FROM findings WHERE session_id = ? GROUP BY category",
                (session_id,),
            )
            for r in cursor.fetchall():
                cat = r["category"]
                summary["by_category"][cat] = r["cnt"]

            return summary

    def verify_evidence_integrity(self, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Verify cryptographic integrity of stored traffic logs and finding links."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT id, session_id, traffic_log_id, evidence_hash FROM findings"
            params = []
            if session_id:
                query += " WHERE session_id = ?"
                params.append(session_id)
            cursor.execute(query, tuple(params))
            finding_rows = cursor.fetchall()

            unlinked_findings = []
            valid_findings = 0
            for f in finding_rows:
                t_id = f["traffic_log_id"]
                if t_id:
                    cursor.execute("SELECT id, evidence_hash FROM traffic_log WHERE id = ?", (t_id,))
                    t_row = cursor.fetchone()
                    if not t_row:
                        unlinked_findings.append({"finding_id": f["id"], "missing_traffic_id": t_id})
                    else:
                        valid_findings += 1
                else:
                    valid_findings += 1

            query_t = "SELECT id, session_id, timestamp, method, url, response_status, response_body, evidence_hash, is_truncated FROM traffic_log"
            params_t = []
            if session_id:
                query_t += " WHERE session_id = ?"
                params_t.append(session_id)
            cursor.execute(query_t, tuple(params_t))
            traffic_rows = cursor.fetchall()
            valid_traffic = 0
            tampered_traffic = []
            import hashlib
            for t in traffic_rows:
                h = t["evidence_hash"] if "evidence_hash" in t.keys() else None
                if not h:
                    continue
                valid_traffic += 1
                is_trunc = t["is_truncated"] if "is_truncated" in t.keys() else 0
                if not is_trunc:
                    raw = f"{t['session_id']}|{t['timestamp']:.4f}|{t['method']}|{t['url']}|{t['response_status']}|{t['response_body'] or ''}"
                    recomputed = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                    if recomputed != h:
                        tampered_traffic.append(t["id"])

            return {
                "verified": len(unlinked_findings) == 0 and len(tampered_traffic) == 0,
                "findings_checked": len(finding_rows),
                "valid_finding_links": valid_findings,
                "unlinked_findings": unlinked_findings,
                "traffic_records_checked": len(traffic_rows),
                "hashed_traffic_records": valid_traffic,
                "tampered_records": tampered_traffic,
            }

    # --- System Settings & Setup State ---

    def get_setting(self, key: str) -> Optional[str]:
        """Retrieve a persistent system configuration setting."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        """Persist or update a system configuration setting."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO system_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                """,
                (key, str(value), now),
            )
            conn.commit()
