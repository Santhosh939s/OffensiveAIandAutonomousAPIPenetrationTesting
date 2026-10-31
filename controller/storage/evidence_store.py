"""Evidence Database Store for Autonomous API Penetration Testing.

Manages persistent SQLite storage of sessions, test plans, raw traffic logs,
tool execution receipts, and security findings.
Enforces that findings cannot be marked CONFIRMED without documented traffic
evidence and an explicit, valid verification rule.
"""

import json
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple


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
}


class EvidenceStore:
    """Thread-safe SQLite storage for API security testing evidence and audit trail."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._shared_conn: Optional[sqlite3.Connection] = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

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
                    FOREIGN KEY(session_id) REFERENCES sessions(session_id),
                    FOREIGN KEY(traffic_log_id) REFERENCES traffic_log(id)
                )
            """)

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

            conn.commit()

    # --- Session Management ---

    def create_session(self, session_id: str, target: str, notes: str = "") -> None:
        """Initialize a new testing session."""
        now = time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO sessions (session_id, target, created_at, updated_at, status, turns_taken, requests_sent, notes)
                VALUES (?, ?, ?, ?, 'ACTIVE', 0, 0, ?)
                """,
                (session_id, target, now, now, notes),
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
        """Log an HTTP request and response interaction."""
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
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO traffic_log (
                    session_id, timestamp, method, url, headers_json, request_body,
                    response_status, response_headers_json, response_body, elapsed_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            conn.commit()
            return cursor.lastrowid

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

        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO findings (
                    session_id, timestamp, endpoint, category, status,
                    evidence_notes, verification_rule, traffic_log_id, raw_evidence_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                }
                for r in rows
            ]

    def get_finding_summary(self, session_id: str) -> Dict[str, Any]:
        """Aggregate finding counts by status and category for executive review."""
        findings = self.get_findings(session_id)
        summary = {
            "total": len(findings),
            "by_status": {s: 0 for s in VALID_FINDING_STATUSES},
            "by_category": {},
        }
        for f in findings:
            st = f.get("status", "UNTESTED")
            summary["by_status"][st] = summary["by_status"].get(st, 0) + 1
            cat = f.get("category", "General")
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
        return summary
