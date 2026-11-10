"""Session Management and Security Service for Autonomous API Testing Platform.

Manages cryptographically secure server-side sessions, token hashing,
sliding expiration (30 min), maximum lifetime (8 hr), CSRF synchronizer tokens,
and protection against session fixation and timing attacks.
"""

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from controller.storage.evidence_store import EvidenceStore


@dataclass(frozen=True)
class AdminSession:
    """Immutable representation of an active validated administrative session."""
    session_token_hash: str
    user_id: int
    username: str
    role: str
    csrf_token: str
    created_at: float
    expires_at: float
    last_activity_at: float
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    must_change_password: bool = False


class SessionService:
    """Manages secure server-side user sessions and CSRF synchronizer tokens."""

    # Default timing invariants
    DEFAULT_INACTIVITY_TIMEOUT: float = 1800.0  # 30 minutes
    DEFAULT_MAX_LIFETIME: float = 28800.0        # 8 hours

    def __init__(
        self,
        store: EvidenceStore,
        inactivity_timeout: float = DEFAULT_INACTIVITY_TIMEOUT,
        max_lifetime: float = DEFAULT_MAX_LIFETIME,
    ):
        self.store = store
        self.inactivity_timeout = inactivity_timeout
        self.max_lifetime = max_lifetime

    @staticmethod
    def hash_token(raw_token: str) -> str:
        """Compute SHA-256 hash of a session token for secure database storage."""
        if not raw_token or not isinstance(raw_token, str):
            return ""
        return hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()

    def create_session(
        self,
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, str, AdminSession]:
        """Create a new authenticated server-side session.

        Returns:
            Tuple of (raw_session_token, raw_csrf_token, AdminSession)
        """
        now = time.time()
        raw_token = secrets.token_urlsafe(32)
        raw_csrf = secrets.token_urlsafe(32)
        token_hash = self.hash_token(raw_token)
        expires_at = now + self.max_lifetime

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO admin_sessions (
                    session_token_hash, user_id, csrf_token,
                    created_at, expires_at, last_activity_at,
                    ip_address, user_agent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token_hash,
                    user_id,
                    raw_csrf,
                    now,
                    expires_at,
                    now,
                    ip_address or "",
                    user_agent or "",
                ),
            )
            # Fetch user details
            cursor.execute("SELECT username, role, must_change_password FROM users WHERE id = ?", (user_id,))
            user_row = cursor.fetchone()
            username = user_row["username"] if user_row else "unknown"
            role = user_row["role"] if user_row else "operator"
            must_change = bool(user_row["must_change_password"] if user_row and "must_change_password" in user_row.keys() else 0)
            conn.commit()

        session_obj = AdminSession(
            session_token_hash=token_hash,
            user_id=user_id,
            username=username,
            role=role,
            csrf_token=raw_csrf,
            created_at=now,
            expires_at=expires_at,
            last_activity_at=now,
            ip_address=ip_address,
            user_agent=user_agent,
            must_change_password=must_change,
        )
        return raw_token, raw_csrf, session_obj

    def validate_session(self, raw_session_token: str) -> Optional[AdminSession]:
        """Validate a raw session token against the database, enforcing expiration.

        Enforces:
        - Absolute lifetime (now < expires_at)
        - Sliding inactivity timeout (now < last_activity_at + inactivity_timeout)
        - Active user status (is_active == 1)
        """
        if not raw_session_token or not isinstance(raw_session_token, str):
            return None

        token_hash = self.hash_token(raw_session_token)
        now = time.time()

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.*, u.username, u.role, u.is_active, u.locked_until, u.must_change_password
                FROM admin_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token_hash = ?
                """,
                (token_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            # 1. Check user active and not locked
            if not row["is_active"] or (row["locked_until"] and row["locked_until"] > now):
                # User deactivated or locked; purge session
                cursor.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (token_hash,))
                conn.commit()
                return None

            # 2. Check absolute max lifetime expiration
            if now > row["expires_at"]:
                cursor.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (token_hash,))
                conn.commit()
                return None

            # 3. Check sliding inactivity expiration
            if (now - row["last_activity_at"]) > self.inactivity_timeout:
                cursor.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (token_hash,))
                conn.commit()
                return None

            # 4. Valid session: slide inactivity timestamp forward
            cursor.execute(
                "UPDATE admin_sessions SET last_activity_at = ? WHERE session_token_hash = ?",
                (now, token_hash),
            )
            conn.commit()

            must_change = bool(row["must_change_password"] if "must_change_password" in row.keys() else 0)
            return AdminSession(
                session_token_hash=token_hash,
                user_id=row["user_id"],
                username=row["username"],
                role=row["role"],
                csrf_token=row["csrf_token"],
                created_at=row["created_at"],
                expires_at=row["expires_at"],
                last_activity_at=now,
                ip_address=row["ip_address"],
                user_agent=row["user_agent"],
                must_change_password=must_change,
            )

    def rotate_session(
        self,
        old_raw_token: Optional[str],
        user_id: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[str, str, AdminSession]:
        """Invalidate old session (if any) and generate a fresh session to prevent fixation."""
        if old_raw_token:
            self.invalidate_session(old_raw_token)
        return self.create_session(user_id=user_id, ip_address=ip_address, user_agent=user_agent)

    def invalidate_session(self, raw_session_token: str) -> bool:
        """Explicitly invalidate and purge a session (e.g. on user logout)."""
        if not raw_session_token:
            return False
        token_hash = self.hash_token(raw_session_token)
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM admin_sessions WHERE session_token_hash = ?", (token_hash,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted

    def invalidate_all_user_sessions(self, user_id: int) -> int:
        """Purge all active sessions for a user (e.g. on password change or lockout)."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM admin_sessions WHERE user_id = ?", (user_id,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def clean_expired_sessions(self) -> int:
        """Purge all expired or idle sessions across the database."""
        now = time.time()
        idle_threshold = now - self.inactivity_timeout
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                DELETE FROM admin_sessions
                WHERE expires_at < ? OR last_activity_at < ?
                """,
                (now, idle_threshold),
            )
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    @staticmethod
    def validate_csrf_token(expected_csrf: str, provided_csrf: Optional[str]) -> bool:
        """Constant-time validation of CSRF synchronizer token."""
        if not expected_csrf or not provided_csrf:
            return False
        return hmac.compare_digest(str(expected_csrf).strip(), str(provided_csrf).strip())

