"""Authentication Service for Autonomous API Penetration Testing Platform.

Provides PBKDF2-HMAC-SHA256 password hashing with 600,000 iterations,
unique 32-byte salts, constant-time verification, password strength rules,
account lockout and rate limiting, generic failure messages,
and secure single-use administrator bootstrap.
"""

import hashlib
import hmac
import json
import logging
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from controller.auth.role_service import Role, RoleService
from controller.auth.session_service import SessionService
from controller.storage.evidence_store import EvidenceStore

logger = logging.getLogger("autonomous_pentest.auth")


class AuthenticationService:
    """Manages user authentication, password hashing, and administrative bootstrap."""

    # Default cryptographic parameters
    DEFAULT_ITERATIONS: int = 600_000
    SALT_BYTES: int = 32
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION_SECONDS: float = 900.0  # 15 minutes
    MIN_PASSWORD_LENGTH: int = 10

    # IP rate limit window (max 20 failed attempts per IP per 15 minutes)
    IP_MAX_FAILED_ATTEMPTS: int = 20
    IP_WINDOW_SECONDS: float = 900.0

    def __init__(
        self,
        store: EvidenceStore,
        session_service: Optional[SessionService] = None,
        iterations: int = DEFAULT_ITERATIONS,
    ):
        self.store = store
        self.session_service = session_service or SessionService(store)
        self.iterations = iterations
        self._ip_failed_attempts: Dict[str, List[float]] = {}

    # --- Cryptographic Primitives ---

    def hash_password(self, password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
        """Compute PBKDF2-HMAC-SHA256 hash with unique salt.

        Returns:
            Tuple of (salt_hex, hash_hex)
        """
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string")

        salt_bytes = salt if salt is not None else secrets.token_bytes(self.SALT_BYTES)
        derived = hashlib.pbkdf2_hmac(
            hash_name="sha256",
            password=password.encode("utf-8"),
            salt=salt_bytes,
            iterations=self.iterations,
        )
        return salt_bytes.hex(), derived.hex()

    def verify_password(self, password: str, salt_hex: str, expected_hash_hex: str) -> bool:
        """Constant-time verification of password against stored PBKDF2 hash."""
        if not password or not salt_hex or not expected_hash_hex:
            return False
        try:
            salt_bytes = bytes.fromhex(salt_hex)
            derived = hashlib.pbkdf2_hmac(
                hash_name="sha256",
                password=password.encode("utf-8"),
                salt=salt_bytes,
                iterations=self.iterations,
            )
            derived_hex = derived.hex()
            return hmac.compare_digest(derived_hex, expected_hash_hex.strip())
        except Exception:
            return False

    # --- Password Policy & Validation ---

    @classmethod
    def generate_secure_random_password(cls, length: int = 24) -> str:
        """Generate a cryptographically secure random initial password meeting all complexity rules."""
        import string
        if length < cls.MIN_PASSWORD_LENGTH:
            length = cls.MIN_PASSWORD_LENGTH

        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        all_chars = upper + lower + digits + special

        # Guarantee at least one of each required character category
        chars = [
            secrets.choice(upper),
            secrets.choice(lower),
            secrets.choice(digits),
            secrets.choice(special),
        ]
        chars += [secrets.choice(all_chars) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(chars)
        return "".join(chars)

    def validate_password_strength(self, password: str, username: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Validate password against complexity rules."""
        if not password or not isinstance(password, str):
            return False, "Password cannot be empty"

        if len(password) < self.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {self.MIN_PASSWORD_LENGTH} characters long"

        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"

        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"

        if not re.search(r"[0-9]", password):
            return False, "Password must contain at least one number"

        if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password):
            return False, "Password must contain at least one special character"

        if username and username.lower() in password.lower():
            return False, "Password cannot contain the username"

        common_weak = {
            "password123!",
            "admin12345!",
            "administrator1!",
            "welcome1234!",
            "qwerty12345!",
        }
        if password.lower() in common_weak:
            return False, "Password is too common; choose a more complex passphrase"

        return True, None

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate format of username."""
        if not username or not isinstance(username, str):
            return False, "Username cannot be empty"
        cleaned = username.strip()
        if len(cleaned) < 3 or len(cleaned) > 32:
            return False, "Username must be between 3 and 32 characters"
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", cleaned):
            return False, "Username may only contain letters, numbers, underscores, dashes, and periods"
        return True, None

    # --- Audit Logging ---

    def _log_audit_event(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
    ) -> None:
        """Record an administrative or security event to admin_audit_log."""
        now = time.time()
        details_json = json.dumps(details or {})
        try:
            with self.store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO admin_audit_log (
                        timestamp, user_id, username, action,
                        resource_type, resource_id, ip_address,
                        details_json, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        user_id,
                        username or "",
                        action,
                        resource_type,
                        resource_id or "",
                        ip_address or "",
                        details_json,
                        status,
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.error("Failed to write to admin_audit_log: %s", exc)

    # --- Administrator Bootstrap & Setup State ---

    def is_setup_completed(self) -> bool:
        """Check whether initial system setup has already been completed."""
        setting = self.store.get_setting("initial_setup_completed")
        if setting and setting.lower() in ("true", "1", "yes"):
            return True
        # If any admin user exists, setup has already occurred
        return self.has_admin()

    def mark_setup_completed(self) -> None:
        """Mark initial administrator setup as completed."""
        self.store.set_setting("initial_setup_completed", "true")

    def has_admin(self) -> bool:
        """Check if any active administrator account already exists."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) as count FROM users WHERE role = ? AND is_active = 1",
                (Role.ADMIN.value,),
            )
            row = cursor.fetchone()
            return bool(row and row["count"] > 0)

    def bootstrap_admin(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        must_change_password: bool = False,
        force_setup: bool = False,
    ) -> Dict[str, Any]:
        """One-time creation of the initial administrator account.

        Raises RuntimeError if an administrator already exists or if initial setup
        was already completed and force_setup is False.
        """
        if self.has_admin():
            self._log_audit_event(
                action="BOOTSTRAP_REJECTED",
                resource_type="USER",
                username=username,
                ip_address=ip_address,
                details={"reason": "Administrator already exists. Unauthorized re-bootstrap attempted."},
                status="DENIED",
            )
            raise RuntimeError(
                "Administrator account already exists. Bootstrap is permitted only once."
            )

        if self.is_setup_completed() and not force_setup:
            self._log_audit_event(
                action="BOOTSTRAP_REJECTED",
                resource_type="USER",
                username=username,
                ip_address=ip_address,
                details={"reason": "Initial setup was already completed. Silent administrator recreation forbidden."},
                status="DENIED",
            )
            raise RuntimeError(
                "Initial setup was already completed. Silent administrator recreation is forbidden. "
                "An explicit setup or recovery operation is required."
            )

        u_valid, u_err = self.validate_username(username)
        if not u_valid:
            raise ValueError(f"Invalid username: {u_err}")

        p_valid, p_err = self.validate_password_strength(password, username)
        if not p_valid:
            raise ValueError(f"Weak password: {p_err}")

        clean_username = username.strip()
        salt_hex, hash_hex = self.hash_password(password)
        now = time.time()
        must_change_int = 1 if must_change_password else 0

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO users (
                    username, password_hash, salt, role,
                    is_active, created_at, updated_at,
                    failed_login_attempts, locked_until, must_change_password
                ) VALUES (?, ?, ?, ?, 1, ?, ?, 0, NULL, ?)
                """,
                (clean_username, hash_hex, salt_hex, Role.ADMIN.value, now, now, must_change_int),
            )
            user_id = cursor.lastrowid
            conn.commit()

        self.mark_setup_completed()

        self._log_audit_event(
            action="BOOTSTRAP_ADMIN_CREATED",
            resource_type="USER",
            resource_id=str(user_id),
            user_id=user_id,
            username=clean_username,
            ip_address=ip_address,
            details={"role": Role.ADMIN.value, "bootstrap": True, "must_change_password": bool(must_change_int)},
            status="SUCCESS",
        )

        return {
            "id": user_id,
            "username": clean_username,
            "role": Role.ADMIN.value,
            "created_at": now,
            "must_change_password": bool(must_change_int),
        }

    # --- Credential Recovery & Management ---

    def reset_admin_password(
        self,
        username: str,
        new_password: str,
        ip_address: Optional[str] = None,
        actor: str = "CLI_RECOVERY",
    ) -> Dict[str, Any]:
        """Emergency reset of an administrator's password via local authority."""
        clean_user = username.strip()
        p_valid, p_err = self.validate_password_strength(new_password, clean_user)
        if not p_valid:
            raise ValueError(f"Weak password: {p_err}")

        salt_hex, hash_hex = self.hash_password(new_password)
        now = time.time()

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, role FROM users WHERE username = ?", (clean_user,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"User '{clean_user}' does not exist")

            user_id = row["id"]
            cursor.execute(
                """
                UPDATE users
                SET password_hash = ?, salt = ?, updated_at = ?,
                    failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (hash_hex, salt_hex, now, user_id),
            )
            conn.commit()

        # Invalidate all active sessions for security
        self.session_service.invalidate_all_user_sessions(user_id)

        self._log_audit_event(
            action="ADMIN_PASSWORD_RESET",
            resource_type="USER",
            resource_id=str(user_id),
            user_id=user_id,
            username=clean_user,
            ip_address=ip_address,
            details={"actor": actor, "sessions_purged": True},
            status="SUCCESS",
        )

        return {
            "id": user_id,
            "username": clean_user,
            "status": "Password reset successfully; all active sessions invalidated.",
        }

    # --- User Creation (Admin Provisioning) ---

    def create_user(
        self,
        username: str,
        password: str,
        role: str,
        creator_user_id: Optional[int] = None,
        creator_username: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new user account with specified role (admin, operator, auditor)."""
        if not RoleService.is_valid_role(role):
            raise ValueError(f"Invalid role '{role}'. Valid roles: {RoleService.get_valid_roles()}")

        u_valid, u_err = self.validate_username(username)
        if not u_valid:
            raise ValueError(f"Invalid username: {u_err}")

        clean_username = username.strip()
        p_valid, p_err = self.validate_password_strength(password, clean_username)
        if not p_valid:
            raise ValueError(f"Weak password: {p_err}")

        salt_hex, hash_hex = self.hash_password(password)
        now = time.time()

        try:
            with self.store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (
                        username, password_hash, salt, role,
                        is_active, created_at, updated_at,
                        failed_login_attempts, locked_until
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, 0, NULL)
                    """,
                    (clean_username, hash_hex, salt_hex, role.lower(), now, now),
                )
                user_id = cursor.lastrowid
                conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{clean_username}' already exists")

        self._log_audit_event(
            action="USER_CREATED",
            resource_type="USER",
            resource_id=str(user_id),
            user_id=creator_user_id,
            username=creator_username,
            ip_address=ip_address,
            details={"new_user_id": user_id, "new_username": clean_username, "role": role.lower()},
            status="SUCCESS",
        )

        return {
            "id": user_id,
            "username": clean_username,
            "role": role.lower(),
            "created_at": now,
        }

    # --- Authentication & Lockout Pipeline ---

    def _check_ip_rate_limit(self, ip_address: Optional[str]) -> bool:
        """Check if an IP address has exceeded the failed attempt ceiling."""
        if not ip_address:
            return True
        now = time.time()
        window_start = now - self.IP_WINDOW_SECONDS
        attempts = [t for t in self._ip_failed_attempts.get(ip_address, []) if t > window_start]
        self._ip_failed_attempts[ip_address] = attempts
        return len(attempts) < self.IP_MAX_FAILED_ATTEMPTS

    def _record_ip_failure(self, ip_address: Optional[str]) -> None:
        """Record a failed login attempt for an IP address."""
        if not ip_address:
            return
        now = time.time()
        window_start = now - self.IP_WINDOW_SECONDS
        attempts = [t for t in self._ip_failed_attempts.get(ip_address, []) if t > window_start]
        attempts.append(now)
        self._ip_failed_attempts[ip_address] = attempts

    def authenticate(
        self,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Authenticate a user with generic error messages and brute-force defenses.

        Returns:
            Tuple of (success: bool, user_data: Optional[Dict], message: str)
        """
        now = time.time()
        clean_user = (username or "").strip()

        # 1. IP Rate limit check
        if not self._check_ip_rate_limit(ip_address):
            self._log_audit_event(
                action="LOGIN_BLOCKED_IP_RATE_LIMIT",
                resource_type="AUTH",
                username=clean_user,
                ip_address=ip_address,
                details={"reason": "Excessive failed attempts from IP address"},
                status="DENIED",
            )
            return False, None, "Too many requests. Please try again later."

        if not clean_user or not password:
            self._record_ip_failure(ip_address)
            return False, None, "Invalid credentials"

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (clean_user,))
            user = cursor.fetchone()

            # Generic failure if user doesn't exist
            if not user:
                self._record_ip_failure(ip_address)
                self._log_audit_event(
                    action="LOGIN_FAILURE",
                    resource_type="AUTH",
                    username=clean_user,
                    ip_address=ip_address,
                    details={"reason": "User not found (generic denial returned)"},
                    status="FAILED",
                )
                return False, None, "Invalid credentials"

            # 2. Check user active status
            if not user["is_active"]:
                self._record_ip_failure(ip_address)
                self._log_audit_event(
                    action="LOGIN_BLOCKED_DEACTIVATED",
                    resource_type="AUTH",
                    user_id=user["id"],
                    username=clean_user,
                    ip_address=ip_address,
                    details={"reason": "Account is deactivated"},
                    status="DENIED",
                )
                return False, None, "Invalid credentials"

            # 3. Check account lockout status
            locked_until = user["locked_until"]
            if locked_until and locked_until > now:
                remaining = int(locked_until - now)
                self._record_ip_failure(ip_address)
                self._log_audit_event(
                    action="LOGIN_BLOCKED_LOCKED_ACCOUNT",
                    resource_type="AUTH",
                    user_id=user["id"],
                    username=clean_user,
                    ip_address=ip_address,
                    details={"locked_until": locked_until, "remaining_seconds": remaining},
                    status="DENIED",
                )
                return False, None, "Invalid credentials"

            # 4. Verify password with constant-time check
            valid = self.verify_password(password, user["salt"], user["password_hash"])

            if not valid:
                # Increment failed attempts
                failed = (user["failed_login_attempts"] or 0) + 1
                new_lockout = None
                if failed >= self.MAX_FAILED_ATTEMPTS:
                    new_lockout = now + self.LOCKOUT_DURATION_SECONDS
                    logger.warning(
                        "Account '%s' locked out after %d failed attempts.", clean_user, failed
                    )

                cursor.execute(
                    """
                    UPDATE users
                    SET failed_login_attempts = ?, locked_until = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (failed, new_lockout, now, user["id"]),
                )
                conn.commit()

                self._record_ip_failure(ip_address)
                self._log_audit_event(
                    action="LOGIN_FAILURE",
                    resource_type="AUTH",
                    user_id=user["id"],
                    username=clean_user,
                    ip_address=ip_address,
                    details={"failed_attempts": failed, "locked": new_lockout is not None},
                    status="FAILED",
                )
                return False, None, "Invalid credentials"

            # 5. Successful login: reset failed counters and update last_login_at
            cursor.execute(
                """
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL,
                    last_login_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (now, now, user["id"]),
            )
            conn.commit()

        must_change = bool(user["must_change_password"] if "must_change_password" in user.keys() else 0)
        user_info = {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "last_login_at": now,
            "must_change_password": must_change,
        }

        self._log_audit_event(
            action="LOGIN_SUCCESS",
            resource_type="AUTH",
            user_id=user["id"],
            username=clean_user,
            ip_address=ip_address,
            details={"role": user["role"], "must_change_password": must_change},
            status="SUCCESS",
        )

        return True, user_info, "Login successful"

    def change_password(
        self,
        user_id: int,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Change a user's password after validating current password and strength."""
        if not current_password or not new_password:
            return False, "Current and new password are both required."

        now = time.time()
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return False, "User not found."

            if not self.verify_password(current_password, user["salt"], user["password_hash"]):
                self._log_audit_event(
                    action="PASSWORD_CHANGE_FAILED",
                    resource_type="USER",
                    user_id=user_id,
                    username=user["username"],
                    ip_address=ip_address,
                    details={"reason": "Incorrect current password"},
                    status="FAILED",
                )
                return False, "Current password verification failed."

            # Password strength validation
            p_valid, p_err = self.validate_password_strength(new_password, user["username"])
            if not p_valid:
                return False, f"Weak new password: {p_err}"

            # Prevent reusing same password
            if self.verify_password(new_password, user["salt"], user["password_hash"]):
                return False, "New password cannot be identical to current password."

            salt_hex, hash_hex = self.hash_password(new_password)
            cursor.execute(
                """
                UPDATE users
                SET password_hash = ?, salt = ?, updated_at = ?,
                    must_change_password = 0, failed_login_attempts = 0, locked_until = NULL
                WHERE id = ?
                """,
                (hash_hex, salt_hex, now, user_id),
            )
            conn.commit()

        self._log_audit_event(
            action="USER_PASSWORD_CHANGED",
            resource_type="USER",
            resource_id=str(user_id),
            user_id=user_id,
            username=user["username"],
            ip_address=ip_address,
            details={"must_change_cleared": True},
            status="SUCCESS",
        )
        return True, "Password changed successfully."

