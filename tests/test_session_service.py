"""Unit and Security Tests for SessionService.

Covers:
7. Cryptographically random session token generation and SHA-256 token hashing
8. Session rotation upon login to defeat session fixation
9. Sliding 30-minute inactivity expiration and 8-hour maximum lifetime
10. Explicit session invalidation on logout
11. Synchronizer CSRF token validation with constant-time check
"""

import hashlib
import time
import unittest

from controller.auth.authentication_service import AuthenticationService
from controller.auth.session_service import SessionService
from controller.storage.evidence_store import EvidenceStore


class TestSessionService(unittest.TestCase):
    """Security test suite for SessionService."""

    def setUp(self):
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(
            store=self.store,
            inactivity_timeout=1.0,  # 1 second for fast sliding expiry test
            max_lifetime=3.0,        # 3 seconds for fast max lifetime test
        )
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,
        )
        self.user = self.auth_service.bootstrap_admin("session_admin", "SessionAdmin999!")

    def tearDown(self):
        self.store.close()

    # -------------------------------------------------------------------------
    # 7. Session Token Generation & Hashing
    # -------------------------------------------------------------------------
    def test_session_token_generation_and_hashing(self):
        """Verify tokens are cryptographically random and stored hashed."""
        raw_token, raw_csrf, session = self.session_service.create_session(
            user_id=self.user["id"],
            ip_address="127.0.0.1",
            user_agent="TestAgent/1.0",
        )

        self.assertGreaterEqual(len(raw_token), 32)
        self.assertGreaterEqual(len(raw_csrf), 32)

        # Database must store the SHA-256 hash, not the raw token
        expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertEqual(session.session_token_hash, expected_hash)

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT session_token_hash FROM admin_sessions WHERE user_id = ?", (self.user["id"],))
            row = cursor.fetchone()
            self.assertEqual(row["session_token_hash"], expected_hash)

        # Validating with raw token succeeds
        validated = self.session_service.validate_session(raw_token)
        self.assertIsNotNone(validated)
        self.assertEqual(validated.username, "session_admin")
        self.assertEqual(validated.role, "admin")

    # -------------------------------------------------------------------------
    # 8. Session Rotation (Fixation Defense)
    # -------------------------------------------------------------------------
    def test_session_rotation(self):
        """Verify session rotation invalidates previous token and issues a new one."""
        old_raw_token, _, _ = self.session_service.create_session(user_id=self.user["id"])
        self.assertIsNotNone(self.session_service.validate_session(old_raw_token))

        # Rotate session
        new_raw_token, _, new_session = self.session_service.rotate_session(
            old_raw_token=old_raw_token,
            user_id=self.user["id"],
            ip_address="127.0.0.1",
        )

        self.assertNotEqual(old_raw_token, new_raw_token)

        # Old session is purged
        self.assertIsNone(self.session_service.validate_session(old_raw_token))

        # New session is active
        self.assertIsNotNone(self.session_service.validate_session(new_raw_token))

    # -------------------------------------------------------------------------
    # 9. Sliding Inactivity Expiration & Max Lifetime Expiration
    # -------------------------------------------------------------------------
    def test_sliding_inactivity_expiration(self):
        """Verify session expires when idle past the inactivity timeout."""
        raw_token, _, _ = self.session_service.create_session(user_id=self.user["id"])
        self.assertIsNotNone(self.session_service.validate_session(raw_token))

        # Sleep past the 1.0 second inactivity timeout
        time.sleep(1.1)

        # Session should now be expired and purged
        validated = self.session_service.validate_session(raw_token)
        self.assertIsNone(validated, "Session must expire after inactivity threshold")

    def test_maximum_lifetime_expiration(self):
        """Verify session terminates when maximum lifetime is exceeded even with activity."""
        raw_token, _, _ = self.session_service.create_session(user_id=self.user["id"])

        # Keep active with requests every 0.6 seconds (less than 1s inactivity timeout)
        time.sleep(0.6)
        self.assertIsNotNone(self.session_service.validate_session(raw_token))

        time.sleep(0.6)
        self.assertIsNotNone(self.session_service.validate_session(raw_token))

        time.sleep(0.6)
        self.assertIsNotNone(self.session_service.validate_session(raw_token))

        # Now wait until total elapsed exceeds max_lifetime (3.0 seconds)
        time.sleep(1.5)
        self.assertIsNone(
            self.session_service.validate_session(raw_token),
            "Session must expire when max_lifetime ceiling is reached",
        )

    # -------------------------------------------------------------------------
    # 10. Logout Invalidation
    # -------------------------------------------------------------------------
    def test_session_invalidation_on_logout(self):
        """Verify invalidating a session completely purges it from the store."""
        raw_token, _, _ = self.session_service.create_session(user_id=self.user["id"])
        self.assertIsNotNone(self.session_service.validate_session(raw_token))

        deleted = self.session_service.invalidate_session(raw_token)
        self.assertTrue(deleted)

        self.assertIsNone(self.session_service.validate_session(raw_token))

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM admin_sessions")
            row = cursor.fetchone()
            self.assertEqual(row["count"], 0)

    # -------------------------------------------------------------------------
    # 11. CSRF Token Validation
    # -------------------------------------------------------------------------
    def test_csrf_token_validation(self):
        """Verify CSRF token matching and rejection of mismatched tokens."""
        _, csrf_token, _ = self.session_service.create_session(user_id=self.user["id"])

        self.assertTrue(self.session_service.validate_csrf_token(csrf_token, csrf_token))
        self.assertFalse(self.session_service.validate_csrf_token(csrf_token, "wrong_token"))
        self.assertFalse(self.session_service.validate_csrf_token(csrf_token, ""))
        self.assertFalse(self.session_service.validate_csrf_token(csrf_token, None))


if __name__ == "__main__":
    unittest.main()
