"""Unit and Security Tests for AuthenticationService.

Covers:
1. Password hashing and verification (PBKDF2-HMAC-SHA256)
2. Unique salt generation per password
3. Constant-time comparison usage
4. Administrator bootstrap allowed only once
5. Login success, generic failure messages, and audit logging
6. Rate limiting, failed login counters, and temporary account lockout
7. Password complexity and validation rules
"""

import hmac
import time
import unittest
from unittest.mock import patch

from controller.auth.authentication_service import AuthenticationService
from controller.auth.role_service import Role
from controller.auth.session_service import SessionService
from controller.storage.evidence_store import EvidenceStore


class TestAuthenticationService(unittest.TestCase):
    """Security and functional test suite for AuthenticationService."""

    def setUp(self):
        # In-memory database with lower iteration count for fast unit test execution
        self.store = EvidenceStore(db_path=":memory:")
        self.session_service = SessionService(self.store)
        self.auth_service = AuthenticationService(
            store=self.store,
            session_service=self.session_service,
            iterations=5_000,  # 5,000 iterations for sub-second test execution
        )

    def tearDown(self):
        self.store.close()

    # -------------------------------------------------------------------------
    # 1 & 2. Password Hashing, Verification, and Unique Salt Generation
    # -------------------------------------------------------------------------
    def test_password_hashing_and_unique_salts(self):
        """Verify PBKDF2-HMAC-SHA256 hashing produces unique salts and deterministic verification."""
        password = "SecurePassword123!"

        salt1, hash1 = self.auth_service.hash_password(password)
        salt2, hash2 = self.auth_service.hash_password(password)

        # Unique salts
        self.assertNotEqual(salt1, salt2, "Subsequent hashes must generate distinct random salts")
        self.assertNotEqual(hash1, hash2, "Distinct salts must produce distinct hash digests")
        self.assertEqual(len(bytes.fromhex(salt1)), 32, "Salt must be exactly 32 bytes")
        self.assertEqual(len(bytes.fromhex(hash1)), 32, "SHA-256 hash digest must be 32 bytes")

        # Correct verification
        self.assertTrue(self.auth_service.verify_password(password, salt1, hash1))
        self.assertTrue(self.auth_service.verify_password(password, salt2, hash2))

        # Incorrect password verification
        self.assertFalse(self.auth_service.verify_password("WrongPassword123!", salt1, hash1))
        self.assertFalse(self.auth_service.verify_password("", salt1, hash1))
        self.assertFalse(self.auth_service.verify_password(password, salt1, "badhash"))

    # -------------------------------------------------------------------------
    # 3. Constant-Time Comparison Usage
    # -------------------------------------------------------------------------
    def test_constant_time_comparison_used(self):
        """Verify that verify_password relies on hmac.compare_digest to prevent timing attacks."""
        salt, expected_hash = self.auth_service.hash_password("Passphrase999!")

        with patch("hmac.compare_digest", wraps=hmac.compare_digest) as mock_compare:
            result = self.auth_service.verify_password("Passphrase999!", salt, expected_hash)
            self.assertTrue(result)
            self.assertTrue(mock_compare.called, "verify_password must invoke hmac.compare_digest")

    # -------------------------------------------------------------------------
    # 4. Administrator Bootstrap Allowed Only Once
    # -------------------------------------------------------------------------
    def test_administrator_bootstrap_lifecycle(self):
        """Verify that administrator bootstrap succeeds once and strictly blocks re-bootstrap."""
        self.assertFalse(self.auth_service.has_admin(), "Fresh store must have no administrator")

        # First bootstrap succeeds
        admin_data = self.auth_service.bootstrap_admin("sysadmin", "SuperSecure123!")
        self.assertEqual(admin_data["username"], "sysadmin")
        self.assertEqual(admin_data["role"], Role.ADMIN.value)
        self.assertTrue(self.auth_service.has_admin())

        # Second bootstrap must be rejected
        with self.assertRaises(RuntimeError) as ctx:
            self.auth_service.bootstrap_admin("anotheradmin", "AnotherPass123!")
        self.assertIn("already exists", str(ctx.exception).lower())

        # Verify audit log recorded both the creation and rejection
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT action, status FROM admin_audit_log ORDER BY id ASC")
            logs = cursor.fetchall()
            self.assertGreaterEqual(len(logs), 2)
            self.assertEqual(logs[0]["action"], "BOOTSTRAP_ADMIN_CREATED")
            self.assertEqual(logs[0]["status"], "SUCCESS")
            self.assertEqual(logs[1]["action"], "BOOTSTRAP_REJECTED")
            self.assertEqual(logs[1]["status"], "DENIED")

    # -------------------------------------------------------------------------
    # 5. Login Success and Generic Failure Messages
    # -------------------------------------------------------------------------
    def test_login_success_and_generic_failure(self):
        """Verify authentication returns generic failure messages and prevents user enumeration."""
        self.auth_service.bootstrap_admin("admin_user", "ValidPassword123!")

        # Success
        success, user, msg = self.auth_service.authenticate("admin_user", "ValidPassword123!")
        self.assertTrue(success)
        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "admin_user")
        self.assertEqual(msg, "Login successful")

        # Failure: Wrong password -> Generic message
        success, user, msg = self.auth_service.authenticate("admin_user", "WrongPassword123!")
        self.assertFalse(success)
        self.assertIsNone(user)
        self.assertEqual(msg, "Invalid credentials")

        # Failure: Non-existent user -> Identical generic message
        success, user, msg = self.auth_service.authenticate("ghost_user", "AnyPassword123!")
        self.assertFalse(success)
        self.assertIsNone(user)
        self.assertEqual(msg, "Invalid credentials")

    # -------------------------------------------------------------------------
    # 6. Rate Limiting, Failed Counters, and Account Lockout
    # -------------------------------------------------------------------------
    def test_failed_login_counter_and_temporary_lockout(self):
        """Verify account locks for 15 minutes after 5 consecutive failed attempts."""
        self.auth_service.bootstrap_admin("target_admin", "AdminSecret123!")

        # 4 consecutive failures
        for i in range(1, 5):
            success, _, msg = self.auth_service.authenticate("target_admin", f"WrongPass_{i}!")
            self.assertFalse(success)
            self.assertEqual(msg, "Invalid credentials")

        # Verify failed counter is 4 and not yet locked
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT failed_login_attempts, locked_until FROM users WHERE username = 'target_admin'")
            row = cursor.fetchone()
            self.assertEqual(row["failed_login_attempts"], 4)
            self.assertIsNone(row["locked_until"])

        # 5th failure triggers lockout
        success, _, msg = self.auth_service.authenticate("target_admin", "WrongPass_5!")
        self.assertFalse(success)
        self.assertEqual(msg, "Invalid credentials")

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT failed_login_attempts, locked_until FROM users WHERE username = 'target_admin'")
            row = cursor.fetchone()
            self.assertEqual(row["failed_login_attempts"], 5)
            self.assertIsNotNone(row["locked_until"])
            self.assertGreater(row["locked_until"], time.time())

        # 6th attempt with CORRECT password is still rejected due to lockout
        success, _, msg = self.auth_service.authenticate("target_admin", "AdminSecret123!")
        self.assertFalse(success, "Account must be locked even with correct password")
        self.assertEqual(msg, "Invalid credentials")

    # -------------------------------------------------------------------------
    # 7. Password Complexity Validation
    # -------------------------------------------------------------------------
    def test_password_complexity_rules(self):
        """Verify strict enforcement of password complexity rules."""
        valid, err = self.auth_service.validate_password_strength("short")
        self.assertFalse(valid)
        self.assertIn("at least 10 characters", err)

        valid, err = self.auth_service.validate_password_strength("alllowercase123!")
        self.assertFalse(valid)
        self.assertIn("uppercase letter", err)

        valid, err = self.auth_service.validate_password_strength("ALLUPPERCASE123!")
        self.assertFalse(valid)
        self.assertIn("lowercase letter", err)

        valid, err = self.auth_service.validate_password_strength("NoNumbersHere!")
        self.assertFalse(valid)
        self.assertIn("number", err)

        valid, err = self.auth_service.validate_password_strength("NoSpecialChar123")
        self.assertFalse(valid)
        self.assertIn("special character", err)

        valid, err = self.auth_service.validate_password_strength("Contains_myuser_123!", username="myuser")
        self.assertFalse(valid)
        self.assertIn("cannot contain the username", err)

        valid, err = self.auth_service.validate_password_strength("StrongPassphrase999!")
        self.assertTrue(valid)
        self.assertIsNone(err)

    # -------------------------------------------------------------------------
    # 8. Password Reset CLI Recovery
    # -------------------------------------------------------------------------
    def test_password_reset_recovery(self):
        """Verify emergency password reset updates hash and clears lockouts."""
        self.auth_service.bootstrap_admin("reset_user", "OldPassword123!")

        res = self.auth_service.reset_admin_password("reset_user", "NewPassword456!", actor="TEST")
        self.assertIn("successfully", res["status"])

        # Old password fails
        success, _, _ = self.auth_service.authenticate("reset_user", "OldPassword123!")
        self.assertFalse(success)

        # New password succeeds
        success, user, _ = self.auth_service.authenticate("reset_user", "NewPassword456!")
        self.assertTrue(success)
        self.assertEqual(user["username"], "reset_user")

    # -------------------------------------------------------------------------
    # 9. First-Run Random Password Generation & Setup Lock
    # -------------------------------------------------------------------------
    def test_first_run_random_password_generation(self):
        """Verify cryptographically strong random password generation."""
        pwd1 = self.auth_service.generate_secure_random_password(length=24)
        pwd2 = self.auth_service.generate_secure_random_password(length=24)
        self.assertNotEqual(pwd1, pwd2)
        self.assertGreaterEqual(len(pwd1), 24)

        # Must meet all password strength rules
        valid, err = self.auth_service.validate_password_strength(pwd1)
        self.assertTrue(valid, f"Generated password failed validation: {err}")

    def test_silent_recreation_prevented_after_admin_deletion(self):
        """Ensure initial administrator cannot be silently recreated after deletion."""
        self.auth_service.bootstrap_admin("initial_admin", "AdminStrongPass123!")
        self.assertTrue(self.auth_service.is_setup_completed())

        # Simulate administrator account deletion
        with self.store._get_connection() as conn:
            conn.cursor().execute("DELETE FROM users WHERE username = 'initial_admin'")
            conn.commit()

        self.assertFalse(self.auth_service.has_admin())
        self.assertTrue(self.auth_service.is_setup_completed())

        # Attempting silent bootstrap must raise RuntimeError
        with self.assertRaises(RuntimeError) as ctx:
            self.auth_service.bootstrap_admin("sneaky_admin", "SneakyPass123!")
        self.assertIn("silent administrator recreation is forbidden", str(ctx.exception).lower())

    def test_must_change_password_and_password_change_flow(self):
        """Verify must_change_password flag tracking and password change validation."""
        admin_data = self.auth_service.bootstrap_admin(
            "temp_admin", "InitialTempPass123!", must_change_password=True
        )
        self.assertTrue(admin_data["must_change_password"])

        # Authenticate returns must_change_password = True
        ok, user_info, _ = self.auth_service.authenticate("temp_admin", "InitialTempPass123!")
        self.assertTrue(ok)
        self.assertTrue(user_info["must_change_password"])

        # Reusing identical password fails
        ok, msg = self.auth_service.change_password(
            user_info["id"], "InitialTempPass123!", "InitialTempPass123!"
        )
        self.assertFalse(ok)
        self.assertIn("identical", msg.lower())

        # Updating to strong new password succeeds
        ok, msg = self.auth_service.change_password(
            user_info["id"], "InitialTempPass123!", "BrandNewStrongPass999!"
        )
        self.assertTrue(ok)

        # Subsequent authenticate returns must_change_password = False
        ok, user_info_new, _ = self.auth_service.authenticate("temp_admin", "BrandNewStrongPass999!")
        self.assertTrue(ok)
        self.assertFalse(user_info_new["must_change_password"])


if __name__ == "__main__":
    unittest.main()
