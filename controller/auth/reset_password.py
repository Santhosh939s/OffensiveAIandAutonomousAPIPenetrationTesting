"""CLI Tool for Local Administrator Password Recovery.

Requires physical or local shell access to the host machine.
Resets the specified administrator's password and purges all active sessions.
"""

import argparse
import getpass
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.auth.authentication_service import AuthenticationService
from controller.config import DEFAULT_CONFIG
from controller.storage.evidence_store import EvidenceStore


def main():
    parser = argparse.ArgumentParser(
        description="Local administrator password recovery for Autonomous API Testing Platform."
    )
    parser.add_argument(
        "--username",
        help="Administrator username to reset",
        default=None,
    )
    parser.add_argument(
        "--db-path",
        help="Path to SQLite evidence database",
        default=DEFAULT_CONFIG.db_path,
    )
    args = parser.parse_args()

    store = EvidenceStore(db_path=args.db_path)
    auth_service = AuthenticationService(store=store)

    print("=" * 65)
    print("AUTONOMOUS API SECURITY PLATFORM - EMERGENCY CREDENTIAL RECOVERY")
    print("=" * 65)

    username = args.username
    if not username:
        username = input("Enter username to reset: ").strip()

    new_password = getpass.getpass("Enter new password: ")
    confirm_password = getpass.getpass("Confirm new password: ")

    if new_password != confirm_password:
        print("[!] Passwords do not match.")
        sys.exit(1)

    valid_p, p_err = auth_service.validate_password_strength(new_password, username)
    if not valid_p:
        print(f"[!] Password Complexity Error: {p_err}")
        print("    Requirements: Min 10 chars, uppercase, lowercase, number, special character.")
        sys.exit(1)

    try:
        res = auth_service.reset_admin_password(
            username=username,
            new_password=new_password,
            ip_address="127.0.0.1 (CLI_RECOVERY)",
            actor="SYSTEM_ADMIN_CLI",
        )
        print("\n[+] SUCCESS:", res["status"])
        print(f"    User ID:  {res['id']}")
        print(f"    Username: {res['username']}")
    except Exception as exc:
        print(f"[!] Password reset failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

