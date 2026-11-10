"""CLI Tool for One-Time Administrator Account Bootstrap.

Prompts for administrator credentials securely without echo, enforces complexity,
and verifies no administrator already exists.
"""

import argparse
import getpass
import os
import sys

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.auth.authentication_service import AuthenticationService
from controller.config import DEFAULT_CONFIG
from controller.storage.evidence_store import EvidenceStore


def main():
    parser = argparse.ArgumentParser(
        description="One-time administrator bootstrap for Autonomous API Testing Platform."
    )
    parser.add_argument(
        "--username",
        help="Administrator username (prompted if omitted)",
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

    if auth_service.has_admin():
        print("[!] ERROR: An active administrator account already exists.")
        print("[!] Administrator bootstrap is a single-use procedure.")
        print("[!] For credential recovery, use: python -m controller.auth.reset_password")
        sys.exit(1)

    print("=" * 65)
    print("AUTONOMOUS API SECURITY PLATFORM - ADMINISTRATOR BOOTSTRAP")
    print("=" * 65)

    username = args.username
    if not username:
        username = input("Enter new administrator username: ").strip()

    valid_u, u_err = auth_service.validate_username(username)
    if not valid_u:
        print(f"[!] Validation Error: {u_err}")
        sys.exit(1)

    password = getpass.getpass("Enter administrator password: ")
    confirm_password = getpass.getpass("Confirm administrator password: ")

    if password != confirm_password:
        print("[!] Passwords do not match.")
        sys.exit(1)

    valid_p, p_err = auth_service.validate_password_strength(password, username)
    if not valid_p:
        print(f"[!] Password Complexity Error: {p_err}")
        print("    Requirements: Min 10 chars, uppercase, lowercase, number, special character.")
        sys.exit(1)

    try:
        res = auth_service.bootstrap_admin(username=username, password=password, ip_address="127.0.0.1 (CLI)")
        print("\n[+] SUCCESS: Administrator account created successfully.")
        print(f"    User ID:  {res['id']}")
        print(f"    Username: {res['username']}")
        print(f"    Role:     {res['role']}")
        print("\nYou may now log in via the dashboard at http://127.0.0.1:8088/login")
    except Exception as exc:
        print(f"[!] Bootstrap failed: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()

