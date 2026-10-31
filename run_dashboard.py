#!/usr/bin/env python3
"""Autonomous API Penetration Testing Live Dashboard Runner.

Starts the Windows-accessible Flask dashboard server on localhost.
Optionally launches the local vulnerable API lab in a background thread for instant testing.

Usage:
    python run_dashboard.py [--port 8088] [--with-lab] [--open-browser]
"""

import argparse
import os
import sys
import threading
import time
import webbrowser

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.app import create_dashboard_app
from controller.config import DEFAULT_CONFIG


def run_lab_server(port: int = 5050):
    """Run local vulnerable API laboratory in background thread."""
    try:
        from lab.app import create_app
        lab_app = create_app()
        print(f"[*] Starting local vulnerable API lab on http://127.0.0.1:{port}...")
        lab_app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    except Exception as exc:
        print(f"[!] Warning: Could not start local lab server: {exc}")


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous API Penetration Testing - Windows Live Dashboard"
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host binding address (default: 127.0.0.1, localhost only)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8088,
        help="Port for the dashboard web UI (default: 8088)",
    )
    parser.add_argument(
        "--with-lab",
        action="store_true",
        help="Automatically launch vulnerable test laboratory on http://127.0.0.1:5050 in background",
    )
    parser.add_argument(
        "--lab-port",
        type=int,
        default=5050,
        help="Port for the vulnerable test laboratory (default: 5050)",
    )
    parser.add_argument(
        "--open-browser",
        action="store_true",
        help="Automatically open the dashboard URL in default web browser",
    )
    args = parser.parse_args()

    # Enforce localhost policy
    if args.host not in ("127.0.0.1", "localhost"):
        print("[!] Safety Policy Violation: Dashboard must bind to localhost (127.0.0.1).")
        sys.exit(1)

    # Banner
    print("=" * 72)
    print("   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING AGENT")
    print("                 LIVE MONITORING CONSOLE")
    print("=" * 72)
    print(f"[*] Dashboard URL    : http://{args.host}:{args.port}")
    print(f"[*] Model Brain      : Qwen2.5-1.5B-Instruct (RebuiltV4 LoRA Checkpoint-200)")
    print(f"[*] Permitted Hosts  : {', '.join(DEFAULT_CONFIG.allowed_hosts)}")
    print(f"[*] Scope Policy     : Enforced by PolicyEngine & ScopeValidator")
    print(f"[*] Evidence Storage : SQLite ({DEFAULT_CONFIG.evidence_db_path})")
    print("=" * 72)

    # Optional local lab server
    if args.with_lab:
        lab_thread = threading.Thread(
            target=run_lab_server,
            args=(args.lab_port,),
            daemon=True,
            name="VulnerableLabThread",
        )
        lab_thread.start()
        time.sleep(1.0)

    # Optional browser opener
    if args.open_browser:
        def _open():
            time.sleep(1.2)
            webbrowser.open(f"http://{args.host}:{args.port}")
        threading.Thread(target=_open, daemon=True).start()

    # Create and run Dashboard Flask application
    dashboard_app = create_dashboard_app()
    try:
        dashboard_app.run(
            host=args.host,
            port=args.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down live dashboard cleanly. Goodbye!")


if __name__ == "__main__":
    main()

