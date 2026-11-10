#!/usr/bin/env python3
"""Autonomous Offensive AI & API Penetration Testing - Standalone Windows Launcher.

Orchestrates all required components in authoritative startup order:
1. Environment & Python Runtime Validation (64-bit, Python >= 3.8)
2. Dependency Manifest Verification
3. Local GGUF Model & llama-cli Engine Detection
4. Evidence Database & Default Policy Verification
5. Network Port Collision Detection & Management (5050, 8088)
6. Autonomous API Lab Server Launch (127.0.0.1:5050)
7. Production Dashboard Web Console Launch (127.0.0.1:8088)
8. Graceful Shutdown & Cleanup Handler (SIGINT/SIGTERM)
"""

import argparse
import atexit
import json
import logging
import os
import platform
import shutil
import signal
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure project root is first in search path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import warnings
warnings.filterwarnings("ignore", message=".*Python 3.8 is no longer supported.*")

# Setup logging
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)
LOG_FILE = LOGS_DIR / "launcher.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("launcher")

PID_FILE = PROJECT_ROOT / ".agent_services.pid"

# Default Model Paths
DEFAULT_GGUF_PATH = PROJECT_ROOT / "models" / "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf"
DEFAULT_ADAPTER_PATH = PROJECT_ROOT / "models" / "training_artifacts" / "final_adapter" / "adapter_model.safetensors"


def is_port_in_use(host: str, port: int) -> bool:
    """Check if a network port is currently occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def wait_for_port(host: str, port: int, timeout_seconds: float = 5.0) -> bool:
    """Wait until a local port starts accepting connections."""
    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        if is_port_in_use(host, port):
            return True
        time.sleep(0.1)
    return False


def preflight_check(model_path: Optional[Path] = None) -> Tuple[bool, List[str], List[str]]:
    """Run comprehensive system preflight diagnostic.
    
    Returns:
        (passed, list_of_success_messages, list_of_error_messages)
    """
    successes = []
    errors = []

    # 1. Python Architecture
    py_ver = platform.python_version()
    is_64bit = sys.maxsize > 2**32
    if sys.version_info < (3, 8) or not is_64bit:
        errors.append(f"Python 3.8+ (64-bit) required. Found Python {py_ver} ({'64-bit' if is_64bit else '32-bit'}).")
    else:
        successes.append(f"Python Runtime: {py_ver} (64-bit Windows)")

    # 2. Critical Dependencies
    required_modules = [
        ("flask", "Flask"),
        ("werkzeug", "Werkzeug"),
        ("httpx", "HTTPX"),
        ("requests", "Requests"),
        ("pydantic", "Pydantic"),
        ("yaml", "PyYAML"),
        ("cryptography", "Cryptography"),
        ("jwt", "PyJWT"),
    ]
    missing_mods = []
    for mod_name, disp_name in required_modules:
        try:
            __import__(mod_name)
        except ImportError:
            missing_mods.append(disp_name)

    if missing_mods:
        errors.append(f"Missing mandatory Python packages: {', '.join(missing_mods)}. Run: pip install -r requirements.txt")
    else:
        successes.append("Mandatory Python Dependencies: All installed and verified")

    # 3. Model GGUF File
    actual_model_path = model_path or DEFAULT_GGUF_PATH
    if not actual_model_path.exists():
        errors.append(f"GGUF model artifact not found at: {actual_model_path}")
    else:
        size_mb = round(actual_model_path.stat().st_size / (1024 * 1024), 2)
        successes.append(f"Local Qwen GGUF Model: Found at '{actual_model_path.name}' ({size_mb} MB)")

    # 4. llama-cli Inference Binary
    cli_candidates = [
        Path(os.environ.get("LLAMA_CLI_PATH", "")) if os.environ.get("LLAMA_CLI_PATH") else None,
        Path(os.environ.get("LLAMACPP_DIR", "")) / "llama-cli.exe" if os.environ.get("LLAMACPP_DIR") else None,
        PROJECT_ROOT / "models" / "bin" / "llama-cli.exe",
        PROJECT_ROOT / "models" / "bin" / "llama-cli",
        Path(shutil.which("llama-cli.exe") or "") if shutil.which("llama-cli.exe") else None,
        Path(shutil.which("llama-cli") or "") if shutil.which("llama-cli") else None,
    ]
    valid_cli = next((c for c in cli_candidates if c and c.exists()), None)
    if not valid_cli:
        errors.append("llama-cli execution binary not found on PATH or in models/bin/. Required for real CPU inference.")
    else:
        successes.append(f"Local Inference Engine: Found '{valid_cli}'")

    # 5. Database & Admin Initialization
    try:
        from controller.storage.evidence_store import EvidenceStore
        from controller.auth.authentication_service import AuthenticationService
        from controller.guardrails.policy_service import PolicyService

        db_path = PROJECT_ROOT / "offensive_ai_evidence.db"
        store = EvidenceStore(str(db_path))
        auth_svc = AuthenticationService(store=store)
        pol_svc = PolicyService(store=store)

        # Check administrator account state
        if not auth_svc.has_admin():
            if auth_svc.is_setup_completed():
                errors.append(
                    "Security Alert: No active administrator found, but initial setup was already completed. "
                    "Silent administrator recreation is strictly forbidden. Use '--recover-admin <username>' or restore credentials."
                )
            else:
                # First-run setup: Check if custom password provided via env
                env_pass = os.environ.get("INITIAL_ADMIN_PASSWORD")
                if env_pass:
                    admin_pass = env_pass
                    must_change = False
                else:
                    admin_pass = auth_svc.generate_secure_random_password(length=24)
                    must_change = True

                admin_user = auth_svc.bootstrap_admin(
                    "admin", admin_pass, must_change_password=must_change, force_setup=True
                )

                # Security critical: Output to terminal stdout ONLY, NEVER log to launcher.log!
                sys.stdout.write("\n" + "#" * 78 + "\n")
                sys.stdout.write(" [!] FIRST-RUN ADMINISTRATOR SETUP COMPLETED (ONE-TIME CREDENTIALS)\n")
                sys.stdout.write(f" [!] Username: {admin_user['username']}\n")
                sys.stdout.write(f" [!] One-Time Temporary Password: {admin_pass}\n")
                sys.stdout.write(" [!] SECURITY NOTE: This password is NOT written to application logs.\n")
                if must_change:
                    sys.stdout.write(" [!] MANDATORY ACTION: Password change is required before normal dashboard operations.\n")
                sys.stdout.write("#" * 78 + "\n\n")
                sys.stdout.flush()

                successes.append(f"Security Engine: Initial administrator generated with secure one-time credentials (ID: {admin_user['id']})")
        else:
            successes.append("Security Engine: Evidence store verified with active administrator account")

        # Ensure at least one default policy exists
        policies = pol_svc.list_policies()
        if not policies:
            pol_svc.create_policy(
                name="Default Localhost Pentest Policy",
                config={
                    "max_requests": 60,
                    "max_turns": 25,
                    "allowed_tools": [
                        "http_request", "httpx_request", "openapi_parser", "jwt_inspector",
                        "parameter_fuzzer", "zap_scanner", "graphql_probe", "inventory_scanner",
                        "business_flow_probe"
                    ],
                },
                creator_id=1,
                targets=[{"host_pattern": "127.0.0.1", "port_range": "5050", "path_prefix": "/"}],
            )
            successes.append("Security Policy: Default localhost penetration testing policy provisioned")
        else:
            successes.append(f"Security Policy: {len(policies)} active policy configuration(s) available")

    except Exception as exc:
        errors.append(f"Database / Policy Service Initialization failed: {exc}")

    passed = len(errors) == 0
    return passed, successes, errors


class ServiceManager:
    """Manages lifecycle of local Vulnerable API Lab and Dashboard processes."""

    def __init__(self, host: str = "127.0.0.1", dashboard_port: int = 8088, lab_port: int = 5050):
        self.host = host
        self.dashboard_port = dashboard_port
        self.lab_port = lab_port

        self.lab_server = None
        self.lab_thread = None
        self.dashboard_app = None

        self._shutdown_called = False

    def start_lab(self) -> bool:
        """Start local vulnerable API laboratory in a background daemon thread."""
        from werkzeug.serving import make_server
        from lab.app import create_app
        from lab.database import LabDatabase

        logger.info("Initializing Vulnerable API Lab on http://%s:%d...", self.host, self.lab_port)
        try:
            lab_db_path = PROJECT_ROOT / "lab" / "vulnerable_lab.db"
            lab_db = LabDatabase(str(lab_db_path))
            app = create_app(db=lab_db)
            self.lab_server = make_server(self.host, self.lab_port, app)

            self.lab_thread = threading.Thread(
                target=self.lab_server.serve_forever,
                name="VulnerableLabServer",
                daemon=True,
            )
            self.lab_thread.start()

            if wait_for_port(self.host, self.lab_port, timeout_seconds=4.0):
                logger.info("Vulnerable API Lab successfully started and listening on http://%s:%d", self.host, self.lab_port)
                return True
            else:
                logger.error("Vulnerable API Lab failed to bind to port %d within timeout.", self.lab_port)
                return False
        except Exception as exc:
            logger.error("Error starting Vulnerable API Lab: %s", exc)
            return False

    def start_dashboard(self, open_browser: bool = True):
        """Start primary Dashboard web console."""
        from dashboard.app import create_dashboard_app

        logger.info("Starting Autonomous Monitoring Console on http://%s:%d...", self.host, self.dashboard_port)
        self.dashboard_app = create_dashboard_app()

        # Write current PID
        try:
            with open(PID_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "pid": os.getpid(),
                    "host": self.host,
                    "dashboard_port": self.dashboard_port,
                    "lab_port": self.lab_port,
                    "start_time": time.time(),
                }, f, indent=2)
        except Exception as exc:
            logger.warning("Could not record service PID: %s", exc)

        if open_browser:
            def _launch_browser():
                time.sleep(1.2)
                webbrowser.open(f"http://{self.host}:{self.dashboard_port}")

            threading.Thread(target=_launch_browser, daemon=True).start()

        try:
            self.dashboard_app.run(
                host=self.host,
                port=self.dashboard_port,
                debug=False,
                use_reloader=False,
                threaded=True,
            )
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt. Initiating clean application shutdown...")
        finally:
            self.shutdown()

    def shutdown(self):
        """Cleanly stop all background services and cleanup temporary files."""
        if self._shutdown_called:
            return
        self._shutdown_called = True

        logger.info("Gracefully stopping all active background services...")
        if self.lab_server:
            try:
                self.lab_server.shutdown()
                logger.info("Vulnerable API Lab stopped successfully.")
            except Exception as exc:
                logger.warning("Error stopping Vulnerable API Lab server: %s", exc)

        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except Exception:
                pass

        logger.info("All services terminated cleanly. Goodbye!")


def print_banner(host: str, dashboard_port: int, lab_port: int, model_name: str):
    """Display startup console banner."""
    print("\n" + "=" * 78)
    print("   OFFENSIVE AI & AUTONOMOUS API PENETRATION TESTING SYSTEM")
    print("                 WINDOWS STANDALONE LAUNCHER")
    print("=" * 78)
    print(f" [*] Dashboard Console   : http://{host}:{dashboard_port}")
    print(f" [*] Vulnerable Lab API  : http://{host}:{lab_port}")
    print(f" [*] Real Qwen AI Model  : {model_name} (Strictly Non-Mock)")
    print(f" [*] Safety Guardrails   : Layer 1 Socket Hooks & ScopeValidator (Active)")
    print(f" [*] Administrative Auth : PBKDF2-HMAC-SHA256 & Session Token Cookies")
    print(f" [*] Operational Mode    : 100% Offline / Local CPU (Zero Cloud Dispatches)")
    print("=" * 78)
    print("  Administrator Access: Secure credentials required (setup during first-run)")
    print("  Press Ctrl+C at any time to cleanly stop all services.")
    print("=" * 78 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous API Penetration Testing - Standalone Windows Launcher"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Binding host (default: 127.0.0.1, localhost only)")
    parser.add_argument("--port", type=int, default=8088, help="Dashboard web UI port (default: 8088)")
    parser.add_argument("--lab-port", type=int, default=5050, help="Vulnerable lab port (default: 5050)")
    parser.add_argument("--no-lab", action="store_true", help="Do not launch internal vulnerable lab server")
    parser.add_argument("--no-browser", action="store_true", help="Do not open browser automatically")
    parser.add_argument("--check-only", action="store_true", help="Run pre-flight check diagnostics and exit")
    parser.add_argument("--model-path", type=str, default=None, help="Custom GGUF model path")
    parser.add_argument("--recover-admin", type=str, default=None, metavar="USERNAME", help="Reset password for an existing administrator")
    parser.add_argument("--new-password", type=str, default=None, help="New password for admin recovery (prompted if omitted)")

    args = parser.parse_args()

    # Safety constraint: enforce localhost binding
    if args.host not in ("127.0.0.1", "localhost"):
        print(f"[!] Safety Policy Violation: Outbound binding '{args.host}' forbidden. Must bind to localhost.")
        sys.exit(1)

    # Handle administrative credential recovery
    if args.recover_admin:
        from controller.storage.evidence_store import EvidenceStore
        from controller.auth.authentication_service import AuthenticationService

        store = EvidenceStore(str(PROJECT_ROOT / "offensive_ai_evidence.db"))
        auth_svc = AuthenticationService(store=store)
        new_pass = args.new_password or auth_svc.generate_secure_random_password(length=24)
        try:
            res = auth_svc.reset_admin_password(args.recover_admin, new_pass, actor="LAUNCHER_CLI_RECOVERY")
            print("\n" + "=" * 78)
            print(f" [+] Administrator password reset successfully for '{args.recover_admin}'.")
            print(f" [+] New Temporary Password: {new_pass}")
            print(" [!] NOTICE: This password is NOT stored in application logs.")
            print("=" * 78 + "\n")
            sys.exit(0)
        except Exception as exc:
            print(f"\n[!] Credential Recovery Failed: {exc}")
            sys.exit(1)

    custom_model = Path(args.model_path) if args.model_path else None
    passed, successes, errors = preflight_check(model_path=custom_model)

    print("\n--- PRE-FLIGHT SYSTEM DIAGNOSTICS ---")
    for s in successes:
        print(f" [+] [PASS] {s}")
    for e in errors:
        print(f" [!] [FAIL] {e}")

    if not passed:
        print("\n[!] Pre-flight validation failed. Critical components are missing or improperly configured.")
        print("[!] Review the errors above and resolve them before starting the system.")
        sys.exit(1)

    if args.check_only:
        print("\n[+] System pre-flight check passed with 100% compliance. Ready for standalone execution.")
        sys.exit(0)

    # Check port conflicts
    if is_port_in_use(args.host, args.port):
        print(f"\n[!] Port Conflict: Port {args.port} is already in use by another process.")
        print(f"[!] Terminate the process using port {args.port} or specify another port via --port <port>.")
        sys.exit(1)

    if not args.no_lab and is_port_in_use(args.host, args.lab_port):
        print(f"\n[!] Port Conflict: Vulnerable Lab port {args.lab_port} is already in use.")
        print(f"[!] Terminate the conflicting process or specify --lab-port <port>.")
        sys.exit(1)

    # Initialize service manager
    manager = ServiceManager(host=args.host, dashboard_port=args.port, lab_port=args.lab_port)

    # Signal handlers for clean shutdown
    def _sig_handler(signum, frame):
        manager.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)
    atexit.register(manager.shutdown)

    # Start lab
    if not args.no_lab:
        if not manager.start_lab():
            print("[!] Could not start Vulnerable API Lab. Aborting startup.")
            manager.shutdown()
            sys.exit(1)

    actual_model = custom_model or DEFAULT_GGUF_PATH
    print_banner(
        host=args.host,
        dashboard_port=args.port,
        lab_port=args.lab_port,
        model_name=actual_model.name,
    )

    # Start dashboard (blocking call)
    manager.start_dashboard(open_browser=not args.no_browser)


if __name__ == "__main__":
    main()
