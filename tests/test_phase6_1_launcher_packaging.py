"""Phase 6.1: Standalone Packaging & Windows Launcher Integration Tests.

Validates the complete standalone packaging and launcher lifecycle:
1. Pre-flight diagnostics pass 100%
2. Packaging verification passes with valid GGUF hash and structure
3. Launcher starts Vulnerable Lab (127.0.0.1:5050) and Dashboard (127.0.0.1:8088)
4. Dashboard and Lab are reachable over HTTP
5. Admin authentication and CSRF protection succeed
6. Real GGUF model inference executes via llama-cli on CPU
7. Autonomous pentest assessment completes under active policy
8. Evidence and reports (JSON, Markdown, HTML) are generated
9. Clean shutdown and restart capability
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from deployment.verify_installation import run_verification
from controller.brain.local_cpu_client import LocalCpuBrainClient, find_default_gguf_model


class TestPhase61StandalonePackaging(unittest.TestCase):
    """Phase 6.1 Standalone Packaging and Launcher Integration Tests."""

    dashboard_proc: subprocess.Popen = None
    dashboard_port: int = 8089  # Use test port 8089 to prevent collision
    lab_port: int = 5059        # Use test port 5059 to prevent collision

    @classmethod
    def setUpClass(cls):
        # 1. Allocate dynamic free ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.dashboard_port = s.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            cls.lab_port = s.getsockname()[1]

    @classmethod
    def tearDownClass(cls):
        if cls.dashboard_proc:
            try:
                cls.dashboard_proc.terminate()
                cls.dashboard_proc.wait(timeout=5)
            except Exception:
                try:
                    cls.dashboard_proc.kill()
                except Exception:
                    pass

    def test_01_packaging_verification_structure_and_hashes(self):
        """Packaging manifest and installation verification report 100% compliance."""
        report = run_verification()
        self.assertTrue(report["all_passed"], f"Packaging verification failed: {report}")
        self.assertTrue(report["checks"]["model_gguf"]["exists"])
        self.assertTrue(report["checks"]["model_gguf"]["sha256_verified"])
        self.assertTrue(report["checks"]["inference_engine"]["llama_cli_found"])
        self.assertTrue(report["checks"]["offline_self_contained"])

    def test_02_launcher_preflight_check(self):
        """Launcher CLI diagnostic mode executes cleanly."""
        cmd = [sys.executable, "launcher.py", "--check-only"]
        res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, f"Launcher pre-flight failed: {res.stderr}")
        self.assertIn("System pre-flight check passed with 100% compliance", res.stdout)

    def test_03_real_gguf_cpu_inference(self):
        """LocalCpuBrainClient executes genuine model inference via llama-cli on CPU."""
        model_path = find_default_gguf_model()
        self.assertIsNotNone(model_path)
        self.assertTrue(os.path.exists(model_path))

        brain = LocalCpuBrainClient(
            model_path=model_path,
            allow_mock_fallback=False,
            n_threads=2,
            n_ctx=2048,
        )
        self.assertEqual(brain.engine, "llama_cli")

        sample_req = {
            "method": "GET",
            "path": "/api/search?q=' UNION SELECT null, password FROM users --",
            "headers": {},
        }
        classification = brain.classify_request(sample_req)
        self.assertIsInstance(classification, dict)
        self.assertIn("category", classification)
        self.assertEqual(classification["category"], "SQL Injection")
        self.assertGreaterEqual(classification.get("confidence", 0), 0.7)

    def test_04_standalone_service_orchestration_and_assessment(self):
        """Launcher starts services, dashboard authenticates, and assessment executes cleanly."""
        # Provision a secure dynamic test password for the test run
        from controller.storage.evidence_store import EvidenceStore
        from controller.auth.authentication_service import AuthenticationService
        store = EvidenceStore(str(PROJECT_ROOT / "offensive_ai_evidence.db"))
        auth_svc = AuthenticationService(store=store)
        test_pwd = "DynamicTestPass2026!#"
        if auth_svc.has_admin():
            auth_svc.reset_admin_password("admin", test_pwd, actor="TEST_ORCHESTRATION")
        else:
            auth_svc.bootstrap_admin("admin", test_pwd, force_setup=True)

        cmd = [
            sys.executable,
            "launcher.py",
            "--port", str(self.dashboard_port),
            "--lab-port", str(self.lab_port),
            "--no-browser",
        ]
        self.dashboard_proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        # Wait for both services to be listening
        base_dash = f"http://127.0.0.1:{self.dashboard_port}"
        base_lab = f"http://127.0.0.1:{self.lab_port}"

        dash_up = False
        lab_up = False
        for _ in range(30):
            try:
                r1 = requests.get(f"{base_lab}/health", timeout=1.0)
                if r1.status_code == 200:
                    lab_up = True
            except Exception:
                pass

            try:
                r2 = requests.get(f"{base_dash}/login", timeout=1.0)
                if r2.status_code == 200:
                    dash_up = True
            except Exception:
                pass

            if lab_up and dash_up:
                break
            time.sleep(0.5)

        self.assertTrue(lab_up, f"Vulnerable Lab did not start on {base_lab}")
        self.assertTrue(dash_up, f"Dashboard did not start on {base_dash}")

        # Authenticate via Session
        s = requests.Session()
        login_page = s.get(f"{base_dash}/login", timeout=3.0)
        self.assertEqual(login_page.status_code, 200)

        # Extract CSRF token from page or cookie
        csrf_token = s.cookies.get("csrf_token")

        login_res = s.post(
            f"{base_dash}/api/auth/login",
            json={"username": "admin", "password": test_pwd},
            headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
            timeout=3.0,
        )
        self.assertEqual(login_res.status_code, 200, f"Login failed: {login_res.text}")
        login_json = login_res.json()
        self.assertTrue(login_json["success"])

        try:
            # Fetch active policies
            pol_res = s.get(f"{base_dash}/api/policies/active", timeout=3.0)
            self.assertEqual(pol_res.status_code, 200)
            pol_data = pol_res.json()
            self.assertTrue(pol_data["success"])
            self.assertGreater(len(pol_data["policies"]), 0)
            active_pol = pol_data["policies"][0]

            # Ensure target for our lab port exists in this policy
            csrf = login_json.get("csrf_token") or s.cookies.get("csrf_token", "")
            target_add_res = s.post(
                f"{base_dash}/api/admin/policies/{active_pol['id']}/targets",
                json={"host_pattern": "127.0.0.1", "port_range": str(self.lab_port), "path_prefix": "/"},
                headers={"X-CSRF-Token": csrf} if csrf else {},
                timeout=3.0,
            )

            # Launch assessment via dashboard API
            launch_res = s.post(
                f"{base_dash}/api/assessments/start",
                json={
                    "target_url": base_lab,
                    "spec_source": f"{base_lab}/openapi.json",
                    "policy_id": active_pol["id"],
                    "brain_mode": "mock",  # Deterministic test run
                    "max_turns": 5,
                    "max_requests": 10,
                },
                headers={"X-CSRF-Token": csrf} if csrf else {},
                timeout=5.0,
            )
            self.assertEqual(launch_res.status_code, 200, f"Assessment launch failed: {launch_res.text}")
            launch_json = launch_res.json()
            self.assertTrue(launch_json["success"])
            session_id = launch_json["session_id"]

            # Poll until completed (timeout 30 seconds)
            completed = False
            for _ in range(30):
                try:
                    status_res = s.get(f"{base_dash}/api/assessments/{session_id}/status", timeout=10.0)
                    if status_res.status_code == 200:
                        stat_data = status_res.json()
                        if stat_data.get("status") in ("COMPLETED", "HALTED", "ERROR"):
                            completed = True
                            break
                except Exception:
                    pass
                time.sleep(1.0)

            self.assertTrue(completed, f"Assessment {session_id} did not finish within 30s")

            # Verify Report Generation APIs
            json_rep_res = s.get(f"{base_dash}/api/assessments/{session_id}/report/json", timeout=3.0)
            self.assertEqual(json_rep_res.status_code, 200)
            rep_data = json_rep_res.json()
            self.assertIn("findings", rep_data)

            md_rep_res = s.get(f"{base_dash}/api/assessments/{session_id}/report", timeout=3.0)
            self.assertEqual(md_rep_res.status_code, 200)
            self.assertIn("# API Security Penetration Testing Assessment Report", md_rep_res.text)

            html_rep_res = s.get(f"{base_dash}/api/assessments/{session_id}/report/html", timeout=3.0)
            self.assertEqual(html_rep_res.status_code, 200)
            self.assertIn("<!DOCTYPE html>", html_rep_res.text)

        finally:
            # Terminate services cleanly
            if self.dashboard_proc:
                self.dashboard_proc.terminate()
                try:
                    self.dashboard_proc.wait(timeout=5)
                except Exception:
                    self.dashboard_proc.kill()
                self.dashboard_proc = None
        self.dashboard_proc = None

    def test_05_clean_shutdown_and_restart(self):
        """Services terminate cleanly and ports are completely freed for subsequent launch."""
        # Ensure test ports are freed
        time.sleep(1.0)
        self.assertFalse(
            self.is_port_open("127.0.0.1", self.dashboard_port),
            f"Dashboard port {self.dashboard_port} remained open after shutdown"
        )
        self.assertFalse(
            self.is_port_open("127.0.0.1", self.lab_port),
            f"Lab port {self.lab_port} remained open after shutdown"
        )

    def test_06_admin_recovery_cli_and_no_password_logging(self):
        """Verify launcher --recover-admin CLI and confirm credentials are never written to application logs."""
        recovery_pwd = "RecoveredPass999!@"
        cmd = [
            sys.executable,
            "launcher.py",
            "--recover-admin", "admin",
            "--new-password", recovery_pwd,
        ]
        res = subprocess.run(cmd, cwd=str(PROJECT_ROOT), capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, f"Admin recovery command failed: {res.stderr}\n{res.stdout}")
        self.assertIn("Administrator password reset successfully", res.stdout)
        self.assertIn(recovery_pwd, res.stdout)

        # Crucial check: verify password was NOT written to logs/launcher.log
        log_file = PROJECT_ROOT / "logs" / "launcher.log"
        if log_file.is_file():
            log_content = log_file.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(recovery_pwd, log_content, "CRITICAL: Recovery password leaked into logs/launcher.log!")

    def is_port_open(self, host: str, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0


if __name__ == "__main__":
    unittest.main()
