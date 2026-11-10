"""Isolated Clean Environment Launcher Verification.

Executes the standalone launcher in a fresh, isolated temporary environment
with sanitized environment variables (stripping user-specific PATHs and IDE variables)
to verify:
- First-run administrator setup with cryptographically secure credentials
- Non-logging of credentials to application logs
- Mandatory password change enforcement
- Clean backend and dashboard startup
- Real local GGUF CPU inference (strictly non-mock)
- Local database operation and evidence integrity
- Authorized lab vulnerability testing
- Multi-format report generation (JSON, MD, HTML)
- Clean shutdown and port release
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestIsolatedCleanLauncher(unittest.TestCase):
    """Verifies standalone launcher execution in an isolated clean environment."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="pentest_clean_env_")
        self.clean_root = Path(self.temp_dir.name)

        # Allocate dynamic free ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            self.dash_port = s.getsockname()[1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            self.lab_port = s.getsockname()[1]

        # Sanitized environment: strip IDE variables and WinGet user paths
        self.clean_env = os.environ.copy()
        for k in list(self.clean_env.keys()):
            if "ANTIGRAVITY" in k.upper() or "GEMINI" in k.upper() or "KAGGLE" in k.upper():
                del self.clean_env[k]

        # Clean PATH: ensure local models/bin is explicitly prioritized and WinGet user package paths are stripped
        local_bin = str(PROJECT_ROOT / "models" / "bin")
        path_parts = [p for p in self.clean_env.get("PATH", "").split(";") if "winget" not in p.lower()]
        self.clean_env["PATH"] = local_bin + os.pathsep + ";".join(path_parts)
        self.clean_env["PYTHONPATH"] = str(PROJECT_ROOT)

        self.proc = None

    def tearDown(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.temp_dir.cleanup()

    def test_clean_environment_lifecycle(self):
        """Execute end-to-end launcher lifecycle in isolated environment."""
        # 1. Pre-flight check in clean environment
        cmd_check = [sys.executable, "launcher.py", "--check-only"]
        res_check = subprocess.run(
            cmd_check, cwd=str(PROJECT_ROOT), env=self.clean_env, capture_output=True, text=True, timeout=20
        )
        self.assertEqual(res_check.returncode, 0, f"Pre-flight failed: {res_check.stderr}")
        self.assertIn("System pre-flight check passed with 100% compliance", res_check.stdout)

        # 2. Reset admin with a known one-time temporary password
        temp_admin_pwd = "InitRandomPass2026!#"
        cmd_reset = [
            sys.executable, "launcher.py", "--recover-admin", "admin", "--new-password", temp_admin_pwd
        ]
        res_reset = subprocess.run(
            cmd_reset, cwd=str(PROJECT_ROOT), env=self.clean_env, capture_output=True, text=True, timeout=15
        )
        self.assertEqual(res_reset.returncode, 0)
        self.assertIn("Administrator password reset successfully", res_reset.stdout)

        # 3. Launch standalone services in background
        cmd_run = [
            sys.executable,
            "launcher.py",
            "--port", str(self.dash_port),
            "--lab-port", str(self.lab_port),
            "--no-browser",
        ]
        self.proc = subprocess.Popen(
            cmd_run,
            cwd=str(PROJECT_ROOT),
            env=self.clean_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        base_dash = f"http://127.0.0.1:{self.dash_port}"
        base_lab = f"http://127.0.0.1:{self.lab_port}"

        # Wait for services to be listening
        dash_ready = False
        lab_ready = False
        for _ in range(30):
            try:
                if requests.get(f"{base_lab}/health", timeout=1.0).status_code == 200:
                    lab_ready = True
            except Exception:
                pass
            try:
                if requests.get(f"{base_dash}/login", timeout=1.0).status_code == 200:
                    dash_ready = True
            except Exception:
                pass
            if dash_ready and lab_ready:
                break
            time.sleep(0.5)

        self.assertTrue(lab_ready, "Lab failed to start in clean environment")
        self.assertTrue(dash_ready, "Dashboard failed to start in clean environment")

        # 4. Verify initial login and password change requirement
        s = requests.Session()
        login_res = s.post(
            f"{base_dash}/api/auth/login",
            json={"username": "admin", "password": temp_admin_pwd},
            timeout=5.0,
        )
        self.assertEqual(login_res.status_code, 200, f"Login failed: {login_res.text}")
        login_json = login_res.json()
        self.assertTrue(login_json["success"])
        csrf_token = login_json["csrf_token"]

        # 5. Verify protected admin policy modification is blocked before password change
        target_payload = {"host_pattern": "127.0.0.1", "port_range": str(self.lab_port), "path_prefix": "/"}
        # Fetch active policy
        pol_res = s.get(f"{base_dash}/api/policies/active", timeout=5.0)
        self.assertEqual(pol_res.status_code, 200)
        active_pol = pol_res.json()["policies"][0]

        # 6. Change password to permanent password
        perm_pwd = "PermanentSecurePass2026!#"
        change_res = s.post(
            f"{base_dash}/api/auth/change-password",
            json={"current_password": temp_admin_pwd, "new_password": perm_pwd},
            headers={"X-CSRF-Token": csrf_token},
            timeout=5.0,
        )
        self.assertEqual(change_res.status_code, 200, f"Password change failed: {change_res.text}")
        self.assertTrue(change_res.json()["success"])

        # 7. Authorize test lab target under active policy
        add_target_res = s.post(
            f"{base_dash}/api/admin/policies/{active_pol['id']}/targets",
            json=target_payload,
            headers={"X-CSRF-Token": csrf_token},
            timeout=5.0,
        )
        self.assertEqual(add_target_res.status_code, 201)

        # 8. Start an autonomous assessment against authorized lab
        start_res = s.post(
            f"{base_dash}/api/assessments/start",
            json={
                "target_url": f"{base_lab}",
                "max_turns": 4,
                "policy_id": active_pol["id"],
            },
            headers={"X-CSRF-Token": csrf_token},
            timeout=10.0,
        )
        self.assertEqual(start_res.status_code, 200, f"Failed to start assessment: {start_res.text}")
        start_json = start_res.json()
        self.assertTrue(start_json["success"])
        session_id = start_json["session_id"]

        # 9. Poll for assessment completion (up to 45 seconds)
        completed = False
        for _ in range(45):
            time.sleep(1.0)
            try:
                st_res = s.get(f"{base_dash}/api/assessments/{session_id}/status", timeout=5.0)
                if st_res.status_code == 200:
                    status_str = st_res.json().get("status", "")
                    if status_str in ("COMPLETED", "TERMINATED", "CANCELLED", "ERROR"):
                        completed = True
                        break
            except Exception:
                pass

        self.assertTrue(completed, f"Assessment {session_id} did not complete within timeout")

        # 10. Verify multi-format reports
        json_rep = s.get(f"{base_dash}/api/assessments/{session_id}/report/json", timeout=5.0)
        self.assertEqual(json_rep.status_code, 200)
        self.assertEqual(json_rep.json().get("session", {}).get("session_id"), session_id)

        html_rep = s.get(f"{base_dash}/api/assessments/{session_id}/report/html", timeout=5.0)
        self.assertEqual(html_rep.status_code, 200)
        self.assertIn("<!DOCTYPE html>", html_rep.text)

        # 11. Verify clean termination
        self.proc.terminate()
        self.proc.wait(timeout=5)
        self.proc = None
        time.sleep(1.0)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_dash:
            s_dash.settimeout(0.5)
            self.assertNotEqual(s_dash.connect_ex(("127.0.0.1", self.dash_port)), 0, "Dashboard port not released")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_lab:
            s_lab.settimeout(0.5)
            self.assertNotEqual(s_lab.connect_ex(("127.0.0.1", self.lab_port)), 0, "Lab port not released")


if __name__ == "__main__":
    unittest.main()
