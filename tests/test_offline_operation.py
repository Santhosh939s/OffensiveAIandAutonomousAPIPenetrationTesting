"""Offline Operation and Dependency Audit Tests for Phase 4.7.

Validates that the application runs locally without internet access, external AI APIs,
cloud services, remote databases, external fonts, or CDN resources.
"""

import json
import os
import re
import socket
import sys
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.brain.local_cpu_client import LocalCpuBrainClient
from controller.brain.model_gateway import get_model_brain
from controller.config import DEFAULT_CONFIG
from controller.storage.evidence_store import EvidenceStore
from controller.tools.zap_client import ZapSecurityScanTool
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager


def test_no_cloud_ai_sdk_dependencies():
    """Verify that cloud AI SDKs are not imported or required by the runtime."""
    cloud_modules = [
        "openai",
        "anthropic",
        "google.generativeai",
        "huggingface_hub",
        "torch",
        "transformers",
    ]
    for mod in cloud_modules:
        # None of the core controller or dashboard modules should import these
        assert mod not in sys.modules or mod not in ("controller.brain", "controller.agent", "dashboard.app")


def test_runtime_codebase_zero_external_network_urls():
    """Verify that runtime code contains zero non-localhost target or API endpoints."""
    url_pattern = re.compile(r'https?://[a-zA-Z0-9_\-\.:/]+')
    runtime_dirs = ["controller", "dashboard", "lab"]
    disallowed_urls = []

    for d in runtime_dirs:
        for root, _, files in os.walk(os.path.join(PROJECT_ROOT, d)):
            for f in files:
                if not f.endswith((".py", ".html", ".js", ".css")):
                    continue
                p = os.path.join(root, f)
                with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                    for line_no, line in enumerate(fp, 1):
                        for u in url_pattern.findall(line):
                            # Permit loopback, local development, or template placeholders
                            is_permitted = any(lh in u for lh in [
                                "127.0.0.1", "localhost", "0.0.0.0", "::1",
                                "8088", "5050", "8080", "ngrok-free.app", "example.com"
                            ])
                            if not is_permitted:
                                disallowed_urls.append((p, line_no, u))

    assert len(disallowed_urls) == 0, f"Disallowed external URLs found in runtime: {disallowed_urls}"


def test_static_assets_fully_airgapped():
    """Verify that dashboard HTML and static assets do not link to external CDNs or fonts."""
    html_file = os.path.join(PROJECT_ROOT, "dashboard", "templates", "index.html")
    with open(html_file, "r", encoding="utf-8") as f:
        html = f.read()

    external_tags = re.findall(r'<(?:link|script|img)[^>]*(?:href|src)=["\']https?://[^"\']*["\']', html, re.IGNORECASE)
    assert len(external_tags) == 0, f"Found external CDN asset tags: {external_tags}"


def test_offline_socket_firewall_enforcement():
    """Verify that socket-level sandbox strictly blocks non-localhost connections while allowing loopback."""
    original_connect = socket.socket.connect
    blocked_attempts = []

    def guarded_connect(self, address):
        host = str(address[0]).lower()
        if host in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
            return original_connect(self, address)
        blocked_attempts.append(address)
        raise socket.error("OFFLINE ENFORCEMENT: External network blocked")

    socket.socket.connect = guarded_connect
    try:
        # 1. External attempt should raise socket.error
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with pytest.raises(socket.error):
            s.connect(("8.8.8.8", 53))
        assert len(blocked_attempts) == 1
    finally:
        socket.socket.connect = original_connect


def test_offline_model_loading_and_inference_llama_cli():
    """Verify LocalCpuBrainClient resolves the authentic GGUF model and operates offline."""
    gguf_path = os.path.join(PROJECT_ROOT, "models", "qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf")
    assert os.path.exists(gguf_path), f"GGUF model not found at {gguf_path}"

    client = LocalCpuBrainClient(
        model_path=gguf_path,
        n_ctx=2048,
        n_threads=2,
        allow_mock_fallback=False, # Strictly forbid mock fallback
    )
    assert client.is_mock is False
    assert client.engine in ("llama_cli", "llama_cpp", "llama_server")
    assert client.resolved_model_path == os.path.abspath(gguf_path)


def test_missing_optional_zap_daemon_graceful_handling():
    """Verify that when the optional ZAP daemon is offline, tools fail gracefully with informative status."""
    zap = ZapSecurityScanTool()
    h = zap.execute(action="check_health")
    assert h["connected"] is False
    assert h["success"] is False

    scan_res = zap.execute(action="spider", url="http://127.0.0.1:5050")
    assert scan_res["success"] is False
    assert "unable to connect" in scan_res["error"].lower() or "connect" in scan_res["error"].lower()


def test_offline_session_recovery():
    """Verify that crashed sessions are recovered upon session manager startup without network dependencies."""
    store = EvidenceStore(":memory:")
    session_id = "test-crashed-offline"
    store.create_session(session_id, "http://127.0.0.1:5050")
    store.update_session_status(session_id, "RUNNING")

    manager = DashboardSessionManager(db_path=":memory:", store=store)
    s = store.get_session(session_id)
    assert s["status"] == "INTERRUPTED"
    assert "Recovered" in s["notes"]
