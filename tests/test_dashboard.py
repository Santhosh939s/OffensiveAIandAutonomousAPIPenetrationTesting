"""Unit and Integration Tests for Phase 6 Live Dashboard.

Tests the Flask API endpoints, scope enforcement, session lifecycle,
Server-Sent Events (SSE) telemetry, traffic masking, and report generation.
"""

import json
import os
import sys
import time
import pytest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager, mask_sensitive_traffic_data
from controller.storage.evidence_store import EvidenceStore


@pytest.fixture
def test_dashboard(tmp_path):
    """Create a test dashboard instance with a temporary SQLite file store."""
    db_file = str(tmp_path / "test_dash.db")
    store = EvidenceStore(db_file)
    manager = DashboardSessionManager(db_path=db_file, store=store)
    app = create_dashboard_app(session_manager=manager)
    app.config["TESTING"] = True
    client = app.test_client()
    return client, manager, store


def test_index_page(test_dashboard):
    """Verify web dashboard HTML UI renders properly."""
    client, _, _ = test_dashboard
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Autonomous API Penetration Testing" in html
    assert "Live Activity" in html
    assert "Traffic Inspector" in html
    assert "Security Findings" in html


def test_system_status(test_dashboard):
    """Verify system diagnostics endpoint returns model and daemon info."""
    client, _, _ = test_dashboard
    response = client.get("/api/system/status")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "online"
    assert "supported_models" in data
    assert "zap_daemon" in data
    assert "127.0.0.1" in data["default_allowed_hosts"]


def test_start_assessment_missing_target(test_dashboard):
    """Verify starting assessment without target URL returns 400."""
    client, _, _ = test_dashboard
    response = client.post("/api/assessments/start", json={})
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "Target URL is required" in data["error"]


def test_start_assessment_scope_rejection(test_dashboard):
    """Verify targeting an unauthorized host is rejected by the policy engine."""
    client, _, _ = test_dashboard
    response = client.post(
        "/api/assessments/start",
        json={
            "target_url": "http://unauthorized-external-domain.org:8080/api",
            "allowed_hosts": ["127.0.0.1", "localhost"],
        },
    )
    assert response.status_code == 400
    data = response.get_json()
    assert data["success"] is False
    assert "scope validation failed" in data["error"].lower()


def test_start_assessment_lifecycle(test_dashboard):
    """Verify starting a mock assessment runs asynchronously and logs status."""
    client, manager, _ = test_dashboard
    response = client.post(
        "/api/assessments/start",
        json={
            "target_url": "http://127.0.0.1:5050",
            "assessment_name": "Test Run",
            "max_turns": 2,
            "max_requests": 5,
            "max_model_calls": 5,
            "brain_mode": "mock",
            "spec_source": "lab/openapi_spec.json",
        },
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["success"] is True
    session_id = data["session_id"]
    assert session_id.startswith("sess_")

    # Check status endpoint
    status_resp = client.get(f"/api/assessments/{session_id}/status")
    assert status_resp.status_code == 200
    status_data = status_resp.get_json()
    assert status_data["session_id"] == session_id
    assert status_data["target"] == "http://127.0.0.1:5050"

    # Wait for completion (deterministic mock completes in ~1-2s)
    for _ in range(30):
        time.sleep(0.2)
        st = manager.get_session_status(session_id)
        if st.get("status") in ("COMPLETED", "FAILED", "CANCELLED"):
            break

    final_status = manager.get_session_status(session_id)
    assert final_status.get("status") in ("COMPLETED", "RUNNING")


def test_cancel_assessment(test_dashboard):
    """Verify cancel assessment stops execution."""
    client, manager, _ = test_dashboard
    response = client.post(
        "/api/assessments/start",
        json={
            "target_url": "http://127.0.0.1:5050",
            "max_turns": 10,
            "brain_mode": "mock",
            "spec_source": "lab/openapi_spec.json",
        },
    )
    session_id = response.get_json()["session_id"]

    cancel_resp = client.post(f"/api/assessments/{session_id}/cancel")
    assert cancel_resp.status_code == 200
    cancel_data = cancel_resp.get_json()
    assert cancel_data["success"] is True

    # Check that cancel is reflected
    time.sleep(0.2)
    status_data = manager.get_session_status(session_id)
    assert status_data["status"] == "CANCELLED"


def test_sensitive_traffic_data_masking():
    """Verify mask_sensitive_traffic_data redacts authorization tokens, passwords, and API keys."""
    raw_traffic = [
        {
            "traffic_id": 1,
            "session_id": "test_s",
            "url": "http://127.0.0.1:5050/api/users",
            "method": "POST",
            "request_headers": {
                "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_token",
                "Content-Type": "application/json",
                "X-Api-Key": "super_secret_api_key_12345",
            },
            "request_body": {
                "username": "admin",
                "password": "RealPlaintextPassword123!",
                "access_token": "secret_access_xyz",
            },
            "response_status": 200,
            "response_headers": {"Set-Cookie": "session_id=secret_cookie_val; HttpOnly"},
            "response_body": "{\"token\": \"eyJnone.alg.token\"}",
            "response_time_ms": 15.0,
            "timestamp": "2026-10-31T12:00:00",
        }
    ]

    masked = mask_sensitive_traffic_data(raw_traffic)
    assert len(masked) == 1
    item = masked[0]

    # Verify headers masked
    assert item["request_headers"]["Authorization"] == "***MASKED***"
    assert item["request_headers"]["X-Api-Key"] == "***MASKED***"
    assert item["request_headers"]["Content-Type"] == "application/json"
    assert item["response_headers"]["Set-Cookie"] == "***MASKED***"

    # Verify request body masked
    assert item["request_body"]["username"] == "admin"
    assert item["request_body"]["password"] == "***MASKED***"
    assert item["request_body"]["access_token"] == "***MASKED***"


def test_list_assessments_endpoint(test_dashboard):
    """Verify listing recent assessments."""
    client, manager, store = test_dashboard
    store.create_session("sess_list_1", "http://127.0.0.1:5050")
    store.create_session("sess_list_2", "http://127.0.0.1:5050")

    resp = client.get("/api/assessments?limit=10")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "sessions" in data
    assert len(data["sessions"]) >= 2


def test_report_and_download_endpoints(test_dashboard):
    """Verify report Markdown and download endpoints."""
    client, manager, store = test_dashboard
    session_id = "sess_report_test"
    store.create_session(session_id, "http://127.0.0.1:5050")
    store.record_finding(
        session_id=session_id,
        endpoint="/api/users/2",
        category="BOLA/IDOR",
        status="CONFIRMED",
        evidence_notes="Observed unauthorized user profile data returned for user 2.",
        verification_rule="BOLA_UNAUTHORIZED_DATA_ACCESS",
        raw_evidence={"response_status": 200, "user_id": 2},
    )

    # Test JSON preview
    resp = client.get(f"/api/assessments/{session_id}/report")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "report_markdown" in data
    assert "BOLA/IDOR" in data["report_markdown"]
    assert "CONFIRMED" in data["report_markdown"]

    # Test download file
    download_resp = client.get(f"/api/assessments/{session_id}/report/download")
    assert download_resp.status_code == 200
    assert "text/markdown" in download_resp.headers["Content-Type"]
    assert f"{session_id}_report.md" in download_resp.headers["Content-Disposition"]
    assert "BOLA/IDOR" in download_resp.get_data(as_text=True)


def test_sse_telemetry_stream(test_dashboard):
    """Verify SSE telemetry stream produces event data."""
    client, manager, _ = test_dashboard
    # Start assessment
    resp = client.post(
        "/api/assessments/start",
        json={
            "target_url": "http://127.0.0.1:5050",
            "max_turns": 1,
            "brain_mode": "mock",
        },
    )
    session_id = resp.get_json()["session_id"]

    # Verify stream generation
    stream = manager.get_sse_stream(session_id)
    first_chunk = next(stream)
    assert "STREAM_CONNECTED" in first_chunk
    assert session_id in first_chunk
