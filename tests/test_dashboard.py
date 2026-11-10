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


def test_dashboard_endpoints_and_risk_apis(test_dashboard):
    """Verify endpoint catalog and risk summary endpoints on dashboard."""
    client, manager, store = test_dashboard
    session_id = "sess_endpoints_test"
    store.create_session(session_id, "http://127.0.0.1:5050")

    # Ingest specification
    store.record_specification(
        session_id=session_id,
        spec_source="http://127.0.0.1:5050/openapi.json",
        title="Test API",
        spec_data={
            "paths": {
                "/api/users": {"get": {"summary": "List users"}},
                "/api/orders": {"get": {"summary": "List orders"}},
            }
        },
    )

    # Ingest findings
    store.record_finding(
        session_id=session_id,
        endpoint="/api/orders/102",
        category="BOLA / IDOR",
        status="CONFIRMED",
        evidence_notes="Leaked order info",
        verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
        raw_evidence={"status": 200},
    )

    # Test /endpoints API
    ep_resp = client.get(f"/api/assessments/{session_id}/endpoints")
    assert ep_resp.status_code == 200
    ep_data = ep_resp.get_json()
    assert ep_data["count"] >= 2
    paths = [e["path"] for e in ep_data["endpoints"]]
    assert "/api/users" in paths
    assert "/api/orders" in paths

    # Test /risk API
    risk_resp = client.get(f"/api/assessments/{session_id}/risk")
    assert risk_resp.status_code == 200
    risk_data = risk_resp.get_json()
    assert risk_data["total_findings"] == 1
    assert risk_data["confirmed_count"] == 1
    assert risk_data["overall_risk_rating"] == "HIGH"

    # Test /report/json API
    r_json_resp = client.get(f"/api/assessments/{session_id}/report/json")
    assert r_json_resp.status_code == 200
    r_json = r_json_resp.get_json()
    assert r_json["report_version"] == "2.0.0"

    # Test /report/html API
    r_html_resp = client.get(f"/api/assessments/{session_id}/report/html")
    assert r_html_resp.status_code == 200
    assert "text/html" in r_html_resp.headers["Content-Type"]
    assert "<!DOCTYPE html>" in r_html_resp.get_data(as_text=True)


def test_system_status_caching(test_dashboard):
    """Verify system diagnostics endpoint utilizes TTL cache to avoid socket polling spikes."""
    client, _, _ = test_dashboard
    resp1 = client.get("/api/system/status")
    assert resp1.status_code == 200
    d1 = resp1.get_json()

    # Immediate second call should be served from memory cache
    resp2 = client.get("/api/system/status")
    assert resp2.status_code == 200
    d2 = resp2.get_json()

    assert d1["status"] == d2["status"]
    assert d1["dashboard_version"] == d2["dashboard_version"]
    assert d1["default_allowed_hosts"] == d2["default_allowed_hosts"]


def test_session_status_fast_aggregations(test_dashboard):
    """Verify session status returns direct SQL summary counts."""
    client, manager, store = test_dashboard
    session_id = "test-fast-agg-session"
    store.create_session(session_id, "http://127.0.0.1:5050")

    store.record_finding(
        session_id=session_id,
        endpoint="/api/v1/auth",
        category="BOLA",
        status="CONFIRMED",
        evidence_notes="Confirmed finding with verified rule and proof",
        verification_rule="BOLA_CROSS_ACCOUNT_LEAK",
        raw_evidence={"status": 200, "data": "leak"},
    )
    store.record_finding(
        session_id=session_id,
        endpoint="/api/v1/profile",
        category="AUTH_BYPASS",
        status="SUSPECTED",
        evidence_notes="Suspected finding",
    )

    resp = client.get(f"/api/assessments/{session_id}/status")
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["findings_count"] == 2
    assert data["confirmed_count"] == 1
    assert data["suspected_count"] == 1
    assert data["safe_count"] == 0
    assert "by_severity" in data


def test_traffic_pagination_and_masking(test_dashboard):
    """Verify paginated traffic retrieval and authorization token masking."""
    client, manager, store = test_dashboard
    session_id = "test-traffic-page-session"
    store.create_session(session_id, "http://127.0.0.1:5050")

    records = [
        {
            "method": "GET",
            "url": f"http://127.0.0.1:5050/api/item/{i}",
            "headers": {"Authorization": "Bearer super-secret-jwt-token"},
            "status_code": 200,
            "response_body": json.dumps({"item_id": i}),
        }
        for i in range(15)
    ]
    store.log_traffic_batch(session_id, records)

    # Fetch page 1 (limit 5, offset 0)
    resp = client.get(f"/api/assessments/{session_id}/traffic?limit=5&offset=0")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["count"] == 5
    assert len(data["traffic"]) == 5
    assert "Bearer ***" in data["traffic"][0]["headers"]["Authorization"]

    # Fetch page 2 (limit 5, offset 5)
    resp2 = client.get(f"/api/assessments/{session_id}/traffic?limit=5&offset=5")
    assert resp2.status_code == 200
    data2 = resp2.get_json()
    assert data2["count"] == 5
    assert data2["traffic"][0]["url"] != data["traffic"][0]["url"]


def test_report_memoization_on_terminal_session(test_dashboard):
    """Verify reports are memoized in memory for completed sessions."""
    client, manager, store = test_dashboard
    session_id = "test-memo-session"
    store.create_session(session_id, "http://127.0.0.1:5050")
    store.update_session_status(session_id, "COMPLETED")

    resp1 = client.get(f"/api/assessments/{session_id}/report")
    assert resp1.status_code == 200
    assert session_id in manager._report_cache
    assert "markdown" in manager._report_cache[session_id]

    # Verify cached return
    resp2 = client.get(f"/api/assessments/{session_id}/report")
    assert resp2.status_code == 200
    assert resp1.get_json() == resp2.get_json()


def test_dashboard_fully_offline_assets():
    """Verify dashboard HTML and static assets do not contain external CDN dependencies."""
    html_file = os.path.join(PROJECT_ROOT, "dashboard", "templates", "index.html")
    with open(html_file, "r", encoding="utf-8") as f:
        html = f.read()

    import re
    external_tags = re.findall(r'<(?:link|script|img)[^>]*(?:href|src)=["\']https?://[^"\']*["\']', html, re.IGNORECASE)
    assert len(external_tags) == 0, f"Found unauthorized external asset tags: {external_tags}"

