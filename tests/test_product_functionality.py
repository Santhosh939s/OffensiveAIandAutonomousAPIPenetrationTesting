"""Unit and Integration Tests for Complete Product Functionality.

Covers:
1. Interrupted-session handling and recovery on daemon restart.
2. Comprehensive assessment configuration and scope/type validation.
3. Multi-session comparison and vulnerability regression diffing.
4. Enriched findings quality (technical impact, safe reproduction steps across all 10 OWASP categories).
5. Multi-format report consistency (Markdown, JSON, HTML) with impact and reproduction steps.
6. Adaptive reasoning engine quality (assessment type filtering, category prioritization, safe abstention).
"""

import os
import tempfile
import time
import pytest
from typing import Dict, Any

from controller.agent.adaptive_engine import AdaptiveTestSelector
from controller.agent.context_manager import CompactContextManager
from controller.config import AgentConfig
from controller.reporting.report_generator import ReportGenerator
from controller.reporting.risk_engine import RiskAssessmentEngine, FindingRiskProfile, Severity
from controller.storage.evidence_store import EvidenceStore
from dashboard.app import create_dashboard_app
from dashboard.session_manager import DashboardSessionManager


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    for _ in range(10):
        try:
            if os.path.exists(path):
                os.remove(path)
            break
        except PermissionError:
            time.sleep(0.1)


# -----------------------------------------------------------------------------
# 1. Interrupted Session Handling & Recovery
# -----------------------------------------------------------------------------

def test_interrupted_session_recovery_on_startup(temp_db):
    """Ensure sessions left in RUNNING status from crashed daemons are cleanly recovered."""
    store = EvidenceStore(db_path=temp_db)
    session_id = "sess_interrupted_test"
    store.create_session(
        session_id=session_id,
        target="http://127.0.0.1:5050",
        notes="Pre-crash running session",
    )
    # Simulate daemon crash while session was active
    store.update_session_status(session_id=session_id, status="RUNNING")

    sess_before = store.get_session(session_id)
    assert sess_before["status"] == "RUNNING"

    # Start session manager (simulating daemon restart)
    manager = DashboardSessionManager(db_path=temp_db, store=store)

    sess_after = store.get_session(session_id)
    assert sess_after["status"] == "INTERRUPTED"
    assert "Marked INTERRUPTED on daemon restart" in sess_after["notes"]


# -----------------------------------------------------------------------------
# 2. Enhanced Assessment Configuration & Validation
# -----------------------------------------------------------------------------

def test_assessment_configuration_validation(temp_db):
    """Test REST API validation for target URL schemes, timeouts, and depths."""
    store = EvidenceStore(db_path=temp_db)
    manager = DashboardSessionManager(db_path=temp_db, store=store)
    app = create_dashboard_app(session_manager=manager)
    client = app.test_client()

    # Invalid URL scheme
    res = client.post("/api/assessments/start", json={"target_url": "ftp://127.0.0.1"})
    assert res.status_code == 400
    assert "valid HTTP or HTTPS address" in res.get_json()["error"]

    # Missing target URL
    res = client.post("/api/assessments/start", json={})
    assert res.status_code == 400
    assert "Target URL is required" in res.get_json()["error"]

    # Invalid timeout bounds
    res = client.post("/api/assessments/start", json={
        "target_url": "http://127.0.0.1:5050",
        "timeout_seconds": 9999,
    })
    assert res.status_code == 400
    assert "timeout_seconds must be between" in res.get_json()["error"]


def test_assessment_start_with_rich_configuration(temp_db):
    """Verify launching assessment with auth credentials, OWASP categories, and depth."""
    store = EvidenceStore(db_path=temp_db)
    manager = DashboardSessionManager(db_path=temp_db, store=store)
    app = create_dashboard_app(session_manager=manager)
    client = app.test_client()

    payload = {
        "target_url": "http://127.0.0.1:5050",
        "assessment_name": "Configured Security Audit",
        "brain_mode": "mock",
        "assessment_type": "rest",
        "assessment_depth": "quick",
        "selected_categories": ["API1", "API2", "API8"],
        "timeout_seconds": 60,
        "auth_type": "bearer",
        "auth_credentials": {"token": "secret_jwt_token_12345"},
        "max_turns": 4,
        "max_requests": 10,
    }

    res = client.post("/api/assessments/start", json=payload)
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    session_id = data["session_id"]

    # Verify session details API
    det_res = client.get(f"/api/assessments/{session_id}/details")
    assert det_res.status_code == 200
    details = det_res.get_json()
    assert details["session_id"] == session_id
    assert "risk_summary" in details

    # Clean up by cancelling and ensuring worker thread exits
    client.post(f"/api/assessments/{session_id}/cancel")
    with manager._lock:
        sess = manager.active_sessions.get(session_id)
        worker_th = sess.get("thread") if sess else None
    if worker_th:
        worker_th.join(timeout=3.0)
    store.close()
    manager.store.close()


# -----------------------------------------------------------------------------
# 3. Findings Comparison & Regression Diffing
# -----------------------------------------------------------------------------

def test_session_findings_comparison(temp_db):
    """Test comparing findings between two assessment sessions (new, resolved, persistent)."""
    store = EvidenceStore(db_path=temp_db)
    manager = DashboardSessionManager(db_path=temp_db, store=store)

    sess_a = "session_run_a"
    sess_b = "session_run_b"

    store.create_session(sess_a, target="http://127.0.0.1:5050", notes="Run A")
    store.create_session(sess_b, target="http://127.0.0.1:5050", notes="Run B")

    # Session A findings: SQL Injection (fixed in B) & BOLA (persistent in B)
    store.record_finding(
        session_id=sess_a,
        endpoint="/api/search",
        category="SQL Injection",
        status="CONFIRMED",
        evidence_notes="Syntax error disclosed in Run A",
        verification_rule="RULE_SQLI_SYNTAX_ERROR",
        traffic_log_id=1,
    )
    store.record_finding(
        session_id=sess_a,
        endpoint="/api/users/1",
        category="BOLA / IDOR",
        status="CONFIRMED",
        evidence_notes="Unauthorized object read in Run A",
        verification_rule="RULE_BOLA_CROSS_USER_ACCESS",
        traffic_log_id=2,
    )

    # Session B findings: BOLA (persistent) & XSS (new regression)
    store.record_finding(
        session_id=sess_b,
        endpoint="/api/users/1",
        category="BOLA / IDOR",
        status="CONFIRMED",
        evidence_notes="Unauthorized object read in Run B",
        verification_rule="RULE_BOLA_CROSS_USER_ACCESS",
        traffic_log_id=3,
    )
    store.record_finding(
        session_id=sess_b,
        endpoint="/api/comments",
        category="XSS",
        status="CONFIRMED",
        evidence_notes="Script tag reflection in Run B",
        verification_rule="RULE_XSS_PAYLOAD_REFLECTED",
        traffic_log_id=4,
    )

    comparison = manager.compare_sessions(sess_a, sess_b)
    assert "error" not in comparison
    assert comparison["summary_counts"]["persistent"] == 1
    assert comparison["summary_counts"]["resolved"] == 1
    assert comparison["summary_counts"]["new"] == 1

    # Persistent: BOLA / IDOR at /api/users/1
    persistent_cat = comparison["persistent_findings"][0]["category"]
    assert "BOLA" in persistent_cat or "IDOR" in persistent_cat

    # Resolved: SQL Injection
    resolved_cat = comparison["resolved_findings"][0]["category"]
    assert "SQL" in resolved_cat

    # New: XSS
    new_cat = comparison["new_findings"][0]["category"]
    assert "XSS" in new_cat

    # Test via Flask API route
    app = create_dashboard_app(session_manager=manager)
    client = app.test_client()
    api_res = client.get(f"/api/assessments/compare?session_a={sess_a}&session_b={sess_b}")
    assert api_res.status_code == 200
    assert api_res.get_json()["summary_counts"]["persistent"] == 1


# -----------------------------------------------------------------------------
# 4. Findings Quality: Technical Impact & Safe Reproduction Steps
# -----------------------------------------------------------------------------

def test_findings_quality_all_owasp_categories():
    """Verify that all 10 OWASP API categories provide technical impact and reproduction steps."""
    categories_to_test = [
        ("API1: BOLA / IDOR", "bola / idor"),
        ("API2: Insecure JWT", "insecure jwt"),
        ("API3: BOPLA", "mass assignment"),
        ("API4: Resource Limits", "unrestricted resource consumption"),
        ("API5: BFLA", "broken function level authorization"),
        ("API6: Business Flows", "business flow abuse"),
        ("API7: SSRF", "ssrf"),
        ("API8: SQL Injection", "sql injection"),
        ("API9: Improper Inventory", "improper inventory management"),
        ("API10: Unsafe API Consumption", "unsafe consumption of apis"),
    ]

    for label, cat_name in categories_to_test:
        profile = RiskAssessmentEngine.get_finding_risk_profile(
            category=cat_name,
            status="CONFIRMED",
            endpoint="/api/test_route",
        )
        assert isinstance(profile, FindingRiskProfile)
        assert profile.technical_impact, f"Missing technical impact for {label}"
        assert profile.reproduction_steps, f"Missing reproduction steps for {label}"
        assert "/api/test_route" in profile.reproduction_steps or "curl" in profile.reproduction_steps
        assert profile.remediation_guidance, f"Missing remediation guidance for {label}"

        # Ensure dictionary representation contains them
        p_dict = profile.to_dict()
        assert "technical_impact" in p_dict
        assert "reproduction_steps" in p_dict


def test_reports_contain_technical_impact_and_reproduction(temp_db):
    """Ensure generated Markdown, JSON, and HTML reports include technical impact and reproduction steps."""
    store = EvidenceStore(db_path=temp_db)
    session_id = "sess_report_enrichment_test"
    store.create_session(session_id, target="http://127.0.0.1:5050")

    store.record_finding(
        session_id=session_id,
        endpoint="/api/user/profile",
        category="Mass Assignment",
        status="CONFIRMED",
        evidence_notes="Admin role attribute bound without authorization",
        verification_rule="RULE_MASS_ASSIGNMENT_CONFIRMED",
        traffic_log_id=1,
    )

    gen = ReportGenerator(evidence_store=store)

    # 1. Markdown Report
    md_report = gen.generate_report(session_id)
    assert "Technical Impact" in md_report
    assert "Safe Reproduction Steps" in md_report
    assert "curl" in md_report

    # 2. JSON Report
    json_report = gen.generate_json_report(session_id)
    finding_obj = json_report["findings"][0]
    assert "technical_impact" in finding_obj
    assert "reproduction_steps" in finding_obj
    assert len(finding_obj["technical_impact"]) > 10

    # 3. HTML Report
    html_report = gen.generate_html_report(session_id)
    assert "Technical Impact:" in html_report
    assert "Safe Reproduction:" in html_report


# -----------------------------------------------------------------------------
# 5. Adaptive Reasoning Quality & Candidate Ranking
# -----------------------------------------------------------------------------

def test_adaptive_selector_graphql_and_category_prioritization():
    """Verify adaptive test selector boosts selected categories and handles GraphQL routing."""
    ctx = CompactContextManager(target_url="http://127.0.0.1:5050", max_turns=10)
    ctx.register_discovered_endpoints([
        {"path": "/graphql", "method": "POST", "summary": "GraphQL Endpoint"},
        {"path": "/api/users/{id}", "method": "GET", "summary": "User Object"},
        {"path": "/api/orders/checkout", "method": "POST", "summary": "Checkout Flow"},
    ])

    # Case A: GraphQL exclusive assessment
    selector_gql = AdaptiveTestSelector(
        context_manager=ctx,
        assessment_type="graphql",
    )
    candidates_gql = selector_gql.evaluate_and_rank_candidates("http://127.0.0.1:5050", [])
    assert len(candidates_gql) > 0
    top_cand = candidates_gql[0]
    assert top_cand.path == "/graphql"
    assert top_cand.recommended_tool == "graphql_probe"

    # Case B: Category priority for API1 (BOLA)
    selector_bola = AdaptiveTestSelector(
        context_manager=ctx,
        selected_categories=["API1"],
    )
    candidates_bola = selector_bola.evaluate_and_rank_candidates("http://127.0.0.1:5050", [])
    assert candidates_bola[0].path == "/api/users/{id}"
    assert "API1" in candidates_bola[0].rationale

    # Case C: Safe stopping when budget exhausted
    ctx.endpoint_probe_counts["POST /graphql"] = 3
    ctx.endpoint_probe_counts["GET /api/users/{id}"] = 3
    ctx.endpoint_probe_counts["POST /api/orders/checkout"] = 3
    candidates_exhausted = selector_bola.evaluate_and_rank_candidates("http://127.0.0.1:5050", [])
    should_stop, reason = selector_bola.should_abstain_or_stop(candidates_exhausted)
    assert should_stop is True
    assert "probe budget limits" in reason

