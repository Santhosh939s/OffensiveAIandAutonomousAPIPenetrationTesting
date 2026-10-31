"""Flask Application Server for the Autonomous API Security Live Dashboard.

Provides REST endpoints and Server-Sent Events (SSE) streaming for monitoring
and managing the autonomous penetration testing agent from a web browser.
"""

import json
import os
import sys
from typing import Optional

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dashboard.session_manager import DashboardSessionManager
from controller.config import DEFAULT_CONFIG
from controller.tools.zap_client import ZapSecurityScanTool
from controller.brain.resource_profile import get_runtime_capabilities


def create_dashboard_app(session_manager: Optional[DashboardSessionManager] = None) -> Flask:
    """Application factory for the dashboard Flask service."""
    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    app = Flask(
        __name__,
        template_folder=templates_dir,
        static_folder=static_dir,
    )
    app.config["JSON_SORT_KEYS"] = False

    manager = session_manager or DashboardSessionManager()

    # --- HTML View Route ---

    @app.route("/")
    def index():
        return render_template("index.html")

    # --- System & Health Status ---

    @app.route("/api/system/status", methods=["GET"])
    def system_status():
        zap_tool = ZapSecurityScanTool()
        zap_health = zap_tool.execute(action="check_health")
        res_profile = get_runtime_capabilities()

        return jsonify({
            "status": "online",
            "dashboard_version": "1.1.0",
            "supported_models": res_profile["available_modes"],
            "active_model_mode": "mock",
            "recommended_mode": res_profile["recommended_mode"],
            "resource_profile": res_profile,
            "zap_daemon": {
                "url": DEFAULT_CONFIG.zap_base_url,
                "connected": zap_health.get("connected", False),
                "version": zap_health.get("version", "offline"),
                "active_scan_allowed": DEFAULT_CONFIG.zap_active_scan_enabled,
            },
            "default_allowed_hosts": list(DEFAULT_CONFIG.allowed_hosts),
        })

    @app.route("/api/system/resources", methods=["GET"])
    def system_resources():
        """Return real-time host RAM, process working set, and hardware recommendations."""
        return jsonify(get_runtime_capabilities())

    # --- Assessment Management APIs ---

    @app.route("/api/assessments/start", methods=["POST"])
    def start_assessment():
        data = request.get_json(force=True, silent=True) or {}
        target_url = str(data.get("target_url", "")).strip()

        if not target_url:
            return jsonify({"success": False, "error": "Target URL is required"}), 400

        assessment_name = data.get("assessment_name", "Live Security Assessment")
        max_turns = int(data.get("max_turns", 10))
        max_requests = int(data.get("max_requests", 25))
        max_model_calls = int(data.get("max_model_calls", 25))
        brain_mode = str(data.get("brain_mode", "mock")).lower()
        remote_endpoint = data.get("remote_endpoint")
        zap_active_scan = bool(data.get("zap_active_scan", False))
        spec_source = data.get("spec_source")
        allowed_hosts = data.get("allowed_hosts")

        res = manager.start_assessment(
            target_url=target_url,
            assessment_name=assessment_name,
            max_turns=max_turns,
            max_requests=max_requests,
            max_model_calls=max_model_calls,
            allowed_hosts=allowed_hosts,
            brain_mode=brain_mode,
            remote_endpoint=remote_endpoint,
            zap_active_scan=zap_active_scan,
            spec_source=spec_source,
        )

        status_code = 200 if res.get("success") else 400
        return jsonify(res), status_code

    @app.route("/api/assessments", methods=["GET"])
    def list_assessments():
        """Retrieve recent assessments from the evidence store."""
        limit = int(request.args.get("limit", 20))
        with manager.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?", (limit,)
            )
            rows = cursor.fetchall()
            sessions = [
                {
                    "session_id": r["session_id"],
                    "target": r["target"],
                    "status": r["status"],
                    "created_at": r["created_at"],
                    "turns_taken": r["turns_taken"],
                    "requests_sent": r["requests_sent"],
                    "notes": r["notes"],
                }
                for r in rows
            ]
        return jsonify({"sessions": sessions})

    @app.route("/api/assessments/<session_id>/status", methods=["GET"])
    def session_status(session_id: str):
        status = manager.get_session_status(session_id)
        if "error" in status:
            return jsonify(status), 404
        return jsonify(status)

    @app.route("/api/assessments/<session_id>/cancel", methods=["POST"])
    def cancel_assessment(session_id: str):
        res = manager.cancel_assessment(session_id)
        status_code = 200 if res.get("success") else 404
        return jsonify(res), status_code

    @app.route("/api/assessments/<session_id>/findings", methods=["GET"])
    def get_findings(session_id: str):
        limit = request.args.get("limit", type=int)
        offset = request.args.get("offset", default=0, type=int)
        findings = manager.get_findings(session_id, limit=limit, offset=offset)
        return jsonify({
            "session_id": session_id,
            "count": len(findings),
            "limit": limit,
            "offset": offset,
            "findings": findings,
        })

    @app.route("/api/assessments/<session_id>/traffic", methods=["GET"])
    def get_traffic(session_id: str):
        limit = request.args.get("limit", type=int)
        offset = request.args.get("offset", default=0, type=int)
        traffic = manager.get_traffic_logs_sanitized(session_id, limit=limit, offset=offset)
        return jsonify({
            "session_id": session_id,
            "count": len(traffic),
            "limit": limit,
            "offset": offset,
            "traffic": traffic,
        })

    @app.route("/api/assessments/<session_id>/report", methods=["GET"])
    def get_report(session_id: str):
        report_md = manager.get_report_markdown(session_id)
        return jsonify({"session_id": session_id, "report_markdown": report_md})

    @app.route("/api/assessments/<session_id>/report/download", methods=["GET"])
    def download_report(session_id: str):
        report_md = manager.get_report_markdown(session_id)
        response = Response(
            report_md,
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment;filename={session_id}_report.md"},
        )
        return response

    # --- Live Telemetry Streaming (SSE) ---

    @app.route("/api/stream/<session_id>", methods=["GET"])
    def stream_telemetry(session_id: str):
        """Server-Sent Events endpoint streaming live controller telemetry."""
        return Response(
            manager.get_sse_stream(session_id),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    return app


if __name__ == "__main__":
    app = create_dashboard_app()
    print("=" * 70)
    print("STARTING AUTONOMOUS API SECURITY TESTING DASHBOARD")
    print("Listening on http://127.0.0.1:8088")
    print("=" * 70)
    app.run(host="127.0.0.1", port=8088, debug=False)

