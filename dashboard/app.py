"""Flask Application Server for the Autonomous API Security Live Dashboard.

Provides REST endpoints and Server-Sent Events (SSE) streaming for monitoring
and managing the autonomous penetration testing agent from a web browser.
"""

import json
import logging
import os
import sys
import threading
import time
from typing import Optional

logger = logging.getLogger("autonomous_pentest.dashboard.app")

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
from controller.auth.authentication_service import AuthenticationService
from controller.auth.session_service import SessionService
from controller.guardrails.policy_service import PolicyService
from dashboard.middleware import require_auth, require_role, require_csrf, get_session_from_request


def create_dashboard_app(
    session_manager: Optional[DashboardSessionManager] = None,
    auth_service: Optional[AuthenticationService] = None,
    session_service: Optional[SessionService] = None,
    policy_service: Optional[PolicyService] = None,
) -> Flask:
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
    store = manager.store
    sess_svc = session_service or SessionService(store=store)
    policy_svc = policy_service or PolicyService(store=store)
    auth_svc = auth_service or AuthenticationService(store=store, session_service=sess_svc)

    app.session_manager = manager
    app.session_service = sess_svc
    app.auth_service = auth_svc
    app.policy_service = policy_svc

    # --- Remote Client Access Control & Local-Only Mode Enforcement ---
    @app.before_request
    def enforce_remote_access_policy():
        """Enforce access control boundaries for remote network clients.

        - Localhost clients (127.0.0.1, ::1, localhost, testclient) operate in documented local-only mode.
        - Remote clients (non-loopback IPs) must present an authenticated session for all assessment operations.
        - Auditor role is enforced as read-only (blocked from starting or cancelling assessments).
        """
        client_ip = (request.remote_addr or "127.0.0.1").strip()
        is_local = client_ip in ("127.0.0.1", "::1", "localhost", "testclient")

        if not is_local:
            # 1. Allow public entry points
            public_prefixes = (
                "/login",
                "/static",
                "/api/auth/login",
                "/api/auth/status",
                "/api/auth/me",
                "/api/system/status",
                "/api/system/resources",
            )
            if request.path == "/" or any(request.path.startswith(p) for p in public_prefixes):
                return None

            # 2. Assessment APIs require an authenticated session for remote callers
            session = get_session_from_request(sess_svc)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Remote access to assessment operations requires an active session.",
                }), 401

            # 3. If caller is an Auditor, enforce read-only restriction on state-changing assessment routes
            if session.role.lower() == "auditor":
                if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                    return jsonify({
                        "success": False,
                        "error": "Insufficient privileges: Auditor role is strictly read-only. Cannot start, cancel, or modify assessments.",
                    }), 403

        return None

    # --- HTML View Routes ---

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/login")
    def login_page():
        return render_template("login.html")

    # --- Administrator & User Authentication APIs ---

    @app.route("/api/auth/login", methods=["POST"])
    def auth_login():
        """Authenticate user credentials, rotate session, and return CSRF token."""
        data = request.get_json(force=True, silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        ip_addr = request.remote_addr or "127.0.0.1"
        user_agent = request.headers.get("User-Agent", "")

        success, user_info, msg = auth_svc.authenticate(
            username=username,
            password=password,
            ip_address=ip_addr,
            user_agent=user_agent,
        )

        if not success or not user_info:
            return jsonify({"success": False, "error": msg}), 401

        # Rotate session to prevent session fixation attacks
        old_token = request.cookies.get("session_token")
        raw_token, csrf_token, _ = sess_svc.rotate_session(
            old_raw_token=old_token,
            user_id=user_info["id"],
            ip_address=ip_addr,
            user_agent=user_agent,
        )

        must_change = bool(user_info.get("must_change_password", False))
        resp = jsonify({
            "success": True,
            "message": "Login successful",
            "csrf_token": csrf_token,
            "must_change_password": must_change,
            "user": {
                "id": user_info["id"],
                "username": user_info["username"],
                "role": user_info["role"],
                "must_change_password": must_change,
            },
        })

        is_secure = request.is_secure or request.headers.get("X-Forwarded-Proto") == "https"
        resp.set_cookie(
            key="session_token",
            value=raw_token,
            max_age=int(sess_svc.max_lifetime),
            httponly=True,
            samesite="Strict",
            secure=is_secure,
            path="/",
        )
        return resp

    @app.route("/api/auth/logout", methods=["POST"])
    @require_auth(sess_svc)
    @require_csrf(sess_svc)
    def auth_logout():
        """Invalidate server-side session and clear client session cookie."""
        token = request.cookies.get("session_token")
        if token:
            sess_svc.invalidate_session(token)
        resp = jsonify({"success": True, "message": "Logged out successfully"})
        resp.set_cookie(
            key="session_token",
            value="",
            expires=0,
            httponly=True,
            samesite="Strict",
            path="/",
        )
        return resp

    @app.route("/api/auth/status", methods=["GET"])
    @app.route("/api/auth/me", methods=["GET"])
    def auth_status():
        """Return current authentication state and CSRF token for valid sessions."""
        session = get_session_from_request(sess_svc)
        setup_req = not auth_svc.has_admin() and not auth_svc.is_setup_completed()
        if session:
            return jsonify({
                "authenticated": True,
                "csrf_token": session.csrf_token,
                "setup_required": setup_req,
                "must_change_password": getattr(session, "must_change_password", False),
                "user": {
                    "id": session.user_id,
                    "username": session.username,
                    "role": session.role,
                    "must_change_password": getattr(session, "must_change_password", False),
                },
            })
        return jsonify({
            "authenticated": False,
            "csrf_token": None,
            "setup_required": setup_req,
            "user": None,
        })

    @app.route("/api/auth/setup", methods=["POST"])
    def auth_setup():
        """First-run administrator account initialization."""
        if auth_svc.has_admin():
            return jsonify({
                "success": False,
                "error": "Administrator account already exists.",
            }), 400
        if auth_svc.is_setup_completed():
            return jsonify({
                "success": False,
                "error": "Initial setup was already completed. Silent administrator recreation is forbidden.",
            }), 403

        data = request.get_json(force=True, silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        ip_addr = request.remote_addr or "127.0.0.1"

        try:
            admin_user = auth_svc.bootstrap_admin(
                username=username,
                password=password,
                ip_address=ip_addr,
                must_change_password=False,
            )
            return jsonify({
                "success": True,
                "message": "Initial administrator account created successfully.",
                "user": {
                    "id": admin_user["id"],
                    "username": admin_user["username"],
                    "role": admin_user["role"],
                },
            }), 201
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/auth/change-password", methods=["POST"])
    @require_auth(sess_svc)
    @require_csrf(sess_svc)
    def auth_change_password():
        """Change the authenticated user's password."""
        session = getattr(request, "admin_session", None)
        if not session:
            return jsonify({"success": False, "error": "Authentication required"}), 401

        data = request.get_json(force=True, silent=True) or {}
        current_password = str(data.get("current_password", ""))
        new_password = str(data.get("new_password", ""))
        ip_addr = request.remote_addr or "127.0.0.1"

        ok, msg = auth_svc.change_password(
            user_id=session.user_id,
            current_password=current_password,
            new_password=new_password,
            ip_address=ip_addr,
        )
        if not ok:
            return jsonify({"success": False, "error": msg}), 400

        return jsonify({
            "success": True,
            "message": msg,
        })

    # --- Protected Administrator Test Endpoints ---

    @app.route("/api/admin/test", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_test():
        """Protected endpoint accessible strictly by authenticated administrators."""
        return jsonify({
            "success": True,
            "message": "Protected administrator endpoint accessed successfully",
            "user": request.admin_session.username,
            "role": request.admin_session.role,
        })

    @app.route("/api/admin/echo", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_echo():
        """Protected state-changing endpoint enforcing admin role and CSRF verification."""
        payload = request.get_json(silent=True) or {}
        return jsonify({
            "success": True,
            "message": "State mutation authorized",
            "echo": payload,
            "user": request.admin_session.username,
            "role": request.admin_session.role,
        })

    # --- Policy & Target Authorization Management APIs ---

    @app.route("/api/policies/active", methods=["GET"])
    def list_active_policies():
        """Retrieve active authorized policies for assessment launcher and UI dropdowns."""
        policies = policy_svc.list_policies(active_only=True)
        summary = [
            {
                "id": p["id"],
                "policy_uuid": p["policy_uuid"],
                "name": p["name"],
                "description": p["description"],
                "current_version": p["current_version"],
                "targets": p.get("targets", []),
                "config": {
                    "max_turns": p.get("config", {}).get("max_turns", 10),
                    "max_requests": p.get("config", {}).get("max_requests", 25),
                    "zap_active_scan_enabled": p.get("config", {}).get("zap_active_scan_enabled", False),
                    "allowed_categories": p.get("config", {}).get("allowed_categories", []),
                    "allowed_tools": p.get("config", {}).get("allowed_tools", []),
                    "allowed_http_methods": p.get("config", {}).get("allowed_http_methods", []),
                    "allowed_auth_modes": p.get("config", {}).get("allowed_auth_modes", []),
                },
            }
            for p in policies
        ]
        return jsonify({"success": True, "policies": summary})

    @app.route("/api/admin/policies/metrics", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_policy_metrics():
        """Aggregated policy metrics for administrator overview card."""
        metrics = policy_svc.get_policy_metrics()
        return jsonify({"success": True, "metrics": metrics})

    @app.route("/api/admin/policies", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_list_policies():
        """Retrieve all policies including inactive, with targets and version counts."""
        active_only = request.args.get("active_only", "false").lower() in ("true", "1")
        policies = policy_svc.list_policies(active_only=active_only)
        return jsonify({"success": True, "policies": policies, "count": len(policies)})

    @app.route("/api/admin/policies", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_create_policy():
        """Create a new policy with configuration and optional target authorizations."""
        data = request.get_json(silent=True) or {}
        name = data.get("name")
        description = data.get("description", "")
        config = data.get("config")
        targets = data.get("targets")

        if not name or not isinstance(name, str) or not name.strip():
            return jsonify({"success": False, "error": "Policy 'name' is required and must be a non-empty string"}), 400
        if config is None or not isinstance(config, dict):
            return jsonify({"success": False, "error": "Policy 'config' must be a valid dictionary"}), 400

        try:
            creator_id = request.admin_session.user_id
            created = policy_svc.create_policy(
                name=name,
                config=config,
                creator_id=creator_id,
                description=description,
                targets=targets,
            )
            return jsonify({"success": True, "policy": created}), 201
        except (ValueError, PermissionError) as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            logger.exception("Failed to create policy: %s", exc)
            return jsonify({"success": False, "error": f"Failed to create policy: {str(exc)}"}), 500

    @app.route("/api/admin/policies/<int:policy_id>", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_get_policy(policy_id: int):
        """Retrieve specific policy details, current configuration, and targets."""
        policy = policy_svc.get_policy(policy_id)
        if not policy:
            return jsonify({"success": False, "error": f"Policy with ID {policy_id} not found"}), 404
        return jsonify({"success": True, "policy": policy})

    @app.route("/api/admin/policies/<int:policy_id>", methods=["PUT"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_update_policy(policy_id: int):
        """Update policy configuration, incrementing immutable version."""
        data = request.get_json(silent=True) or {}
        config = data.get("config")
        change_summary = data.get("change_summary", "")
        targets = data.get("targets")
        name = data.get("name")
        description = data.get("description")

        if config is None or not isinstance(config, dict):
            return jsonify({"success": False, "error": "Policy 'config' must be a valid dictionary"}), 400

        try:
            modifier_id = request.admin_session.user_id
            updated = policy_svc.update_policy(
                policy_id=policy_id,
                new_config=config,
                modifier_id=modifier_id,
                change_summary=change_summary,
                new_targets=targets,
                name=name,
                description=description,
            )
            return jsonify({"success": True, "policy": updated})
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except PermissionError as exc:
            return jsonify({"success": False, "error": str(exc)}), 403
        except Exception as exc:
            logger.exception("Failed to update policy: %s", exc)
            return jsonify({"success": False, "error": f"Failed to update policy: {str(exc)}"}), 500

    @app.route("/api/admin/policies/<int:policy_id>/activate", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_activate_policy(policy_id: int):
        """Enable an inactive policy."""
        try:
            ok = policy_svc.activate_policy(policy_id, actor_id=request.admin_session.user_id)
            if not ok:
                return jsonify({"success": False, "error": f"Policy with ID {policy_id} not found"}), 404
            return jsonify({"success": True, "message": f"Policy {policy_id} activated successfully"})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/policies/<int:policy_id>/deactivate", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_deactivate_policy(policy_id: int):
        """Disable an active policy."""
        try:
            ok = policy_svc.deactivate_policy(policy_id, actor_id=request.admin_session.user_id)
            if not ok:
                return jsonify({"success": False, "error": f"Policy with ID {policy_id} not found"}), 404
            return jsonify({"success": True, "message": f"Policy {policy_id} deactivated successfully"})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/policies/<int:policy_id>/versions", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_list_policy_versions(policy_id: int):
        """Retrieve all historical immutable versions of a policy."""
        policy = policy_svc.get_policy(policy_id)
        if not policy:
            return jsonify({"success": False, "error": f"Policy with ID {policy_id} not found"}), 404
        versions = policy_svc.list_policy_versions(policy_id)
        return jsonify({"success": True, "policy_id": policy_id, "versions": versions})

    @app.route("/api/admin/policies/<int:policy_id>/versions/<int:version>", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_get_policy_version(policy_id: int, version: int):
        """Retrieve specific immutable historical version details."""
        ver = policy_svc.get_policy_version(policy_id, version)
        if not ver:
            return jsonify({"success": False, "error": f"Version {version} not found for policy {policy_id}"}), 404
        return jsonify({"success": True, "version": ver})

    @app.route("/api/admin/policies/<int:policy_id>/rollback", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_rollback_policy(policy_id: int):
        """Rollback policy configuration by creating a new version with historical config."""
        data = request.get_json(silent=True) or {}
        target_version = data.get("target_version")
        if target_version is None:
            return jsonify({"success": False, "error": "'target_version' is required"}), 400
        try:
            target_version = int(target_version)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "'target_version' must be an integer"}), 400

        try:
            updated = policy_svc.rollback_policy_version(
                policy_id=policy_id,
                target_version=target_version,
                modifier_id=request.admin_session.user_id,
            )
            return jsonify({"success": True, "policy": updated, "message": f"Successfully rolled back to configuration of version {target_version}"})
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": f"Rollback failed: {str(exc)}"}), 500

    @app.route("/api/admin/policies/<int:policy_id>/targets", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_list_policy_targets(policy_id: int):
        """Retrieve authorized target patterns for a policy."""
        active_only = request.args.get("active_only", "false").lower() in ("true", "1")
        policy = policy_svc.get_policy(policy_id)
        if not policy:
            return jsonify({"success": False, "error": f"Policy with ID {policy_id} not found"}), 404
        targets = policy_svc.list_target_authorizations(policy_id, active_only=active_only)
        return jsonify({"success": True, "policy_id": policy_id, "targets": targets})

    @app.route("/api/admin/policies/<int:policy_id>/targets", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_add_policy_target(policy_id: int):
        """Add an authorized target endpoint pattern to a policy."""
        data = request.get_json(silent=True) or {}
        try:
            target = policy_svc.add_target_authorization(
                policy_id=policy_id,
                target_def=data,
                actor_id=request.admin_session.user_id,
            )
            return jsonify({"success": True, "target": target}), 201
        except ValueError as exc:
            return jsonify({"success": False, "error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"success": False, "error": f"Failed to add target: {str(exc)}"}), 500

    @app.route("/api/admin/policies/<int:policy_id>/targets/<int:target_id>/revoke", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_revoke_policy_target(policy_id: int, target_id: int):
        """Revoke a target authorization."""
        try:
            ok = policy_svc.revoke_target_authorization(
                target_id=target_id,
                actor_id=request.admin_session.user_id,
                policy_id=policy_id,
            )
            if not ok:
                return jsonify({"success": False, "error": f"Target authorization {target_id} not found for policy {policy_id}"}), 404
            return jsonify({"success": True, "message": f"Target authorization {target_id} revoked"})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    # --- Quick Scope & Domain Policy Toggles ---

    @app.route("/api/policies/scope-status", methods=["GET"])
    @app.route("/api/admin/policies/scope-status", methods=["GET"])
    def get_policy_scope_status():
        """Retrieve quick toggle states and authorized targets for the policy dashboard."""
        policy_id = request.args.get("policy_id", type=int)
        status = policy_svc.get_quick_scope_status(policy_id=policy_id)
        return jsonify({"success": True, "scope_status": status})

    @app.route("/api/admin/policies/toggle-external", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_toggle_external_domains():
        """Toggle external domain scanning mode on/off."""
        data = request.get_json(silent=True) or {}
        enabled = bool(data.get("enabled", False))
        policy_id = data.get("policy_id")
        if policy_id is None:
            active_pols = policy_svc.list_policies(active_only=True)
            if not active_pols:
                return jsonify({"success": False, "error": "No active policy found"}), 404
            policy_id = active_pols[0]["id"]
        else:
            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid policy_id"}), 400

        actor_id = getattr(request.admin_session, "user_id", 1)
        try:
            status = policy_svc.toggle_external_domains(policy_id=policy_id, enabled=enabled, actor_id=actor_id)
            return jsonify({
                "success": True,
                "message": f"External domain testing mode {'enabled' if enabled else 'disabled'}",
                "scope_status": status,
            })
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/policies/toggle-full-control", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_toggle_full_control():
        """Toggle full autonomous penetration permissions (all tools, categories, methods, max limits)."""
        data = request.get_json(silent=True) or {}
        enabled = bool(data.get("enabled", False))
        policy_id = data.get("policy_id")
        if policy_id is None:
            active_pols = policy_svc.list_policies(active_only=True)
            if not active_pols:
                return jsonify({"success": False, "error": "No active policy found"}), 404
            policy_id = active_pols[0]["id"]
        else:
            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid policy_id"}), 400

        actor_id = getattr(request.admin_session, "user_id", 1)
        try:
            status = policy_svc.toggle_full_control(policy_id=policy_id, enabled=enabled, actor_id=actor_id)
            return jsonify({
                "success": True,
                "message": f"Full penetration testing permissions {'granted (All Tools & Categories ON)' if enabled else 'reverted to Safe Restricted mode'}",
                "scope_status": status,
            })
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/policies/quick-add-domain", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_quick_add_domain():
        """Quickly authorize a personal or hosted target domain."""
        data = request.get_json(silent=True) or {}
        domain = str(data.get("domain", "")).strip()
        if not domain:
            return jsonify({"success": False, "error": "Target domain or URL is required"}), 400

        policy_id = data.get("policy_id")
        if policy_id is None:
            active_pols = policy_svc.list_policies(active_only=True)
            if not active_pols:
                return jsonify({"success": False, "error": "No active policy found"}), 404
            policy_id = active_pols[0]["id"]
        else:
            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid policy_id"}), 400

        actor_id = getattr(request.admin_session, "user_id", 1)
        try:
            status = policy_svc.quick_authorize_domain(policy_id=policy_id, domain_or_url=domain, actor_id=actor_id)
            return jsonify({
                "success": True,
                "message": f"Domain '{domain}' successfully authorized for penetration testing",
                "scope_status": status,
            })
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/policies/quick-remove-domain", methods=["POST"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    @require_csrf(sess_svc)
    def admin_quick_remove_domain():
        """Quickly revoke authorization for a domain."""
        data = request.get_json(silent=True) or {}
        target_id = data.get("target_id")
        if target_id is None:
            return jsonify({"success": False, "error": "target_id is required"}), 400
        try:
            target_id = int(target_id)
        except (ValueError, TypeError):
            return jsonify({"success": False, "error": "Invalid target_id"}), 400

        policy_id = data.get("policy_id")
        if policy_id is not None:
            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "Invalid policy_id"}), 400

        actor_id = getattr(request.admin_session, "user_id", 1)
        try:
            status = policy_svc.quick_remove_domain(policy_id=policy_id or 1, target_id=target_id, actor_id=actor_id)
            return jsonify({
                "success": True,
                "message": "Target authorization revoked successfully",
                "scope_status": status,
            })
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 400

    @app.route("/api/admin/audit-log", methods=["GET"])
    @require_auth(sess_svc)
    @require_role(sess_svc, "admin")
    def admin_get_audit_log():
        """Retrieve administrative policy audit log entries."""
        limit = request.args.get("limit", default=50, type=int)
        offset = request.args.get("offset", default=0, type=int)
        logs = policy_svc.get_audit_log(limit=limit, offset=offset)
        return jsonify({"success": True, "audit_log": logs, "count": len(logs)})

    # --- System & Health Status (with thread-safe TTL cache) ---
    _status_cache = {"timestamp": 0.0, "data": None}
    _status_lock = threading.Lock()

    @app.route("/api/system/status", methods=["GET"])
    def system_status():
        now = time.time()
        with _status_lock:
            if _status_cache["data"] is not None and (now - _status_cache["timestamp"]) < 5.0:
                return jsonify(_status_cache["data"])

        zap_tool = ZapSecurityScanTool()
        zap_health = zap_tool.execute(action="check_health")
        res_profile = get_runtime_capabilities()

        data = {
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
        }

        with _status_lock:
            _status_cache["timestamp"] = time.time()
            _status_cache["data"] = data

        return jsonify(data)

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

        # Validate URL scheme
        import urllib.parse
        parsed = urllib.parse.urlparse(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return jsonify({
                "success": False,
                "error": "Target URL must be a valid HTTP or HTTPS address (e.g. http://127.0.0.1:5050)",
            }), 400

        assessment_name = data.get("assessment_name", "Live Security Assessment")
        max_turns = int(data.get("max_turns", 10))
        max_requests = int(data.get("max_requests", 25))
        max_model_calls = int(data.get("max_model_calls", 25))
        brain_mode = str(data.get("brain_mode", "mock")).lower()
        remote_endpoint = data.get("remote_endpoint")
        zap_active_scan = bool(data.get("zap_active_scan", False))
        spec_source = data.get("spec_source")
        auth_context = data.get("auth_context")
        allowed_hosts = data.get("allowed_hosts")

        assessment_type = str(data.get("assessment_type", "auto")).lower()
        selected_categories = data.get("selected_categories")
        assessment_depth = str(data.get("assessment_depth", "standard")).lower()
        timeout_seconds = data.get("timeout_seconds")
        if timeout_seconds is not None:
            try:
                timeout_seconds = int(timeout_seconds)
                if timeout_seconds <= 0 or timeout_seconds > 1800:
                    return jsonify({"success": False, "error": "timeout_seconds must be between 1 and 1800"}), 400
            except ValueError:
                return jsonify({"success": False, "error": "timeout_seconds must be an integer"}), 400

        auth_type = str(data.get("auth_type", "none")).lower()
        auth_credentials = data.get("auth_credentials")

        policy_id = data.get("policy_id")
        if policy_id is not None:
            try:
                policy_id = int(policy_id)
            except (ValueError, TypeError):
                return jsonify({"success": False, "error": "policy_id must be an integer"}), 400

        session = get_session_from_request(sess_svc)
        if session and session.role.lower() == "auditor":
            return jsonify({
                "success": False,
                "error": "Insufficient privileges: Auditor role is strictly read-only. Cannot start assessments.",
            }), 403

        operator_id = session.user_id if session else None

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
            auth_context=auth_context,
            assessment_type=assessment_type,
            selected_categories=selected_categories,
            assessment_depth=assessment_depth,
            timeout_seconds=timeout_seconds,
            auth_type=auth_type,
            auth_credentials=auth_credentials,
            policy_id=policy_id,
            operator_id=operator_id,
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

    @app.route("/api/assessments/<session_id>/details", methods=["GET"])
    def session_details(session_id: str):
        details = manager.get_session_details(session_id)
        if "error" in details:
            return jsonify(details), 404
        return jsonify(details)

    @app.route("/api/assessments/compare", methods=["GET"])
    def compare_assessments():
        session_a = request.args.get("session_a", "").strip()
        session_b = request.args.get("session_b", "").strip()
        if not session_a or not session_b:
            return jsonify({"success": False, "error": "Both session_a and session_b parameters are required"}), 400

        comparison = manager.compare_sessions(session_a, session_b)
        if "error" in comparison:
            return jsonify(comparison), 404
        return jsonify(comparison)

    @app.route("/api/assessments/<session_id>/cancel", methods=["POST"])
    def cancel_assessment(session_id: str):
        session = get_session_from_request(sess_svc)
        if session and session.role.lower() == "auditor":
            return jsonify({
                "success": False,
                "error": "Insufficient privileges: Auditor role is strictly read-only. Cannot cancel assessments.",
            }), 403

        actor_id = session.user_id if session else None
        actor_role = session.role if session else None

        res = manager.cancel_assessment(session_id, actor_id=actor_id, actor_role=actor_role)
        if not res.get("success"):
            err = res.get("error", "")
            if "permission" in err.lower() or "cannot cancel" in err.lower():
                status_code = 403
            else:
                status_code = 404
        else:
            status_code = 200
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

    @app.route("/api/assessments/<session_id>/report/json", methods=["GET"])
    def get_report_json(session_id: str):
        report_data = manager.get_report_json(session_id)
        return jsonify(report_data)

    @app.route("/api/assessments/<session_id>/report/html", methods=["GET"])
    def get_report_html(session_id: str):
        report_html = manager.get_report_html(session_id)
        return Response(report_html, mimetype="text/html")

    @app.route("/api/assessments/<session_id>/risk", methods=["GET"])
    def get_risk_summary(session_id: str):
        risk_data = manager.get_risk_summary(session_id)
        return jsonify(risk_data)

    @app.route("/api/assessments/<session_id>/endpoints", methods=["GET"])
    def get_endpoints(session_id: str):
        endpoints = manager.get_discovered_endpoints(session_id)
        return jsonify({
            "session_id": session_id,
            "count": len(endpoints),
            "endpoints": endpoints,
        })

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

