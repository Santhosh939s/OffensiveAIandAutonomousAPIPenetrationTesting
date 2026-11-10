"""Authentication and CSRF Middleware for Flask Dashboard Service.

Provides deterministic route-level decorators for:
- Session authentication verification
- Role-based authorization gating
- CSRF synchronizer token verification for state-mutating requests
"""

from functools import wraps
from typing import Callable, Optional

from flask import jsonify, request

from controller.auth.role_service import RoleService
from controller.auth.session_service import SessionService


def get_session_from_request(session_service: SessionService):
    """Extract and validate session token from cookies or Authorization header."""
    raw_token = request.cookies.get("session_token")
    if not raw_token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()

    if not raw_token:
        return None

    return session_service.validate_session(raw_token)


def require_auth(session_service: SessionService):
    """Decorator requiring a valid active server-side session."""
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            session = get_session_from_request(session_service)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Please log in.",
                }), 401
            request.admin_session = session

            # Enforce password change before normal dashboard operations
            if getattr(session, "must_change_password", False) and request.path not in (
                "/api/auth/change-password",
                "/api/auth/logout",
                "/api/auth/status",
                "/api/auth/me",
            ):
                return jsonify({
                    "success": False,
                    "error": "Password change required before normal use. Please update credentials via /api/auth/change-password.",
                    "must_change_password": True,
                }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_role(session_service: SessionService, required_role: str):
    """Decorator requiring a specific role (e.g. 'admin')."""
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            session = get_session_from_request(session_service)
            if not session:
                return jsonify({
                    "success": False,
                    "error": "Authentication required. Please log in.",
                }), 401
            request.admin_session = session

            if session.role.lower() != required_role.lower():
                return jsonify({
                    "success": False,
                    "error": f"Insufficient privileges. Role '{required_role}' required.",
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_csrf(session_service: SessionService):
    """Decorator requiring valid X-CSRF-Token header matching the session."""
    def decorator(fn: Callable):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Only validate on state-changing HTTP methods
            if request.method in ("POST", "PUT", "DELETE", "PATCH"):
                session = getattr(request, "admin_session", None) or get_session_from_request(session_service)
                if not session:
                    return jsonify({
                        "success": False,
                        "error": "Authentication required for CSRF validation.",
                    }), 401
                request.admin_session = session

                header_csrf = request.headers.get("X-CSRF-Token", "")
                if not header_csrf:
                    return jsonify({
                        "success": False,
                        "error": "CSRF verification failed: Missing X-CSRF-Token header.",
                    }), 403

                if not session_service.validate_csrf_token(session.csrf_token, header_csrf):
                    return jsonify({
                        "success": False,
                        "error": "CSRF verification failed: Invalid or mismatched token.",
                    }), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator

