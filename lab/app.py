"""Flask application for the Local API Security Laboratory.

Runs strictly on 127.0.0.1. Provides intentionally vulnerable REST endpoints
demonstrating OWASP API Top 10 weaknesses (BOLA/IDOR, Mass Assignment,
Weak/Unsigned JWT Authentication, and Unsafe Input Query Handling).
All data is fictitious dummy test data.
"""

import base64
import json
import logging
import sqlite3
import time
from typing import Optional

from flask import Flask, jsonify, request

from .database import LabDatabase
from .seed_data import seed_database

logger = logging.getLogger(__name__)


def _create_none_alg_jwt(payload: dict) -> str:
    """Generate an insecure JWT token with header alg='none' for demonstration."""
    header = {"alg": "none", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    # Unsigned token ends with trailing dot
    return f"{h_b64}.{p_b64}."


def create_app(db: Optional[LabDatabase] = None) -> Flask:
    """Application factory for the vulnerable API laboratory."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    # Initialize database
    database = db or LabDatabase(":memory:")
    seed_database(database)
    app.db = database

    # -------------------------------------------------------------
    # 1. Health check endpoint (Baseline)
    # -------------------------------------------------------------
    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "service": "vulnerable-api-lab",
            "version": "1.0.0",
            "binding": "127.0.0.1",
        }), 200

    # -------------------------------------------------------------
    # 2. User listing endpoint (Public Directory)
    # -------------------------------------------------------------
    @app.route("/api/users", methods=["GET"])
    def list_users():
        users = app.db.execute_query(
            "SELECT id, username, full_name, role FROM users ORDER BY id ASC"
        )
        return jsonify({
            "count": len(users),
            "users": users,
        }), 200

    # -------------------------------------------------------------
    # 3. User detail endpoint (VULNERABILITY: BOLA / IDOR)
    # -------------------------------------------------------------
    @app.route("/api/users/<int:user_id>", methods=["GET"])
    def get_user_detail(user_id: int):
        """Intentionally vulnerable to BOLA / IDOR.
        
        Returns sensitive record details (email, password hash, api_token, is_admin)
        for any user ID without verifying requester authorization or ownership.
        """
        rows = app.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        if not rows:
            return jsonify({"error": f"User ID {user_id} not found"}), 404

        user = dict(rows[0])
        # Flaw: Leaks internal sensitive attributes without authorization check
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "full_name": user["full_name"],
            "email": user["email"],
            "role": user["role"],
            "is_admin": bool(user["is_admin"]),
            "api_token": user["api_token"],
            "password_hash": user["password"],  # Sensitive leak
        }), 200

    # -------------------------------------------------------------
    # 4. Authentication simulation (VULNERABILITY: Weak Auth & 'none' JWT)
    # -------------------------------------------------------------
    @app.route("/api/login", methods=["POST"])
    def login():
        """Simulates authentication with two deliberate security weaknesses:
        
        1. Password bypass: Empty password string allows logging in as any user.
        2. Insecure Token: Issues JWT with algorithm set to 'none' and no cryptographic signature.
        """
        data = request.get_json(silent=True) or {}
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username:
            return jsonify({"error": "Username required"}), 400

        rows = app.db.execute_query("SELECT * FROM users WHERE username = ?", (username,))
        if not rows:
            return jsonify({"error": "Invalid credentials"}), 401

        user = dict(rows[0])

        # Weakness 1: Empty password bypass or correct password accepted
        if password != "" and password != user["password"]:
            return jsonify({"error": "Invalid credentials"}), 401

        # Weakness 2: Generate unsigned JWT with alg="none"
        now = int(time.time())
        token_payload = {
            "sub": user["username"],
            "user_id": user["id"],
            "role": user["role"],
            "is_admin": user["is_admin"],
            "iat": now,
            "exp": now + 3600,
        }
        insecure_jwt = _create_none_alg_jwt(token_payload)

        return jsonify({
            "success": True,
            "message": "Authentication successful (demo unsigned JWT issued)",
            "token": insecure_jwt,
            "token_type": "Bearer",
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"],
            },
        }), 200

    # -------------------------------------------------------------
    # 5. User profile update (VULNERABILITY: Mass Assignment)
    # -------------------------------------------------------------
    @app.route("/api/users/<int:user_id>", methods=["PUT"])
    def update_user_profile(user_id: int):
        """Intentionally vulnerable to Mass Assignment.
        
        Directly binds all incoming JSON keys into the database row without
        filtering protected fields (such as 'role' or 'is_admin').
        """
        rows = app.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        if not rows:
            return jsonify({"error": f"User ID {user_id} not found"}), 404

        data = request.get_json(silent=True) or {}
        if not data:
            return jsonify({"error": "No update fields provided"}), 400

        # Vulnerable pattern: dynamically constructs UPDATE query from all user-supplied keys
        allowed_columns = {"username", "full_name", "email", "role", "is_admin"}
        set_clauses = []
        params = []

        for key, val in data.items():
            if key in allowed_columns:
                set_clauses.append(f"{key} = ?")
                params.append(val)

        if not set_clauses:
            return jsonify({"error": "No modifiable fields supplied"}), 400

        params.append(user_id)
        query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
        app.db.execute_commit(query, tuple(params))

        # Return updated record
        updated_rows = app.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        return jsonify({
            "success": True,
            "message": "Profile updated successfully",
            "user": dict(updated_rows[0]),
        }), 200

    # -------------------------------------------------------------
    # 6. Search endpoint (VULNERABILITY: Unsafe Input / SQL Syntax Error)
    # -------------------------------------------------------------
    @app.route("/api/search", methods=["GET"])
    def search_items():
        """Intentionally vulnerable to unsafe query string interpolation.
        
        Injecting special characters (like single quote `'`) triggers an unhandled
        syntax error directly visible in the response body, demonstrating SQL injection risk.
        """
        q = request.args.get("q", "")
        if not q:
            items = app.db.execute_query("SELECT * FROM items")
            return jsonify({"count": len(items), "items": items}), 200

        # Intentionally unsafe string interpolation:
        unsafe_query = f"SELECT id, name, description, price FROM items WHERE name LIKE '%{q}%'"

        try:
            items = app.db.execute_raw_unsafe_query(unsafe_query)
            return jsonify({"query": q, "count": len(items), "items": items}), 200
        except sqlite3.OperationalError as exc:
            # Emits explicit SQL syntax error pattern for evidence recorder
            logger.warning("Unsafe SQL query threw exception: %s", exc)
            return jsonify({
                "error": f"Database SQL syntax error in query: {unsafe_query}",
                "detail": str(exc),
            }), 500

    # -------------------------------------------------------------
    # 7. Catalog list endpoint (Safe Baseline)
    # -------------------------------------------------------------
    @app.route("/api/items", methods=["GET"])
    def list_items():
        items = app.db.execute_query("SELECT * FROM items")
        return jsonify({"count": len(items), "items": items}), 200

    # -------------------------------------------------------------
    # 8. OpenAPI Specification endpoints
    # -------------------------------------------------------------
    @app.route("/openapi.json", methods=["GET"])
    def get_openapi_json():
        return jsonify(get_lab_openapi_spec()), 200

    @app.route("/openapi.yaml", methods=["GET"])
    def get_openapi_yaml():
        import yaml
        spec_yaml = yaml.dump(get_lab_openapi_spec(), sort_keys=False)
        return spec_yaml, 200, {"Content-Type": "application/x-yaml"}

    return app


def get_lab_openapi_spec() -> dict:
    """Generate OpenAPI 3.0 specification for the Local API Security Laboratory."""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "Local Vulnerable API Laboratory",
            "version": "1.0.0",
            "description": "Intentionally vulnerable REST API lab designed for autonomous penetration testing.",
        },
        "servers": [
            {"url": "http://127.0.0.1:5000", "description": "Local test lab"},
        ],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health Check",
                    "operationId": "get_health",
                    "responses": {"200": {"description": "Service is healthy"}},
                }
            },
            "/api/users": {
                "get": {
                    "summary": "List Users",
                    "operationId": "list_users",
                    "responses": {"200": {"description": "Public list of users"}},
                }
            },
            "/api/users/{id}": {
                "get": {
                    "summary": "Get User Details (BOLA / IDOR)",
                    "operationId": "get_user_by_id",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "User identifier",
                        }
                    ],
                    "responses": {
                        "200": {"description": "User record with sensitive attributes"},
                        "404": {"description": "User not found"},
                    },
                },
                "put": {
                    "summary": "Update User Profile (Mass Assignment)",
                    "operationId": "update_user_by_id",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "full_name": {"type": "string"},
                                        "email": {"type": "string"},
                                        "role": {"type": "string"},
                                        "is_admin": {"type": "integer"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Profile updated"}},
                },
            },
            "/api/login": {
                "post": {
                    "summary": "User Login Simulation (Weak Auth / None JWT)",
                    "operationId": "login_user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "username": {"type": "string"},
                                        "password": {"type": "string"},
                                    },
                                    "required": ["username"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "JWT authentication token issued"},
                        "401": {"description": "Authentication failed"},
                    },
                }
            },
            "/api/search": {
                "get": {
                    "summary": "Catalog Search (Unsafe Query / SQL Injection)",
                    "operationId": "search_items",
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "Search keyword",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Matching catalog items"},
                        "500": {"description": "Database query error"},
                    },
                }
            },
            "/api/items": {
                "get": {
                    "summary": "List Catalog Items",
                    "operationId": "list_items",
                    "responses": {"200": {"description": "List of catalog items"}},
                }
            },
        },
    }


def run_lab_server(port: int = 5000, db_path: str = ":memory:") -> None:
    """Start local lab server strictly bound to 127.0.0.1."""
    db = LabDatabase(db_path)
    app = create_app(db)
    print(f"[*] Starting Local API Security Lab on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_lab_server(port=5000)
