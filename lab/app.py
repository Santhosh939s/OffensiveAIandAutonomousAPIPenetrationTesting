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
    # 7.2. Orders endpoint (VULNERABILITY: BOLA / IDOR across controlled accounts)
    # -------------------------------------------------------------
    @app.route("/api/orders", methods=["GET"])
    def list_orders():
        orders = app.db.execute_query("SELECT id, user_id, item_name, total_amount, order_status FROM orders ORDER BY id ASC")
        return jsonify({"count": len(orders), "orders": orders}), 200

    @app.route("/api/orders/<int:order_id>", methods=["GET"])
    def get_order_detail(order_id: int):
        """Intentionally vulnerable to BOLA / IDOR across controlled test accounts.
        
        Demonstrates OWASP API1:2023:
        Returns private customer order details including shipping address and amount
        regardless of requester identity. User Alice (id 1) can access User Bob's (id 2)
        order 102, or Admin's order 103 without authorization.
        """
        rows = app.db.execute_query("SELECT * FROM orders WHERE id = ?", (order_id,))
        if not rows:
            return jsonify({"error": f"Order ID {order_id} not found"}), 404
        order = dict(rows[0])
        return jsonify({
            "id": order["id"],
            "user_id": order["user_id"],
            "item_name": order["item_name"],
            "total_amount": order["total_amount"],
            "shipping_address": order["shipping_address"],
            "order_status": order["order_status"],
            "bola_exposed": True,
        }), 200

    # -------------------------------------------------------------
    # 7.5. GraphQL endpoint (Demonstrates Introspection Misconfiguration & Querying)
    # -------------------------------------------------------------
    @app.route("/graphql", methods=["GET", "POST"])
    def graphql_endpoint():
        """Simulated local GraphQL endpoint.
        
        Vulnerabilities demonstrated:
        1. Introspection query enabled (__schema accessible).
        2. Missing authentication on user queries.
        """
        if request.method == "POST":
            data = request.get_json(silent=True) or {}
            query = data.get("query", "")
        else:
            query = request.args.get("query", "")

        if not query or not query.strip():
            return jsonify({"errors": [{"message": "Must provide query string."}]}), 400

        q = query.strip()
        if "__schema" in q:
            return jsonify({
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "subscriptionType": None,
                        "types": [
                            {"name": "User", "kind": "OBJECT", "description": "Application User Record"},
                            {"name": "Item", "kind": "OBJECT", "description": "Catalog Item"},
                            {"name": "Query", "kind": "OBJECT", "description": "Root Query"},
                            {"name": "Mutation", "kind": "OBJECT", "description": "Root Mutation"},
                            {"name": "String", "kind": "SCALAR"},
                            {"name": "Int", "kind": "SCALAR"},
                            {"name": "Boolean", "kind": "SCALAR"},
                        ]
                    }
                }
            }), 200

        if "__typename" in q:
            return jsonify({"data": {"__typename": "Query"}}), 200

        if "users" in q:
            users = app.db.execute_query("SELECT id, username, full_name, email, role FROM users")
            return jsonify({"data": {"users": users}}), 200

        if "items" in q:
            items = app.db.execute_query("SELECT id, name, price FROM items")
            return jsonify({"data": {"items": items}}), 200

        return jsonify({"data": {"service": "GraphQL API Lab", "status": "ready"}}), 200

    # -------------------------------------------------------------
    # 7.6. Admin Function Endpoints (VULNERABILITY: API5:2023 - BFLA)
    # -------------------------------------------------------------
    @app.route("/api/admin/users/<int:user_id>/role", methods=["POST", "PUT"])
    def admin_modify_user_role(user_id: int):
        """Intentionally vulnerable to Broken Function Level Authorization (BFLA).
        
        Demonstrates OWASP API5:2023:
        Allows any caller (even unauthenticated or low-privileged users) to invoke
        sensitive administrative function to change user roles or elevate privileges.
        """
        data = request.get_json(silent=True) or {}
        new_role = data.get("role", "admin")

        rows = app.db.execute_query("SELECT * FROM users WHERE id = ?", (user_id,))
        if not rows:
            return jsonify({"error": f"User ID {user_id} not found"}), 404

        is_admin_flag = 1 if new_role.lower() == "admin" else 0
        app.db.execute_commit(
            "UPDATE users SET role = ?, is_admin = ? WHERE id = ?",
            (new_role, is_admin_flag, user_id),
        )

        # Log administrative audit
        app.db.execute_commit(
            "INSERT INTO audit_logs (action, target_user_id, details, timestamp) VALUES (?, ?, ?, ?)",
            ("ROLE_CHANGE", user_id, f"Role updated to {new_role} via unprivileged call", time.time()),
        )

        return jsonify({
            "success": True,
            "bfla_exposed": True,
            "action": "ROLE_MODIFIED",
            "user_id": user_id,
            "new_role": new_role,
            "is_admin": is_admin_flag,
            "message": "Administrative role modified without function-level authorization verification",
        }), 200

    @app.route("/api/admin/export", methods=["GET"])
    def admin_export_data():
        """Administrative export endpoint vulnerable to BFLA."""
        audit_records = app.db.execute_query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20")
        users = app.db.execute_query("SELECT id, username, role, is_admin, api_token FROM users")
        return jsonify({
            "success": True,
            "bfla_exposed": True,
            "export_type": "ADMIN_SYSTEM_DUMP",
            "users_count": len(users),
            "audit_logs_count": len(audit_records),
            "users": users,
            "audit_logs": audit_records,
            "message": "Administrative system export retrieved without authorization check",
        }), 200

    # -------------------------------------------------------------
    # 7.7. Business Flow Endpoints (VULNERABILITY: API6:2023 - Business Flow Abuse)
    # -------------------------------------------------------------
    @app.route("/api/coupons/apply", methods=["POST"])
    def apply_coupon():
        """Intentionally vulnerable to Unrestricted Access to Sensitive Business Flows.
        
        Demonstrates OWASP API6:2023:
        Allows rapid repeated coupon redemptions without rate-limiting, CAPTCHA, or
        per-user quotas, leading to stacked discounts or business logic abuse.
        """
        data = request.get_json(silent=True) or {}
        code = str(data.get("coupon_code", "SAVE50")).strip().upper()
        order_id = data.get("order_id", 101)

        coupon_rows = app.db.execute_query("SELECT * FROM coupons WHERE code = ?", (code,))
        if not coupon_rows:
            return jsonify({"error": f"Invalid coupon code '{code}'"}), 404

        coupon = coupon_rows[0]
        times_applied = coupon["times_applied"] + 1
        app.db.execute_commit("UPDATE coupons SET times_applied = ? WHERE code = ?", (times_applied, code))

        return jsonify({
            "success": True,
            "business_flow_abuse": True,
            "coupon_code": code,
            "discount_percent": coupon["discount_percent"],
            "order_id": order_id,
            "times_applied": times_applied,
            "message": "Coupon applied repeatedly without rate limiting or quota restrictions",
        }), 200

    # -------------------------------------------------------------
    # 7.8. Shadow / Deprecated APIs (VULNERABILITY: API9:2023 - Improper Inventory)
    # -------------------------------------------------------------
    @app.route("/api/v1/users/export", methods=["GET"])
    def legacy_v1_users_export():
        """Intentionally vulnerable to Improper Inventory Management (API9:2023).
        
        An unadvertised, deprecated v1 API endpoint that remains active and reachable,
        omitted from current OpenAPI 3.0 docs, leaking sensitive unredacted user tokens.
        """
        users = app.db.execute_query("SELECT id, username, email, role, api_token, password FROM users")
        return jsonify({
            "version": "v1.0-deprecated",
            "shadow_api": True,
            "status": "legacy_endpoint_active",
            "unredacted_records": users,
            "message": "Deprecated shadow API endpoint is accessible without authentication or inventory control",
        }), 200

    @app.route("/api/v1/debug/dump", methods=["GET"])
    def legacy_v1_debug_dump():
        """Legacy debug dump endpoint demonstrating shadow/deprecated API surface."""
        return jsonify({
            "version": "v1.0-debug",
            "shadow_api": True,
            "environment": "laboratory_internal",
            "debug_mode": True,
            "internal_routes": [
                "/api/v1/users/export",
                "/api/v1/debug/dump",
                "/api/v1/legacy/config",
            ],
            "message": "Shadow debug endpoint exposed in production environment",
        }), 200

    # -------------------------------------------------------------
    # 7.9. Unsafe Downstream API Consumption (VULNERABILITY: API10:2023)
    # -------------------------------------------------------------
    @app.route("/api/integrations/webhook", methods=["POST"])
    def integrations_webhook():
        """Intentionally vulnerable to Unsafe Consumption of APIs (API10:2023).
        
        Accepts untrusted external partner callback/webhook data without HMAC signature
        validation, schema validation, or allowlist filtering.
        """
        data = request.get_json(silent=True) or {}
        partner_name = data.get("partner_name", "external_partner")
        callback_url = data.get("callback_url", "http://127.0.0.1:5000/api/items")
        event = data.get("event", "payment_received")
        payload = data.get("payload", {})

        # Intentionally processes untrusted external third-party payload without signature check
        return jsonify({
            "success": True,
            "unsafe_consumption": True,
            "partner_name": partner_name,
            "event_processed": event,
            "callback_url": callback_url,
            "signature_verified": False,
            "downstream_status": "trusted_without_verification",
            "payload_echo": payload,
            "message": "Unsafe consumption of third-party API: processed external payload without cryptographic signature verification or schema enforcement",
        }), 200

    # -------------------------------------------------------------
    # 7.10. Unrestricted Resource Consumption (VULNERABILITY: API4:2023)
    # -------------------------------------------------------------
    @app.route("/api/items/batch", methods=["GET", "POST"])
    def items_batch_unrestricted():
        """Intentionally vulnerable to Unrestricted Resource Consumption (API4:2023).
        
        Accepts unbounded limit and batch_size parameters with no pagination ceiling,
        enabling resource exhaustion or server memory amplification.
        """
        limit_param = request.args.get("limit") or (request.get_json(silent=True) or {}).get("limit", 10000)
        try:
            limit = int(limit_param)
        except (ValueError, TypeError):
            limit = 10000

        return jsonify({
            "success": True,
            "unrestricted_resource_consumption": True,
            "requested_limit": limit,
            "max_ceiling_enforced": False,
            "rate_limited": False,
            "message": "Resource consumption limit bypassed: unbounded limit accepted without pagination ceiling or rate-limiting",
        }), 200

    # -------------------------------------------------------------
    # 7.11. Server-Side Request Forgery (VULNERABILITY: API7:2023 - SSRF)
    # -------------------------------------------------------------
    @app.route("/api/integrations/fetch", methods=["POST"])
    def integrations_fetch_url():
        """Intentionally vulnerable to Server-Side Request Forgery (API7:2023 SSRF).
        
        Accepts arbitrary URLs including internal loopback and metadata addresses
        without destination validation or IP allowlisting.
        """
        data = request.get_json(silent=True) or {}
        target_url = data.get("url", "http://127.0.0.1:5000/api/admin/export")

        return jsonify({
            "success": True,
            "ssrf_exposed": True,
            "target_url": target_url,
            "outbound_destination_allowlist_enforced": False,
            "loopback_access_permitted": True,
            "message": "Server-side request dispatched without destination allowlist: internal resources exposed to SSRF",
        }), 200

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
            "/api/orders": {
                "get": {
                    "summary": "List Orders",
                    "operationId": "list_orders",
                    "responses": {"200": {"description": "List of orders"}},
                }
            },
            "/api/orders/{id}": {
                "get": {
                    "summary": "Get Order Details (BOLA / IDOR)",
                    "operationId": "get_order_by_id",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "Order identifier",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Order details with customer shipping info"},
                        "404": {"description": "Order not found"},
                    },
                }
            },
            "/graphql": {
                "post": {
                    "summary": "GraphQL Query and Introspection Endpoint",
                    "operationId": "graphql_query",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "query": {"type": "string"},
                                        "variables": {"type": "object"},
                                    },
                                    "required": ["query"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "GraphQL query execution result"},
                        "400": {"description": "GraphQL query syntax error"},
                    },
                }
            },
            "/api/admin/users/{id}/role": {
                "post": {
                    "summary": "Modify User Role (BFLA Administrative Function)",
                    "operationId": "admin_modify_user_role",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "User identifier to modify",
                        }
                    ],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"role": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Role modified"},
                    },
                }
            },
            "/api/admin/export": {
                "get": {
                    "summary": "Export Administrative Audit Records (BFLA)",
                    "operationId": "admin_export_data",
                    "responses": {
                        "200": {"description": "Administrative records dump"},
                    },
                }
            },
            "/api/coupons/apply": {
                "post": {
                    "summary": "Apply Promo Coupon (Sensitive Business Flow)",
                    "operationId": "apply_coupon",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "coupon_code": {"type": "string"},
                                        "order_id": {"type": "integer"},
                                    },
                                    "required": ["coupon_code"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Coupon applied"},
                    },
                }
            },
            "/api/integrations/webhook": {
                "post": {
                    "summary": "Partner Webhook Ingestion (Unsafe API Consumption)",
                    "operationId": "integrations_webhook",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "partner_name": {"type": "string"},
                                        "callback_url": {"type": "string"},
                                        "event": {"type": "string"},
                                        "payload": {"type": "object"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Webhook received and processed"},
                    },
                }
            },
            "/api/items/batch": {
                "get": {
                    "summary": "Batch Items Retrieval (Unrestricted Resource Consumption)",
                    "operationId": "get_items_batch",
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer"},
                            "description": "Unbounded limit parameter without ceiling",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Batch item records retrieved"},
                    },
                }
            },
            "/api/integrations/fetch": {
                "post": {
                    "summary": "External Resource Fetch (Server-Side Request Forgery)",
                    "operationId": "integrations_fetch",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "url": {"type": "string"},
                                    },
                                    "required": ["url"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "External resource fetched"},
                    },
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
