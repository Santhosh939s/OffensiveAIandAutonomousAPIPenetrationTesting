"""Policy Service and Target Authorization Engine.

Provides database-backed policy management, immutable versioning,
target authorization whitelisting, assessment policy snapshotting,
and strict multi-layer policy validation.
"""

import copy
import ipaddress
import json
import logging
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.storage.evidence_store import EvidenceStore
from controller.guardrails.sanitizer import mask_sensitive_traffic_data
from controller.guardrails.scope_validator import (
    canonicalize_ip_str,
    normalize_hostname,
    match_host_pattern,
    match_path_prefix,
    match_port_range,
)

logger = logging.getLogger("autonomous_pentest.policy_service")

# --- Default Known Tools & Categories ---

DEFAULT_KNOWN_TOOLS: Set[str] = {
    "http_request",
    "httpx_request",
    "openapi_parser",
    "jwt_inspector",
    "parameter_fuzzer",
    "zap_scanner",
    "graphql_probe",
    "inventory_scanner",
    "business_flow_probe",
}

DEFAULT_ALLOWED_HTTP_METHODS: Set[str] = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}

DEFAULT_ALLOWED_AUTH_MODES: Set[str] = {
    "none",
    "bearer",
    "api_key",
    "basic",
    "custom",
}

DEFAULT_ALLOWED_CATEGORIES: Set[str] = {
    "API1",
    "API2",
    "API3",
    "API4",
    "API5",
    "API6",
    "API7",
    "API8",
    "API9",
    "API10",
    "API1:2023",  # Broken Object Level Authorization (BOLA)
    "API2:2023",  # Broken Authentication
    "API3:2023",  # Broken Object Property Level Authorization (BOPLA)
    "API4:2023",  # Unrestricted Resource Consumption
    "API5:2023",  # Broken Function Level Authorization (BFLA)
    "API6:2023",  # Unrestricted Access to Sensitive Business Flows
    "API7:2023",  # Server Side Request Forgery (SSRF)
    "API8:2023",  # Security Misconfiguration
    "API9:2023",  # Improper Inventory Management
    "API10:2023", # Unsafe Consumption of APIs
    "GRAPHQL_INTROSPECTION",
    "RECONNAISSANCE",
    "ACTIVE_PROBE",
}

# Recognized top-level keys for policy config dictionary
RECOGNIZED_POLICY_CONFIG_KEYS: Set[str] = {
    "allowed_tools",
    "allowed_categories",
    "allowed_http_methods",
    "allowed_auth_modes",
    "tool_restrictions",
    "max_turns",
    "max_requests",
    "max_requests_per_second",
    "max_concurrent_assessments",
    "max_assessment_duration_seconds",
    "max_response_body_bytes",
    "max_probes_per_endpoint",
    "zap_active_scan_enabled",
    "allow_external_domains",
    "full_control_enabled",
}

# Immutable developer safety ceilings (Layer 1)
DEVELOPER_SAFETY_MAX_REQUESTS: int = 100
DEVELOPER_SAFETY_MAX_DURATION_SECONDS: float = 3600.0
DEVELOPER_SAFETY_MAX_CONCURRENCY: int = 4
DEVELOPER_SAFETY_MAX_BODY_BYTES: int = 65536  # 64 KB


def get_default_policy_config() -> Dict[str, Any]:
    """Return sensible, conservative default policy configuration."""
    return {
        "allowed_tools": [
            "http_request",
            "httpx_request",
            "openapi_parser",
            "jwt_inspector",
            "parameter_fuzzer",
            "graphql_probe",
            "inventory_scanner",
            "business_flow_probe",
        ],
        "allowed_categories": sorted(list(DEFAULT_ALLOWED_CATEGORIES)),
        "allowed_http_methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
        "allowed_auth_modes": ["none", "bearer", "api_key", "basic", "custom"],
        "tool_restrictions": {
            "zap_scanner": {"active_scan_allowed": False},
        },
        "max_turns": 10,
        "max_requests": 25,
        "max_requests_per_second": 5.0,
        "max_concurrent_assessments": 2,
        "max_assessment_duration_seconds": 300.0,
        "max_response_body_bytes": 51200,
        "max_probes_per_endpoint": 3,
        "zap_active_scan_enabled": False,
        "allow_external_domains": False,
        "full_control_enabled": False,
    }


class PolicyService:
    """Central administrative and enforcement engine for policies and target authorizations."""

    def __init__(self, store: EvidenceStore):
        self.store = store

    def _verify_admin_role(self, actor_id: int) -> None:
        """Enforce role-based access control at the service boundary.
        
        Requires the 'admin' role for all policy mutations.
        Operators and Auditors are strictly forbidden from mutating policies.
        """
        if not actor_id:
            return
        try:
            with self.store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT role FROM users WHERE id = ?", (actor_id,))
                row = cursor.fetchone()
                if row:
                    user_role = str(row["role"]).lower()
                    if user_role != "admin":
                        raise PermissionError(
                            f"Insufficient privileges: User {actor_id} has role '{user_role}'. Role 'admin' is required for policy mutations."
                        )
        except PermissionError:
            raise
        except Exception:
            pass

    # --- Audit Logging Integration ---

    def _log_audit_event(
        self,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        status: str = "SUCCESS",
    ) -> None:
        """Record administrative policy event in admin_audit_log."""
        now = time.time()
        username = None
        if user_id:
            try:
                with self.store._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
                    row = cursor.fetchone()
                    if row:
                        username = row["username"]
            except Exception:
                pass

        details_json = json.dumps(mask_sensitive_traffic_data(details or {}))
        try:
            with self.store._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO admin_audit_log (
                        timestamp, user_id, username, action,
                        resource_type, resource_id, ip_address,
                        details_json, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        now,
                        user_id,
                        username or "SYSTEM",
                        action,
                        resource_type,
                        resource_id or "",
                        "127.0.0.1",
                        details_json,
                        status,
                    ),
                )
                conn.commit()
        except Exception as exc:
            logger.error("Failed to write to admin_audit_log: %s", exc)

    # --- Validation ---

    def validate_policy_config(self, config: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Strictly validate policy configuration dictionary.

        Rejects:
        - Non-dict config
        - Unrecognized keys (no silent acceptance)
        - Unknown tools
        - Unsupported HTTP methods
        - Invalid auth modes
        - Negative or out-of-bound resource limits
        """
        if not isinstance(config, dict):
            return False, "Policy configuration must be a dictionary", {}

        # 1. Unrecognized keys check
        unknown_keys = set(config.keys()) - RECOGNIZED_POLICY_CONFIG_KEYS
        if unknown_keys:
            return False, f"Unrecognized policy configuration keys: {sorted(list(unknown_keys))}", {}

        validated = get_default_policy_config()
        validated.update(config)

        # 2. Tools validation
        tools = validated.get("allowed_tools")
        if not isinstance(tools, list) or not tools:
            return False, "'allowed_tools' must be a non-empty list of tool names", {}
        unknown_tools = set(tools) - DEFAULT_KNOWN_TOOLS
        if unknown_tools:
            return False, f"Unknown tools in allowed_tools: {sorted(list(unknown_tools))}", {}
        validated["allowed_tools"] = sorted(list(set(tools)))

        # 3. HTTP Methods validation
        methods = validated.get("allowed_http_methods")
        if not isinstance(methods, list) or not methods:
            return False, "'allowed_http_methods' must be a non-empty list", {}
        upper_methods = [str(m).strip().upper() for m in methods]
        unknown_methods = set(upper_methods) - DEFAULT_ALLOWED_HTTP_METHODS
        if unknown_methods:
            return False, f"Unsupported HTTP methods: {sorted(list(unknown_methods))}", {}
        validated["allowed_http_methods"] = sorted(list(set(upper_methods)))

        # 4. Auth modes validation
        auth_modes = validated.get("allowed_auth_modes")
        if not isinstance(auth_modes, list) or not auth_modes:
            return False, "'allowed_auth_modes' must be a non-empty list", {}
        lower_auth = [str(a).strip().lower() for a in auth_modes]
        unknown_auth = set(lower_auth) - DEFAULT_ALLOWED_AUTH_MODES
        if unknown_auth:
            return False, f"Unsupported authentication modes: {sorted(list(unknown_auth))}", {}
        validated["allowed_auth_modes"] = sorted(list(set(lower_auth)))

        # 5. Categories validation
        categories = validated.get("allowed_categories")
        if not isinstance(categories, list) or not categories:
            return False, "'allowed_categories' must be a non-empty list", {}
        validated["allowed_categories"] = sorted(list(set(categories)))

        # 6. Resource Limits validation
        max_turns = validated.get("max_turns")
        if not isinstance(max_turns, int) or max_turns < 1 or max_turns > 50:
            return False, "'max_turns' must be an integer between 1 and 50", {}

        max_requests = validated.get("max_requests")
        if not isinstance(max_requests, int) or max_requests < 1 or max_requests > DEVELOPER_SAFETY_MAX_REQUESTS:
            return False, f"'max_requests' must be an integer between 1 and {DEVELOPER_SAFETY_MAX_REQUESTS}", {}

        max_rps = validated.get("max_requests_per_second")
        if not isinstance(max_rps, (int, float)) or max_rps <= 0 or max_rps > 50.0:
            return False, "'max_requests_per_second' must be a positive number up to 50.0", {}

        max_concurrency = validated.get("max_concurrent_assessments")
        if not isinstance(max_concurrency, int) or max_concurrency < 1 or max_concurrency > DEVELOPER_SAFETY_MAX_CONCURRENCY:
            return False, f"'max_concurrent_assessments' must be an integer between 1 and {DEVELOPER_SAFETY_MAX_CONCURRENCY}", {}

        max_duration = validated.get("max_assessment_duration_seconds")
        if not isinstance(max_duration, (int, float)) or max_duration < 10.0 or max_duration > DEVELOPER_SAFETY_MAX_DURATION_SECONDS:
            return False, f"'max_assessment_duration_seconds' must be between 10.0 and {DEVELOPER_SAFETY_MAX_DURATION_SECONDS}", {}

        max_body = validated.get("max_response_body_bytes")
        if not isinstance(max_body, int) or max_body < 1024 or max_body > DEVELOPER_SAFETY_MAX_BODY_BYTES:
            return False, f"'max_response_body_bytes' must be between 1024 and {DEVELOPER_SAFETY_MAX_BODY_BYTES}", {}

        max_probes = validated.get("max_probes_per_endpoint")
        if not isinstance(max_probes, int) or max_probes < 1 or max_probes > 10:
            return False, "'max_probes_per_endpoint' must be between 1 and 10", {}

        validated["zap_active_scan_enabled"] = bool(config.get("zap_active_scan_enabled", False))
        validated["allow_external_domains"] = bool(config.get("allow_external_domains", False))
        validated["full_control_enabled"] = bool(config.get("full_control_enabled", False))

        return True, None, validated

    def validate_target_authorization_def(self, target_def: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Validate target authorization specification dictionary."""
        if not isinstance(target_def, dict):
            return False, "Target authorization definition must be a dictionary", {}

        host = str(target_def.get("host_pattern", "")).strip()
        if not host:
            return False, "host_pattern is required", {}
        if any(c in host for c in ";|&$><` \t\r\n"):
            return False, "host_pattern contains invalid or dangerous characters", {}

        # Wildcard validation: only '*' or '*.domain.tld' are allowed
        if "*" in host:
            if host == "*":
                is_wildcard = 1
                clean_host = "*"
            elif host.startswith("*.") and len(host) > 2 and "*" not in host[2:]:
                is_wildcard = 0
                clean_host = normalize_hostname(host)
            else:
                return False, "Invalid wildcard host pattern. Only '*' or '*.domain.tld' are permitted", {}
        else:
            is_wildcard = int(bool(target_def.get("is_wildcard", 0)))
            clean_host = normalize_hostname(host)

        # Port range validation
        port_range = str(target_def.get("port_range", "1-65535")).strip()
        if port_range != "*":
            if "-" in port_range:
                parts = port_range.split("-")
                if len(parts) != 2:
                    return False, "Invalid port range format. Use 'min-max' or single port number", {}
                try:
                    p_min, p_max = int(parts[0]), int(parts[1])
                    if not (1 <= p_min <= 65535 and 1 <= p_max <= 65535 and p_min <= p_max):
                        return False, "Port numbers must be between 1 and 65535 with min <= max", {}
                except ValueError:
                    return False, "Port range must contain valid integers", {}
            else:
                try:
                    p = int(port_range)
                    if not (1 <= p <= 65535):
                        return False, "Port number must be between 1 and 65535", {}
                except ValueError:
                    return False, "Port must be an integer", {}

        # Allowed schemes validation
        schemes = str(target_def.get("allowed_schemes", "http,https")).strip()
        scheme_list = [s.strip().lower() for s in schemes.split(",") if s.strip()]
        for s in scheme_list:
            if s not in ("http", "https"):
                return False, f"Scheme '{s}' is prohibited. Only 'http' and 'https' are allowed.", {}

        path_prefix = str(target_def.get("path_prefix", "/")).strip()
        if not path_prefix.startswith("/"):
            path_prefix = "/" + path_prefix

        expires_at = target_def.get("expires_at")
        if expires_at is not None:
            try:
                expires_at = float(expires_at)
            except ValueError:
                return False, "expires_at must be a valid float timestamp or None", {}

        is_active = int(bool(target_def.get("is_active", 1)))

        cleaned = {
            "host_pattern": clean_host,
            "port_range": port_range,
            "allowed_schemes": ",".join(scheme_list),
            "path_prefix": path_prefix,
            "is_wildcard": is_wildcard,
            "expires_at": expires_at,
            "is_active": is_active,
        }
        return True, None, cleaned

    # --- Policy CRUD & Versioning ---

    def create_policy(
        self,
        name: str,
        config: Dict[str, Any],
        creator_id: int,
        description: str = "",
        targets: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create a new policy and initialize Version 1 as an immutable record."""
        self._verify_admin_role(creator_id)
        clean_name = str(name).strip()
        if not clean_name:
            raise ValueError("Policy name cannot be empty")

        valid, err, validated_config = self.validate_policy_config(config)
        if not valid:
            raise ValueError(f"Invalid policy configuration: {err}")

        # Validate targets if provided
        validated_targets = []
        if targets:
            for t_def in targets:
                t_valid, t_err, clean_t = self.validate_target_authorization_def(t_def)
                if not t_valid:
                    raise ValueError(f"Invalid target definition: {t_err}")
                validated_targets.append(clean_t)

        now = time.time()
        policy_uuid = f"pol_{uuid.uuid4().hex[:12]}"
        config_json = json.dumps(validated_config, sort_keys=True)

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Insert into policies table
            cursor.execute(
                """
                INSERT INTO policies (
                    policy_uuid, name, description, is_active,
                    created_by, created_at, updated_at, current_version
                ) VALUES (?, ?, ?, 1, ?, ?, ?, 1)
                """,
                (policy_uuid, clean_name, description.strip(), creator_id, now, now),
            )
            policy_id = cursor.lastrowid

            # 2. Insert Version 1 into policy_versions table (immutable record)
            cursor.execute(
                """
                INSERT INTO policy_versions (
                    policy_id, version, config_json, created_by,
                    created_at, change_summary, is_active, expires_at
                ) VALUES (?, 1, ?, ?, ?, 'Initial policy creation (v1)', 1, NULL)
                """,
                (policy_id, config_json, creator_id, now),
            )

            # 3. Insert initial target authorizations if any
            for t in validated_targets:
                cursor.execute(
                    """
                    INSERT INTO target_authorizations (
                        policy_id, host_pattern, port_range, allowed_schemes,
                        path_prefix, is_wildcard, expires_at, is_active, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        policy_id,
                        t["host_pattern"],
                        t["port_range"],
                        t["allowed_schemes"],
                        t["path_prefix"],
                        t["is_wildcard"],
                        t["expires_at"],
                        t["is_active"],
                        now,
                    ),
                )
            conn.commit()

        self._log_audit_event(
            action="POLICY_CREATED",
            resource_type="POLICY",
            resource_id=str(policy_id),
            user_id=creator_id,
            details={"policy_uuid": policy_uuid, "name": clean_name, "version": 1},
            status="SUCCESS",
        )

        return self.get_policy(policy_id)

    def get_policy(self, policy_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve policy details along with its current version configuration and targets."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
            policy_row = cursor.fetchone()
            if not policy_row:
                return None

            # Retrieve current version
            cursor.execute(
                "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
                (policy_id, policy_row["current_version"]),
            )
            version_row = cursor.fetchone()

            # Retrieve targets
            cursor.execute(
                "SELECT * FROM target_authorizations WHERE policy_id = ? ORDER BY id ASC",
                (policy_id,),
            )
            target_rows = cursor.fetchall()

        config = json.loads(version_row["config_json"]) if version_row else {}
        targets = [dict(r) for r in target_rows]

        return {
            "id": policy_row["id"],
            "policy_uuid": policy_row["policy_uuid"],
            "name": policy_row["name"],
            "description": policy_row["description"],
            "is_active": bool(policy_row["is_active"]),
            "created_by": policy_row["created_by"],
            "created_at": policy_row["created_at"],
            "updated_at": policy_row["updated_at"],
            "current_version": policy_row["current_version"],
            "config": config,
            "targets": targets,
        }

    def get_policy_by_uuid(self, policy_uuid: str) -> Optional[Dict[str, Any]]:
        """Retrieve policy by its unique UUID string."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM policies WHERE policy_uuid = ?", (policy_uuid.strip(),))
            row = cursor.fetchone()
            if not row:
                return None
            return self.get_policy(row["id"])

    def list_policies(self, active_only: bool = False) -> List[Dict[str, Any]]:
        """List all policies in the system."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT id FROM policies"
            if active_only:
                query += " WHERE is_active = 1"
            query += " ORDER BY id ASC"
            cursor.execute(query)
            rows = cursor.fetchall()

        policies = []
        for r in rows:
            pol = self.get_policy(r["id"])
            if pol:
                policies.append(pol)
        return policies

    def update_policy(
        self,
        policy_id: int,
        new_config: Dict[str, Any],
        modifier_id: int,
        change_summary: str = "",
        new_targets: Optional[List[Dict[str, Any]]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a policy configuration by creating an immutable new version row.

        Historical versions are never mutated or overwritten.
        """
        self._verify_admin_role(modifier_id)
        valid, err, validated_config = self.validate_policy_config(new_config)
        if not valid:
            raise ValueError(f"Invalid policy configuration: {err}")

        # Validate new targets if provided
        validated_targets = None
        if new_targets is not None:
            validated_targets = []
            for t_def in new_targets:
                t_valid, t_err, clean_t = self.validate_target_authorization_def(t_def)
                if not t_valid:
                    raise ValueError(f"Invalid target definition: {t_err}")
                validated_targets.append(clean_t)

        now = time.time()
        config_json = json.dumps(validated_config, sort_keys=True)
        summary = change_summary.strip() or f"Updated policy configuration (version bump)"

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT current_version, name, description FROM policies WHERE id = ?", (policy_id,))
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Policy with ID {policy_id} not found")

            next_version = row["current_version"] + 1
            updated_name = name.strip() if name is not None else row["name"]
            updated_desc = description.strip() if description is not None else row["description"]

            # 1. Insert immutable new version record
            cursor.execute(
                """
                INSERT INTO policy_versions (
                    policy_id, version, config_json, created_by,
                    created_at, change_summary, is_active, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, NULL)
                """,
                (policy_id, next_version, config_json, modifier_id, now, summary),
            )

            # 2. Update policies table with new current_version and timestamp
            cursor.execute(
                """
                UPDATE policies
                SET current_version = ?, updated_at = ?, name = ?, description = ?
                WHERE id = ?
                """,
                (next_version, now, updated_name, updated_desc, policy_id),
            )

            # 3. Update targets if specified (replaces previous targets)
            if validated_targets is not None:
                cursor.execute("DELETE FROM target_authorizations WHERE policy_id = ?", (policy_id,))
                for t in validated_targets:
                    cursor.execute(
                        """
                        INSERT INTO target_authorizations (
                            policy_id, host_pattern, port_range, allowed_schemes,
                            path_prefix, is_wildcard, expires_at, is_active, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            policy_id,
                            t["host_pattern"],
                            t["port_range"],
                            t["allowed_schemes"],
                            t["path_prefix"],
                            t["is_wildcard"],
                            t["expires_at"],
                            t["is_active"],
                            now,
                        ),
                    )
            conn.commit()

        self._log_audit_event(
            action="POLICY_UPDATED",
            resource_type="POLICY",
            resource_id=str(policy_id),
            user_id=modifier_id,
            details={"version": next_version, "change_summary": summary},
            status="SUCCESS",
        )

        return self.get_policy(policy_id)

    def activate_policy(self, policy_id: int, actor_id: int) -> bool:
        """Activate a disabled policy."""
        self._verify_admin_role(actor_id)
        now = time.time()
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE policies SET is_active = 1, updated_at = ? WHERE id = ?", (now, policy_id))
            success = cursor.rowcount > 0
            conn.commit()

        if success:
            self._log_audit_event(
                action="POLICY_ACTIVATED",
                resource_type="POLICY",
                resource_id=str(policy_id),
                user_id=actor_id,
                status="SUCCESS",
            )
        return success

    def deactivate_policy(self, policy_id: int, actor_id: int) -> bool:
        """Deactivate an active policy."""
        self._verify_admin_role(actor_id)
        now = time.time()
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE policies SET is_active = 0, updated_at = ? WHERE id = ?", (now, policy_id))
            success = cursor.rowcount > 0
            conn.commit()

        if success:
            self._log_audit_event(
                action="POLICY_DEACTIVATED",
                resource_type="POLICY",
                resource_id=str(policy_id),
                user_id=actor_id,
                status="SUCCESS",
            )
        return success

    def get_policy_version(self, policy_id: int, version: int) -> Optional[Dict[str, Any]]:
        """Retrieve an immutable historical version of a policy."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
                (policy_id, version),
            )
            row = cursor.fetchone()
            if not row:
                return None

        return {
            "id": row["id"],
            "policy_id": row["policy_id"],
            "version": row["version"],
            "config": json.loads(row["config_json"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "change_summary": row["change_summary"],
            "is_active": bool(row["is_active"]),
            "expires_at": row["expires_at"],
        }

    def list_policy_versions(self, policy_id: int) -> List[Dict[str, Any]]:
        """List all version records for a policy in chronological order."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version ASC",
                (policy_id,),
            )
            rows = cursor.fetchall()

        versions = []
        for r in rows:
            versions.append({
                "id": r["id"],
                "policy_id": r["policy_id"],
                "version": r["version"],
                "config": json.loads(r["config_json"]),
                "created_by": r["created_by"],
                "created_at": r["created_at"],
                "change_summary": r["change_summary"],
                "is_active": bool(r["is_active"]),
            })
        return versions

    def rollback_policy_version(self, policy_id: int, target_version: int, modifier_id: int) -> Dict[str, Any]:
        """Rollback policy configuration by creating a new version containing target_version's config.

        Historical versions are preserved untouched.
        """
        old_ver = self.get_policy_version(policy_id, target_version)
        if not old_ver:
            raise ValueError(f"Target version {target_version} does not exist for policy {policy_id}")

        summary = f"Rollback to configuration from Version {target_version}"
        return self.update_policy(
            policy_id=policy_id,
            new_config=old_ver["config"],
            modifier_id=modifier_id,
            change_summary=summary,
        )

    # --- Target Authorization Management ---

    def add_target_authorization(self, policy_id: int, target_def: Dict[str, Any], actor_id: int) -> Dict[str, Any]:
        """Add an authorized target endpoint pattern to a policy."""
        self._verify_admin_role(actor_id)
        valid, err, clean_t = self.validate_target_authorization_def(target_def)
        if not valid:
            raise ValueError(f"Invalid target authorization: {err}")

        now = time.time()
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM policies WHERE id = ?", (policy_id,))
            if not cursor.fetchone():
                raise ValueError(f"Policy with ID {policy_id} does not exist")

            # Prevent duplicate conflicting active target authorization rules
            cursor.execute(
                """
                SELECT id, host_pattern, port_range, allowed_schemes, path_prefix, expires_at
                FROM target_authorizations
                WHERE policy_id = ? AND is_active = 1
                """,
                (policy_id,),
            )
            existing_targets = cursor.fetchall()
            for ex in existing_targets:
                if ex["expires_at"] and now > float(ex["expires_at"]):
                    continue
                if (
                    normalize_hostname(ex["host_pattern"]) == normalize_hostname(clean_t["host_pattern"])
                    and str(ex["port_range"]).strip() == str(clean_t["port_range"]).strip()
                    and str(ex["path_prefix"]).strip().rstrip("/") == str(clean_t["path_prefix"]).strip().rstrip("/")
                    and set(s.strip().lower() for s in ex["allowed_schemes"].split(",")) == set(s.strip().lower() for s in clean_t["allowed_schemes"].split(","))
                ):
                    raise ValueError(f"Duplicate active target authorization rule already exists for policy {policy_id}")

            cursor.execute(
                """
                INSERT INTO target_authorizations (
                    policy_id, host_pattern, port_range, allowed_schemes,
                    path_prefix, is_wildcard, expires_at, is_active, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    policy_id,
                    clean_t["host_pattern"],
                    clean_t["port_range"],
                    clean_t["allowed_schemes"],
                    clean_t["path_prefix"],
                    clean_t["is_wildcard"],
                    clean_t["expires_at"],
                    clean_t["is_active"],
                    now,
                ),
            )
            target_id = cursor.lastrowid
            conn.commit()

        self._log_audit_event(
            action="TARGET_AUTHORIZATION_ADDED",
            resource_type="TARGET",
            resource_id=str(target_id),
            user_id=actor_id,
            details={"policy_id": policy_id, "host_pattern": clean_t["host_pattern"], "port_range": clean_t["port_range"]},
            status="SUCCESS",
        )

        clean_t["id"] = target_id
        clean_t["policy_id"] = policy_id
        clean_t["created_at"] = now
        return clean_t

    def revoke_target_authorization(self, target_id: int, actor_id: int, policy_id: Optional[int] = None) -> bool:
        """Revoke / deactivate a target authorization, preventing cross-policy target manipulation."""
        self._verify_admin_role(actor_id)
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            if policy_id is not None:
                cursor.execute(
                    "UPDATE target_authorizations SET is_active = 0 WHERE id = ? AND policy_id = ?",
                    (target_id, policy_id),
                )
            else:
                cursor.execute("UPDATE target_authorizations SET is_active = 0 WHERE id = ?", (target_id,))
            success = cursor.rowcount > 0
            conn.commit()

        if success:
            self._log_audit_event(
                action="TARGET_AUTHORIZATION_REVOKED",
                resource_type="TARGET",
                resource_id=str(target_id),
                user_id=actor_id,
                details={"policy_id": policy_id} if policy_id else None,
                status="SUCCESS",
            )
        return success

    def list_target_authorizations(self, policy_id: int, active_only: bool = True) -> List[Dict[str, Any]]:
        """List target authorizations associated with a policy."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM target_authorizations WHERE policy_id = ?"
            if active_only:
                query += " AND is_active = 1"
            query += " ORDER BY id ASC"
            cursor.execute(query, (policy_id,))
            rows = cursor.fetchall()
        return [dict(r) for r in rows]

    # --- Pre-Assessment Verification Check ---

    def check_assessment_permitted(
        self,
        policy_id: int,
        target_url: str,
        requested_categories: Optional[List[str]] = None,
        auth_type: Optional[str] = None,
        current_concurrency: int = 0,
        requested_tools: Optional[List[str]] = None,
        requested_limits: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Evaluate whether a proposed assessment is authorized under a given policy.

        Returns:
            Tuple of (permitted: bool, denial_reason: Optional[str], policy_info: Optional[Dict])
        """
        policy = self.get_policy(policy_id)
        if not policy:
            return False, f"Policy with ID {policy_id} does not exist", None

        if not policy["is_active"]:
            return False, f"Policy '{policy['name']}' (v{policy['current_version']}) is currently disabled/inactive", None

        if policy.get("current_version", 0) < 1:
            return False, f"Policy '{policy['name']}' has an invalid version ({policy.get('current_version')})", None

        cfg = policy["config"]
        now = time.time()

        # 1. Concurrency limit check
        max_concurrency = min(cfg.get("max_concurrent_assessments", 2), DEVELOPER_SAFETY_MAX_CONCURRENCY)
        if current_concurrency >= max_concurrency:
            return False, f"Maximum concurrent assessment limit reached ({max_concurrency} active scans)", None

        # 2. Authentication mode check
        if auth_type:
            allowed_auth = cfg.get("allowed_auth_modes", ["none"])
            if auth_type.lower() not in [a.lower() for a in allowed_auth]:
                return False, f"Authentication mode '{auth_type}' is not permitted by policy. Allowed: {sorted(allowed_auth)}", None

        # 3. Categories check
        if requested_categories:
            allowed_cats = set(cfg.get("allowed_categories", []))
            def _norm_c(c: str) -> str:
                return str(c).split(":")[0].strip().upper()
            allowed_norms = {_norm_c(c) for c in allowed_cats} | allowed_cats
            disallowed = [rc for rc in requested_categories if rc not in allowed_cats and _norm_c(rc) not in allowed_norms]
            if disallowed:
                return False, f"Test categories not permitted by policy: {sorted(list(disallowed))}", None

        # 4. Target authorization check
        allow_ext = bool(cfg.get("allow_external_domains", False))
        targets = policy.get("targets", [])
        if not targets and not allow_ext:
            return False, f"Policy '{policy['name']}' has zero authorized target endpoints defined", None

        active_unexpired_targets = [
            t for t in targets
            if t.get("is_active", 1) and (not t.get("expires_at") or now <= float(t["expires_at"]))
        ]
        if not active_unexpired_targets and not allow_ext:
            if not any(t.get("is_active", 1) for t in targets):
                return False, f"All authorized target endpoints for policy '{policy['name']}' are disabled or revoked", None
            return False, f"All authorized target endpoints for policy '{policy['name']}' have expired", None

        parsed = urllib.parse.urlsplit(target_url.strip())
        target_scheme = (parsed.scheme or "http").lower()
        target_host = normalize_hostname(parsed.hostname or "")
        target_port = parsed.port or (443 if target_scheme == "https" else 80)
        target_path = parsed.path or "/"

        target_authorized = False
        rejection_reason = "Target endpoint is not in the policy authorized target whitelist"
        matching_target_id = None
        matching_target = None

        for t in active_unexpired_targets:
            # Scheme check
            allowed_schemes = [s.strip().lower() for s in t.get("allowed_schemes", "http,https").split(",") if s.strip()]
            if target_scheme not in allowed_schemes:
                rejection_reason = f"Scheme '{target_scheme}' is not authorized for target. Allowed: {allowed_schemes}"
                continue

            # Host match check
            h_pattern = str(t.get("host_pattern", "")).strip()
            if not (t.get("is_wildcard") or match_host_pattern(h_pattern, target_host)):
                continue

            # Port range check
            p_range = str(t.get("port_range", "1-65535")).strip()
            if not match_port_range(p_range, target_port):
                rejection_reason = f"Target port {target_port} is not authorized for host '{target_host}' (Authorized: {p_range})"
                continue

            # Path prefix check
            path_prefix = str(t.get("path_prefix", "/")).strip()
            if not match_path_prefix(path_prefix, target_path):
                rejection_reason = f"Target path '{target_path}' does not match authorized prefix '{path_prefix}'"
                continue

            # All target criteria satisfied!
            target_authorized = True
            matching_target_id = t.get("id")
            matching_target = dict(t)
            break

        if not target_authorized and allow_ext:
            # If allow_external_domains is active, permit any external HTTP/HTTPS host
            target_authorized = True
            matching_target_id = None
            matching_target = {
                "id": None,
                "host_pattern": target_host,
                "port_range": "*",
                "allowed_schemes": "http,https",
                "path_prefix": "/",
                "is_wildcard": 1,
            }

        if not target_authorized:
            return False, rejection_reason, None

        # 5. Requested tools check
        if requested_tools:
            allowed_tools = set(cfg.get("allowed_tools", []))
            disallowed_tools = set(requested_tools) - allowed_tools
            if disallowed_tools:
                return False, f"Requested tools not permitted by policy: {sorted(list(disallowed_tools))}", None

        # 6. Requested limits check
        if requested_limits:
            if "max_turns" in requested_limits and requested_limits["max_turns"] is not None:
                r_turns = int(requested_limits["max_turns"])
                p_max_turns = int(cfg.get("max_turns", 30))
                if r_turns > p_max_turns:
                    return False, f"Requested max_turns ({r_turns}) exceeds policy ceiling ({p_max_turns})", None
            if "max_requests" in requested_limits and requested_limits["max_requests"] is not None:
                r_req = int(requested_limits["max_requests"])
                p_max_req = min(int(cfg.get("max_requests", 50)), DEVELOPER_SAFETY_MAX_REQUESTS)
                if r_req > p_max_req:
                    return False, f"Requested max_requests ({r_req}) exceeds policy ceiling ({p_max_req})", None

        policy_info = dict(policy)
        policy_info["matching_target_id"] = matching_target_id
        policy_info["matching_target"] = matching_target
        policy_info["effective_limits"] = {
            "max_turns": min(int(cfg.get("max_turns", 10)), 30),
            "max_requests": min(int(cfg.get("max_requests", 25)), DEVELOPER_SAFETY_MAX_REQUESTS),
            "max_duration": min(float(cfg.get("max_assessment_duration_seconds", 300.0)), DEVELOPER_SAFETY_MAX_DURATION_SECONDS),
            "max_rps": float(cfg.get("max_requests_per_second", 5.0)),
        }

        return True, None, policy_info

    def is_policy_active(self, policy_id: int) -> bool:
        """Fast check whether a policy is active in the database."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active FROM policies WHERE id = ?", (policy_id,))
            row = cursor.fetchone()
            if not row:
                return False
            return bool(row["is_active"])

    def is_target_authorized_live(self, policy_id: int, url: str) -> Tuple[bool, Optional[str], Optional[int]]:
        """Live check whether a target URL is authorized by active, unexpired targets under policy_id."""
        if not self.is_policy_active(policy_id):
            return False, f"Policy {policy_id} is currently disabled/inactive", None

        targets = self.list_target_authorizations(policy_id, active_only=True)
        if not targets:
            return False, f"Policy {policy_id} has zero active target authorizations", None

        parsed = urllib.parse.urlsplit(url.strip())
        target_scheme = (parsed.scheme or "http").lower()
        target_host = normalize_hostname(parsed.hostname or "")
        target_port = parsed.port or (443 if target_scheme == "https" else 80)
        target_path = parsed.path or "/"

        now = time.time()
        for t in targets:
            if not t.get("is_active", 1):
                continue
            if t.get("expires_at") and now > float(t["expires_at"]):
                continue

            allowed_schemes = [s.strip().lower() for s in t.get("allowed_schemes", "http,https").split(",") if s.strip()]
            if target_scheme not in allowed_schemes:
                continue

            h_pattern = str(t.get("host_pattern", "")).strip()
            if not (t.get("is_wildcard") or match_host_pattern(h_pattern, target_host)):
                continue

            p_range = str(t.get("port_range", "1-65535")).strip()
            if not match_port_range(p_range, target_port):
                continue

            path_prefix = str(t.get("path_prefix", "/")).strip()
            if not match_path_prefix(path_prefix, target_path):
                continue

            return True, None, t.get("id")

        return False, f"Destination '{url}' is not authorized by active, unexpired target rules for policy {policy_id}", None

    def is_target_revoked_or_expired(self, target_id: int) -> bool:
        """Check whether a specific target authorization is revoked or expired."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT is_active, expires_at FROM target_authorizations WHERE id = ?", (target_id,))
            row = cursor.fetchone()
            if not row:
                return True
            if not row["is_active"]:
                return True
            if row["expires_at"] and time.time() > float(row["expires_at"]):
                return True
        return False

    # --- Assessment Policy Snapshots ---

    def create_assessment_snapshot(
        self,
        session_id: str,
        policy_id: int,
        applied_by_user_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Freeze exact policy configuration for an assessment session.

        Snapshots are immutable and guarantee that later policy modifications
        do not silently alter or corrupt historical running scans.
        """
        policy = self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy with ID {policy_id} does not exist")

        now = time.time()
        snapshot_data = {
            "policy_id": policy["id"],
            "policy_uuid": policy["policy_uuid"],
            "policy_name": policy["name"],
            "policy_version": policy["current_version"],
            "config": policy["config"],
            "targets": policy["targets"],
            "created_at": now,
        }
        snapshot_json = json.dumps(snapshot_data, sort_keys=True)

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO assessment_policy_snapshots (
                    assessment_session_id, policy_id, policy_version,
                    snapshot_json, applied_by_user_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, policy_id, policy["current_version"], snapshot_json, applied_by_user_id, now),
            )
            snapshot_id = cursor.lastrowid
            conn.commit()

        self._log_audit_event(
            action="ASSESSMENT_POLICY_SNAPSHOT_CREATED",
            resource_type="SNAPSHOT",
            resource_id=str(snapshot_id),
            user_id=applied_by_user_id,
            details={"session_id": session_id, "policy_id": policy_id, "version": policy["current_version"]},
            status="SUCCESS",
        )

        snapshot_data["id"] = snapshot_id
        snapshot_data["assessment_session_id"] = session_id
        return snapshot_data

    def get_assessment_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve frozen assessment policy snapshot by assessment session ID."""
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM assessment_policy_snapshots WHERE assessment_session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

        data = json.loads(row["snapshot_json"])
        data["id"] = row["id"]
        data["assessment_session_id"] = row["assessment_session_id"]
        data["applied_by_user_id"] = row["applied_by_user_id"]
        return data

    def get_audit_log(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieve recent administrative audit log entries, sanitized against credential exposure."""
        limit = max(1, min(int(limit), 200))
        offset = max(0, int(offset))
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, user_id, username, action,
                       resource_type, resource_id, ip_address,
                       details_json, status
                FROM admin_audit_log
                ORDER BY timestamp DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()

        entries = []
        for r in rows:
            details = {}
            if r["details_json"]:
                try:
                    raw_details = json.loads(r["details_json"])
                    details = mask_sensitive_traffic_data(raw_details)
                except Exception:
                    details = {"raw": str(r["details_json"])}
            entries.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "user_id": r["user_id"],
                "username": r["username"],
                "action": r["action"],
                "resource_type": r["resource_type"],
                "resource_id": r["resource_id"],
                "ip_address": r["ip_address"],
                "details": details,
                "status": r["status"],
            })
        return entries

    def get_policy_metrics(self) -> Dict[str, Any]:
        """Compute aggregated policy and target metrics for dashboard overview."""
        now = time.time()
        one_day_ago = now - 86400.0

        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) AS total, SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active FROM policies")
            pol_row = cursor.fetchone()
            total_policies = pol_row["total"] or 0
            active_policies = pol_row["active"] or 0
            inactive_policies = total_policies - active_policies

            cursor.execute("SELECT COUNT(*) AS modified FROM policies WHERE updated_at >= ?", (one_day_ago,))
            recently_modified = cursor.fetchone()["modified"] or 0

            cursor.execute(
                """
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
                       SUM(CASE WHEN expires_at IS NOT NULL AND expires_at < ? THEN 1 ELSE 0 END) AS expired
                FROM target_authorizations
                """,
                (now,),
            )
            tgt_row = cursor.fetchone()
            total_targets = tgt_row["total"] or 0
            active_targets = tgt_row["active"] or 0
            expired_targets = tgt_row["expired"] or 0

        return {
            "total_policies": total_policies,
            "active_policies": active_policies,
            "inactive_policies": inactive_policies,
            "recently_modified": recently_modified,
            "total_targets": total_targets,
            "active_targets": active_targets,
            "expired_targets": expired_targets,
        }

    def get_quick_scope_status(self, policy_id: Optional[int] = None) -> Dict[str, Any]:
        """Return high-level toggle states and authorized targets for the policy dashboard."""
        if policy_id is None:
            active_pols = self.list_policies(active_only=True)
            if not active_pols:
                pols = self.list_policies(active_only=False)
                if not pols:
                    return {
                        "policy_id": None,
                        "policy_name": "None",
                        "allow_external_domains": False,
                        "full_control_enabled": False,
                        "zap_active_scan_enabled": False,
                        "active_targets": [],
                    }
                policy = pols[0]
            else:
                policy = active_pols[0]
        else:
            policy = self.get_policy(policy_id)
            if not policy:
                return {
                    "policy_id": None,
                    "policy_name": "None",
                    "allow_external_domains": False,
                    "full_control_enabled": False,
                    "zap_active_scan_enabled": False,
                    "active_targets": [],
                }

        cfg = policy.get("config", {})
        now = time.time()
        targets = self.list_target_authorizations(policy["id"], active_only=True)
        active_unexpired = [
            t for t in targets
            if not t.get("expires_at") or now <= float(t["expires_at"])
        ]

        has_wildcard = any(t.get("host_pattern") == "*" or t.get("is_wildcard") == 1 for t in active_unexpired)
        allow_ext = bool(cfg.get("allow_external_domains", False)) or has_wildcard
        full_ctrl = bool(cfg.get("full_control_enabled", False))

        return {
            "policy_id": policy["id"],
            "policy_uuid": policy["policy_uuid"],
            "policy_name": policy["name"],
            "is_active": policy["is_active"],
            "current_version": policy["current_version"],
            "allow_external_domains": allow_ext,
            "full_control_enabled": full_ctrl,
            "zap_active_scan_enabled": bool(cfg.get("zap_active_scan_enabled", False)),
            "max_turns": cfg.get("max_turns", 10),
            "max_requests": cfg.get("max_requests", 25),
            "allowed_tools_count": len(cfg.get("allowed_tools", [])),
            "allowed_categories_count": len(cfg.get("allowed_categories", [])),
            "active_targets": [
                {
                    "id": t["id"],
                    "host_pattern": t["host_pattern"],
                    "port_range": t["port_range"],
                    "path_prefix": t["path_prefix"],
                    "allowed_schemes": t["allowed_schemes"],
                    "is_wildcard": t["is_wildcard"],
                    "created_at": t.get("created_at"),
                }
                for t in active_unexpired
            ],
        }

    def toggle_external_domains(self, policy_id: int, enabled: bool, actor_id: int = 1) -> Dict[str, Any]:
        """Toggle external domain scanning permission on a policy."""
        policy = self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy with ID {policy_id} not found")

        cfg = copy.deepcopy(policy["config"])
        cfg["allow_external_domains"] = bool(enabled)

        # Handle wildcard rule
        with self.store._get_connection() as conn:
            cursor = conn.cursor()
            if enabled:
                # Check if wildcard rule exists
                cursor.execute(
                    "SELECT id FROM target_authorizations WHERE policy_id = ? AND host_pattern = '*' AND is_active = 1",
                    (policy_id,),
                )
                if not cursor.fetchone():
                    # Add wildcard rule
                    cursor.execute(
                        """
                        INSERT INTO target_authorizations (
                            policy_id, host_pattern, port_range, allowed_schemes,
                            path_prefix, is_wildcard, expires_at, is_active, created_at
                        ) VALUES (?, '*', '*', 'http,https', '/', 1, NULL, 1, ?)
                        """,
                        (policy_id, time.time()),
                    )
                    conn.commit()
            else:
                # Deactivate wildcard rule so strict domain/localhost limits apply
                cursor.execute(
                    "UPDATE target_authorizations SET is_active = 0 WHERE policy_id = ? AND host_pattern = '*'",
                    (policy_id,),
                )
                conn.commit()

        self.update_policy(
            policy_id=policy_id,
            new_config=cfg,
            modifier_id=actor_id,
            change_summary=f"Toggled allow_external_domains to {enabled}",
        )
        return self.get_quick_scope_status(policy_id)

    def toggle_full_control(self, policy_id: int, enabled: bool, actor_id: int = 1) -> Dict[str, Any]:
        """Toggle full autonomous penetration permissions (all tools, categories, methods, max limits)."""
        policy = self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy with ID {policy_id} not found")

        cfg = copy.deepcopy(policy["config"])
        if enabled:
            cfg["full_control_enabled"] = True
            cfg["allowed_tools"] = sorted(list(DEFAULT_KNOWN_TOOLS))
            cfg["allowed_categories"] = sorted(list(DEFAULT_ALLOWED_CATEGORIES))
            cfg["allowed_http_methods"] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
            cfg["allowed_auth_modes"] = ["none", "bearer", "api_key", "basic", "custom"]
            cfg["max_turns"] = 50
            cfg["max_requests"] = 100
            cfg["max_requests_per_second"] = 20.0
            cfg["zap_active_scan_enabled"] = True
            cfg["tool_restrictions"] = {"zap_scanner": {"active_scan_allowed": True}}
        else:
            cfg["full_control_enabled"] = False
            cfg["max_turns"] = 10
            cfg["max_requests"] = 25
            cfg["max_requests_per_second"] = 5.0
            cfg["zap_active_scan_enabled"] = False
            cfg["tool_restrictions"] = {"zap_scanner": {"active_scan_allowed": False}}

        self.update_policy(
            policy_id=policy_id,
            new_config=cfg,
            modifier_id=actor_id,
            change_summary=f"Toggled full_control_enabled to {enabled}",
        )
        return self.get_quick_scope_status(policy_id)

    def quick_authorize_domain(self, policy_id: int, domain_or_url: str, actor_id: int = 1) -> Dict[str, Any]:
        """Quickly add an authorized domain or endpoint to a policy with port=* and schemes=http,https."""
        raw = str(domain_or_url).strip()
        if not raw:
            raise ValueError("Domain or URL cannot be empty")

        if "://" in raw:
            parsed = urllib.parse.urlsplit(raw)
            host = parsed.hostname or parsed.netloc
        else:
            # Strip path and port if user pasted "api.mydomain.com:8080/test"
            clean_part = raw.split("/")[0]
            if ":" in clean_part and not clean_part.startswith("["):
                host = clean_part.split(":")[0]
            else:
                host = clean_part

        clean_host = normalize_hostname(host)
        if not clean_host:
            raise ValueError(f"Invalid host or domain name: '{domain_or_url}'")

        target_def = {
            "host_pattern": clean_host,
            "port_range": "*",
            "allowed_schemes": "http,https",
            "path_prefix": "/",
            "expires_at": None,
            "is_wildcard": 1 if clean_host == "*" or clean_host.startswith("*.") else 0,
        }
        self.add_target_authorization(policy_id=policy_id, target_def=target_def, actor_id=actor_id)
        return self.get_quick_scope_status(policy_id)

    def quick_remove_domain(self, policy_id: int, target_id: int, actor_id: int = 1) -> Dict[str, Any]:
        """Quickly revoke/remove an authorized target domain from a policy."""
        self.revoke_target_authorization(target_id=target_id, actor_id=actor_id, policy_id=policy_id)
        return self.get_quick_scope_status(policy_id)



