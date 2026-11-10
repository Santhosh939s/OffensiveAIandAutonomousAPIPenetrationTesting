"""Role and Permission Service for Autonomous API Penetration Testing Platform.

Defines initial system roles: admin, operator, and auditor, along with
granular role-based permissions and hierarchical access verification.
"""

from enum import Enum
from typing import Dict, List, Optional, Set


class Role(str, Enum):
    """System user roles with deterministic access privileges."""
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class Permission(str, Enum):
    """Fine-grained platform permissions."""
    # Administrative & Configuration Permissions
    MANAGE_USERS = "manage_users"
    MANAGE_POLICIES = "manage_policies"
    MANAGE_TARGETS = "manage_targets"
    VIEW_AUDIT_LOG = "view_audit_log"
    ACCESS_ADMIN_TEST = "access_admin_test"

    # Assessment Execution Permissions
    EXECUTE_ASSESSMENT = "execute_assessment"
    CANCEL_ASSESSMENT = "cancel_assessment"

    # Read-Only Inspection Permissions
    VIEW_POLICIES = "view_policies"
    VIEW_FINDINGS = "view_findings"
    VIEW_TRAFFIC = "view_traffic"
    VIEW_REPORTS = "view_reports"


class RoleService:
    """Manages role capabilities and verifies user permissions."""

    # Explicit role-to-permission mapping
    ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
        Role.ADMIN: {
            Permission.MANAGE_USERS,
            Permission.MANAGE_POLICIES,
            Permission.MANAGE_TARGETS,
            Permission.VIEW_AUDIT_LOG,
            Permission.ACCESS_ADMIN_TEST,
            Permission.EXECUTE_ASSESSMENT,
            Permission.CANCEL_ASSESSMENT,
            Permission.VIEW_POLICIES,
            Permission.VIEW_FINDINGS,
            Permission.VIEW_TRAFFIC,
            Permission.VIEW_REPORTS,
        },
        Role.OPERATOR: {
            Permission.EXECUTE_ASSESSMENT,
            Permission.CANCEL_ASSESSMENT,
            Permission.VIEW_POLICIES,
            Permission.VIEW_FINDINGS,
            Permission.VIEW_TRAFFIC,
            Permission.VIEW_REPORTS,
        },
        Role.AUDITOR: {
            Permission.VIEW_POLICIES,
            Permission.VIEW_FINDINGS,
            Permission.VIEW_TRAFFIC,
            Permission.VIEW_REPORTS,
            Permission.VIEW_AUDIT_LOG,
        },
    }

    @classmethod
    def get_valid_roles(cls) -> List[str]:
        """Return list of valid role names."""
        return [r.value for r in Role]

    @classmethod
    def is_valid_role(cls, role_name: str) -> bool:
        """Validate if role string exists in the system."""
        try:
            Role(str(role_name).lower())
            return True
        except ValueError:
            return False

    @classmethod
    def has_permission(cls, user_role: str, permission: Permission) -> bool:
        """Deterministic permission check for a given role."""
        try:
            r = Role(str(user_role).lower())
        except ValueError:
            return False
        return permission in cls.ROLE_PERMISSIONS.get(r, set())

    @classmethod
    def is_admin(cls, user_role: str) -> bool:
        """Check if user role is admin."""
        return str(user_role).lower() == Role.ADMIN.value

    @classmethod
    def get_role_permissions(cls, user_role: str) -> Set[str]:
        """Return set of permission strings for a given role."""
        try:
            r = Role(str(user_role).lower())
            return {p.value for p in cls.ROLE_PERMISSIONS.get(r, set())}
        except ValueError:
            return set()

