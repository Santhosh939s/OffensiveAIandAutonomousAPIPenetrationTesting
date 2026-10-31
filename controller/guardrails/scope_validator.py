"""Scope validator for Autonomous API Penetration Testing.

Strictly restricts all outbound requests to explicitly authorized localhost
targets (127.0.0.1, localhost, ::1) to ensure safe, controlled testing.
Rejects any external target, domain, cloud metadata service, or invalid scheme.
"""

import ipaddress
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Set

from controller.config import DEFAULT_CONFIG, AgentConfig


@dataclass(frozen=True)
class ScopeValidationResult:
    """Outcome of validating a target URL against scope policy."""
    is_valid: bool
    reason: str
    normalized_url: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None


class ScopeValidator:
    """Deterministic scope enforcer ensuring targets are strictly within authorized boundaries."""

    # Disallowed cloud metadata endpoints and local loopback bypass tricks
    BLOCKED_IPS: Set[str] = {
        "169.254.169.254",  # AWS/GCP/Azure link-local metadata
        "0.0.0.0",          # Binding address
        "255.255.255.255",  # Broadcast
    }

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG

    def validate_url(self, raw_url: str) -> ScopeValidationResult:
        """Validate that a proposed target URL is strictly in-scope (localhost only)."""
        if not raw_url or not isinstance(raw_url, str):
            return ScopeValidationResult(
                is_valid=False,
                reason="Target URL must be a non-empty string"
            )

        stripped = raw_url.strip()
        try:
            parsed = urllib.parse.urlsplit(stripped)
        except Exception as exc:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Failed to parse target URL: {exc}"
            )

        scheme = (parsed.scheme or "").lower()
        if scheme not in self.config.allowed_schemes:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Scheme '{scheme}' is prohibited. Only {sorted(self.config.allowed_schemes)} are allowed."
            )

        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return ScopeValidationResult(
                is_valid=False,
                reason="URL does not contain a valid hostname"
            )

        # Check explicit blocked IPs
        if hostname in self.BLOCKED_IPS:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Hostname '{hostname}' is a strictly blocked IP (e.g. metadata/broadcast)."
            )

        # Disallow non-localhost hostnames
        if hostname not in self.config.allowed_hosts:
            # Check if it resolves to a loopback IP address
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if not ip_obj.is_loopback:
                    return ScopeValidationResult(
                        is_valid=False,
                        reason=f"Target IP '{hostname}' is out of scope (localhost loopback only)."
                    )
            except ValueError:
                # Not a raw IP, and not in allowed_hosts
                return ScopeValidationResult(
                    is_valid=False,
                    reason=f"External target domain '{hostname}' is out of scope. Localhost testing only."
                )

        port = parsed.port
        normalized = urllib.parse.urlunsplit(parsed)

        return ScopeValidationResult(
            is_valid=True,
            reason="Target is within authorized localhost scope",
            normalized_url=normalized,
            hostname=hostname,
            port=port
        )
