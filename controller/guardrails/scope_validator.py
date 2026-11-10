"""Scope validator for Autonomous API Penetration Testing.

Strictly restricts all outbound requests to explicitly authorized targets
(localhost loopback by default, or administrator-approved target authorization rules)
to ensure safe, controlled testing.

Enforces Layer 1 developer safety invariants (non-overridable cloud metadata,
broadcast, binding address prohibitions) and Layer 2 administrator target whitelists,
including IP canonicalization, DNS resolution validation / DNS rebinding defenses,
and redirect destination revalidation.
"""

import ipaddress
import socket
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from controller.config import DEFAULT_CONFIG, AgentConfig


@dataclass(frozen=True)
class ScopeValidationResult:
    """Outcome of validating a target URL against scope policy."""
    is_valid: bool
    reason: str
    normalized_url: Optional[str] = None
    hostname: Optional[str] = None
    port: Optional[int] = None
    canonical_ip: Optional[str] = None


def canonicalize_ip_str(host: str) -> Optional[ipaddress._BaseAddress]:
    """Parse host as an IP address handling decimal, octal, hex, and integer forms.

    Returns ipaddress.IPv4Address or ipaddress.IPv6Address, or None if not an IP representation.
    """
    clean = host.strip()
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]

    # 1. Standard ipaddress parsing (e.g. '127.0.0.1', '::1')
    try:
        ip_obj = ipaddress.ip_address(clean)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            return ip_obj.ipv4_mapped
        return ip_obj
    except ValueError:
        pass

    # 2. Pure integer representation (e.g. '2130706433' -> 127.0.0.1, '2852039166' -> 169.254.169.254)
    if clean.isdigit():
        try:
            val = int(clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # 3. Hex integer representation (e.g. '0x7f000001', '0xa9fea9fe')
    if clean.lower().startswith("0x"):
        try:
            val = int(clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # 4. Dotted notation with octal, hex, or decimal octets (e.g. '0177.0.0.1', '0x7f.0.0.1')
    parts = clean.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                p_str = p.strip()
                if p_str.lower().startswith("0x"):
                    octets.append(int(p_str, 16))
                elif p_str.startswith("0") and len(p_str) > 1 and p_str.isdigit():
                    octets.append(int(p_str, 8))
                elif p_str.isdigit():
                    octets.append(int(p_str, 10))
                else:
                    return None
            if all(0 <= o <= 255 for o in octets):
                return ipaddress.IPv4Address(bytes(octets))
        except (ValueError, OverflowError):
            pass

    return None


def normalize_hostname(host: str) -> str:
    """Normalize hostname handling whitespace, lowercase, trailing dot (FQDN), and IDN/Punycode."""
    if not host or not isinstance(host, str):
        return ""
    clean = host.strip().lower().rstrip(".")
    if clean.startswith("[") and clean.endswith("]"):
        clean = clean[1:-1]
    # Handle IDN (Internationalized Domain Names)
    try:
        clean = clean.encode("idna").decode("ascii")
    except Exception:
        pass
    return clean


def match_host_pattern(pattern: str, target_host: str, target_ip_obj: Optional[ipaddress._BaseAddress] = None) -> bool:
    """Match a normalized target host against a host pattern safely.

    Supports:
    - Pure wildcard: '*'
    - Exact hostname match
    - Wildcard subdomain: '*.domain.tld' (authorizes domain.tld and *.domain.tld, but NEVER domain.tld.evil.test or evil-domain.tld)
    - Canonical IP match (IPv4 and IPv6)
    - CIDR block match (e.g. '192.168.1.0/24')
    """
    p_clean = normalize_hostname(pattern)
    h_clean = normalize_hostname(target_host)

    if not p_clean or not h_clean:
        return False

    if p_clean == "*" or pattern.strip() == "*":
        return True

    if p_clean == h_clean:
        return True

    # IP and CIDR matching
    h_ip = target_ip_obj or canonicalize_ip_str(h_clean)
    p_ip = canonicalize_ip_str(p_clean)

    if h_ip and p_ip and h_ip == p_ip:
        return True

    if "/" in pattern and h_ip:
        try:
            net = ipaddress.ip_network(pattern.strip(), strict=False)
            if h_ip in net:
                return True
        except ValueError:
            pass

    # Wildcard domain matching: *.example.local
    if p_clean.startswith("*."):
        base = p_clean[2:]
        if h_clean == base or h_clean.endswith("." + base):
            return True

    return False


def match_path_prefix(prefix: str, target_path: str) -> bool:
    """Safely match path prefix preventing path prefix bypass (e.g. /api/v1 must NOT match /api/v10)."""
    p = (prefix or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    t = (target_path or "/").strip()
    if not t.startswith("/"):
        t = "/" + t

    if p == "/":
        return True

    p_clean = p.rstrip("/")
    if t == p_clean or t == p_clean + "/":
        return True
    if t.startswith(p_clean + "/"):
        return True

    return False


def match_port_range(port_range: str, effective_port: int) -> bool:
    """Evaluate whether effective_port falls within configured port_range (single, range, or wildcard)."""
    pr = str(port_range or "*").strip()
    if pr == "*":
        return 1 <= effective_port <= 65535
    if "-" in pr:
        parts = pr.split("-")
        if len(parts) != 2:
            return False
        try:
            p_min, p_max = int(parts[0]), int(parts[1])
            return p_min <= effective_port <= p_max
        except ValueError:
            return False
    try:
        return int(pr) == effective_port
    except ValueError:
        return False



class ScopeValidator:
    """Deterministic scope enforcer ensuring targets are strictly within authorized boundaries."""

    # Layer 1 Safety Invariant: Disallowed cloud metadata endpoints and loopback bypass tricks
    BLOCKED_IPS: Set[str] = {
        "169.254.169.254",  # AWS/GCP/Azure/OpenStack link-local metadata
        "100.100.100.200",  # Alibaba Cloud metadata
        "0.0.0.0",          # Binding address
        "255.255.255.255",  # Broadcast
    }

    BLOCKED_HOSTNAMES: Set[str] = {
        "metadata.google.internal",
        "instance-data",
        "metadata",
    }

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or DEFAULT_CONFIG

    def validate_url(
        self,
        raw_url: str,
        target_authorizations: Optional[List[Dict[str, Any]]] = None,
        validate_dns: bool = False,
        allow_external_domains: bool = False,
    ) -> ScopeValidationResult:
        """Validate that a proposed target URL conforms to Layer 1 safety and Layer 2 scope policy."""
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

        # 1. Scheme Check
        scheme = (parsed.scheme or "").lower()
        if scheme not in self.config.allowed_schemes:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Scheme '{scheme}' is prohibited. Only {sorted(self.config.allowed_schemes)} are allowed."
            )

        hostname = normalize_hostname(parsed.hostname or "")
        if not hostname:
            return ScopeValidationResult(
                is_valid=False,
                reason="URL does not contain a valid hostname"
            )

        # 2. Layer 1 Check: Explicit Blocked Hostnames (Metadata names)
        if hostname in self.BLOCKED_HOSTNAMES:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Hostname '{hostname}' is a strictly prohibited cloud metadata domain (Layer 1 safety invariant)."
            )

        # 3. Canonical IP Normalization & Layer 1 IP Checks
        ip_obj = canonicalize_ip_str(hostname)
        canonical_ip_str = str(ip_obj) if ip_obj else None

        # Check raw hostname or canonical IP against blocked set
        if hostname in self.BLOCKED_IPS or (canonical_ip_str and canonical_ip_str in self.BLOCKED_IPS):
            blocked_val = canonical_ip_str or hostname
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Destination '{blocked_val}' is a strictly blocked IP (Layer 1 safety invariant: cloud metadata/broadcast/binding)."
            )

        # Check if canonical IP is link-local or unspecified (0.0.0.0)
        if ip_obj and (ip_obj.is_link_local or ip_obj.is_unspecified):
            return ScopeValidationResult(
                is_valid=False,
                reason=f"IP '{ip_obj}' is a link-local or unspecified address prohibited by Layer 1 safety."
            )

        effective_port = parsed.port or (443 if scheme == "https" else 80)
        target_path = parsed.path or "/"

        # 4. DNS Resolution & Rebinding Check (if requested or required)
        if validate_dns and not ip_obj:
            dns_valid, dns_reason, resolved_ips = self.resolve_and_validate_dns(
                hostname=hostname,
                allow_external=bool(target_authorizations and len(target_authorizations) > 0),
            )
            if not dns_valid:
                return ScopeValidationResult(
                    is_valid=False,
                    reason=f"DNS resolution failure: {dns_reason}",
                    hostname=hostname,
                )

        # 5. Layer 2: Scope & Target Authorization Enforcement
        if target_authorizations and len(target_authorizations) > 0:
            now = time.time()
            matched = False
            rejection_reason = "Target URL is not authorized by the active policy target whitelist."

            for rule in target_authorizations:
                if not rule.get("is_active", 1):
                    continue

                # Expiration check
                exp = rule.get("expires_at")
                if exp is not None and now > float(exp):
                    continue

                # Scheme check
                allowed_schemes = [s.strip().lower() for s in rule.get("allowed_schemes", "http,https").split(",") if s.strip()]
                if scheme not in allowed_schemes:
                    continue

                # Host pattern match
                h_pat = str(rule.get("host_pattern", "")).strip()
                if not (rule.get("is_wildcard") or match_host_pattern(h_pat, hostname, ip_obj)):
                    continue

                # Port range check
                p_range = str(rule.get("port_range", "*")).strip()
                if not match_port_range(p_range, effective_port):
                    rejection_reason = f"Port {effective_port} is not authorized for host '{hostname}' under policy rules."
                    continue

                # Path prefix check
                p_prefix = str(rule.get("path_prefix", "/")).strip()
                if not match_path_prefix(p_prefix, target_path):
                    rejection_reason = f"Path '{target_path}' does not match authorized prefix '{p_prefix}'."
                    continue

                # Target matched an authorized rule!
                matched = True
                break

            if not matched:
                if allow_external_domains:
                    return ScopeValidationResult(
                        is_valid=True,
                        reason="Authorized by policy external domain testing mode",
                        normalized_url=f"{scheme}://{hostname}:{effective_port}{target_path}",
                        hostname=hostname,
                        port=effective_port,
                        canonical_ip=canonical_ip_str,
                    )
                return ScopeValidationResult(
                    is_valid=False,
                    reason=rejection_reason,
                    hostname=hostname,
                    port=effective_port,
                    canonical_ip=canonical_ip_str,
                )

        else:
            if allow_external_domains:
                return ScopeValidationResult(
                    is_valid=True,
                    reason="Authorized by policy external domain testing mode",
                    normalized_url=f"{scheme}://{hostname}:{effective_port}{target_path}",
                    hostname=hostname,
                    port=effective_port,
                    canonical_ip=canonical_ip_str,
                )

            # Default scope: Localhost loopback only
            is_loopback = False
            if hostname in self.config.allowed_hosts:
                is_loopback = True
            elif ip_obj and ip_obj.is_loopback:
                is_loopback = True

            if not is_loopback:
                if ip_obj:
                    return ScopeValidationResult(
                        is_valid=False,
                        reason=f"Target IP '{hostname}' is out of scope (localhost loopback only without active target authorization).",
                        canonical_ip=canonical_ip_str,
                    )
                else:
                    return ScopeValidationResult(
                        is_valid=False,
                        reason=f"External target domain '{hostname}' is out of scope. Localhost testing only without active target authorization.",
                    )

        # Normalize URL
        normalized = urllib.parse.urlunsplit(parsed)

        return ScopeValidationResult(
            is_valid=True,
            reason="Target is within authorized scope",
            normalized_url=normalized,
            hostname=hostname,
            port=effective_port,
            canonical_ip=canonical_ip_str,
        )

    def resolve_and_validate_dns(
        self,
        hostname: str,
        allow_external: bool = False,
    ) -> Tuple[bool, Optional[str], List[str]]:
        """Resolve a hostname to IP addresses and verify against Layer 1 safety and DNS rebinding."""
        try:
            addr_info = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            # In offline environments, if hostname is localhost, fallback safely
            if hostname in ("localhost", "127.0.0.1", "::1"):
                return True, None, ["127.0.0.1"]
            return False, f"Could not resolve hostname '{hostname}': {exc}", []

        resolved_ips: List[str] = []
        for info in addr_info:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            resolved_ips.append(ip_str)

            ip_obj = canonicalize_ip_str(ip_str)
            canonical = str(ip_obj) if ip_obj else ip_str

            # Layer 1 Check on resolved address (DNS Rebinding Defense)
            if canonical in self.BLOCKED_IPS:
                return False, f"DNS resolution for '{hostname}' resolved to blocked IP '{canonical}' (DNS rebinding defense)", resolved_ips

            if ip_obj and (ip_obj.is_link_local or ip_obj.is_unspecified):
                return False, f"DNS resolution for '{hostname}' resolved to link-local/unspecified IP '{canonical}'", resolved_ips

            if not allow_external and ip_obj and not ip_obj.is_loopback:
                return False, f"DNS resolution for '{hostname}' resolved to non-loopback IP '{canonical}' in localhost-only mode", resolved_ips

        return True, None, resolved_ips

    def validate_redirect(
        self,
        original_url: str,
        redirect_location: str,
        target_authorizations: Optional[List[Dict[str, Any]]] = None,
        validate_dns: bool = False,
    ) -> ScopeValidationResult:
        """Validate that a redirect target location is within authorized scope.

        Prevents redirect-based SSRF, cloud metadata exfiltration, and out-of-scope pivoting.
        """
        if not redirect_location or not isinstance(redirect_location, str):
            return ScopeValidationResult(
                is_valid=False,
                reason="Redirect location must be a non-empty string"
            )

        try:
            resolved_url = urllib.parse.urljoin(original_url.strip(), redirect_location.strip())
        except Exception as exc:
            return ScopeValidationResult(
                is_valid=False,
                reason=f"Failed to resolve redirect URL: {exc}"
            )

        return self.validate_url(
            raw_url=resolved_url,
            target_authorizations=target_authorizations,
            validate_dns=validate_dns,
        )


def validate_destination_ip(
    ip_target: Any,
    allow_external: bool = False,
    allow_private: bool = False,
) -> Tuple[bool, str]:
    """Validate a candidate IP address against Layer 1 safety and Layer 2 scope rules.

    Evaluates:
    - IPv4-mapped IPv6 normalization (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
    - Prohibited metadata, broadcast, and binding addresses (Layer 1 safety)
    - Unspecified addresses (0.0.0.0, ::)
    - Link-local addresses (169.254.0.0/16, fe80::/10)
    - Multicast addresses (224.0.0.0/4, ff00::/8)
    - Loopback addresses (127.0.0.0/8, ::1)
    - Reserved addresses (240.0.0.0/4)
    - Private network addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - External public addresses
    """
    if isinstance(ip_target, str):
        clean = ip_target.strip().strip("[]")
        ip_obj = canonicalize_ip_str(clean)
    else:
        ip_obj = ip_target

    if not ip_obj:
        return False, f"Invalid or non-canonical destination IP representation '{ip_target}'"

    # Normalize IPv4-mapped IPv6 (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    canon_str = str(ip_obj)

    # Layer 1 Safety Invariant: Prohibited IPs (cloud metadata, broadcast, binding)
    if canon_str in ScopeValidator.BLOCKED_IPS:
        return False, f"Destination '{canon_str}' is a strictly prohibited IP (cloud metadata/broadcast/binding)."

    # Unspecified address (0.0.0.0, ::)
    if ip_obj.is_unspecified:
        return False, f"Destination '{canon_str}' is an unspecified binding address prohibited by Layer 1 safety."

    # Link-local (169.254.0.0/16, fe80::/10)
    if ip_obj.is_link_local:
        return False, f"Destination '{canon_str}' is a link-local address prohibited by Layer 1 safety."

    # Multicast (224.0.0.0/4, ff00::/8)
    if ip_obj.is_multicast:
        return False, f"Destination '{canon_str}' is a multicast address prohibited by Layer 1 safety."

    # Loopback (127.0.0.0/8, ::1) - evaluated before is_reserved/is_private as ::1 is marked both in Py3.8
    if ip_obj.is_loopback:
        return True, "Authorized loopback address"

    # Reserved (240.0.0.0/4)
    if ip_obj.is_reserved:
        return False, f"Destination '{canon_str}' is a reserved address prohibited by Layer 1 safety."

    # Private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    if ip_obj.is_private:
        if not allow_private:
            return False, f"Destination '{canon_str}' is a private network address out of scope in default localhost mode."
        return True, "Authorized private address"

    # External public addresses
    if not allow_external:
        return False, f"Destination '{canon_str}' is an external public address out of scope in default localhost mode."

    return True, "Authorized external address"


# Dynamic external targets & domains registry for operator-controlled policy enforcement
_allow_all_external_destinations: bool = False
_authorized_external_hosts: Set[str] = set()


def set_external_domains_allowed(allowed: bool) -> None:
    """Set global permission for external domain resolution."""
    global _allow_all_external_destinations
    _allow_all_external_destinations = bool(allowed)


def add_authorized_external_host(host: str) -> None:
    """Register an explicitly authorized external hostname."""
    global _authorized_external_hosts
    if host:
        _authorized_external_hosts.add(normalize_hostname(host))


def clear_authorized_external_hosts() -> None:
    """Clear authorized external hostnames and reset permission flag."""
    global _authorized_external_hosts, _allow_all_external_destinations
    _authorized_external_hosts.clear()
    _allow_all_external_destinations = False


def is_destination_external_allowed(host: str) -> bool:
    """Check if destination host is authorized for external network communication."""
    if _allow_all_external_destinations:
        return True
    clean = normalize_hostname(host)
    if clean in _authorized_external_hosts:
        return True
    return False


def validate_destination_address(
    host: str,
    port: int,
    allow_external: bool = False,
    allow_private: bool = False,
) -> Tuple[bool, str]:
    """Resolve and validate a destination host and port at connection time.

    Verifies all resolved IP addresses (preventing mixtures of permitted and prohibited IPs).
    Protects against DNS rebinding occurring between URL validation and socket creation.
    """
    clean_host = normalize_hostname(host)
    if not clean_host:
        return False, "Destination host is empty or invalid"

    if clean_host in ScopeValidator.BLOCKED_HOSTNAMES:
        return False, f"Hostname '{clean_host}' is a prohibited cloud metadata domain (Layer 1 safety)."

    # Dynamic operator external permissions (e.g. user hosted domain testing)
    if not allow_external and is_destination_external_allowed(clean_host):
        allow_external = True
        allow_private = True

    # If clean_host is directly an IP literal, validate it first
    direct_ip = canonicalize_ip_str(clean_host)
    if direct_ip:
        ok_dir, reason_dir = validate_destination_ip(direct_ip, allow_external=allow_external, allow_private=allow_private)
        if not ok_dir:
            return False, reason_dir

    # Resolve via socket.getaddrinfo at connection time (DNS rebinding defense)
    try:
        addr_info = socket.getaddrinfo(clean_host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if clean_host in ("localhost", "127.0.0.1", "::1"):
            return True, "Localhost fallback"
        return False, f"DNS resolution failed for '{clean_host}': {exc}"

    if not addr_info:
        return False, f"DNS resolution returned empty address list for '{clean_host}'"

    for res in addr_info:
        sa = res[4]
        ip_str = sa[0]
        ok, reason = validate_destination_ip(ip_str, allow_external=allow_external, allow_private=allow_private)
        if not ok:
            return False, f"DNS resolution for '{clean_host}' resolved to prohibited IP '{ip_str}': {reason}"

    return True, "All resolved destination addresses authorized"
