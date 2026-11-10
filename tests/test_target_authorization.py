"""Tests for Target Authorization Engine and Scope Validation.

Validates Layer 1 developer safety invariants, Layer 2 target authorization whitelisting,
canonical IP normalization, DNS resolution and rebinding defense, and redirect revalidation.
"""

import time
import pytest
from unittest.mock import patch
import socket

from controller.guardrails.scope_validator import ScopeValidator, canonicalize_ip_str
from controller.guardrails.policy_service import PolicyService, get_default_policy_config
from controller.storage.evidence_store import EvidenceStore


@pytest.fixture
def temp_store(tmp_path):
    db_file = tmp_path / "test_target_auth.db"
    return EvidenceStore(str(db_file))


@pytest.fixture
def scope_validator():
    return ScopeValidator()


class TestCanonicalIpNormalization:
    """Verify robust detection and canonicalization of diverse IP encodings."""

    def test_canonicalize_standard_ips(self):
        assert str(canonicalize_ip_str("127.0.0.1")) == "127.0.0.1"
        assert str(canonicalize_ip_str("169.254.169.254")) == "169.254.169.254"
        assert str(canonicalize_ip_str("::1")) == "::1"
        assert str(canonicalize_ip_str("[::1]")) == "::1"

    def test_canonicalize_integer_dword_ips(self):
        # 2130706433 is 127.0.0.1
        assert str(canonicalize_ip_str("2130706433")) == "127.0.0.1"
        # 2852039166 is 169.254.169.254
        assert str(canonicalize_ip_str("2852039166")) == "169.254.169.254"

    def test_canonicalize_hex_ips(self):
        # 0x7f000001 is 127.0.0.1
        assert str(canonicalize_ip_str("0x7f000001")) == "127.0.0.1"
        # 0xa9fea9fe is 169.254.169.254
        assert str(canonicalize_ip_str("0xa9fea9fe")) == "169.254.169.254"
        # Dotted hex: 0x7f.0.0.1
        assert str(canonicalize_ip_str("0x7f.0.0.1")) == "127.0.0.1"

    def test_canonicalize_octal_ips(self):
        # 0177.0.0.1 is 127.0.0.1
        assert str(canonicalize_ip_str("0177.0.0.1")) == "127.0.0.1"

    def test_canonicalize_ipv6_mapped_ipv4(self):
        # ::ffff:127.0.0.1 maps to 127.0.0.1
        assert str(canonicalize_ip_str("::ffff:127.0.0.1")) == "127.0.0.1"


class TestLayer1SafetyInvariants:
    """Layer 1 restrictions must strictly block cloud metadata, binding, and broadcast regardless of configuration."""

    def test_layer1_blocks_cloud_metadata_ip(self, scope_validator):
        res = scope_validator.validate_url("http://169.254.169.254/latest/meta-data/")
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason or "Layer 1" in res.reason

    def test_layer1_blocks_encoded_metadata_ip(self, scope_validator):
        # Integer notation for 169.254.169.254: 2852039166
        res = scope_validator.validate_url("http://2852039166/computeMetadata/v1/")
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason

    def test_layer1_blocks_metadata_hostnames(self, scope_validator):
        res = scope_validator.validate_url("http://metadata.google.internal/computeMetadata/v1/")
        assert res.is_valid is False
        assert "cloud metadata domain" in res.reason

    def test_layer1_cannot_be_overridden_by_target_authorizations(self, scope_validator):
        """Even if an admin explicitly configures 169.254.169.254 in targets, Layer 1 rejects it."""
        dangerous_targets = [{
            "host_pattern": "169.254.169.254",
            "port_range": "80",
            "allowed_schemes": "http",
            "path_prefix": "/",
            "is_active": 1,
        }]
        res = scope_validator.validate_url("http://169.254.169.254/secret", target_authorizations=dangerous_targets)
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason

    def test_layer1_blocks_binding_and_broadcast(self, scope_validator):
        res_bind = scope_validator.validate_url("http://0.0.0.0:8000/api")
        assert res_bind.is_valid is False

        res_bcast = scope_validator.validate_url("http://255.255.255.255:8000/api")
        assert res_bcast.is_valid is False


class TestLayer2TargetAuthorizations:
    """Layer 2 target authorization matching logic."""

    def test_target_authorization_matching_host_port_path(self, scope_validator):
        targets = [{
            "host_pattern": "127.0.0.1",
            "port_range": "8000-8080",
            "allowed_schemes": "http,https",
            "path_prefix": "/api/v1",
            "is_active": 1,
        }]

        # Valid target within port range and path prefix
        res_valid = scope_validator.validate_url("http://127.0.0.1:8000/api/v1/users", target_authorizations=targets)
        assert res_valid.is_valid is True

        # Invalid port: 9000 is outside 8000-8080
        res_port = scope_validator.validate_url("http://127.0.0.1:9000/api/v1/users", target_authorizations=targets)
        assert res_port.is_valid is False
        assert "Port 9000 is not authorized" in res_port.reason

        # Invalid path: /admin does not match prefix /api/v1
        res_path = scope_validator.validate_url("http://127.0.0.1:8000/admin/settings", target_authorizations=targets)
        assert res_path.is_valid is False
        assert "does not match authorized prefix" in res_path.reason

    def test_target_authorization_expired_rule_is_rejected(self, scope_validator):
        past_time = time.time() - 3600  # Expired 1 hour ago
        targets = [{
            "host_pattern": "127.0.0.1",
            "port_range": "8000",
            "allowed_schemes": "http",
            "path_prefix": "/api",
            "expires_at": past_time,
            "is_active": 1,
        }]

        res = scope_validator.validate_url("http://127.0.0.1:8000/api/test", target_authorizations=targets)
        assert res.is_valid is False
        assert "not authorized by the active policy target whitelist" in res.reason

    def test_target_authorization_wildcard_domain_matching(self, scope_validator):
        targets = [{
            "host_pattern": "*.test-target.local",
            "port_range": "443",
            "allowed_schemes": "https",
            "path_prefix": "/",
            "is_active": 1,
        }]

        res = scope_validator.validate_url("https://api.test-target.local/v1", target_authorizations=targets)
        assert res.is_valid is True

        res_mismatch = scope_validator.validate_url("https://other-domain.local/v1", target_authorizations=targets)
        assert res_mismatch.is_valid is False


class TestRedirectDestinationValidation:
    """Redirect revalidation prevents SSRF and out-of-scope pivoting."""

    def test_relative_redirect_within_scope(self, scope_validator):
        targets = [{
            "host_pattern": "127.0.0.1",
            "port_range": "8000",
            "allowed_schemes": "http",
            "path_prefix": "/api",
            "is_active": 1,
        }]

        res = scope_validator.validate_redirect(
            original_url="http://127.0.0.1:8000/api/login",
            redirect_location="/api/dashboard",
            target_authorizations=targets,
        )
        assert res.is_valid is True
        assert res.normalized_url == "http://127.0.0.1:8000/api/dashboard"

    def test_redirect_to_metadata_rejected(self, scope_validator):
        res = scope_validator.validate_redirect(
            original_url="http://127.0.0.1:8000/api/redirect?url=foo",
            redirect_location="http://169.254.169.254/latest/meta-data/",
        )
        assert res.is_valid is False
        assert "strictly blocked IP" in res.reason

    def test_redirect_to_prohibited_scheme_rejected(self, scope_validator):
        res = scope_validator.validate_redirect(
            original_url="http://127.0.0.1:8000/api/open",
            redirect_location="gopher://127.0.0.1:70/",
        )
        assert res.is_valid is False
        assert "Scheme 'gopher' is prohibited" in res.reason


class TestDnsRebindingPrevention:
    """DNS resolution checks prevent rebinding attacks against loopback or metadata."""

    def test_dns_rebinding_to_metadata_blocked(self, scope_validator):
        """If a domain resolves to 169.254.169.254, DNS rebinding defense catches and rejects it."""
        mock_addrinfo = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            valid, reason, _ = scope_validator.resolve_and_validate_dns("evil-rebind.com", allow_external=True)
            assert valid is False
            assert "DNS rebinding defense" in reason

