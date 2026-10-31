"""JWT Inspector Tool for Autonomous API Penetration Testing.

Decodes JWT headers and payload claims without claiming cryptographic verification.
Extracts token metadata, algorithm, expiration, subject, and authorization roles.
Identifies common JWT security weaknesses (none algorithm, excessive lifetimes,
sensitive claim exposure, and suspicious key-id indicators).
"""

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional

from controller.tools.registry import BaseTool


def _base64url_decode(segment: str) -> bytes:
    """Decode a base64url encoded string with appropriate padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def extract_jwt_token(raw_string: str) -> Optional[str]:
    """Extract a JWT string from raw text, headers, or Bearer prefixes."""
    if not raw_string or not isinstance(raw_string, str):
        return None
    cleaned = raw_string.strip()
    if cleaned.lower().startswith("bearer "):
        cleaned = cleaned[7:].strip()

    # Pattern: three base64url strings separated by dots
    match = re.search(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", cleaned)
    if match:
        return match.group(0)
    return cleaned if cleaned.count(".") == 2 else None


def inspect_jwt(token: str) -> Dict[str, Any]:
    """Inspect and decode JWT structure, headers, and claims.
    
    IMPORTANT: This performs offline structural decoding only.
    It DOES NOT cryptographically verify the token signature.
    """
    extracted_token = extract_jwt_token(token)
    if not extracted_token:
        return {
            "success": False,
            "error": "Invalid JWT structure: Token must be a valid 3-segment string (header.payload.signature)",
        }

    parts = extracted_token.split(".")
    if len(parts) != 3:
        return {
            "success": False,
            "error": f"Invalid JWT structure: expected 3 segments separated by dots, got {len(parts)}",
        }

    header_raw, payload_raw, signature_raw = parts

    # 1. Decode Header
    try:
        header_bytes = _base64url_decode(header_raw)
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to decode JWT header: {exc}",
        }

    # 2. Decode Payload
    try:
        payload_bytes = _base64url_decode(payload_raw)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        return {
            "success": False,
            "error": f"Failed to decode JWT payload: {exc}",
        }

    # 3. Extract standard claims
    algorithm = header.get("alg")
    token_type = header.get("typ")
    key_id = header.get("kid")
    jku = header.get("jku")
    jwk = header.get("jwk")

    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")
    sub = payload.get("sub")
    iss = payload.get("iss")
    aud = payload.get("aud")

    roles = (
        payload.get("roles")
        or payload.get("role")
        or payload.get("scopes")
        or payload.get("scope")
        or payload.get("authorities")
        or payload.get("permissions")
    )

    now = int(time.time())
    is_expired = None
    if isinstance(exp, (int, float)):
        is_expired = now > exp

    # 4. Security Observations
    security_observations: List[str] = []
    flaw_indicators: List[Dict[str, Any]] = []

    # None algorithm check
    if str(algorithm).lower() == "none":
        msg = "Algorithm is set to 'none' (Critical: unsigned token acceptance risk)"
        security_observations.append(msg)
        flaw_indicators.append({"type": "NONE_ALGORITHM", "severity": "HIGH", "detail": msg})

    # Expiration checks
    if is_expired:
        msg = f"Token expired at epoch {exp} (Current: {now})"
        security_observations.append(msg)
    elif exp is None:
        msg = "Token does not define an expiration ('exp') claim"
        security_observations.append(msg)
        flaw_indicators.append({"type": "NO_EXPIRATION", "severity": "MEDIUM", "detail": msg})
    elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
        lifetime = exp - iat
        if lifetime > 30 * 86400:  # > 30 days
            msg = f"Excessive token lifetime detected ({round(lifetime / 86400, 1)} days)"
            security_observations.append(msg)

    # Key ID injection or traversal check
    if key_id and isinstance(key_id, str):
        if "../" in key_id or "..\\" in key_id or "'" in key_id or "|" in key_id:
            msg = f"Suspicious character pattern in key ID ('kid'): {key_id}"
            security_observations.append(msg)
            flaw_indicators.append({"type": "SUSPICIOUS_KID", "severity": "HIGH", "detail": msg})

    # JKU / JWK header check
    if jku or jwk:
        msg = "Header specifies external JWK or JKU URL; verify that strict domain allowlists are enforced."
        security_observations.append(msg)

    # Sensitive claim data leakage check
    sensitive_keys = {"password", "secret", "private_key", "ssn", "credit_card", "pass_hash"}
    for k in payload.keys():
        if k.lower() in sensitive_keys:
            msg = f"Potentially sensitive claim '{k}' exposed in unencrypted JWT payload"
            security_observations.append(msg)
            flaw_indicators.append({"type": "SENSITIVE_CLAIM_EXPOSURE", "severity": "MEDIUM", "detail": msg})

    return {
        "success": True,
        "signature_verified": False,
        "verification_disclaimer": "DECODED ONLY. Cryptographic signature was not verified against any secret/key.",
        "header": header,
        "payload": payload,
        "extracted_fields": {
            "algorithm": algorithm,
            "token_type": token_type,
            "key_id": key_id,
            "subject": sub,
            "issuer": iss,
            "audience": aud,
            "issued_at": iat,
            "expires_at": exp,
            "is_expired": is_expired,
            "roles_or_scopes": roles,
        },
        "has_signature": bool(signature_raw),
        "security_observations": security_observations,
        "flaw_indicators": flaw_indicators,
    }


class JwtInspectorTool(BaseTool):
    """Standard JwtInspectorTool implementing the BaseTool interface."""

    def __init__(self):
        super().__init__(
            name="jwt_inspector",
            description="Decodes and inspects JSON Web Tokens (JWT) structure, headers, and claims without verifying signature.",
            parameters_schema={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "The encoded JWT string (header.payload.signature) or Bearer token"},
                },
                "required": ["token"],
            },
            category="inspection",
            is_destructive=False,
        )

    def execute(self, **kwargs) -> Dict[str, Any]:
        token = kwargs.get("token", "")
        return inspect_jwt(token)
