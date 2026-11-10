"""Security Data Sanitization and Secret Masking.

Provides deterministic redaction and masking of credentials, bearer tokens,
passwords, API keys, session cookies, and sensitive authorization headers
across model prompts, traffic inspection, event streams, and reports.
"""

import json
import re
from typing import Any, List

SENSITIVE_KEY_PATTERNS: List[re.Pattern] = [
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]+", re.IGNORECASE),
    re.compile(r'"(password|api_token|token|secret|key|authorization)"\s*:\s*"[^"]+"', re.IGNORECASE),
    re.compile(r"session=[a-zA-Z0-9_\-]+", re.IGNORECASE),
]


def mask_sensitive_traffic_data(data: Any) -> Any:
    """Mask credentials, tokens, session cookies, and API keys from strings, dicts, or lists."""
    if data is None:
        return ""
    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(term in k_lower for term in ("password", "token", "secret", "key", "auth", "cookie")):
                masked_dict[k] = "***MASKED***"
            elif isinstance(v, (dict, list, str)):
                masked_dict[k] = mask_sensitive_traffic_data(v)
            else:
                masked_dict[k] = v
        return masked_dict
    elif isinstance(data, list):
        return [mask_sensitive_traffic_data(item) for item in data]

    masked = str(data)
    # Mask Authorization header tokens
    masked = re.sub(
        r"(Bearer\s+)[a-zA-Z0-9_\-\.]+",
        r"\1***",
        masked,
        flags=re.IGNORECASE,
    )
    # Mask Basic auth tokens
    masked = re.sub(
        r"(Basic\s+)[a-zA-Z0-9+/=]+",
        r"\1***",
        masked,
        flags=re.IGNORECASE,
    )
    # Mask sensitive JSON fields
    masked = re.sub(
        r'("(password|api_token|token|secret|key|authorization)"\s*:\s*)"[^"]+"',
        r'\1"***"',
        masked,
        flags=re.IGNORECASE,
    )
    # Mask cookie session identifiers
    masked = re.sub(
        r"(session=)[a-zA-Z0-9_\-]+",
        r"\1***",
        masked,
        flags=re.IGNORECASE,
    )
    return masked

