"""Configuration module for Autonomous API Penetration Testing Controller.

Defines deterministic execution bounds, network limits, scope constraints,
and safety parameters. Localhost targets only are allowed by default.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Set, Tuple


@dataclass(frozen=True)
class AgentConfig:
    """Immutable runtime configuration for the autonomous testing agent."""

    # Loop and turn limits
    max_turns: int = 10
    max_requests_per_session: int = 30
    max_model_calls: int = 25
    max_probes_per_endpoint: int = 3
    adaptive_selection_enabled: bool = True
    early_stopping_enabled: bool = True

    # HTTP Network limits
    http_connect_timeout: float = 5.0  # seconds
    http_read_timeout: float = 10.0  # seconds
    max_response_body_bytes: int = 50 * 1024  # 50 KB ceiling

    # Target scope boundaries (Localhost only)
    allowed_hosts: Set[str] = field(
        default_factory=lambda: {"127.0.0.1", "localhost", "::1"}
    )
    allowed_schemes: Set[str] = field(default_factory=lambda: {"http", "https"})
    allowed_http_methods: Set[str] = field(
        default_factory=lambda: {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
    )

    # Database
    db_path: str = "offensive_ai_evidence.db"

    # OWASP ZAP Daemon Configuration (Localhost Only)
    zap_base_url: str = "http://127.0.0.1:8080"
    zap_api_key: Optional[str] = None
    zap_active_scan_enabled: bool = False  # Disabled by default for safe operation
    zap_max_spider_depth: int = 2
    zap_poll_interval: float = 0.5  # seconds
    zap_max_poll_seconds: float = 10.0  # seconds

    # Brain Model Configuration
    base_model_name: str = "Qwen/Qwen2.5-1.5B-Instruct"
    adapter_checkpoint_name: str = "RebuiltV4_Checkpoint-200"

    @property
    def http_timeout(self) -> Tuple[float, float]:
        """Return requests-compatible timeout tuple (connect, read)."""
        return (self.http_connect_timeout, self.http_read_timeout)


# Default global instance
DEFAULT_CONFIG = AgentConfig()

