"""Brain package containing model gateway, prompt templates, and reasoning interfaces."""

from .model_gateway import (
    ModelBrainClient,
    DeterministicMockBrainClient,
    LocalQwenBrainClient,
    RemoteHttpQwenBrainClient,
    get_model_brain,
    extract_and_validate_json,
)
from .local_cpu_client import LocalCpuBrainClient
from .prompts import (
    SYSTEM_PROMPT,
    format_classification_prompt,
    format_test_planning_prompt,
    format_action_selection_prompt,
    format_evidence_analysis_prompt,
    format_reporting_prompt,
)

__all__ = [
    "ModelBrainClient",
    "DeterministicMockBrainClient",
    "LocalCpuBrainClient",
    "LocalQwenBrainClient",
    "RemoteHttpQwenBrainClient",
    "get_model_brain",
    "SYSTEM_PROMPT",
    "format_classification_prompt",
    "format_test_planning_prompt",
    "format_action_selection_prompt",
    "format_evidence_analysis_prompt",
    "format_reporting_prompt",
]

