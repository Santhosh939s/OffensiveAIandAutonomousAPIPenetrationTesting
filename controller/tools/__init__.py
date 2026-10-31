"""Tools package for Autonomous API Penetration Testing."""

from .registry import ToolRegistry, ToolDefinition, BaseTool
from .http_request import execute_http_request, HttpRequestTool
from .httpx_client import execute_httpx_request, probe_multiple_endpoints_httpx, HttpxRequestTool
from .openapi_parser import OpenApiParserTool
from .jwt_inspector import inspect_jwt, extract_jwt_token, JwtInspectorTool
from .parameter_fuzzer import probe_api_parameters, ParameterFuzzerTool
from .zap_client import ZapSecurityScanTool


def build_default_tool_registry() -> ToolRegistry:
    """Create and return a ToolRegistry populated with the approved default tools."""
    registry = ToolRegistry()

    # Register class-based standard tools
    registry.register_tool(HttpRequestTool())
    registry.register_tool(HttpxRequestTool())
    registry.register_tool(OpenApiParserTool())
    registry.register_tool(JwtInspectorTool())
    registry.register_tool(ParameterFuzzerTool())
    registry.register_tool(ZapSecurityScanTool())

    return registry


__all__ = [
    "ToolRegistry",
    "ToolDefinition",
    "BaseTool",
    "HttpRequestTool",
    "HttpxRequestTool",
    "OpenApiParserTool",
    "JwtInspectorTool",
    "ParameterFuzzerTool",
    "ZapSecurityScanTool",
    "execute_http_request",
    "execute_httpx_request",
    "probe_multiple_endpoints_httpx",
    "inspect_jwt",
    "extract_jwt_token",
    "probe_api_parameters",
    "build_default_tool_registry",
]
