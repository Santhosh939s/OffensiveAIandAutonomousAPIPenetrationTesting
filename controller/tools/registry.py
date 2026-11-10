"""Tool registry and standard tool interface for Autonomous API Penetration Testing.

Maintains registered tools, validates invocations against schemas, and provides
schema descriptions to the model brain for informed action selection.
Supports OpenAPI discovery tools, HTTP clients, and scanner adapters.
"""

import abc
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Retained strictly for backwards-compatibility; cannot be used to bypass dispatch authorization
_REGISTRY_GATE_SENTINEL = object()

# Thread-local dispatch context establishing trusted, single-use dispatch authorization
_dispatch_state = threading.local()


class BaseTool(abc.ABC):
    """Abstract base class establishing the standard tool interface."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters_schema: Dict[str, Any],
        category: str = "active_probe",
        is_destructive: bool = False,
    ):
        self.name = name
        self.description = description
        self.parameters_schema = parameters_schema
        self.category = category
        self.is_destructive = is_destructive
        self.policy_engine: Optional[Any] = None
        self.require_policy: bool = False

    def set_policy_engine(self, policy_engine: Any, require_policy: bool = False) -> None:
        """Attach a policy engine to enforce authorization during direct tool execution."""
        self.policy_engine = policy_engine
        self.require_policy = require_policy

    def _check_execution_policy(self, kwargs: Dict[str, Any]) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """Validate execution through attached policy engine if present, or enforce default-deny if require_policy=True.

        Direct callers cannot bypass this gate by importing sentinels or passing '_gated' flags.
        Only ToolRegistry's trusted dispatch context can establish prior authorization.
        """
        clean_kwargs = {k: v for k, v in kwargs.items() if k != "_gated"}

        # Verify whether this exact tool instance was authorized by ToolRegistry dispatch
        is_authorized_by_registry = (
            getattr(_dispatch_state, "active_grant", None) is not None
            and getattr(_dispatch_state, "authorized_tool", None) is self
        )
        if is_authorized_by_registry:
            # Single-use consumption: immediately invalidate so subsequent or nested calls must re-authorize
            _dispatch_state.active_grant = None
            _dispatch_state.authorized_tool = None
            return True, None, clean_kwargs

        if self.policy_engine is not None:
            dec = self.policy_engine.evaluate_action(self.name, clean_kwargs, reserve_budget=True)
            if not dec.approved:
                return False, f"Policy rejection: {dec.reason}", clean_kwargs
            return True, None, dec.sanitized_arguments or clean_kwargs

        if self.require_policy:
            return False, f"Policy rejection: Tool '{self.name}' requires policy enforcement context. Denied by default.", clean_kwargs

        return True, None, clean_kwargs

    @abc.abstractmethod
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the tool logic and return a structured dictionary receipt."""
        pass

    def validate_arguments(self, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate proposed arguments against parameters_schema."""
        if not isinstance(arguments, dict):
            return False, "Arguments must be provided as a dictionary"

        required_fields = self.parameters_schema.get("required", [])
        for field in required_fields:
            if field not in arguments or arguments[field] is None:
                return False, f"Missing required parameter: '{field}'"

        return True, None

    def get_description(self) -> Dict[str, Any]:
        """Return structured schema metadata for model prompting."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "is_destructive": self.is_destructive,
            "parameters": self.parameters_schema,
        }


@dataclass
class ToolDefinition:
    """Wrapper for callable functions registered as tools."""
    name: str
    description: str
    parameters_schema: Dict[str, Any]
    handler: Callable[..., Dict[str, Any]]
    category: str = "active_probe"
    is_destructive: bool = False

    def execute(self, **kwargs) -> Dict[str, Any]:
        return self.handler(**kwargs)

    def validate_arguments(self, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(arguments, dict):
            return False, "Arguments must be a dictionary"
        required_fields = self.parameters_schema.get("required", [])
        for field in required_fields:
            if field not in arguments or arguments[field] is None:
                return False, f"Missing required parameter: '{field}'"
        return True, None

    def get_description(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "is_destructive": self.is_destructive,
            "parameters": self.parameters_schema,
        }


class ToolRegistry:
    """Registry maintaining approved tools available to the controller."""

    def __init__(self, policy_engine: Optional[Any] = None, require_policy: bool = False):
        self._tools: Dict[str, Union[BaseTool, ToolDefinition]] = {}
        self.policy_engine = policy_engine
        self.require_policy = require_policy
        if policy_engine is not None:
            self._propagate_policy_engine()

    def set_policy_engine(self, policy_engine: Any, require_policy: Optional[bool] = None) -> None:
        """Attach a policy engine to enforce authorization before any tool execution."""
        self.policy_engine = policy_engine
        if require_policy is not None:
            self.require_policy = require_policy
        self._propagate_policy_engine()

    def _propagate_policy_engine(self) -> None:
        for tool in self._tools.values():
            if hasattr(tool, "set_policy_engine"):
                tool.set_policy_engine(self.policy_engine, self.require_policy)

    def register(
        self,
        name: str,
        description: str,
        parameters_schema: Dict[str, Any],
        handler: Optional[Callable[..., Dict[str, Any]]] = None,
        category: str = "active_probe",
        is_destructive: bool = False,
    ) -> None:
        """Register a tool via parameters and a handler function."""
        if handler is None:
            raise ValueError("Handler callable must be provided for function registration")
        self._tools[name] = ToolDefinition(
            name=name,
            description=description,
            parameters_schema=parameters_schema,
            handler=handler,
            category=category,
            is_destructive=is_destructive,
        )

    def register_tool(self, tool: BaseTool) -> None:
        """Register an instance of BaseTool."""
        if not isinstance(tool, BaseTool):
            raise TypeError("tool must be an instance of BaseTool")
        if hasattr(tool, "set_policy_engine"):
            tool.set_policy_engine(self.policy_engine, self.require_policy)
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Union[BaseTool, ToolDefinition]]:
        """Retrieve a registered tool by name."""
        return self._tools.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._tools

    def list_tool_names(self) -> List[str]:
        """Return a list of all registered tool names."""
        return list(self._tools.keys())

    def get_tool_descriptions(self) -> List[Dict[str, Any]]:
        """Return structured schemas for prompting the model brain."""
        return [tool.get_description() for tool in self._tools.values()]

    def validate_tool_arguments(self, name: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate arguments against the registered tool's schema."""
        tool = self.get(name)
        if not tool:
            return False, f"Tool '{name}' is not registered"
        return tool.validate_arguments(arguments)

    def execute(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool handler with provided arguments."""
        tool = self.get(name)
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{name}' is not registered",
                "tool_name": name,
                "policy_denied": True,
            }

        # Policy Engine Guardrail (defense-in-depth per-invocation enforcement)
        if self.policy_engine is not None:
            decision = self.policy_engine.evaluate_action(name, arguments, reserve_budget=True)
            if not decision.approved:
                return {
                    "success": False,
                    "error": f"Policy rejection: {decision.reason}",
                    "tool_name": name,
                    "policy_denied": True,
                }
            arguments = decision.sanitized_arguments or arguments
        elif self.require_policy:
            return {
                "success": False,
                "error": "Policy rejection: Missing policy enforcement context. Action denied by default.",
                "tool_name": name,
                "policy_denied": True,
            }

        valid, err_msg = tool.validate_arguments(arguments)
        if not valid:
            if self.policy_engine and hasattr(self.policy_engine, "release_request_reservation"):
                self.policy_engine.release_request_reservation(1)
            return {
                "success": False,
                "error": f"Invalid arguments for tool '{name}': {err_msg}",
                "tool_name": name,
            }

        try:
            exec_args = {k: v for k, v in arguments.items() if k != "_gated"}
            # Establish trusted, single-use dispatch grant for this specific tool instance
            grant = object()
            _dispatch_state.active_grant = grant
            _dispatch_state.authorized_tool = tool
            try:
                res = tool.execute(**exec_args)
            finally:
                _dispatch_state.active_grant = None
                _dispatch_state.authorized_tool = None

            if isinstance(res, dict) and "tool_name" not in res:
                res["tool_name"] = name
            if self.policy_engine and hasattr(self.policy_engine, "record_completed_request"):
                self.policy_engine.record_completed_request(1)
            return res
        except TypeError as te:
            if self.policy_engine and hasattr(self.policy_engine, "release_request_reservation"):
                self.policy_engine.release_request_reservation(1)
            return {
                "success": False,
                "error": f"Argument signature mismatch: {te}",
                "tool_name": name,
            }
        except Exception as exc:
            if self.policy_engine and hasattr(self.policy_engine, "release_request_reservation"):
                self.policy_engine.release_request_reservation(1)
            return {
                "success": False,
                "error": f"Tool execution failed: {exc}",
                "tool_name": name,
            }
