"""Tool registry and standard tool interface for Autonomous API Penetration Testing.

Maintains registered tools, validates invocations against schemas, and provides
schema descriptions to the model brain for informed action selection.
Supports OpenAPI discovery tools, HTTP clients, and scanner adapters.
"""

import abc
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


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

    def __init__(self):
        self._tools: Dict[str, Union[BaseTool, ToolDefinition]] = {}

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
            }

        valid, err_msg = tool.validate_arguments(arguments)
        if not valid:
            return {
                "success": False,
                "error": f"Invalid arguments for tool '{name}': {err_msg}",
                "tool_name": name,
            }

        try:
            res = tool.execute(**arguments)
            if isinstance(res, dict) and "tool_name" not in res:
                res["tool_name"] = name
            return res
        except TypeError as te:
            return {
                "success": False,
                "error": f"Argument signature mismatch: {te}",
                "tool_name": name,
            }
        except Exception as exc:
            return {
                "success": False,
                "error": f"Tool execution failed: {exc}",
                "tool_name": name,
            }
