"""Model Gateway for Qwen2.5-1.5B-Instruct Brain.

Provides an abstract interface and implementations for interacting with the core
LLM brain. Decouples the Python controller from hardware-specific inference (GPU/CPU).
Includes a deterministic mock brain for unit tests and local development, and a
LocalQwenBrainClient for GPU execution with RebuiltV4 adapter weights.
"""

import abc
import json
import logging
import re
from typing import Any, Dict, List, Optional

from controller.brain import prompts

logger = logging.getLogger(__name__)


def extract_and_validate_json(raw_text: str, schema_type: str = "generic") -> Dict[str, Any]:
    """Robust JSON extraction and schema validation for model outputs.
    
    Handles:
    - Direct JSON string parsing
    - Markdown fenced blocks (```json ... ``` or ``` ... ```)
    - Extracting innermost or outermost JSON object
    - Schema validation for 'action', 'plan', 'analysis', and 'classification'
    - Controlled fallback to safe no_action or structured error on failure
    """
    if not raw_text or not isinstance(raw_text, str):
        return {"error": "Empty or non-string model output", "raw_output": str(raw_text)}

    parsed: Optional[Dict[str, Any]] = None

    # Attempt 1: Direct JSON parse
    try:
        candidate = json.loads(raw_text.strip())
        if isinstance(candidate, dict):
            parsed = candidate
    except Exception:
        pass

    # Attempt 2: Markdown fenced block regex
    if parsed is None:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw_text, re.DOTALL)
        if match:
            try:
                candidate = json.loads(match.group(1).strip())
                if isinstance(candidate, dict):
                    parsed = candidate
            except Exception:
                pass

    # Attempt 3: Find outermost matching braces
    if parsed is None:
        first_brace = raw_text.find("{")
        last_brace = raw_text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                candidate = json.loads(raw_text[first_brace : last_brace + 1].strip())
                if isinstance(candidate, dict):
                    parsed = candidate
            except Exception:
                pass

    # Attempt 4: Clean relaxed json fixes (e.g. trailing commas)
    if parsed is None:
        cleaned = re.sub(r",\s*([\]}])", r"\1", raw_text)
        first_brace = cleaned.find("{")
        last_brace = cleaned.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            try:
                candidate = json.loads(cleaned[first_brace : last_brace + 1].strip())
                if isinstance(candidate, dict):
                    parsed = candidate
            except Exception:
                pass

    # Attempt 5: Truncated JSON repair (balance open quotes and braces)
    if parsed is None and "{" in raw_text:
        try:
            trimmed = raw_text[raw_text.find("{"):].strip()
            if "```" in trimmed:
                trimmed = trimmed.split("```")[0].strip()
            quote_count = len(re.findall(r'(?<!\\)"', trimmed))
            if quote_count % 2 != 0:
                trimmed += '"'
            open_braces = trimmed.count("{") - trimmed.count("}")
            if open_braces > 0:
                trimmed += "}" * open_braces
            candidate = json.loads(trimmed)
            if isinstance(candidate, dict):
                parsed = candidate
        except Exception:
            pass

    # Attempt 6: Schema-based regex field extraction for partial action outputs
    if parsed is None and schema_type == "action":
        at_match = re.search(r'"action_type"\s*:\s*"([^"]+)"', raw_text)
        tn_match = re.search(r'"tool_name"\s*:\s*"([^"]+)"', raw_text)
        rs_match = re.search(r'"reasoning"\s*:\s*"([^"]+)"', raw_text)
        if at_match:
            parsed = {
                "action_type": at_match.group(1),
                "tool_name": tn_match.group(1) if tn_match else "",
                "arguments": {},
                "reasoning": rs_match.group(1) if rs_match else "Extracted from model output via regex recovery",
            }
            args_match = re.search(r'"arguments"\s*:\s*(\{.*?\})', raw_text, re.DOTALL)
            if args_match:
                try:
                    parsed["arguments"] = json.loads(args_match.group(1))
                except Exception:
                    pass

    # If parsing completely failed, return safe schema-specific fallback
    if parsed is None:
        logger.warning("Failed to extract valid JSON from model response: %s", raw_text[:200])
        if schema_type == "action":
            return {
                "action_type": "no_action",
                "tool_name": "",
                "arguments": {},
                "reasoning": "Model output could not be parsed as valid JSON; halting turn safely.",
                "error": "JSON_PARSE_FAILURE",
                "raw_output": raw_text,
            }
        elif schema_type == "plan":
            return {
                "plan_title": "Invalid Plan (Parse Failure)",
                "steps": [],
                "rationale": "Model output could not be parsed as valid JSON.",
                "error": "JSON_PARSE_FAILURE",
                "raw_output": raw_text,
            }
        elif schema_type == "analysis":
            return {
                "status": "NOT_DEMONSTRATED",
                "category": "Uncertain",
                "analysis": "Model response could not be parsed into structured JSON evidence analysis.",
                "verification_rule": None,
                "error": "JSON_PARSE_FAILURE",
                "raw_output": raw_text,
            }
        else:
            return {
                "error": "Failed to parse valid JSON from model response",
                "raw_output": raw_text,
            }

    # Schema Validation
    if schema_type == "action":
        action_type = parsed.get("action_type")
        if action_type not in {"execute_tool", "complete", "no_action"}:
            # Normalize or return safe no_action
            if "tool_name" in parsed and parsed["tool_name"]:
                parsed["action_type"] = "execute_tool"
            else:
                return {
                    "action_type": "no_action",
                    "tool_name": "",
                    "arguments": {},
                    "reasoning": f"Unrecognized action_type '{action_type}' returned by model",
                    "error": "INVALID_ACTION_SCHEMA",
                    "raw_output": raw_text,
                }
        if "arguments" not in parsed or not isinstance(parsed["arguments"], dict):
            parsed["arguments"] = {}

    elif schema_type == "plan":
        if "steps" not in parsed or not isinstance(parsed["steps"], list):
            parsed["steps"] = []
        if "plan_title" not in parsed:
            parsed["plan_title"] = "Autonomous Security Test Plan"

    elif schema_type == "analysis":
        if "status" not in parsed:
            parsed["status"] = "NOT_DEMONSTRATED"
        if "analysis" not in parsed:
            parsed["analysis"] = "No analysis text provided"

    elif schema_type == "classification":
        if "category" not in parsed:
            parsed["category"] = "Benign"

    return parsed


class ModelBrainClient(abc.ABC):
    """Abstract interface defining required intelligence capabilities for the model brain."""

    @abc.abstractmethod
    def classify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify an HTTP request into one of the 8 security categories."""
        pass

    @abc.abstractmethod
    def create_test_plan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Formulate an initial sequential security testing plan."""
        pass

    @abc.abstractmethod
    def select_next_action(
        self,
        current_turn: int,
        max_turns: int,
        plan_steps: List[Dict[str, Any]],
        recent_observations: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Propose the next tool to execute or signal completion."""
        pass

    @abc.abstractmethod
    def analyze_evidence(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate raw HTTP response/evidence and determine finding status."""
        pass

    @abc.abstractmethod
    def generate_report(self, session_summary: Dict[str, Any]) -> str:
        """Synthesize a complete markdown security assessment report."""
        pass


class DeterministicMockBrainClient(ModelBrainClient):
    """Deterministic intelligence brain for local unit testing and development.
    
    Produces schema-compliant, consistent decisions mirroring the fine-tuned
    Qwen2.5-1.5B model without requiring PyTorch or CUDA hardware.
    """

    def __init__(self, simulated_scenario: str = "standard_scan"):
        self.simulated_scenario = simulated_scenario
        self.call_history: List[Dict[str, Any]] = []

    def classify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        self.call_history.append({"method": "classify_request", "data": request_data})
        req_str = json.dumps(request_data).lower()

        # Heuristic rules matching the 8 classes for simulation
        if "union select" in req_str or "or 1=1" in req_str or "' or '" in req_str:
            category = "SQL Injection"
            confidence = 0.99
            reasoning = "Payload contains classic SQL boolean/union tautology patterns."
        elif "<script>" in req_str or "javascript:" in req_str or "onerror=" in req_str:
            category = "XSS"
            confidence = 0.98
            reasoning = "Payload contains unescaped HTML script tags or event handlers."
        elif "../" in req_str or "..%2f" in req_str:
            category = "Directory Traversal"
            confidence = 0.97
            reasoning = "Path traversal sequences detected in URI/parameters."
        elif "jndi:ldap" in req_str or "jndi:rmi" in req_str:
            category = "LOG4J"
            confidence = 0.99
            reasoning = "Log4j JNDI lookup string pattern identified."
        elif "cmd.exe" in req_str or "/bin/sh" in req_str or "; whoami" in req_str:
            category = "RCE"
            confidence = 0.96
            reasoning = "OS command invocation syntax detected."
        elif "session=" in req_str and ("admin" in req_str or "role=root" in req_str):
            category = "Cookie Injection"
            confidence = 0.94
            reasoning = "Manipulated cookie parameter targeting privilege escalation."
        elif "%0d%0a" in req_str or "\r\n" in req_str:
            category = "Log Forging"
            confidence = 0.95
            reasoning = "Carriage return and newline characters intended for log injection."
        else:
            category = "Benign"
            confidence = 0.99
            reasoning = "Standard application traffic with normal parameter structures."

        return {
            "category": category,
            "confidence": confidence,
            "reasoning": reasoning,
        }

    def create_test_plan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        self.call_history.append({"method": "create_test_plan", "target": target_url})
        steps = []
        step_num = 1

        # Default structured plan
        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()

            # Substitute path parameters (e.g. {id} -> 2)
            test_path = path
            if "{id}" in test_path:
                test_path = test_path.replace("{id}", "2")
            elif "{" in test_path and "}" in test_path:
                test_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "1", test_path)

            full_url = f"{target_url.rstrip('/')}/{test_path.lstrip('/')}"
            
            step_params = {
                "url": full_url,
                "method": method,
            }
            if "body" in ep:
                step_params["body"] = json.dumps(ep["body"]) if isinstance(ep["body"], (dict, list)) else str(ep["body"])
                step_params["headers"] = {"Content-Type": "application/json"}
            elif "/api/login" in path and method == "POST":
                step_params["body"] = json.dumps({"username": "admin", "password": ""})
                step_params["headers"] = {"Content-Type": "application/json"}
            elif "/api/users" in path and method == "PUT":
                step_params["body"] = json.dumps({"role": "admin", "is_admin": 1})
                step_params["headers"] = {"Content-Type": "application/json"}
            elif "/api/search" in path and method == "GET":
                step_params["url"] = f"{full_url}?q='"

            if "headers" in ep:
                step_params.setdefault("headers", {}).update(ep["headers"])

            # Use httpx_request if available, else http_request
            tool_to_use = "httpx_request" if any(t.get("name") == "httpx_request" for t in available_tools) else "http_request"

            # Step A: Targeted HTTP request
            steps.append({
                "step_number": step_num,
                "tool": tool_to_use,
                "purpose": f"Evaluate endpoint {method} {path}",
                "parameters": step_params,
            })
            step_num += 1

            # Step B: Parameter testing if parameters present
            if ep.get("parameters"):
                steps.append({
                    "step_number": step_num,
                    "tool": "parameter_fuzzer",
                    "purpose": f"Test input validation on parameters for {path}",
                    "parameters": {
                        "url": full_url,
                        "method": method,
                        "parameters": {
                            (p["name"] if isinstance(p, dict) else str(p)): "test"
                            for p in ep["parameters"]
                        },
                    },
                })
                step_num += 1

        return {
            "plan_title": f"Autonomous Security Assessment of {target_url}",
            "steps": steps,
            "rationale": "Perform structured reconnaissance followed by non-destructive boundary probe verification.",
        }

    def select_next_action(
        self,
        current_turn: int,
        max_turns: int,
        plan_steps: List[Dict[str, Any]],
        recent_observations: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        self.call_history.append({
            "method": "select_next_action",
            "turn": current_turn,
            "observations_count": len(recent_observations),
        })

        if current_turn > max_turns:
            return {
                "action_type": "complete",
                "tool_name": "",
                "arguments": {},
                "reasoning": "Maximum turn limit reached. Terminating assessment.",
            }

        # Find the next pending step from plan that has not been executed yet
        executed_tools = [obs.get("tool_name") for obs in recent_observations]
        next_step = None
        for step in plan_steps:
            if step["step_number"] > len(recent_observations):
                next_step = step
                break

        if not next_step:
            return {
                "action_type": "complete",
                "tool_name": "",
                "arguments": {},
                "reasoning": "All planned test steps have been executed. Proceeding to report synthesis.",
            }

        return {
            "action_type": "execute_tool",
            "tool_name": next_step["tool"],
            "arguments": next_step["parameters"],
            "reasoning": next_step["purpose"],
        }

    def analyze_evidence(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        self.call_history.append({"method": "analyze_evidence", "tool": tool_name})

        # Analyze HTTP response body/status for evidence
        body = tool_result.get("body") or ""
        status = tool_result.get("status_code")

        # Check for confirmed indicators
        if ("syntax error" in body.lower() and "sql" in body.lower()) or "unrecognized token" in body.lower():
            return {
                "status": "CONFIRMED",
                "category": "SQL Injection",
                "analysis": "Server response explicitly contains an unhandled database SQL syntax error.",
                "verification_rule": "SQL_SYNTAX_ERROR_MATCH",
            }
        elif "password_hash" in body and "api_token" in body and "/api/users/" in arguments.get("url", ""):
            return {
                "status": "CONFIRMED",
                "category": "BOLA / IDOR",
                "analysis": "Endpoint returned private user attributes (password_hash and api_token) across accounts without authorization.",
                "verification_rule": "UNAUTHENTICATED_DATA_ACCESS",
            }
        elif "is_admin" in body and "role" in body and arguments.get("method") == "PUT":
            return {
                "status": "CONFIRMED",
                "category": "Mass Assignment",
                "analysis": "Unrestricted profile update endpoint permitted elevating user privileges to admin role, confirmed by response payload.",
                "verification_rule": "ROLE_ELEVATION_VERIFIED",
            }
        elif "/api/login" in arguments.get("url", "") and "demo unsigned jwt" in body.lower():
            return {
                "status": "CONFIRMED",
                "category": "Insecure Authentication",
                "analysis": "Authentication endpoint allowed unauthenticated login and issued an unsigned 'none' algorithm JWT token.",
                "verification_rule": "TOKEN_ALGORITHM_NONE_ACCEPTED",
            }
        elif tool_name == "jwt_inspector":
            extracted = tool_result.get("extracted_fields", {})
            if str(extracted.get("algorithm")).lower() == "none":
                return {
                    "status": "CONFIRMED",
                    "category": "Insecure JWT",
                    "analysis": "JWT token issued with algorithm 'none', indicating unauthenticated/unsigned token weakness.",
                    "verification_rule": "TOKEN_ALGORITHM_NONE_ACCEPTED",
                }
            return {
                "status": "NOT_DEMONSTRATED",
                "category": "Authentication",
                "analysis": "JWT structure parsed normally with standard cryptographic algorithm claims.",
                "verification_rule": None,
            }
        elif tool_name == "zap_scanner":
            alerts = tool_result.get("alerts", [])
            if alerts:
                top_alert = alerts[0]
                return {
                    "status": "SUSPECTED",
                    "category": top_alert.get("name") or top_alert.get("alert") or "ZAP Alert",
                    "analysis": f"OWASP ZAP reported {len(alerts)} potential vulnerability alerts. Top finding: {top_alert.get('name', 'Alert')} ({top_alert.get('risk', 'Unknown')} Risk).",
                    "verification_rule": None,
                }
            return {
                "status": "NOT_DEMONSTRATED",
                "category": "Automated Scanner",
                "analysis": "OWASP ZAP scan finished without detecting automated vulnerability alerts.",
                "verification_rule": None,
            }
        elif tool_result.get("anomaly_detected"):
            return {
                "status": "SUSPECTED",
                "category": "Input Validation Flaw",
                "analysis": tool_result.get("observation_notes", "Parameter probe produced an anomalous server response."),
                "verification_rule": None,
            }
        elif status == 200:
            return {
                "status": "NOT_DEMONSTRATED",
                "category": "General Security",
                "analysis": "Endpoint responded with standard 200 OK without triggering security anomalies.",
                "verification_rule": None,
            }
        else:
            return {
                "status": "NOT_DEMONSTRATED",
                "category": "General Security",
                "analysis": f"Endpoint returned status {status}; no vulnerability demonstrated.",
                "verification_rule": None,
            }

    def generate_report(self, session_summary: Dict[str, Any]) -> str:
        self.call_history.append({"method": "generate_report"})
        session_id = session_summary.get("session_id", "UNKNOWN")
        target = session_summary.get("target", "localhost")
        findings = session_summary.get("findings", [])

        report_lines = [
            f"# API Security Assessment Report",
            f"**Session ID:** `{session_id}`  ",
            f"**Target System:** `{target}`  ",
            f"**Status:** COMPLETED  ",
            "",
            "## 1. Executive Summary",
            f"An autonomous API security evaluation was conducted against authorized target `{target}`.",
            f"Total findings identified: {len(findings)}.",
            "",
            "## 2. Findings Summary",
            "| ID | Endpoint | Category | Status | Verification Rule |",
            "|---|---|---|---|---|",
        ]

        if not findings:
            report_lines.append("| - | None | None | Clean | No vulnerabilities identified |")
        else:
            for f in findings:
                report_lines.append(
                    f"| {f.get('id', '-')} | `{f.get('endpoint', '/')}` | {f.get('category', 'N/A')} | "
                    f"**{f.get('status', 'UNTESTED')}** | `{f.get('verification_rule', 'None')}` |"
                )

        report_lines.extend([
            "",
            "## 3. Evidence and Recommendations",
            "- Local testing strictly observed all safety guardrails.",
            "- Ensure strict input validation and robust error handling on all API routes.",
        ])

        return "\n".join(report_lines)


class LocalQwenBrainClient(ModelBrainClient):
    """Inference gateway for local or GPU-hosted Qwen2.5-1.5B with RebuiltV4 LoRA adapter.
    
    Dynamically loads transformers/peft only when instantiated on a machine with PyTorch.
    Supports 4-bit NF4 quantization on Tesla T4 GPU instances via BitsAndBytesConfig.
    Maintains rigorous execution metrics and safe abstention gates.
    """

    DEFAULT_ADAPTER_PATH = "staging_rebuiltv4_training_checkpoints/checkpoint-200"

    def __init__(
        self,
        base_model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
        adapter_path: Optional[str] = None,
        device: str = "auto",
        load_in_4bit: bool = True,
    ):
        self.base_model_name = base_model_name
        self.adapter_path = adapter_path or self.DEFAULT_ADAPTER_PATH
        self.device = device
        self.load_in_4bit = load_in_4bit
        self.model = None
        self.tokenizer = None
        self.metrics: Dict[str, Any] = {
            "total_inferences": 0,
            "valid_decisions": 0,
            "invalid_decisions": 0,
            "abstentions": 0,
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_latency_seconds": 0.0,
        }
        self._load_model()

    def _load_model(self) -> None:
        """Load Qwen base model with 4-bit NF4 quantization and attach RebuiltV4 LoRA adapter."""
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
            from peft import PeftModel
        except ImportError as exc:
            raise RuntimeError(
                f"LocalQwenBrainClient requires torch, transformers, and peft. Error: {exc}"
            )

        logger.info("Loading base tokenizer: %s", self.base_model_name)
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.base_model_name,
            trust_remote_code=True,
        )
        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        quant_config = None
        if self.load_in_4bit and torch.cuda.is_available():
            try:
                from transformers import BitsAndBytesConfig
                quant_config = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True,
                )
                logger.info("Configured 4-bit NF4 quantization (BitsAndBytesConfig) for GPU")
            except ImportError:
                logger.warning("bitsandbytes not available; falling back to standard precision")

        logger.info("Loading base model: %s (4-bit: %s)", self.base_model_name, bool(quant_config))
        base_model = AutoModelForCausalLM.from_pretrained(
            self.base_model_name,
            quantization_config=quant_config,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            device_map=self.device,
            trust_remote_code=True,
        )

        if self.adapter_path:
            logger.info("Attaching RebuiltV4 adapter weights from: %s", self.adapter_path)
            self.model = PeftModel.from_pretrained(base_model, self.adapter_path)
        else:
            self.model = base_model

        self.model.eval()

    def _generate(self, prompt: str, max_new_tokens: int = 512) -> str:
        """Perform text generation with the loaded model and track metrics."""
        import torch

        start_time = time.time()
        inputs = self.tokenizer(prompt, return_tensors="pt")
        prompt_len = inputs["input_ids"].shape[1]

        if hasattr(self.model, "device"):
            inputs = {k: v.to(self.model.device) for k, v in inputs.items()}

        with torch.no_grad():
            output_tokens = self.model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        duration = time.time() - start_time
        generated_tokens = output_tokens[0][prompt_len:]
        completion_len = len(generated_tokens)
        decoded = self.tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()

        # Update metrics
        self.metrics["total_inferences"] += 1
        self.metrics["total_prompt_tokens"] += prompt_len
        self.metrics["total_completion_tokens"] += completion_len
        self.metrics["total_latency_seconds"] += round(duration, 3)

        return decoded

    def classify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        prompt = prompts.format_classification_prompt(request_data)
        raw_output = self._generate(prompt, max_new_tokens=128)
        parsed = extract_and_validate_json(raw_output, schema_type="classification")
        if parsed.get("category"):
            self.metrics["valid_decisions"] += 1
        else:
            self.metrics["invalid_decisions"] += 1
        return parsed

    def create_test_plan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        prompt = prompts.format_test_planning_prompt(target_url, endpoints, available_tools)
        raw_output = self._generate(prompt, max_new_tokens=1024)
        parsed = extract_and_validate_json(raw_output, schema_type="plan")
        if parsed.get("steps") and len(parsed["steps"]) > 0:
            self.metrics["valid_decisions"] += 1
        else:
            self.metrics["invalid_decisions"] += 1
        return parsed

    def select_next_action(
        self,
        current_turn: int,
        max_turns: int,
        plan_steps: List[Dict[str, Any]],
        recent_observations: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        prompt = prompts.format_action_selection_prompt(
            current_turn, max_turns, plan_steps, recent_observations, available_tools
        )
        raw_output = self._generate(prompt, max_new_tokens=512)
        parsed = extract_and_validate_json(raw_output, schema_type="action")

        action_type = parsed.get("action_type")
        tool_name = parsed.get("tool_name", "")
        known_tools = {t.get("name") for t in available_tools}

        if action_type in {"complete", "no_action"}:
            self.metrics["abstentions"] += 1
            return parsed
        elif action_type == "execute_tool":
            if tool_name in known_tools:
                self.metrics["valid_decisions"] += 1
                return parsed
            else:
                self.metrics["invalid_decisions"] += 1
                self.metrics["abstentions"] += 1
                return {
                    "action_type": "no_action",
                    "tool_name": "",
                    "arguments": {},
                    "reasoning": f"Model selected unregistered tool '{tool_name}'; abstaining safely.",
                    "error": "UNREGISTERED_TOOL_REJECTED",
                    "raw_output": raw_output,
                }
        else:
            self.metrics["invalid_decisions"] += 1
            self.metrics["abstentions"] += 1
            return {
                "action_type": "no_action",
                "tool_name": "",
                "arguments": {},
                "reasoning": "Model produced invalid action schema; abstaining safely.",
                "error": "INVALID_ACTION_SCHEMA",
                "raw_output": raw_output,
            }

    def analyze_evidence(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        prompt = prompts.format_evidence_analysis_prompt(tool_name, arguments, tool_result)
        raw_output = self._generate(prompt, max_new_tokens=512)
        parsed = extract_and_validate_json(raw_output, schema_type="analysis")

        valid_statuses = {"CONFIRMED", "SUSPECTED", "NOT_DEMONSTRATED", "UNTESTED"}
        if parsed.get("status") in valid_statuses:
            self.metrics["valid_decisions"] += 1
        else:
            self.metrics["invalid_decisions"] += 1
        return parsed

    def generate_report(self, session_summary: Dict[str, Any]) -> str:
        prompt = prompts.format_reporting_prompt(session_summary)
        return self._generate(prompt, max_new_tokens=2048)


class RemoteHttpQwenBrainClient(ModelBrainClient):
    """Client communicating with a GPU-hosted Qwen inference endpoint over HTTP.
    
    Allows a lightweight local Python controller (on Windows without PyTorch/Transformers)
    to interact with the real fine-tuned Qwen model running on a GPU instance (e.g. Kaggle).
    """

    def __init__(
        self,
        endpoint_url: str = "http://127.0.0.1:8000",
        timeout: float = 30.0,
    ):
        self.endpoint_url = endpoint_url.rstrip("/")
        self.timeout = timeout
        self.metrics: Dict[str, Any] = {
            "total_inferences": 0,
            "valid_decisions": 0,
            "invalid_decisions": 0,
            "abstentions": 0,
        }

    def _post(self, route: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        import httpx

        url = f"{self.endpoint_url}/{route.lstrip('/')}"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                self.metrics["total_inferences"] += 1
                if resp.status_code == 200:
                    return resp.json()
                else:
                    self.metrics["invalid_decisions"] += 1
                    return {"error": f"Remote server returned HTTP {resp.status_code}: {resp.text[:300]}"}
        except Exception as exc:
            self.metrics["invalid_decisions"] += 1
            return {"error": f"Remote model inference failure: {str(exc)}"}

    def classify_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        res = self._post("/api/classify", {"request": request_data})
        if "category" in res:
            self.metrics["valid_decisions"] += 1
            return res
        return {"category": "Benign", "error": res.get("error", "Classification failed")}

    def create_test_plan(
        self,
        target_url: str,
        endpoints: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        res = self._post(
            "/api/plan",
            {"target_url": target_url, "endpoints": endpoints, "available_tools": available_tools},
        )
        if res.get("steps"):
            self.metrics["valid_decisions"] += 1
            return res
        return {"plan_title": "Remote Fallback Plan", "steps": [], "error": res.get("error")}

    def select_next_action(
        self,
        current_turn: int,
        max_turns: int,
        plan_steps: List[Dict[str, Any]],
        recent_observations: List[Dict[str, Any]],
        available_tools: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        res = self._post(
            "/api/action",
            {
                "current_turn": current_turn,
                "max_turns": max_turns,
                "plan_steps": plan_steps,
                "recent_observations": recent_observations,
                "available_tools": available_tools,
            },
        )
        if res.get("action_type") in {"execute_tool", "complete", "no_action"}:
            if res.get("action_type") in {"complete", "no_action"}:
                self.metrics["abstentions"] += 1
            else:
                self.metrics["valid_decisions"] += 1
            return res
        self.metrics["abstentions"] += 1
        return {
            "action_type": "no_action",
            "tool_name": "",
            "arguments": {},
            "reasoning": "Remote model connection failure; abstaining safely.",
            "error": res.get("error", "REMOTE_INFERENCE_ERROR"),
        }

    def analyze_evidence(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        res = self._post(
            "/api/analyze",
            {"tool_name": tool_name, "arguments": arguments, "tool_result": tool_result},
        )
        if res.get("status"):
            self.metrics["valid_decisions"] += 1
            return res
        return {
            "status": "NOT_DEMONSTRATED",
            "category": "Uncertain",
            "analysis": "Remote inference failed to return structured evidence analysis.",
            "error": res.get("error"),
        }

    def generate_report(self, session_summary: Dict[str, Any]) -> str:
        res = self._post("/api/report", {"session_summary": session_summary})
        return res.get("report_markdown", "# Audit Report\nRemote report generation unavailable.")


_BRAIN_SINGLETONS: Dict[str, ModelBrainClient] = {}


def clear_cached_brains() -> None:
    """Clear cached brain clients and release memory."""
    global _BRAIN_SINGLETONS
    _BRAIN_SINGLETONS.clear()
    import gc
    gc.collect()


def get_model_brain(
    mode: str = "mock",
    adapter_path: Optional[str] = None,
    base_model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
    endpoint_url: Optional[str] = None,
    model_path: Optional[str] = None,
    reuse_instance: bool = True,
) -> ModelBrainClient:
    """Factory creating or retrieving a cached ModelBrainClient instance."""
    mode_norm = str(mode).strip().lower()
    cache_key = f"{mode_norm}:{base_model_name}:{adapter_path}:{endpoint_url}:{model_path}"

    if reuse_instance and cache_key in _BRAIN_SINGLETONS:
        return _BRAIN_SINGLETONS[cache_key]

    if mode_norm == "mock":
        instance = DeterministicMockBrainClient()
    elif mode_norm in ("local_cpu", "cpu"):
        from controller.brain.local_cpu_client import LocalCpuBrainClient
        instance = LocalCpuBrainClient(model_path=model_path)
    elif mode_norm == "local_qwen":
        instance = LocalQwenBrainClient(base_model_name=base_model_name, adapter_path=adapter_path)
    elif mode_norm == "remote":
        instance = RemoteHttpQwenBrainClient(endpoint_url=endpoint_url or "http://127.0.0.1:8000")
    else:
        raise ValueError(
            f"Unknown brain client mode '{mode}'. Choose 'mock', 'local_cpu', 'local_qwen', or 'remote'."
        )

    if reuse_instance:
        _BRAIN_SINGLETONS[cache_key] = instance
    return instance


