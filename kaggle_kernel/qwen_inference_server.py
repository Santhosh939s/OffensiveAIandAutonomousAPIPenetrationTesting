"""Phase 4: Lightweight REST API Server for Remote Qwen GPU Inference.

Serves the 4-bit NF4 quantized Qwen2.5-1.5B-Instruct + RebuiltV4 Checkpoint-200 model
over a standard HTTP REST API, allowing the local lightweight Windows controller
(without PyTorch or CUDA) to query the model on a remote Kaggle Tesla T4 GPU instance.

Endpoints:
- GET  /health: Health check, GPU status, VRAM usage
- POST /api/classify: API request classification (8 classes)
- POST /api/plan: OpenAPI autonomous test plan generation
- POST /api/action: ReAct action selection turn
- POST /api/analyze: HTTP response & ZAP evidence analysis
- POST /api/report: Markdown audit report synthesis
"""

import argparse
import os
import sys
import time
from typing import Any, Dict

from flask import Flask, jsonify, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from controller.brain.model_gateway import LocalQwenBrainClient
from kaggle_kernel.phase4_qwen_autonomous_lab import resolve_adapter_path


def create_inference_app(brain: LocalQwenBrainClient) -> Flask:
    app = Flask(__name__)

    @app.route("/health", methods=["GET"])
    def health():
        import torch
        cuda_avail = torch.cuda.is_available()
        vram_gb = round(torch.cuda.memory_allocated() / 1e9, 3) if cuda_avail else 0.0
        return jsonify({
            "status": "healthy",
            "model": brain.base_model_name,
            "adapter": brain.adapter_path,
            "cuda_available": cuda_avail,
            "allocated_vram_gb": vram_gb,
            "metrics": brain.metrics,
        })

    @app.route("/api/classify", methods=["POST"])
    def classify():
        data = request.get_json(force=True)
        req_dict = data.get("request", {})
        result = brain.classify_request(req_dict)
        return jsonify(result)

    @app.route("/api/plan", methods=["POST"])
    def plan():
        data = request.get_json(force=True)
        target_url = data.get("target_url", "http://127.0.0.1:5000")
        endpoints = data.get("endpoints", [])
        available_tools = data.get("available_tools", [])
        result = brain.create_test_plan(target_url, endpoints, available_tools)
        return jsonify(result)

    @app.route("/api/action", methods=["POST"])
    def action():
        data = request.get_json(force=True)
        current_turn = data.get("current_turn", 1)
        max_turns = data.get("max_turns", 10)
        plan_steps = data.get("plan_steps", [])
        recent_obs = data.get("recent_observations", [])
        available_tools = data.get("available_tools", [])
        result = brain.select_next_action(
            current_turn, max_turns, plan_steps, recent_obs, available_tools
        )
        return jsonify(result)

    @app.route("/api/analyze", methods=["POST"])
    def analyze():
        data = request.get_json(force=True)
        tool_name = data.get("tool_name", "")
        arguments = data.get("arguments", {})
        tool_result = data.get("tool_result", {})
        result = brain.analyze_evidence(tool_name, arguments, tool_result)
        return jsonify(result)

    @app.route("/api/report", methods=["POST"])
    def report():
        data = request.get_json(force=True)
        summary = data.get("session_summary", {})
        report_md = brain.generate_report(summary)
        return jsonify({"report_markdown": report_md})

    return app


def main():
    parser = argparse.ArgumentParser(description="Qwen Remote Inference REST Server")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    args = parser.parse_args()

    adapter_path = resolve_adapter_path()
    print("=" * 70)
    print("STARTING QWEN GPU INFERENCE REST SERVER")
    print(f"[*] Base Model: Qwen/Qwen2.5-1.5B-Instruct")
    print(f"[*] Adapter: {adapter_path}")
    print(f"[*] Quantization: 4-bit NF4 (BitsAndBytesConfig)")
    print("=" * 70)

    brain = LocalQwenBrainClient(
        base_model_name="Qwen/Qwen2.5-1.5B-Instruct",
        adapter_path=adapter_path,
        load_in_4bit=True,
    )
    app = create_inference_app(brain)
    print(f"[+] Server ready. Listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

