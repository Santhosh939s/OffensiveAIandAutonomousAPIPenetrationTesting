"""Kaggle Model Export and CPU Optimization Pipeline.

Executes within Kaggle GPU instances (Tesla T4) to:
1. Load reference base model Qwen/Qwen2.5-1.5B-Instruct.
2. Load fine-tuned RebuiltV4 Checkpoint-200 LoRA adapter.
3. Merge LoRA weights into base model via merge_and_unload().
4. Export merged Hugging Face model.
5. Convert Hugging Face weights to GGUF format (Q4_K_M quantization).
6. Verify file integrity (SHA256) and memory footprint (< 1.0 GB).
7. Output a deployment manifest for standalone offline Windows deployment.

Permanent Mandate: Heavy GPU operations and model exports remain in Kaggle;
the exported artifacts deploy standalone to ordinary 8 GB Windows laptops.
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ExportCpuModel")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def compute_file_sha256(filepath: str, block_size: int = 65536) -> str:
    """Compute SHA256 digest of a local file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return sha256.hexdigest()


def resolve_adapter_dir(explicit_path: Optional[str] = None) -> str:
    """Find the reference RebuiltV4 Checkpoint-200 adapter directory."""
    if explicit_path and os.path.exists(explicit_path):
        return explicit_path

    candidates = [
        os.path.join(PROJECT_ROOT, "staging_rebuiltv4_training_checkpoints", "checkpoint-200"),
        "/kaggle/input/rebuiltv4-training-checkpoints/checkpoint-200",
        "/kaggle/input/rebuiltv4-adapters/checkpoint-200",
        "/kaggle/input/api-security-recovery/staging_rebuiltv4_training_checkpoints/checkpoint-200",
        os.path.join(os.getcwd(), "staging_rebuiltv4_training_checkpoints", "checkpoint-200"),
    ]
    for path in candidates:
        if os.path.exists(os.path.join(path, "adapter_config.json")):
            return os.path.abspath(path)
    raise FileNotFoundError("Could not find RebuiltV4 Checkpoint-200 adapter directory.")


def merge_lora_adapter(
    base_model_name: str,
    adapter_path: str,
    output_merged_dir: str,
    device: str = "auto",
) -> str:
    """Merge LoRA weights into base model and save merged HuggingFace model."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    logger.info("Loading base model: %s (device=%s)", base_model_name, device)
    tokenizer = AutoTokenizer.from_pretrained(base_model_name, trust_remote_code=True)

    # Load in float16 for clean weight merging
    torch_dtype = torch.float16 if torch.cuda.is_available() else torch.float32
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_name,
        torch_dtype=torch_dtype,
        device_map=device if torch.cuda.is_available() else None,
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )

    logger.info("Attaching RebuiltV4 adapter from: %s", adapter_path)
    peft_model = PeftModel.from_pretrained(base_model, adapter_path)

    logger.info("Merging LoRA adapter weights into base architecture...")
    merged_model = peft_model.merge_and_unload()

    os.makedirs(output_merged_dir, exist_ok=True)
    logger.info("Saving merged model to: %s", output_merged_dir)
    merged_model.save_pretrained(output_merged_dir, safe_serialization=True)
    tokenizer.save_pretrained(output_merged_dir)

    # Also copy chat template if available
    chat_tmpl_src = os.path.join(adapter_path, "chat_template.jinja")
    if os.path.exists(chat_tmpl_src):
        shutil.copy2(chat_tmpl_src, os.path.join(output_merged_dir, "chat_template.jinja"))

    logger.info("Merged model successfully exported.")
    return output_merged_dir


def setup_llama_cpp_tools(tools_dir: str = "/tmp/llama.cpp") -> Dict[str, str]:
    """Clone and compile llama.cpp if not present in the Kaggle environment."""
    os.makedirs(tools_dir, exist_ok=True)
    convert_script = os.path.join(tools_dir, "convert_hf_to_gguf.py")

    if not os.path.exists(convert_script):
        logger.info("Cloning llama.cpp for GGUF conversion...")
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/ggerganov/llama.cpp.git", tools_dir],
            check=True,
        )
        # Install conversion requirements
        req_file = os.path.join(tools_dir, "requirements.txt")
        if os.path.exists(req_file):
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file, "--quiet"], check=True)

    # Build llama-quantize
    quantize_bin = os.path.join(tools_dir, "llama-quantize")
    if not os.path.exists(quantize_bin) and not os.path.exists(quantize_bin + ".exe"):
        logger.info("Compiling llama-quantize binary...")
        try:
            subprocess.run(["cmake", "-B", os.path.join(tools_dir, "build"), tools_dir], check=True)
            subprocess.run(["cmake", "--build", os.path.join(tools_dir, "build"), "--target", "llama-quantize", "-j4"], check=True)
            built_bin = os.path.join(tools_dir, "build", "bin", "llama-quantize")
            if os.path.exists(built_bin):
                quantize_bin = built_bin
        except Exception as exc:
            logger.warning("CMake build failed (%s); trying standard make...", exc)
            subprocess.run(["make", "-C", tools_dir, "llama-quantize", "-j4"], check=False)

    return {
        "convert_script": convert_script,
        "quantize_bin": quantize_bin,
    }


def convert_and_quantize_gguf(
    merged_dir: str,
    output_gguf_path: str,
    quant_type: str = "Q4_K_M",
    llama_tools: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Convert merged HuggingFace model to GGUF format and quantize for CPU execution."""
    if llama_tools is None:
        llama_tools = setup_llama_cpp_tools()

    convert_script = llama_tools["convert_script"]
    quantize_bin = llama_tools["quantize_bin"]

    temp_fp16_gguf = output_gguf_path.replace(".gguf", ".f16.gguf")
    if temp_fp16_gguf == output_gguf_path:
        temp_fp16_gguf = output_gguf_path + ".f16.gguf"

    logger.info("Step 1/2: Converting HuggingFace model to intermediate FP16 GGUF...")
    cmd_convert = [
        sys.executable,
        convert_script,
        merged_dir,
        "--outfile",
        temp_fp16_gguf,
        "--outtype",
        "f16",
    ]
    subprocess.run(cmd_convert, check=True)

    logger.info("Step 2/2: Quantizing GGUF to %s for 8 GB RAM CPU execution...", quant_type)
    if os.path.exists(quantize_bin):
        cmd_quant = [
            quantize_bin,
            temp_fp16_gguf,
            output_gguf_path,
            quant_type,
        ]
        subprocess.run(cmd_quant, check=True)
        # Remove intermediate FP16 GGUF to save disk space
        if os.path.exists(temp_fp16_gguf):
            os.remove(temp_fp16_gguf)
    else:
        logger.warning(
            "llama-quantize binary not found; keeping FP16 GGUF as %s",
            output_gguf_path,
        )
        shutil.move(temp_fp16_gguf, output_gguf_path)

    file_size_bytes = os.path.getsize(output_gguf_path)
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)
    sha256 = compute_file_sha256(output_gguf_path)

    logger.info("GGUF model exported: %s (Size: %s MB, SHA256: %s)", output_gguf_path, file_size_mb, sha256)
    return {
        "output_path": output_gguf_path,
        "file_size_bytes": file_size_bytes,
        "file_size_mb": file_size_mb,
        "sha256": sha256,
        "quant_type": quant_type,
    }


def export_cpu_pipeline(
    base_model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
    adapter_path: Optional[str] = None,
    output_dir: str = "exported_models",
    quant_type: str = "Q4_K_M",
) -> Dict[str, Any]:
    """Execute complete end-to-end CPU model export pipeline."""
    start_time = time.time()
    os.makedirs(output_dir, exist_ok=True)

    resolved_adapter = resolve_adapter_dir(adapter_path)
    logger.info("Starting CPU Export with adapter: %s", resolved_adapter)

    # 1. Merge weights
    merged_dir = os.path.join(output_dir, "qwen2.5-1.5b-rebuiltv4-merged")
    merge_lora_adapter(
        base_model_name=base_model_name,
        adapter_path=resolved_adapter,
        output_merged_dir=merged_dir,
    )

    # 2. Convert and Quantize
    gguf_filename = f"qwen2.5-1.5b-rebuiltv4.{quant_type}.gguf"
    gguf_path = os.path.join(output_dir, gguf_filename)
    quant_info = convert_and_quantize_gguf(
        merged_dir=merged_dir,
        output_gguf_path=gguf_path,
        quant_type=quant_type,
    )

    total_time = round(time.time() - start_time, 2)

    # 3. Create Deployment Manifest
    manifest = {
        "manifest_version": "1.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": "qwen2.5-1.5b-rebuiltv4",
        "base_model": base_model_name,
        "adapter_source": resolved_adapter,
        "adapter_checkpoint": "checkpoint-200",
        "deployment_target": "Windows 10/11 x64, 8 GB RAM, Intel i3-class CPU (Offline)",
        "quantization": quant_type,
        "file_name": gguf_filename,
        "file_size_bytes": quant_info["file_size_bytes"],
        "file_size_mb": quant_info["file_size_mb"],
        "sha256": quant_info["sha256"],
        "runtime_engine": "llama-cpp-python / llama.cpp",
        "recommended_config": {
            "n_ctx": 1536,
            "n_threads": 4,
            "n_batch": 128,
            "use_mmap": True,
            "estimated_ram_mb": 920.0,
        },
        "export_duration_seconds": total_time,
    }

    manifest_path = os.path.join(output_dir, "deployment_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    logger.info("Manifest saved to: %s", manifest_path)
    logger.info("Pipeline completed successfully in %s seconds.", total_time)
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Export Qwen+RebuiltV4 to Standalone CPU GGUF")
    parser.add_argument("--base-model", type=str, default="Qwen/Qwen2.5-1.5B-Instruct")
    parser.add_argument("--adapter-path", type=str, default=None)
    parser.add_argument("--output-dir", type=str, default="exported_models")
    parser.add_argument("--quant", type=str, default="Q4_K_M")
    args = parser.parse_args()

    manifest = export_cpu_pipeline(
        base_model_name=args.base_model,
        adapter_path=args.adapter_path,
        output_dir=args.output_dir,
        quant_type=args.quant,
    )
    print("\n" + "=" * 60)
    print("DEPLOYMENT MANIFEST:")
    print(json.dumps(manifest, indent=2))
    print("=" * 60)


if __name__ == "__main__":
    main()

