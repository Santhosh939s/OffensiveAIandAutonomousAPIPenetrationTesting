"""
scripts/merge_quantize_deliver.py - Complete LoRA Merge, GGUF Q4_K_M Quantization & Local CPU Verification
"""

import os
import sys
import json
import time
import shutil
import hashlib
import argparse
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def compute_file_sha256(filepath: str, block_size: int = 65536) -> str:
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(block_size), b""):
            sha256.update(block)
    return sha256.hexdigest()

def merge_and_export_gguf(
    adapter_path: Path,
    base_model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
    output_dir: Path = PROJECT_ROOT / "exported_models",
    target_models_dir: Path = PROJECT_ROOT / "models",
    quant_type: str = "Q4_K_M"
):
    print("=" * 80)
    print("STARTING LO-RA MERGE & CPU GGUF QUANTIZATION PIPELINE")
    print("=" * 80)
    print(f"Base Model:       {base_model_name}")
    print(f"LoRA Adapter:     {adapter_path}")
    print(f"Export Dir:       {output_dir}")
    print(f"Models Dir:       {target_models_dir}")
    print(f"Quantization:     {quant_type}")

    if not adapter_path.exists():
        raise FileNotFoundError(f"Adapter directory not found at: {adapter_path}")

    output_dir.mkdir(parents=True, exist_ok=True)
    target_models_dir.mkdir(parents=True, exist_ok=True)

    # 1. Inspect adapter files
    print("\n--- Step 1: Adapter Verification ---")
    adapter_files = list(adapter_path.iterdir())
    for f in adapter_files:
        if f.is_file():
            size_mb = f.stat().st_size / (1024 * 1024)
            sha = compute_file_sha256(str(f)) if f.stat().st_size < 100 * 1024 * 1024 else "calculating..."
            print(f"  {f.name} ({size_mb:.2f} MB) - SHA256: {sha}")

    # 2. Merge LoRA adapter into base model
    print("\n--- Step 2: Merging LoRA Weights into Base Architecture ---")
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from peft import PeftModel

    merged_model_dir = output_dir / "qwen2.5-1.5b-classification-merged"
    adapter_marker = merged_model_dir / ".adapter_source.json"
    needs_merge = True
    if (merged_model_dir / "model.safetensors").exists() and adapter_marker.exists():
        try:
            marker_data = json.loads(adapter_marker.read_text(encoding="utf-8"))
            if marker_data.get("adapter_path") == str(adapter_path.resolve()):
                needs_merge = False
                print(f"Merged model already exists and matches adapter: {merged_model_dir}")
        except Exception:
            needs_merge = True

    if needs_merge:
        if merged_model_dir.exists():
            shutil.rmtree(str(merged_model_dir))
        merged_model_dir.mkdir(parents=True, exist_ok=True)
        print(f"Loading base model {base_model_name} in float16 (memory-efficient for 8GB RAM)...")
        tokenizer = AutoTokenizer.from_pretrained(str(adapter_path), trust_remote_code=True)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        base_model = AutoModelForCausalLM.from_pretrained(
            base_model_name,
            torch_dtype=torch.float16,
            low_cpu_mem_usage=True,
            trust_remote_code=True
        )

        print(f"Attaching LoRA adapter from {adapter_path}...")
        peft_model = PeftModel.from_pretrained(base_model, str(adapter_path))

        print("Executing merge_and_unload()...")
        merged_model = peft_model.merge_and_unload()

        print(f"Saving merged model to {merged_model_dir}...")
        merged_model.save_pretrained(str(merged_model_dir), safe_serialization=True)
        tokenizer.save_pretrained(str(merged_model_dir))
        adapter_marker.write_text(json.dumps({"adapter_path": str(adapter_path.resolve()), "merged_at": time.time()}))
        print("Merged model successfully exported.")
        del merged_model, base_model, peft_model
        import gc
        gc.collect()

    # 3. Intermediate GGUF Conversion
    print("\n--- Step 3: Intermediate GGUF (FP16) Conversion ---")
    convert_script = PROJECT_ROOT / "scripts" / "llama_cpp_tools" / "convert_hf_to_gguf.py"
    if not convert_script.exists():
        raise FileNotFoundError(f"convert_hf_to_gguf.py not found at: {convert_script}")

    temp_fp16_gguf = output_dir / "qwen2.5-1.5b-classification.f16.gguf"
    if not temp_fp16_gguf.exists():
        print(f"Running conversion: {convert_script} -> {temp_fp16_gguf}")
        convert_cmd = [
            sys.executable,
            str(convert_script),
            str(merged_model_dir),
            "--outfile",
            str(temp_fp16_gguf),
            "--outtype",
            "f16",
        ]
        subprocess.run(convert_cmd, check=True)
        print(f"Intermediate FP16 GGUF created: {temp_fp16_gguf.stat().st_size / (1024*1024):.2f} MB")
    else:
        print(f"Intermediate FP16 GGUF already exists at {temp_fp16_gguf}.")

    # 4. Quantize to Q4_K_M
    print(f"\n--- Step 4: Quantizing to {quant_type} ---")
    llama_quantize = shutil.which("llama-quantize.exe") or shutil.which("llama-quantize")
    if not llama_quantize:
        candidate = Path(r"C:\Users\santhosh\AppData\Local\Microsoft\WinGet\Packages\ggml.llamacpp_Microsoft.Winget.Source_8wekyb3d8bbwe\llama-quantize.exe")
        if candidate.exists():
            llama_quantize = str(candidate)

    if not llama_quantize:
        raise FileNotFoundError("llama-quantize binary not found in PATH or standard packages.")

    final_gguf_name = f"qwen2.5-1.5b-offensive-ai.{quant_type}.gguf"
    final_gguf_in_models = target_models_dir / final_gguf_name
    final_gguf_in_root = PROJECT_ROOT / final_gguf_name

    print(f"Quantizing via {llama_quantize} -> {final_gguf_in_models}...")
    quant_cmd = [
        llama_quantize,
        str(temp_fp16_gguf),
        str(final_gguf_in_models),
        quant_type
    ]
    subprocess.run(quant_cmd, check=True)

    # Clean up intermediate FP16 file to conserve disk space
    if temp_fp16_gguf.exists():
        temp_fp16_gguf.unlink()
        print(f"Cleaned up intermediate file {temp_fp16_gguf.name}")

    # Copy to root workspace
    shutil.copy2(str(final_gguf_in_models), str(final_gguf_in_root))
    print(f"Copied final GGUF to root workspace: {final_gguf_in_root}")

    # 5. Model Verification & Telemetry
    print("\n--- Step 5: Final Model Integrity & Telemetry ---")
    file_size_bytes = final_gguf_in_models.stat().st_size
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)
    file_size_gb = round(file_size_bytes / (1024 * 1024 * 1024), 3)
    sha256_hash = compute_file_sha256(str(final_gguf_in_models))

    print(f"Final Model:      {final_gguf_in_models}")
    print(f"Size:             {file_size_mb} MB ({file_size_gb} GB)")
    print(f"SHA-256:          {sha256_hash}")

    # Generate Manifest
    manifest = {
        "manifest_version": "2.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_id": "qwen2.5-1.5b-offensive-ai",
        "base_model": base_model_name,
        "adapter_source": str(adapter_path),
        "quantization": quant_type,
        "file_name": final_gguf_name,
        "file_size_bytes": file_size_bytes,
        "file_size_mb": file_size_mb,
        "sha256": sha256_hash,
        "runtime_engine": "llama.cpp / llama-cli",
        "recommended_config": {
            "n_ctx": 4096,
            "n_threads": 4,
            "n_batch": 128,
            "use_mmap": True,
            "estimated_ram_mb": file_size_mb + 100.0,
        }
    }
    manifest_path = target_models_dir / "qwen2.5-1.5b-offensive-ai.manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Saved deployment manifest to: {manifest_path}")

    # 6. Real Local Inference Test
    print("\n--- Step 6: Real Standalone CPU Local Inference Test ---")
    sys.path.insert(0, str(PROJECT_ROOT))
    from controller.brain.local_cpu_client import LocalCpuBrainClient

    # Enforce strictly no mock fallback
    client = LocalCpuBrainClient(
        model_path=str(final_gguf_in_models),
        allow_mock_fallback=False
    )
    print(f"Local client initialized. Active engine: {client.engine} (Mock fallback allowed: {client.allow_mock_fallback})")
    assert client.engine == "llama_cli", f"Expected llama_cli engine, got {client.engine}"

    test_queries = [
        {
            "name": "Benign Query",
            "request": {
                "method": "GET",
                "path": "/api/v1/products?category=electronics&sort=asc",
                "headers": {"Accept": "application/json"},
                "body": {},
                "cookies": {}
            },
            "expected_category": "Benign"
        },
        {
            "name": "SQL Injection Query",
            "request": {
                "method": "POST",
                "path": "/api/v1/auth/login",
                "headers": {"Content-Type": "application/json"},
                "body": {"username": "admin' OR '1'='1' --", "password": "x"},
                "cookies": {}
            },
            "expected_category": "SQL Injection"
        },
        {
            "name": "XSS Query",
            "request": {
                "method": "POST",
                "path": "/comments",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": {"comment": "<script>alert(document.cookie)</script>"},
                "cookies": {}
            },
            "expected_category": "XSS"
        },
        {
            "name": "RCE Query",
            "request": {
                "method": "POST",
                "path": "/tools/ping",
                "headers": {"Content-Type": "application/json"},
                "body": {"host": "127.0.0.1; cat /etc/passwd"},
                "cookies": {}
            },
            "expected_category": "RCE"
        },
        {
            "name": "Directory Traversal Query",
            "request": {
                "method": "GET",
                "path": "/files?path=../../../../etc/shadow",
                "headers": {},
                "body": {},
                "cookies": {}
            },
            "expected_category": "Directory Traversal"
        }
    ]

    results = []
    for tq in test_queries:
        t0 = time.time()
        classification = client.classify_request(tq["request"])
        dur = time.time() - t0
        predicted = classification.get("category")
        confidence = classification.get("confidence")
        print(f"Test [{tq['name']}]: Predicted: '{predicted}' (Expected: {tq['expected_category']}) in {dur:.2f}s | Confidence: {confidence}")
        results.append({
            "test": tq["name"],
            "expected": tq["expected_category"],
            "predicted": predicted,
            "confidence": confidence,
            "latency_seconds": round(dur, 2)
        })

    print("\n" + "=" * 80)
    print("ALL STEPS COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    return manifest, results

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter-dir", type=str, required=True, help="Path to final adapter directory")
    args = parser.parse_args()
    merge_and_export_gguf(Path(args.adapter_dir))

