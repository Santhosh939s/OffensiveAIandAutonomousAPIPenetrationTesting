"""
build_master_cumulative_notebook.py
Assembles all code ever written or executed in this project into a single
cumulative reference Jupyter notebook:
1. All 264 original manual/historical pipeline cells (from git commit 97bf79d).
2. The 6-cell Checkpoint Restoration Verification run.
3. The 9-cell RebuiltV4 Checkpoint-200 Capability Evaluation run.
4. Clean markdown dividers, table of contents, and execution logs.
"""

import subprocess
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT_NOTEBOOK = ROOT / "urop_offensive_ai_master_all_executions.ipynb"

print("1. Extracting original 264 historical cells from Git...")
cmd = ['git', 'show', '97bf79d:kaggle_kernel/urop-offensive-ai.ipynb']
res = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, encoding='utf-8', errors='replace')
if res.returncode != 0:
    raise RuntimeError(f"Git show failed: {res.stderr}")

nb_original = json.loads(res.stdout)
original_cells = nb_original.get("cells", [])
print(f"   Extracted {len(original_cells)} original cells.")

print("2. Loading Restore Verification cells...")
restore_file = ROOT / "urop-offensive-ai.ipynb"
with restore_file.open("r", encoding="utf-8") as f:
    nb_restore = json.load(f)
restore_cells = nb_restore.get("cells", [])
print(f"   Loaded {len(restore_cells)} restore verification cells.")

print("3. Loading Capability Evaluation cells...")
eval_file = ROOT / "capability_eval_kaggle.ipynb"
with eval_file.open("r", encoding="utf-8") as f:
    nb_eval = json.load(f)
eval_cells = nb_eval.get("cells", [])
print(f"   Loaded {len(eval_cells)} capability evaluation cells.")

# Build master cells list with clear section dividers
master_cells = []

# Master Header Cell
header_md = {
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "# UROP Offensive AI & Autonomous API Penetration Testing\n",
        "## Master Cumulative Code Repository (All Executions & Historical Code)\n",
        "\n",
        "> **Repository Policy:** This notebook is a **cumulative, append-only reference archive** containing all code ever written, manually executed, or run in Kaggle GPU environments across the entire lifecycle of this project.\n",
        ">\n",
        "> **Table of Contents:**\n",
        "> 1. **Part I: Historical Pipeline & Manual Explorations (Cells 1 to 264)**\n",
        ">    * ATRDF Datasets 1–4 ingestion, exploratory data analysis, and field inspection\n",
        ">    * Header cleaning, URL decoding, and payload normalization\n",
        ">    * `rebuilt_v1`, `rebuilt_v2`, and `rebuilt_v3` data rebuilding\n",
        ">    * Leakage detection and cryptographic hash-group split allocation\n",
        ">    * 9,000-record balanced subset creation for RebuiltV4 (Cell 199)\n",
        ">    * RebuiltV4 LoRA fine-tuning (Cells 201–210), training logs, and evaluations\n",
        "> 2. **Part II: Execution Run — Checkpoint Restoration & Health Verification (6 Cells)**\n",
        ">    * Cryptographic checksums, adapter integrity, optimizer/scaler/scheduler verification\n",
        "> 3. **Part III: Execution Run — RebuiltV4 Checkpoint-200 Capability Evaluation (9 Cells)**\n",
        ">    * 20-case multi-task capability benchmark across Capabilities A, B, C, D, E on Kaggle dual T4 GPU\n",
        "> 4. **Part IV: Future Runs (RebuiltV5 Pilot Multi-Task Training, etc.)**\n"
    ]
}
master_cells.append(header_md)

# Divider for Part I
master_cells.append({
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "---\n",
        "# ======================================================================\n",
        "# PART I: ORIGINAL MANUAL CODE & HISTORICAL REBUILTV4 PIPELINE (264 CELLS)\n",
        "# ======================================================================\n",
        "> The following 264 cells represent the complete original research and development notebook,\n",
        "> including all dataset preparation, feature extraction, RebuiltV1–V4 scripts, and initial runs.\n"
    ]
})

# Add all 264 original cells
master_cells.extend(original_cells)

# Divider for Part II
master_cells.append({
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "---\n",
        "# ======================================================================\n",
        "# PART II: EXECUTION RUN — CHECKPOINT RESTORATION & HEALTH VERIFICATION\n",
        "# ======================================================================\n",
        "> Executed successfully on Kaggle (Version 18). Verified Checkpoint-200 and Checkpoint-300\n",
        "> adapter weights, optimizer states, schedulers, scalers, and trainer states.\n"
    ]
})

# Add all 6 restore verification cells
master_cells.extend(restore_cells)

# Divider for Part III
master_cells.append({
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "---\n",
        "# ======================================================================\n",
        "# PART III: EXECUTION RUN — REBUILTV4 CHECKPOINT-200 CAPABILITY EVALUATION\n",
        "# ======================================================================\n",
        "> Executed successfully on Kaggle dual Tesla T4 GPU (Version 21).\n",
        "> Evaluated Checkpoint-200 across 20 held-out cases spanning 5 core capabilities.\n"
    ]
})

# Add all 9 capability evaluation cells
master_cells.extend(eval_cells)

# Divider for Part IV (Placeholder for RebuiltV5 Pilot and future runs)
master_cells.append({
    "cell_type": "markdown",
    "metadata": {},
    "source": [
        "---\n",
        "# ======================================================================\n",
        "# PART IV: UPCOMING RUNS — REBUILTV5 MULTI-TASK PILOT (APPEND-ONLY)\n",
        "# ======================================================================\n",
        "> Future execution cells (e.g. RebuiltV5 Pilot multi-task training on dual Tesla T4 GPUs)\n",
        "> will be appended here after successful execution.\n"
    ]
})

master_notebook = {
    "cells": master_cells,
    "metadata": nb_original.get("metadata", {
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.10.12"
        }
    }),
    "nbformat": 4,
    "nbformat_minor": 5
}

print(f"4. Writing master cumulative notebook to {OUTPUT_NOTEBOOK}...")
with OUTPUT_NOTEBOOK.open("w", encoding="utf-8") as f:
    json.dump(master_notebook, f, indent=1, ensure_ascii=False)

print(f"   Successfully written! Total cells in master notebook: {len(master_cells)}")
