"""
create_resumption_notebook.py
Generates the Kaggle resumption notebook and metadata for:
- Resuming 30,000-record training from Checkpoint-1250 (steps 1,251 to 1,875)
- Mounting checkpoint-1250 from santhosh939s/offensive-ai-checkpoint-1250
- Mounting 30k training and validation datasets from santhosh939s/offensive-ai-classification-training
- Mounting quarantined independent test set from santhosh939s/offensive-ai-quarantined-test
- Running 2x Tesla T4 DDP distributed training
"""

import os
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Read resume_expanded_classification.py
script_file = ROOT / "finetuning" / "resume_expanded_classification.py"
script_text = script_file.read_text(encoding="utf-8")

cells = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# Offensive AI API Security — Resumed 30,000-Record Training Experiment\n",
            "\n",
            "This notebook executes the exact resumption of the 30,000-record classification training:\n",
            "- Resumption Checkpoint: `checkpoint-1250` (Step 1,250 of 1,875, loss=1.816e-5, epoch=0.6667)\n",
            "- Remaining Workload: Exactly 625 optimizer steps (Steps 1,251 to 1,875, ~10,000 records)\n",
            "- Hardware: 2x Tesla T4 GPUs via PyTorch DDP (`torchrun --nproc_per_node=2`)\n",
            "- Preserved Optimizer & Scheduler: Restored exactly from AdamW `optimizer.pt` and cosine `scheduler.pt`\n",
            "- Checkpoint Interval: Every 125 steps (1375, 1500, 1625, 1750, 1875)\n",
            "- Immediate Save: `classification_training_checkpoint_final` saved immediately before evaluations\n",
            "- Evaluation Benchmarks:\n",
            "  1. Original Validation Benchmark (1,000 records)\n",
            "  2. Corrected Validation Benchmark (1,000 records)\n",
            "  3. XSS/RCE Boundary Contrast Diagnostic Subset (700 records)\n",
            "  4. Quarantined Independent Test Benchmark (`master_test_4100_repaired.jsonl`)"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 1. Environment & Dependencies Setup\n",
            "!nvidia-smi\n",
            "!pip install -q bitsandbytes accelerate peft transformers datasets psutil scikit-learn\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 2. Verify Mounted Kaggle Inputs\n",
            "import os\n",
            "from pathlib import Path\n",
            "\n",
            "print('Listing /kaggle/input structure:')\n",
            "input_root = Path('/kaggle/input')\n",
            "if input_root.exists():\n",
            "    for d in sorted(input_root.iterdir()):\n",
            "        print(f' * {d.name}/')\n",
            "        if d.is_dir():\n",
            "            for f in sorted(list(d.glob('**/*')))[:15]:\n",
            "                if f.is_file():\n",
            "                    print(f'     - {f.relative_to(d)} ({f.stat().st_size:,} bytes)')\n",
            "else:\n",
            "    print('Warning: /kaggle/input does not exist!')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 3. Write Resumption Training & Evaluation Script\n",
            "from pathlib import Path\n",
            "\n",
            "script_file = Path('/kaggle/working/resume_expanded_classification.py')\n",
            "script_file.write_text(" + json.dumps(script_text) + ", encoding='utf-8')\n",
            "print(f'Wrote {script_file.name}: {script_file.stat().st_size:,} bytes')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 4. Execute Resumed Training via 2x Tesla T4 PyTorch DDP\n",
            "import subprocess\n",
            "import sys\n",
            "import os\n",
            "import torch\n",
            "\n",
            "env = os.environ.copy()\n",
            "for k in ['RANK', 'LOCAL_RANK', 'WORLD_SIZE', 'MASTER_ADDR', 'MASTER_PORT']:\n",
            "    env.pop(k, None)\n",
            "env['CUDA_VISIBLE_DEVICES'] = '0,1'\n",
            "env['TOKENIZERS_PARALLELISM'] = 'false'\n",
            "env['OMP_NUM_THREADS'] = '4'\n",
            "\n",
            "num_gpus = torch.cuda.device_count() if torch.cuda.is_available() else 0\n",
            "print(f'Detected available GPU count: {num_gpus}')\n",
            "\n",
            "if num_gpus > 1:\n",
            "    cmd = [\n",
            "        'torchrun',\n",
            "        '--standalone',\n",
            "        '--nnodes=1',\n",
            "        f'--nproc_per_node={num_gpus}',\n",
            "        '/kaggle/working/resume_expanded_classification.py'\n",
            "    ]\n",
            "else:\n",
            "    cmd = [sys.executable, '/kaggle/working/resume_expanded_classification.py']\n",
            "\n",
            "print('Executing:', ' '.join(cmd))\n",
            "res = subprocess.run(cmd, env=env, capture_output=False)\n",
            "if res.returncode != 0:\n",
            "    raise RuntimeError(f'Resumed training failed with exit code {res.returncode}')\n",
            "print('Resumed training and comprehensive evaluation finished successfully!')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 5. Display Metrics Report & Artifact Files\n",
            "import json\n",
            "from pathlib import Path\n",
            "\n",
            "report_path = Path('/kaggle/working/classification_training_output/classification_training_metrics_report.json')\n",
            "if report_path.exists():\n",
            "    print('=' * 80)\n",
            "    print('FINAL CLASSIFICATION TRAINING METRICS REPORT:')\n",
            "    print('=' * 80)\n",
            "    print(report_path.read_text(encoding='utf-8'))\n",
            "else:\n",
            "    print('Warning: Metrics report not found!')\n",
            "\n",
            "print('\\nClassification training output directory contents:')\n",
            "for p in sorted(Path('/kaggle/working/classification_training_output').glob('**/*')):\n",
            "    if p.is_file():\n",
            "        print(f'{p.relative_to(\"/kaggle/working\")}: {p.stat().st_size:,} bytes')\n"
        ]
    }
]

notebook = {
    "cells": cells,
    "metadata": {
        "accelerator": "GPU",
        "colab": {
            "provenance": []
        },
        "kernelspec": {
            "display_name": "Python 3",
            "language": "python",
            "name": "python3"
        },
        "language_info": {
            "name": "python",
            "version": "3.10"
        }
    },
    "nbformat": 4,
    "nbformat_minor": 4
}

out_nb = ROOT / "kaggle_kernel" / "offensive-ai-completion.ipynb"
with open(out_nb, "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=1)

print(f"Created notebook at {out_nb} ({out_nb.stat().st_size:,} bytes)")

# Update kernel-metadata.json
metadata = {
    "id": "santhosh939s/offensive-ai-completion",
    "title": "Offensive AI Completion",
    "code_file": "offensive-ai-completion.ipynb",
    "language": "python",
    "kernel_type": "notebook",
    "is_private": False,
    "enable_gpu": True,
    "enable_tpu": False,
    "enable_internet": True,
    "dataset_sources": [
        "santhosh939s/offensive-ai-classification-training",
        "santhosh939s/offensive-ai-quarantined-test",
        "santhosh939s/offensive-ai-checkpoint-1250"
    ],
    "kernel_sources": [],
    "competition_sources": [],
    "model_sources": []
}

out_meta = ROOT / "kaggle_kernel" / "kernel-metadata.json"
with open(out_meta, "w", encoding="utf-8") as f:
    json.dump(metadata, f, indent=2)

print(f"Updated metadata at {out_meta}")
