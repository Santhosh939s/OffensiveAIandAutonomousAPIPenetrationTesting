"""
create_stage1_notebook.py
Builds a lightweight Kaggle notebook (< 50 KB) that mounts:
- santhosh939s/offensive-ai-training-stage1 (stage1_train_5000_repaired.jsonl, stage1_val_1000_repaired.jsonl)
- santhosh939s/rebuiltv4-training-checkpoints (checkpoint-200 baseline)
And executes distributed training via finetuning/train_stage1_5000.py.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

script_path = ROOT / "finetuning" / "train_stage1_5000.py"
script_text = script_path.read_text(encoding="utf-8")

cells = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# Offensive AI API Penetration Testing Model — Initial Training Stage (5,000 Records)\n",
            "\n",
            "This notebook executes the initial training stage on 5,000 newly balanced classification records.\n",
            "- Base model: `Qwen/Qwen2.5-1.5B-Instruct`\n",
            "- Model initialization: Preserved Baseline Checkpoint-200 adapter\n",
            "- Training dataset: 5,000 new classification records (625 per class, 0 RebuiltV4 baseline records)\n",
            "- Validation dataset: 1,000 balanced validation records (125 per class)\n",
            "- Hardware: 2x Tesla T4 GPUs via PyTorch DDP (`torchrun --nproc_per_node=2`)\n",
            "- Optimizations: Dynamic sequence batch padding, group_by_length=True, effective batch size 16\n",
            "- Epochs: Exactly 1.0 epoch (313 optimizer steps)\n",
            "- Comparative evaluation: Full metrics (Accuracy, Macro/Weighted F1, Per-class Precision/Recall/F1, Confusion Matrix)\n",
            "  evaluated on identical validation records against the baseline model."
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
            "# 2. Verify Dataset & Adapter Inputs\n",
            "import os\n",
            "from pathlib import Path\n",
            "print('Listing /kaggle/input contents:')\n",
            "for p in sorted(Path('/kaggle/input').glob('*')):\n",
            "    print(' -', p.name)\n",
            "    if p.is_dir():\n",
            "        for sub in sorted(list(p.glob('*')))[:10]:\n",
            "            print('    *', sub.name)\n",
            "\n",
            "# Verify Stage 1 files\n",
            "stage1_dir = Path('/kaggle/input/offensive-ai-training-stage1')\n",
            "train_file = stage1_dir / 'stage1_train_5000_repaired.jsonl'\n",
            "val_file = stage1_dir / 'stage1_val_1000_repaired.jsonl'\n",
            "print(f'Train exists: {train_file.exists()} ({train_file.stat().st_size:,} bytes)' if train_file.exists() else 'Train missing!')\n",
            "print(f'Val exists:   {val_file.exists()} ({val_file.stat().st_size:,} bytes)' if val_file.exists() else 'Val missing!')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 3. Write Optimized Training Script\n",
            "script_file = Path('/kaggle/working/train_stage1_5000.py')\n",
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
            "# 4. Execute Stage 1 Training via Distributed Data Parallel\n",
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
            "        '/kaggle/working/train_stage1_5000.py'\n",
            "    ]\n",
            "else:\n",
            "    cmd = [sys.executable, '/kaggle/working/train_stage1_5000.py']\n",
            "\n",
            "print('Executing:', ' '.join(cmd))\n",
            "res = subprocess.run(cmd, env=env, capture_output=False)\n",
            "if res.returncode != 0:\n",
            "    raise RuntimeError(f'Training failed with exit code {res.returncode}')\n",
            "print('Training and evaluation finished successfully!')\n"
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
            "report_path = Path('/kaggle/working/initial_training_output/initial_training_metrics_report.json')\n",
            "if report_path.exists():\n",
            "    print('=' * 80)\n",
            "    print('INITIAL TRAINING METRICS & COMPARATIVE EVALUATION REPORT:')\n",
            "    print('=' * 80)\n",
            "    print(report_path.read_text(encoding='utf-8'))\n",
            "else:\n",
            "    print('Warning: Metrics report not found.')\n",
            "\n",
            "print('\\nOutput directory artifacts:')\n",
            "for p in sorted(Path('/kaggle/working/initial_training_output').glob('**/*')):\n",
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

out_path = ROOT / "kaggle_kernel" / "urop-offensive-ai.ipynb"
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(notebook, f, indent=1)

print(f"Created notebook at: {out_path} ({out_path.stat().st_size:,} bytes)")
