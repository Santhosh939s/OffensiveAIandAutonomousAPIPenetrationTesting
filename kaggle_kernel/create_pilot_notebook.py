"""
create_pilot_notebook.py
Builds a self-contained Kaggle notebook embedding pilot_train_800.jsonl,
pilot_val_100.jsonl, and train_phase_c_pilot.py, then saves to kaggle_kernel/urop-offensive-ai.ipynb.
"""

import json
import gzip
import base64
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

train_path = ROOT / "dataset" / "splits" / "pilot_train_800.jsonl"
val_path = ROOT / "dataset" / "splits" / "pilot_val_100.jsonl"
script_path = ROOT / "finetuning" / "train_phase_d_optimized.py"

train_bytes = train_path.read_bytes()
val_bytes = val_path.read_bytes()
script_text = script_path.read_text(encoding="utf-8")

train_b64_gz = base64.b64encode(gzip.compress(train_bytes)).decode("ascii")
val_b64_gz = base64.b64encode(gzip.compress(val_bytes)).decode("ascii")

cells = [
    {
        "cell_type": "markdown",
        "metadata": {},
        "source": [
            "# Model Phase D: 1,000-Record Throughput Optimization Benchmark (Version 29)\n",
            "\n",
            "This notebook executes the optimized 1,000-sample pilot benchmark for Phase D.\n",
            "- Base model: `Qwen/Qwen2.5-1.5B-Instruct`\n",
            "- Initialization: `RebuiltV4 Checkpoint-200`\n",
            "- Quantization: 4-bit NF4 double-quantization\n",
            "- Optimizations: Dynamic sequence batch padding, group_by_length=True, batch size 2, clean DDP synchronization\n",
            "- Effective batch size: 16 (2 GPUs x batch 2 x accum 4), 1 epoch\n",
            "- Metrics: Step loss, peak VRAM per GPU, padding ratio, accuracy, macro F1, reload verification"
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
            "# 2. Extract Pilot Datasets\n",
            "import base64\n",
            "import gzip\n",
            "from pathlib import Path\n",
            "\n",
            f"train_b64 = '{train_b64_gz}'\n",
            f"val_b64 = '{val_b64_gz}'\n",
            "\n",
            "train_file = Path('/kaggle/working/pilot_train_800.jsonl')\n",
            "val_file = Path('/kaggle/working/pilot_val_100.jsonl')\n",
            "\n",
            "train_file.write_bytes(gzip.decompress(base64.b64decode(train_b64)))\n",
            "val_file.write_bytes(gzip.decompress(base64.b64decode(val_b64)))\n",
            "\n",
            "print(f'Wrote {train_file.name}: {train_file.stat().st_size} bytes')\n",
            "print(f'Wrote {val_file.name}: {val_file.stat().st_size} bytes')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 3. Write Optimized Training Script\n",
            "script_file = Path('/kaggle/working/train_phase_d_optimized.py')\n",
            "script_file.write_text(" + json.dumps(script_text) + ", encoding='utf-8')\n",
            "print(f'Wrote {script_file.name}: {script_file.stat().st_size} bytes')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 4. Check Dataset & Adapter Inputs\n",
            "import os\n",
            "from pathlib import Path\n",
            "print('Listing /kaggle/input contents:')\n",
            "for p in Path('/kaggle/input').glob('*'):\n",
            "    print(' -', p)\n",
            "    if p.is_dir():\n",
            "        for sub in list(p.glob('*'))[:10]:\n",
            "            print('    *', sub)\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 5. Execute Optimized Pilot Training & Benchmark\n",
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
            "        '/kaggle/working/train_phase_d_optimized.py'\n",
            "    ]\n",
            "else:\n",
            "    cmd = [sys.executable, '/kaggle/working/train_phase_d_optimized.py']\n",
            "\n",
            "print('Executing:', ' '.join(cmd))\n",
            "res = subprocess.run(cmd, env=env, capture_output=False)\n",
            "if res.returncode != 0:\n",
            "    raise RuntimeError(f'Training failed with exit code {res.returncode}')\n",
            "print('Training finished successfully!')\n"
        ]
    },
    {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [
            "# 6. Display Telemetry Report & Checkpoint Files\n",
            "import json\n",
            "from pathlib import Path\n",
            "\n",
            "report_path = Path('/kaggle/working/qwen_pilot_phase_d_output/pilot_telemetry_metrics.json')\n",
            "if report_path.exists():\n",
            "    print('=' * 60)\n",
            "    print('PHASE D OPTIMIZED TELEMETRY REPORT:')\n",
            "    print('=' * 60)\n",
            "    print(report_path.read_text(encoding='utf-8'))\n",
            "else:\n",
            "    print('Warning: Telemetry report not found.')\n",
            "\n",
            "print('\\nOutput files:')\n",
            "for p in Path('/kaggle/working/qwen_pilot_phase_d_output').glob('**/*'):\n",
            "    if p.is_file():\n",
            "        print(f'{p.relative_to(\"/kaggle/working\")}: {p.stat().st_size} bytes')\n"
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

print(f"Created notebook at: {out_path} ({out_path.stat().st_size} bytes)")

