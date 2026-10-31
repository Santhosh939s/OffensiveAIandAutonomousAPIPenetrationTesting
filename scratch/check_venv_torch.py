import os
import subprocess

venv_py = r"C:\Users\santhosh\.gemini\antigravity-ide\brain\27c97d48-c567-4878-ad73-3bcfdd978b71\scratch\venv\Scripts\python.exe"
print("Venv python exists:", os.path.exists(venv_py))
if os.path.exists(venv_py):
    cmd = [venv_py, "-c", "import torch; print('Torch:', torch.__version__, 'CUDA:', torch.cuda.is_available(), 'Count:', torch.cuda.device_count())"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("Output:", res.stdout.strip())
    print("Error:", res.stderr.strip())
