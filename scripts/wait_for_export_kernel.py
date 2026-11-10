import time
import sys
from kaggle.api.kaggle_api_extended import KaggleApi

api = KaggleApi()
api.authenticate()

for _ in range(60):  # max 15 minutes
    status = api.kernels_status("santhosh939s/offensive-ai-gguf-export")
    status_str = str(status.status)
    print(f"Current status: {status_str}", flush=True)
    if "COMPLETE" in status_str or "ERROR" in status_str:
        sys.exit(0 if "COMPLETE" in status_str else 1)
    time.sleep(15)

print("Timeout waiting for kernel.", flush=True)
sys.exit(2)
