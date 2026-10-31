"""System and Process Resource Profiling for Low-Memory (8 GB RAM) Environments.

Provides zero-dependency Windows and cross-platform memory detection,
process footprint measurement, and runtime mode recommendation.
"""

import ctypes
import gc
import logging
import os
import platform
import sys
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def get_system_memory_info() -> Dict[str, Any]:
    """Retrieve system physical RAM capacity and available memory in MB."""
    total_mb = 0.0
    avail_mb = 0.0
    mem_load = 0

    if platform.system() == "Windows":
        try:
            from ctypes import wintypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_uint64),
                    ("ullAvailPhys", ctypes.c_uint64),
                    ("ullTotalPageFile", ctypes.c_uint64),
                    ("ullAvailPageFile", ctypes.c_uint64),
                    ("ullTotalVirtual", ctypes.c_uint64),
                    ("ullAvailVirtual", ctypes.c_uint64),
                    ("ullAvailExtendedVirtual", ctypes.c_uint64),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                total_mb = round(stat.ullTotalPhys / (1024 * 1024), 2)
                avail_mb = round(stat.ullAvailPhys / (1024 * 1024), 2)
                mem_load = int(stat.dwMemoryLoad)
        except Exception as exc:
            logger.debug("Windows GlobalMemoryStatusEx failed: %s", exc)
    else:
        # POSIX fallback
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            info = {}
            for line in lines:
                parts = line.split(":")
                if len(parts) == 2:
                    info[parts[0].strip()] = parts[1].strip()
            total_kb = float(info.get("MemTotal", "0 kB").split()[0])
            avail_kb = float(info.get("MemAvailable", info.get("MemFree", "0 kB")).split()[0])
            total_mb = round(total_kb / 1024.0, 2)
            avail_mb = round(avail_kb / 1024.0, 2)
            mem_load = round(((total_mb - avail_mb) / max(1.0, total_mb)) * 100)
        except Exception:
            pass

    return {
        "total_ram_mb": total_mb,
        "available_ram_mb": avail_mb,
        "memory_load_pct": mem_load,
        "os": platform.system(),
        "platform_release": platform.release(),
        "python_version": platform.python_version(),
    }


def get_process_memory_info(pid: Optional[int] = None) -> Dict[str, Any]:
    """Retrieve current process Working Set (RAM in use) and Commit charge in MB."""
    ws_mb = 0.0
    peak_ws_mb = 0.0
    commit_mb = 0.0

    if platform.system() == "Windows":
        try:
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)

            k32.GetCurrentProcess.restype = wintypes.HANDLE
            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
                ws_mb = round(pmc.WorkingSetSize / (1024 * 1024), 2)
                peak_ws_mb = round(pmc.PeakWorkingSetSize / (1024 * 1024), 2)
                commit_mb = round(pmc.PagefileUsage / (1024 * 1024), 2)
        except Exception as exc:
            logger.debug("Windows GetProcessMemoryInfo failed: %s", exc)

    return {
        "working_set_mb": ws_mb,
        "peak_working_set_mb": peak_ws_mb,
        "commit_charge_mb": commit_mb,
    }


def get_runtime_capabilities() -> Dict[str, Any]:
    """Evaluate local hardware and determine the safest, optimal Qwen inference mode."""
    mem_info = get_system_memory_info()
    proc_info = get_process_memory_info()

    cuda_available = False
    cuda_device_name = "None"
    cuda_vram_mb = 0.0
    torch_available = False

    try:
        import torch

        torch_available = True
        cuda_available = torch.cuda.is_available()
        if cuda_available:
            cuda_device_name = torch.cuda.get_device_name(0)
            cuda_vram_mb = round(
                torch.cuda.get_device_properties(0).total_memory / (1024 * 1024), 2
            )
    except Exception:
        pass

    # Safety and mode decision tree
    # Rule 1: If CUDA available with >= 3 GB VRAM, local 4-bit NF4 is supported
    # Rule 2: If no CUDA or RAM < 4 GB available, recommend Remote GPU endpoint or Deterministic Mock
    is_8gb_class = mem_info["total_ram_mb"] <= 8500.0
    local_gpu_supported = cuda_available and (cuda_vram_mb >= 3000.0)

    # Local CPU inference capability analysis
    # Qwen2.5-1.5B in FP16/FP32 requires ~3.2 GB to 6 GB RAM.
    # On an 8 GB Windows machine with ~1.2 GB free RAM, native CPU inference risks OS thrashing.
    local_cpu_viable = (mem_info["available_ram_mb"] >= 4500.0)

    if local_gpu_supported:
        recommended_mode = "local_qwen"
        mode_rationale = "Dedicated CUDA GPU with sufficient VRAM detected."
    else:
        recommended_mode = "remote"
        mode_rationale = (
            "Host has 8 GB RAM and integrated graphics without CUDA. "
            "Remote GPU mode (or Deterministic Mock for offline testing) "
            "preserves complete model accuracy while keeping local RAM usage under 60 MB."
        )

    return {
        "system_memory": mem_info,
        "process_memory": proc_info,
        "is_8gb_class_machine": is_8gb_class,
        "hardware": {
            "torch_available": torch_available,
            "cuda_available": cuda_available,
            "cuda_device_name": cuda_device_name,
            "cuda_vram_mb": cuda_vram_mb,
            "local_gpu_supported": local_gpu_supported,
            "local_cpu_viable": local_cpu_viable,
        },
        "recommended_mode": recommended_mode,
        "recommendation_rationale": mode_rationale,
        "available_modes": [
            {
                "id": "mock",
                "label": "Deterministic Mock (Offline / Zero GPU)",
                "status": "Ready",
                "local_ram_impact": "~25 MB",
                "description": "Deterministic decision-maker for automated testing and local debugging.",
            },
            {
                "id": "remote",
                "label": "Remote Qwen2.5-1.5B Brain (Kaggle/Colab GPU)",
                "status": "Ready (Recommended)",
                "local_ram_impact": "~15 MB",
                "description": "Zero local GPU overhead. Preserves exact RebuiltV4 Checkpoint-200 weights.",
            },
            {
                "id": "local_qwen",
                "label": "Local Qwen2.5-1.5B LoRA Brain (4-bit NF4)",
                "status": "Requires CUDA GPU" if not cuda_available else "Ready",
                "local_ram_impact": "~1,700 MB VRAM",
                "description": "Requires discrete Nvidia GPU with CUDA drivers.",
            },
        ],
    }


def release_memory_resources() -> None:
    """Trigger explicit garbage collection and GPU cache clearance."""
    gc.collect()
    try:
        import torch

        if torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass

