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
    """Retrieve process Working Set (RAM in use) and Commit charge in MB for current or given PID."""
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
            k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            k32.OpenProcess.restype = wintypes.HANDLE
            k32.CloseHandle.argtypes = [wintypes.HANDLE]
            k32.CloseHandle.restype = wintypes.BOOL

            psapi.GetProcessMemoryInfo.argtypes = [
                wintypes.HANDLE,
                ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                wintypes.DWORD,
            ]
            psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

            target_pid = pid or os.getpid()
            h_proc = None
            should_close = False
            if target_pid == os.getpid():
                h_proc = k32.GetCurrentProcess()
            else:
                # PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
                h_proc = k32.OpenProcess(0x0410, False, target_pid)
                should_close = True

            if h_proc:
                try:
                    pmc = PROCESS_MEMORY_COUNTERS()
                    pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                    if psapi.GetProcessMemoryInfo(h_proc, ctypes.byref(pmc), pmc.cb):
                        ws_mb = round(pmc.WorkingSetSize / (1024 * 1024), 2)
                        peak_ws_mb = round(pmc.PeakWorkingSetSize / (1024 * 1024), 2)
                        commit_mb = round(pmc.PagefileUsage / (1024 * 1024), 2)
                finally:
                    if should_close and h_proc:
                        k32.CloseHandle(h_proc)
        except Exception as exc:
            logger.debug("Windows GetProcessMemoryInfo failed: %s", exc)

    return {
        "pid": pid or os.getpid(),
        "working_set_mb": ws_mb,
        "peak_working_set_mb": peak_ws_mb,
        "commit_charge_mb": commit_mb,
    }


def get_process_tree_memory_info(parent_pid: Optional[int] = None) -> Dict[str, Any]:
    """Retrieve aggregate process tree memory info (parent + all child processes such as llama-cli/llama-server)."""
    root_pid = parent_pid or os.getpid()
    all_pids = [root_pid]
    proc_details = []

    if platform.system() == "Windows":
        try:
            import ctypes.wintypes
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.wintypes.DWORD),
                    ("cntUsage", ctypes.wintypes.DWORD),
                    ("th32ProcessID", ctypes.wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", ctypes.wintypes.DWORD),
                    ("cntThreads", ctypes.wintypes.DWORD),
                    ("th32ParentProcessID", ctypes.wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            k32 = ctypes.WinDLL("kernel32")
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            entry = PROCESSENTRY32()
            entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
            children_map = {}

            if k32.Process32First(snap, ctypes.byref(entry)):
                while True:
                    ppid = entry.th32ParentProcessID
                    cpid = entry.th32ProcessID
                    exe_name = entry.szExeFile.decode("latin-1", errors="ignore").rstrip("\x00")
                    if ppid not in children_map:
                        children_map[ppid] = []
                    children_map[ppid].append((cpid, exe_name))
                    if not k32.Process32Next(snap, ctypes.byref(entry)):
                        break
            k32.CloseHandle(snap)

            # Traverse tree from root_pid
            to_visit = [root_pid]
            visited = set()
            while to_visit:
                curr = to_visit.pop(0)
                if curr in visited:
                    continue
                visited.add(curr)
                for child_pid, child_name in children_map.get(curr, []):
                    if child_pid not in all_pids:
                        all_pids.append(child_pid)
                        to_visit.append(child_pid)
        except Exception as exc:
            logger.debug("Failed to inspect child processes via Toolhelp32: %s", exc)

    total_ws = 0.0
    total_peak_ws = 0.0
    total_commit = 0.0

    for p in all_pids:
        info = get_process_memory_info(p)
        total_ws += info["working_set_mb"]
        total_peak_ws += info["peak_working_set_mb"]
        total_commit += info["commit_charge_mb"]
        proc_details.append(info)

    return {
        "root_pid": root_pid,
        "process_count": len(all_pids),
        "all_pids": all_pids,
        "aggregate_working_set_mb": round(total_ws, 2),
        "aggregate_peak_working_set_mb": round(total_peak_ws, 2),
        "aggregate_commit_charge_mb": round(total_commit, 2),
        "processes": proc_details,
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

