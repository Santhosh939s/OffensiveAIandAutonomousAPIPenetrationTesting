#!/usr/bin/env python3
"""Autonomous Offensive AI - Inference Engine Provisioning Tool.

Identifies, provisions, and verifies compatible llama.cpp CPU inference binaries
(llama-cli.exe and required dynamic runtime libraries) for portable standalone deployment.

Supported sources:
1. Local staging or project directory (models/bin/)
2. Custom source directory or zip archive (--source-dir / --archive)
3. Windows Package Manager (winget install ggml.llamacpp)
4. System PATH or standard installation directories

Compatible llama.cpp specifications:
- llama.cpp build >= b3000 / v0.3.0+
- Architecture: Windows x86_64
- Required runtime DLLs: llama.dll, llama-cli-impl.dll, llama-common.dll,
  ggml.dll, ggml-base.dll, ggml-cpu-x64.dll (or AVX2 backend), libomp.dll
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_BIN_DIR = PROJECT_ROOT / "models" / "bin"

REQUIRED_CORE_FILES = [
    "llama-cli.exe",
    "llama.dll",
    "llama-cli-impl.dll",
    "llama-server-impl.dll",
    "llama-common.dll",
    "mtmd.dll",
    "ggml.dll",
    "ggml-base.dll",
    "libomp.dll",
]

OPTIONAL_BACKEND_DLLS = [
    "ggml-cpu-x64.dll",
    "ggml-cpu-haswell.dll",
    "ggml-cpu-alderlake.dll",
    "ggml-cpu-sse42.dll",
    "ggml-cpu-zen4.dll",
    "ggml-cpu-skylakex.dll",
    "ggml-cpu-cascadelake.dll",
    "ggml-cpu-cannonlake.dll",
    "ggml-cpu-sapphirerapids.dll",
    "ggml-cpu-icelake.dll",
    "ggml-cpu-cooperlake.dll",
    "ggml-cpu-ivybridge.dll",
    "ggml-cpu-sandybridge.dll",
    "ggml-cpu-piledriver.dll",
    "ggml-rpc.dll",
]


def find_system_llamacpp() -> List[Path]:
    """Search for existing llama.cpp installations on the system."""
    discovered = []

    # 1. Environment variables
    env_cli = os.environ.get("LLAMA_CLI_PATH")
    if env_cli and Path(env_cli).is_file():
        discovered.append(Path(env_cli).resolve())

    env_dir = os.environ.get("LLAMACPP_DIR")
    if env_dir and (Path(env_dir) / "llama-cli.exe").is_file():
        discovered.append((Path(env_dir) / "llama-cli.exe").resolve())

    # 2. Local project bin
    local_cli = MODELS_BIN_DIR / "llama-cli.exe"
    if local_cli.is_file():
        discovered.append(local_cli.resolve())

    # 3. System PATH
    which_cli = shutil.which("llama-cli.exe") or shutil.which("llama-cli")
    if which_cli and Path(which_cli).is_file():
        p = Path(which_cli).resolve()
        if p not in discovered:
            discovered.append(p)

    # 4. Standard Program Files
    pf_candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "llama.cpp" / "llama-cli.exe",
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "llama.cpp" / "llama-cli.exe",
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "chocolatey" / "bin" / "llama-cli.exe",
    ]
    for c in pf_candidates:
        if c.is_file() and c.resolve() not in discovered:
            discovered.append(c.resolve())

    # 5. User WinGet package directories
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        winget_pkg_dir = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        if winget_pkg_dir.is_dir():
            for p in winget_pkg_dir.glob("*llamacpp*"):
                candidate = p / "llama-cli.exe"
                if candidate.is_file() and candidate.resolve() not in discovered:
                    discovered.append(candidate.resolve())

    return discovered


def verify_binary(binary_path: Path) -> Tuple[bool, str]:
    """Execute llama-cli.exe --version to verify operational readiness."""
    if not binary_path.is_file():
        return False, f"File not found: {binary_path}"

    bin_dir = binary_path.parent
    env = os.environ.copy()
    # Ensure binary's parent directory is first in PATH so companion DLLs resolve
    env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")

    try:
        proc = subprocess.run(
            [str(binary_path), "--version"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        output = (proc.stdout + "\n" + proc.stderr).strip()
        if proc.returncode == 0:
            ver_line = output.splitlines()[0] if output else "OK"
            return True, f"Verified operational: {ver_line}"
        return False, f"Process returned exit code {proc.returncode}: {output[:200]}"
    except Exception as exc:
        return False, f"Execution failed: {exc}"


def provision_from_directory(source_dir: Path, target_dir: Optional[Path] = None) -> Tuple[bool, List[str]]:
    """Copy llama-cli and companion runtime DLLs to target directory."""
    target = target_dir or MODELS_BIN_DIR
    target.mkdir(parents=True, exist_ok=True)
    copied = []

    # Copy core binaries and DLLs
    all_targets = REQUIRED_CORE_FILES + OPTIONAL_BACKEND_DLLS
    for name in all_targets:
        src = source_dir / name
        if src.is_file():
            dst = target / name
            shutil.copy2(src, dst)
            copied.append(name)

    # Also copy any remaining DLLs present in source directory
    for src in source_dir.glob("*.dll"):
        if src.name not in copied:
            shutil.copy2(src, target / src.name)
            copied.append(src.name)

    cli_target = target / "llama-cli.exe"
    if not cli_target.is_file():
        return False, [f"llama-cli.exe not found in source: {source_dir}"]

    ok, msg = verify_binary(cli_target)
    if not ok:
        return False, [f"Provisioned binary failed verification: {msg}"]

    return True, copied


def main():
    parser = argparse.ArgumentParser(
        description="Offline llama.cpp CPU inference engine provisioning and verification utility."
    )
    parser.add_argument("--source-dir", type=str, help="Directory containing llama-cli.exe and runtime DLLs")
    parser.add_argument("--archive", type=str, help="Zip archive of official llama.cpp release")
    parser.add_argument("--target-dir", type=str, default=str(MODELS_BIN_DIR), help="Destination directory (default: models/bin)")
    parser.add_argument("--check-only", action="store_true", help="Scan and verify existing installations without copying")
    parser.add_argument("--auto-copy-discovered", action="store_true", help="Auto-copy first verified system installation into models/bin")

    args = parser.parse_args()
    target_path = Path(args.target_dir)

    print("=" * 72)
    print("   LLAMA.CPP CPU INFERENCE ENGINE PROVISIONING & VERIFICATION")
    print("=" * 72)

    discovered = find_system_llamacpp()
    print(f"\n[*] Discovered {len(discovered)} llama.cpp execution binary candidate(s):")
    valid_candidates = []
    for c in discovered:
        ok, msg = verify_binary(c)
        status = "[VALID]" if ok else "[INVALID]"
        print(f"    {status:9} {c}")
        print(f"              {msg}")
        if ok:
            valid_candidates.append(c)

    if args.check_only:
        if valid_candidates:
            print("\n[+] Compatible llama.cpp inference binary is ready for production execution.")
            sys.exit(0)
        else:
            print("\n[!] No valid llama.cpp binaries detected on system.")
            sys.exit(1)

    # Handle explicit source directory
    if args.source_dir:
        src_path = Path(args.source_dir)
        print(f"\n[*] Provisioning from explicit directory: {src_path} -> {target_path}")
        ok, details = provision_from_directory(src_path, target_path)
        if ok:
            print(f"[+] Successfully provisioned {len(details)} runtime file(s) into {target_path}:")
            for f in details:
                print(f"    - {f}")
            sys.exit(0)
        else:
            print(f"[!] Provisioning failed: {details}")
            sys.exit(1)

    # Handle zip archive
    if args.archive:
        archive_path = Path(args.archive)
        if not archive_path.is_file():
            print(f"[!] Archive not found: {archive_path}")
            sys.exit(1)
        temp_extract = target_path / "_temp_extract"
        try:
            print(f"\n[*] Extracting {archive_path} to temporary staging...")
            with zipfile.ZipFile(archive_path, "r") as z:
                z.extractall(temp_extract)
            ok, details = provision_from_directory(temp_extract, target_path)
            if ok:
                print(f"[+] Successfully extracted and provisioned {len(details)} file(s).")
                sys.exit(0)
            else:
                print(f"[!] Provisioning from archive failed: {details}")
                sys.exit(1)
        finally:
            if temp_extract.is_dir():
                shutil.rmtree(temp_extract, ignore_errors=True)

    # Auto-copy from first valid candidate if requested
    if args.auto_copy_discovered and valid_candidates:
        first_valid = valid_candidates[0]
        src_dir = first_valid.parent
        print(f"\n[*] Auto-provisioning local repository models/bin from: {src_dir}")
        ok, details = provision_from_directory(src_dir, target_path)
        if ok:
            print(f"[+] Local models/bin provisioned successfully with {len(details)} runtime file(s).")
            sys.exit(0)
        else:
            print(f"[!] Auto-provisioning failed: {details}")
            sys.exit(1)

    # Check if target models/bin already has working binary
    target_cli = target_path / "llama-cli.exe"
    if target_cli.is_file():
        ok, msg = verify_binary(target_cli)
        if ok:
            print(f"\n[+] Local repository models/bin/llama-cli.exe is already fully operational: {msg}")
            sys.exit(0)

    print("\n[!] To provision the local repository models/bin directory:")
    print("    python deployment/provision_engine.py --auto-copy-discovered")
    print("    python deployment/provision_engine.py --source-dir <path_to_llamacpp>")
    print("    python deployment/provision_engine.py --archive <path_to_llama_zip>")


if __name__ == "__main__":
    main()
