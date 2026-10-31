"""
smoke_test_distributed_init.py
Two-process distributed initialization smoke test.
Verifies that:
1. Multi-process distributed launcher (torchrun) spawns two ranks cleanly.
2. LOCAL_RANK and RANK environment variables are assigned correctly (Rank 0 and Rank 1).
3. Process group initializes successfully (NCCL on GPU, GLOO on CPU fallback).
4. Cross-rank communication and all-reduce tensor synchronization works.
5. Both ranks terminate cleanly with exit code 0.
"""

import os
import sys
import torch
import torch.distributed as dist

def main():
    local_rank = int(os.environ.get("LOCAL_RANK", 0))
    global_rank = int(os.environ.get("RANK", 0))
    world_size = int(os.environ.get("WORLD_SIZE", 1))

    is_cuda = torch.cuda.is_available()
    backend = "nccl" if is_cuda else "gloo"

    if is_cuda:
        torch.cuda.set_device(local_rank)
        device = torch.device(f"cuda:{local_rank}")
    else:
        device = torch.device("cpu")

    print(f"[Rank {global_rank}/{world_size}] Starting distributed initialization (local_rank={local_rank}, backend={backend}, device={device})...")

    # Initialize distributed process group
    dist.init_process_group(
        backend=backend,
        init_method="env://",
    )

    actual_rank = dist.get_rank()
    actual_world = dist.get_world_size()
    assert actual_rank == global_rank, f"Rank mismatch: expected {global_rank}, got {actual_rank}"
    assert actual_world == world_size, f"World size mismatch: expected {world_size}, got {actual_world}"

    # Verify cross-rank all-reduce synchronization
    tensor = torch.tensor([float(actual_rank + 1)], device=device)
    dist.all_reduce(tensor, op=dist.ReduceOp.SUM)

    # If world_size == 2: Rank 0 has value 1, Rank 1 has value 2. Sum should be 3.0 on both ranks!
    expected_sum = (world_size * (world_size + 1)) / 2.0
    actual_sum = tensor.item()

    assert actual_sum == expected_sum, f"[Rank {actual_rank}] All-reduce error: expected {expected_sum}, got {actual_sum}"
    print(f"[Rank {actual_rank}] Distributed sync VERIFIED! All-reduce sum across {world_size} ranks: {actual_sum} (Expected: {expected_sum})")

    # Clean termination
    dist.barrier()
    dist.destroy_process_group()
    print(f"[Rank {actual_rank}] Process group destroyed cleanly. Exit code 0.")

if __name__ == "__main__":
    main()
