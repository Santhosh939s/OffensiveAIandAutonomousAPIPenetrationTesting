"""
test_distributed_spawn.py
Uses torch.multiprocessing to simulate distributed multi-rank initialization.
Verifies that 2 processes initialize their process group, synchronize, and exit cleanly.
"""

import os
import torch
import torch.distributed as dist
import torch.multiprocessing as mp

def run_worker(rank, world_size):
    os.environ['MASTER_ADDR'] = '127.0.0.1'
    os.environ['MASTER_PORT'] = '29530'
    os.environ['USE_LIBUV'] = '0'

    print(f"[Worker Rank {rank}/{world_size}] Initializing process group with GLOO backend...")
    dist.init_process_group("gloo", rank=rank, world_size=world_size)

    actual_rank = dist.get_rank()
    actual_world = dist.get_world_size()
    assert actual_rank == rank
    assert actual_world == world_size

    # All-reduce tensor sum
    tensor = torch.tensor([float(rank + 1)])
    dist.all_reduce(tensor, op=dist.ReduceOp.SUM)

    expected = (world_size * (world_size + 1)) / 2.0
    assert tensor.item() == expected, f"Sum mismatch: {tensor.item()} vs {expected}"

    print(f"[Worker Rank {rank}] Synchronization SUCCESS: all-reduce sum = {tensor.item()} (expected {expected})")

    dist.barrier()
    dist.destroy_process_group()
    print(f"[Worker Rank {rank}] Terminated cleanly.")

if __name__ == '__main__':
    world_size = 2
    print(f"Spawning {world_size} worker processes for distributed smoke test...")
    mp.spawn(run_worker, args=(world_size,), nprocs=world_size, join=True)
    print("Multi-process distributed initialization smoke test PASSED [OK]")
