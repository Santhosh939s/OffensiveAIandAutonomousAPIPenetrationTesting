# Phase 4.2 – CPU Optimization and Thread Scheduling Architecture

## Executive Summary

Phase 4.2 establishes a disciplined CPU thread allocation, execution concurrency, and process scheduling architecture for the **Offensive AI and Autonomous API Penetration Testing** platform.

The operational target profile is an entry-level/resource-constrained host environment:
- **Processor:** Intel Core i3-class or 4-logical-core x86_64 CPU
- **Operating System:** Windows 10/11
- **Available System Memory:** ~8 GB physical RAM (~1.3 GB free during background workloads)
- **AI Engine:** Offline local CPU inference via fine-tuned Qwen2.5-1.5B-Instruct Q4_K_M GGUF weights

---

## 1. Multi-Thread Allocation & Contention Analysis

On a 4-logical-core CPU, naive configuration of inference engines (such as setting `threads = os.cpu_count()`) induces heavy kernel context-switching, cache-line bouncing, and thread contention between the llama inference worker, the Flask HTTP/SSE event loop, and asynchronous security tool probe workers.

### Empirical Thread Benchmark (Qwen2.5-1.5B Q4_K_M GGUF)

A controlled parameter sweep was performed on the active hardware using the local standalone `llama-cli.exe` engine with 2048-token context length:

| Thread Allocation (`-t`, `-tb`) | Inference Latency (Single Decision) | Process CPU % (across 4 cores) | System Responsiveness | Core Allocation Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **2 Threads** | 13.683s | ~18.2% | Excellent | 2 cores inference, 2 cores available. Underutilizes available computing budget. |
| **3 Threads (Optimal)** | **12.430s** | **~24.8%** | **Optimal** | **3 cores dedicated to AVX2 matrix arithmetic; 1 full core dedicated to Flask SSE server, tool I/O, and OS.** |
| **4 Threads** | 13.764s | ~32.4% | Degraded | Induces CPU starvation for OS and background HTTP workers; context-switch latency increases turn time by +1.33s. |

### Architectural Enforcement:
In `controller/brain/local_cpu_client.py`:
```python
self.n_threads = n_threads or min(4, max(1, (os.cpu_count() or 2) - 1))
```
On 4-core hardware, this dynamically resolves to **3 threads**, leaving 1 full logical core unburdened.

---

## 2. Process Scheduling & Non-Blocking Worker Architecture

### Autonomous Controller Loop
- Background assessment workflows run within dedicated daemon threads (`threading.Thread(target=run_worker, daemon=True)`).
- Inter-thread communication is managed using synchronized `queue.Queue` channels with timeout guards (`timeout=1.0`), preventing CPU busy-waiting loops.
- Yielding patterns ensure the Flask WSGI server remains immediately responsive to client HTTP polling and Server-Sent Event (SSE) heartbeats (`: ping\n\n`).

### Child Process Management
- Standalone CLI execution in `LocalCpuBrainClient._generate` leverages `subprocess.run` with explicit timeouts (`inference_timeout=60.0s`), strict output stream piping, and zero resident zombie retention.
- Resident server mode (`llama_server`) terminates gracefully via `atexit` handlers using `SIGTERM` followed by process confirmation.

---

## 3. Concurrency Limits & Starvation Prevention

To prevent CPU oversubscription:
- **Maximum Concurrent Assessments:** Bounded to `DEFAULT_MAX_CONCURRENT_ASSESSMENTS = 4` in `dashboard/session_manager.py`.
- **Preemptive Rejection:** Requests exceeding capacity return an immediate `RESOURCE_BUSY_MAX_CONCURRENCY` status code (HTTP 429 semantics) rather than queueing unbounded threads that could cause CPU thrashing.
- **Cooperative Cancellation:** `cancel_assessment` issues an instantaneous `threading.Event.set()` signal, allowing running tasks to safely break at the boundary of their current turn without orphaning CPU-intensive subprocesses.

