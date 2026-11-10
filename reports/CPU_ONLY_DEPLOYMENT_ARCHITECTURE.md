# CPU-Only Deployment Architecture & Low-Memory Optimization Guide

**Target Deployment Specification:**
- **Operating System:** Windows 10 / 11 (64-bit)
- **RAM:** 8 GB Physical RAM
- **Processor:** Intel Core i3 / Ryzen 3 or equivalent CPU
- **Graphics:** Integrated Graphics (Intel UHD / Iris Xe) — **No CUDA, No NVIDIA GPU**
- **Network:** Fully Offline / Local Airgap (No permanent internet, No remote LLM APIs)

---

## 1. System Memory Budget (8 GB Ceiling)

On an 8 GB Windows machine, the operating system kernel and background services consume between 3.0 GB and 3.5 GB of RAM. The autonomous API penetration-testing suite is architected to operate within a strict **2.2 GB working set**:

```
+-----------------------------------------------------------+
|                   8.0 GB Total Physical RAM               |
+-----------------------------+-----------------------------+
|  Windows OS & Services      |  ~3.2 - 3.5 GB              |
|  Local CPU Model (Q4_K_M)   |  ~1.1 - 1.4 GB (via MMAP)   |
|  Controller & Evidence DB   |  ~180 - 250 MB              |
|  Local Web Dashboard        |  ~90 - 140 MB               |
|  Active Testing Tools (HTTP)|  ~50 - 100 MB               |
|  Free Safety Buffer         |  ~2.6 - 3.0 GB              |
+-----------------------------+-----------------------------+
```

---

## 2. Model Execution Engine (`controller/brain/local_cpu_client.py`)

### A. Memory-Mapped Quantization (Q4_K_M)
- Model size on disk: ~980 MB.
- By configuring `use_mmap = True`, the operating system loads model tensor weights on-demand from the Windows page cache, preventing the entire model from occupying active physical RAM simultaneously.

### B. KV-Cache & Context Control
- `n_ctx`: Bounded to 1,536 - 2,048 tokens. In llama.cpp, this restricts the active key-value attention cache memory footprint to under 80 MB.
- `n_batch`: Bounded to 128 tokens per evaluation batch, avoiding memory spikes during prompt ingestion.

### C. Core i3 CPU Thread Management
- Default thread count is configured dynamically:
  $$\text{Threads} = \min(4, \max(1, \text{cpu\_count} - 1))$$
  This prevents CPU starvation, allowing the Windows GUI and local assessment tools to remain responsive during model generation.

---

## 3. Portable Directory Discovery

The application implements relative path resolution rooted at the codebase root (`PROJECT_ROOT` via `Path(__file__).resolve().parent.parent`):
1. **Model Discovery:** Automatic cascading search for `qwen2.5-1.5b-offensive-ai.Q4_K_M.gguf` across `models/`, `exported_models/`, and user-defined `QWEN_CPU_GGUF_PATH` environment variables.
2. **Database Discovery:** SQLite database defaults to `data/evidence_store.db` or `:memory:`, with automated directory creation.
3. **Report Storage:** Output markdown and HTML reports generate into `reports/assessments/`.
4. **Zero Hardcoded Absolute Paths:** Production controller code contains no machine-specific absolute drive roots.

