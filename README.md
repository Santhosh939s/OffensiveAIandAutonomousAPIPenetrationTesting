# Offensive AI and Autonomous API Penetration Testing

An automated machine learning and security evaluation framework for API vulnerability classification and autonomous penetration testing, powered by fine-tuned **Qwen2.5-1.5B-Instruct** with parameter-efficient LoRA adapters.

---

## Architecture Overview

```
OffensiveAIandAutonomousAPIPenetrationTesting/
├── .gitignore                      # Git exclusion rules (weights/large zips excluded)
├── README.md                       # Repository overview and documentation
├── PROJECT_STATUS.md               # Detailed audit, checkpoint metrics, and automation status
├── PROJECT_RECOVERY_NOTES.md       # Original recovery notes and specifications
├── finetuning/
│   └── train_rebuilt_v4.py         # Multi-GPU (2x Tesla T4) DDP QLoRA fine-tuning script
├── evaluation/
│   ├── test_sample_2000.jsonl      # Standardized 2,000-example held-out test sample
│   ├── original_sample2000.json    # Step-4500 checkpoint evaluation report
│   └── rebuiltv4_sample2000.json   # Step-300 RebuiltV4 checkpoint evaluation report
└── kaggle_kernel/
    ├── kernel-metadata.json        # Kaggle API kernel configuration
    └── urop-offensive-ai.ipynb     # Interactive experiment and execution notebook
```

---

## Model Specifications

| Parameter | Specification |
| :--- | :--- |
| **Base Model** | `Qwen/Qwen2.5-1.5B-Instruct` |
| **Fine-Tuning Method** | QLoRA (NF4 4-bit Quantization, FP16 Compute) |
| **LoRA Target Modules** | `q_proj`, `k_proj`, `v_proj`, `o_proj`, `up_proj`, `down_proj`, `gate_proj` |
| **LoRA Hyperparameters** | Rank $r=16$, Alpha $\alpha=32$, Dropout $0.05$ |
| **Classification Task** | 8 API Security Categories (`Benign`, `Cookie Injection`, `Directory Traversal`, `LOG4J`, `Log Forging`, `RCE`, `SQL Injection`, `XSS`) |

---

## Evaluation Benchmark Summary (2,000 Sample Slice)

| Metric | Original Model (Step 4500) | RebuiltV4 (Step 300) |
| :--- | :--- | :--- |
| **Accuracy** | 99.20% | **99.65%** |
| **Macro F1** | 0.9828 | **0.9924** |
| **Weighted F1** | 0.9937 | **0.9981** |
| **Invalid Predictions** | 7 (0.35%) | 7 (0.35%) |

---

## Automation Workflow

- **Antigravity IDE**: Local development, experiment design, script validation, and report inspection.
- **GitHub**: Source code and experiment configuration version control (`Santhosh939s/OffensiveAIandAutonomousAPIPenetrationTesting`).
- **Kaggle API CLI v2.2.5**: Automated headless job dispatch (`kaggle kernels push`) and result retrieval (`kaggle kernels output`).
- **Kaggle Datasets**: Persistent, versioned artifact storage for large model weights and evaluation runs.
