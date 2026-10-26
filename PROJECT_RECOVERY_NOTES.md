# MSK API Security Model — Recovery Notes

## Base model
Qwen/Qwen2.5-1.5B-Instruct

## Original model
Project path:
api_pentest_research/qwen_api_security_lora_resume_3000/checkpoint-4500

Original ZIP:
MSK_API_Security_Model_step4500.zip

Do not overwrite the original checkpoint or ZIP.

## RebuiltV4
Adapter path:
api_pentest_research/qwen_api_security_lora_rebuilt_v4

Training script:
api_pentest_research/finetuning/train_rebuilt_v4.py

Training configuration:
- Fresh LoRA adapter
- Rank 16, alpha 32, dropout 0.05
- 4-bit NF4 quantization
- FP16 compute
- Effective batch size 16
- 300 training steps
- Save/evaluate every 100 steps
- Two Tesla T4 GPUs used for training

Reduced training dataset:
api_pentest_research/finetuning/rebuilt_v4/train.jsonl
9,000 examples: 2,000 Benign and 1,000 per attack class.

## Evaluation on the same 2,000-example sample

Original:
- Accuracy: 0.9920
- Macro F1: 0.9828
- Weighted F1: 0.9937
- Invalid outputs: 7

RebuiltV4:
- Accuracy: 0.9965
- Macro F1: 0.9924
- Weighted F1: 0.9981
- Invalid outputs: 7

Sample results favor RebuiltV4, but this is not yet a final model selection.

## LOG4J-only evaluation on 687 examples

Original:
- Detected: 684/687
- Recall: 99.5633%
- Three INVALID predictions

RebuiltV4:
- Detected: 683/687
- Recall: 99.4178%
- Three INVALID and one RCE prediction

The 2,000-example sample contained only 30 LOG4J examples. Do not infer perfect full-dataset performance from that small sample.

## Next steps
1. Restore or reopen the Kaggle project and verify the saved files.
2. Evaluate both adapters on the complete 45,912-example test set.
3. Use both Tesla T4 GPUs in parallel where suitable, after checking VRAM.
4. Compare accuracy, macro F1, weighted F1, per-class precision/recall/F1, invalid outputs, and confusion matrices.
5. Investigate Cookie Injection recall and invalid outputs.
6. Do not retrain until the full-test results are reviewed.
7. Keep the original model and ZIP unchanged.

## Important paths
Project root: /kaggle/working/api_pentest_research
New adapter: /kaggle/working/api_pentest_research/qwen_api_security_lora_rebuilt_v4
Evaluation reports:
finetuning/rebuilt_v4/evaluation/

## Persistence warning
This recovery package is a copy of the listed artifacts, not a complete copy of every dataset or the entire project. Download the ZIP and save a Kaggle notebook version. The full original datasets are not included.
