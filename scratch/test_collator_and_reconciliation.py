"""
test_collator_and_reconciliation.py
Verification script for:
1. Fixed MultiTaskCompletionCollator with explicit prompt/completion boundary, overlength rejection,
   completion label preservation, and sequence-length enforcement (<= 2048).
2. Reconciled batch-size and step-count calculations for 2-GPU (dual Tesla T4) and 1-GPU fallback.
"""

import os
import sys

# Mock Tokenizer for unit testing without external dependencies
class MockTokenizer:
    def __init__(self):
        self.pad_token_id = 0
        self.eos_token_id = 1

    def __call__(self, text, add_special_tokens=False):
        # Deterministic token assignment based on whitespace split or synthetic IDs
        tokens = [abs(hash(w)) % 10000 + 10 for w in text.split()]
        if not tokens:
            tokens = [10]
        return {"input_ids": tokens}

class MultiTaskCompletionCollator:
    """
    Masks prompt tokens (system + user) with -100 so cross-entropy loss is computed
    strictly across the assistant completion tokens.
    
    Explicit Boundary & Truncation Handling:
    - Enforces a minimum assistant completion budget (min_completion_tokens).
    - If prompt length exceeds (max_length - min_completion_tokens), the example is REJECTED.
    - If assistant completion exceeds available budget, it is safely truncated.
    - Asserts that completion labels are NEVER all masked (-100).
    - Guarantees final sequence length never exceeds max_length.
    """
    def __init__(self, tokenizer, max_length=2048, min_completion_tokens=16):
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.min_completion_tokens = min_completion_tokens
        self.marker = "<|im_start|>assistant\n"

    def process_single(self, text):
        if self.marker not in text:
            raise ValueError("Assistant completion marker '<|im_start|>assistant\\n' missing in text.")

        prompt_text, completion_text = text.rsplit(self.marker, 1)
        prompt_text += self.marker

        prompt_ids = self.tokenizer(prompt_text, add_special_tokens=False)["input_ids"]
        completion_ids = self.tokenizer(completion_text, add_special_tokens=False)["input_ids"]

        prompt_len = len(prompt_ids)
        comp_len = len(completion_ids)

        # Check prompt/completion boundary budget
        available_completion_budget = self.max_length - prompt_len

        if available_completion_budget < self.min_completion_tokens:
            raise ValueError(
                f"Overlength sequence rejected: prompt length ({prompt_len} tokens) leaves insufficient "
                f"completion budget ({available_completion_budget} < {self.min_completion_tokens} tokens) "
                f"under max_length={self.max_length}. Cannot retain both a valid prompt and a useful completion."
            )

        if comp_len == 0:
            raise ValueError("Empty assistant completion: cannot compute loss on zero completion tokens.")

        # Truncate completion if it exceeds available budget, retaining full prompt
        if comp_len > available_completion_budget:
            completion_ids = completion_ids[:available_completion_budget]

        input_ids = prompt_ids + completion_ids
        labels = [-100] * len(prompt_ids) + completion_ids.copy()

        # Invariant checks
        assert len(input_ids) <= self.max_length, f"Sequence length {len(input_ids)} exceeds max_length {self.max_length}"
        assert len(input_ids) == len(labels), "input_ids and labels length mismatch"
        assert any(l != -100 for l in labels), "All completion labels are masked (-100). Training supervision is absent."
        assert labels.count(-100) == len(prompt_ids), "Prompt masking count does not match prompt length."
        assert len(completion_ids) >= min(comp_len, self.min_completion_tokens), "Completion budget violation."

        return input_ids, labels

    def __call__(self, features):
        rows = []
        for feature in features:
            text = feature["text"]
            input_ids, labels = self.process_single(text)
            rows.append((input_ids, labels))

        max_len = max(len(ids) for ids, _ in rows)
        pad_id = self.tokenizer.pad_token_id

        input_batch, label_batch, mask_batch = [], [], []
        for ids, labels in rows:
            padding = max_len - len(ids)
            input_batch.append(ids + [pad_id] * padding)
            label_batch.append(labels + [-100] * padding)
            mask_batch.append([1] * len(ids) + [0] * padding)

        return {
            "input_ids": input_batch,
            "labels": label_batch,
            "attention_mask": mask_batch,
        }

def run_collator_tests():
    print("=" * 70)
    print("TEST 1: MULTI-TASK COLLATOR BOUNDARY & TRUNCATION VERIFICATION")
    print("=" * 70)
    tokenizer = MockTokenizer()
    collator = MultiTaskCompletionCollator(tokenizer, max_length=2048, min_completion_tokens=16)

    # Case A: Short sequence (10 prompt tokens, 5 completion tokens)
    prompt_short = " ".join([f"w{i}" for i in range(10)]) + " <|im_start|>assistant\n"
    comp_short = " ".join([f"c{i}" for i in range(5)])
    inp_a, lab_a = collator.process_single(prompt_short + comp_short)
    assert len(inp_a) == 16  # 11 prompt (including marker) + 5 comp
    assert lab_a[:11] == [-100] * 11
    assert all(l != -100 for l in lab_a[11:])
    print(f"Case A (Short Sequence): PASS (len={len(inp_a)}, prompt_masked={lab_a.count(-100)}, trained={len(lab_a) - lab_a.count(-100)})")

    # Case B: Normal sequence (500 prompt tokens, 300 completion tokens)
    prompt_norm = " ".join([f"w{i}" for i in range(500)]) + " <|im_start|>assistant\n"
    comp_norm = " ".join([f"c{i}" for i in range(300)])
    inp_b, lab_b = collator.process_single(prompt_norm + comp_norm)
    assert len(inp_b) == 801  # 501 prompt (including marker) + 300 comp
    assert lab_b[:501] == [-100] * 501
    assert all(l != -100 for l in lab_b[501:])
    print(f"Case B (Normal Sequence): PASS (len={len(inp_b)}, prompt_masked={lab_b.count(-100)}, trained={len(lab_b) - lab_b.count(-100)})")

    # Case C: Overlength completion safely truncated (1000 prompt tokens, 1500 completion tokens, max_length=2048)
    # Available budget = 2048 - 1001 = 1047 tokens. Completion truncated from 1500 -> 1047 tokens.
    prompt_c = " ".join([f"w{i}" for i in range(1000)]) + " <|im_start|>assistant\n"
    comp_c = " ".join([f"c{i}" for i in range(1500)])
    inp_c, lab_c = collator.process_single(prompt_c + comp_c)
    assert len(inp_c) == 2048, f"Expected 2048, got {len(inp_c)}"
    assert lab_c[:1001] == [-100] * 1001
    assert len(lab_c) == 2048
    trained_tokens = len(lab_c) - lab_c.count(-100)
    assert trained_tokens == 1047
    print(f"Case C (Overlength Completion Truncated): PASS (total_len={len(inp_c)} <= 2048, prompt_masked=1001, trained={trained_tokens})")

    # Case D: Overlength prompt rejected (2040 prompt tokens, leaving only 8 budget < min_completion_tokens=16)
    prompt_d = " ".join([f"w{i}" for i in range(2039)]) + " <|im_start|>assistant\n"
    comp_d = " ".join([f"c{i}" for i in range(50)])
    rejected_d = False
    try:
        collator.process_single(prompt_d + comp_d)
    except ValueError as e:
        rejected_d = True
        print(f"Case D (Prompt Leaves Insufficient Completion Budget): PASS (Rejected as expected with: {e})")
    assert rejected_d, "Case D should have raised ValueError for insufficient completion budget!"

    # Case E: Excessive prompt exceeding max_length completely (2100 prompt tokens)
    prompt_e = " ".join([f"w{i}" for i in range(2100)]) + " <|im_start|>assistant\n"
    comp_e = "valid completion"
    rejected_e = False
    try:
        collator.process_single(prompt_e + comp_e)
    except ValueError as e:
        rejected_e = True
        print(f"Case E (Prompt Exceeds MAX_LENGTH completely): PASS (Rejected as expected with: {e})")
    assert rejected_e, "Case E should have raised ValueError!"

    # Case F: Batch test verifying padding and attention mask
    batch = collator([
        {"text": prompt_short + comp_short},
        {"text": prompt_norm + comp_norm},
    ])
    assert len(batch["input_ids"]) == 2
    assert len(batch["input_ids"][0]) == len(batch["input_ids"][1])
    assert batch["attention_mask"][0].count(1) == len(inp_a)
    assert batch["attention_mask"][0].count(0) == len(batch["input_ids"][0]) - len(inp_a)
    assert batch["labels"][0][len(inp_a):] == [-100] * (len(batch["input_ids"][0]) - len(inp_a))
    print("ALL COLLATOR BOUNDARY TESTS PASSED SUCCESSFULLY [OK]\n")

def print_batch_size_reconciliation():
    print("=" * 70)
    print("RECONCILIATION: BATCH SIZE, ACCUMULATION, AND STEP CALCULATIONS")
    print("=" * 70)
    dataset_records = 800  # train.jsonl
    max_steps = 150
    per_device_batch = 1
    grad_accum = 8

    # Scenario 1: Target Dual Tesla T4 (world_size = 2 via torchrun)
    world_size_2 = 2
    eff_batch_2 = per_device_batch * grad_accum * world_size_2
    steps_per_epoch_2 = dataset_records / eff_batch_2
    est_epochs_2 = max_steps / steps_per_epoch_2
    total_exposures_2 = max_steps * eff_batch_2
    micro_batches_per_gpu_per_epoch_2 = dataset_records / (per_device_batch * world_size_2)

    print("--- SCENARIO 1: DUAL TESLA T4 GPUs (torchrun --nproc_per_node=2) [PRIMARY TARGET] ---")
    print(f"  * Training Records:               {dataset_records}")
    print(f"  * World Size (GPUs):              {world_size_2} (Tesla T4)")
    print(f"  * Per-Device Train Batch Size:    {per_device_batch}")
    print(f"  * Gradient Accumulation Steps:    {grad_accum}")
    print(f"  * Effective Batch Size:           {eff_batch_2} samples / optimizer step (1 x 8 x 2)")
    print(f"  * Micro-Batches per GPU / Epoch:  {int(micro_batches_per_gpu_per_epoch_2)}")
    print(f"  * Dataset Batches (Steps) / Epoch:{steps_per_epoch_2:.1f} optimizer steps")
    print(f"  * Max Optimizer Steps:            {max_steps}")
    print(f"  * Estimated Epochs at 150 Steps:  {est_epochs_2:.2f} epochs")
    print(f"  * Total Sample Exposures:         {total_exposures_2} samples")
    print(f"  * Num Train Epochs in Config:     {int(est_epochs_2)} (Exact match with num_train_epochs=3)\n")

    # Scenario 2: Single GPU Fallback (world_size = 1)
    world_size_1 = 1
    eff_batch_1 = per_device_batch * grad_accum * world_size_1
    steps_per_epoch_1 = dataset_records / eff_batch_1
    est_epochs_1 = max_steps / steps_per_epoch_1
    total_exposures_1 = max_steps * eff_batch_1
    micro_batches_per_gpu_per_epoch_1 = dataset_records / (per_device_batch * world_size_1)

    print("--- SCENARIO 2: SINGLE GPU FALLBACK (world_size = 1) ---")
    print(f"  * Training Records:               {dataset_records}")
    print(f"  * World Size (GPUs):              {world_size_1}")
    print(f"  * Per-Device Train Batch Size:    {per_device_batch}")
    print(f"  * Gradient Accumulation Steps:    {grad_accum}")
    print(f"  * Effective Batch Size:           {eff_batch_1} samples / optimizer step (1 x 8 x 1)")
    print(f"  * Micro-Batches per GPU / Epoch:  {int(micro_batches_per_gpu_per_epoch_1)}")
    print(f"  * Dataset Batches (Steps) / Epoch:{steps_per_epoch_1:.1f} optimizer steps")
    print(f"  * Max Optimizer Steps:            {max_steps}")
    print(f"  * Estimated Epochs at 150 Steps:  {est_epochs_1:.2f} epochs")
    print(f"  * Total Sample Exposures:         {total_exposures_1} samples\n")
    print("=" * 70)

if __name__ == "__main__":
    run_collator_tests()
    print_batch_size_reconciliation()
