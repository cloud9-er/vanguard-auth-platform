import json
import time

from ai_analyzer import rule_flags, analyze
with open("labeled_cases.json") as f:
    cases = json.load(f)
with open("labeled_cases_extra.json") as f:
    cases += json.load(f)


def score(pairs):
    """pairs: list of (actual_label, predicted_label). Returns simple metrics."""
    tp = sum(1 for y, p in pairs if y and p)
    fp = sum(1 for y, p in pairs if not y and p)
    fn = sum(1 for y, p in pairs if y and not p)
    tn = sum(1 for y, p in pairs if not y and not p)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 2), "recall": round(recall, 2)}


rules_pairs = []
model_only_pairs = []   # the model's own verdict; unreadable replies count as "not flagged"
combined_pairs = []     # what the system does: any flag or unreadable reply means review
parse_failures = 0
latencies = []
misses = []

for case in cases:
    label = case["label"]
    approval = case["approval"]

    rules_pairs.append((label, bool(rule_flags(approval))))

    start = time.perf_counter()
    result = analyze(approval)
    latencies.append(time.perf_counter() - start)

    model_flag = result["model_advisory"]["flagged"]
    if model_flag is None:
        parse_failures += 1
    model_only_pairs.append((label, model_flag is True))
    combined_pairs.append((label, result["needs_review"]))

    if result["needs_review"] != label:
              misses.append((case["id"], label, result["rule_flags"], model_flag, result["model_advisory"]["reason"]))
n = len(cases)
print(f"Cases: {n}")
print(f"Parse failures (model reply unreadable): {parse_failures}/{n}")
print(f"Average latency per case: {sum(latencies)/n:.2f}s")
print()
print("Rules only:       ", score(rules_pairs))
print("Model verdict only:", score(model_only_pairs))
print("Combined system:  ", score(combined_pairs))
print()
print("Disagreements with the label:")
for case_id, label, rules, model_flag, reason in misses:
    print(f"  {case_id} label={label} rules={rules} model={model_flag} reason={reason}")