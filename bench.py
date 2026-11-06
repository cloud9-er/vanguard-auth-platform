import json
import statistics
import time

from ai_analyzer import rule_flags, analyze

cases = json.load(open("labeled_cases.json")) + json.load(open("labeled_cases_extra.json"))

rule_ms, full_ms = [], []
for c in cases:
    t = time.perf_counter()
    rule_flags(c["approval"])
    rule_ms.append((time.perf_counter() - t) * 1000)

    t = time.perf_counter()
    analyze(c["approval"])
    full_ms.append((time.perf_counter() - t) * 1000)

print("N =", len(cases))
print(f"Rules median: {statistics.median(rule_ms):.3f} ms")
print(f"Full analyze (rules + model) median: {statistics.median(full_ms):.0f} ms")