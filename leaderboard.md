# Leaderboard

Results from running `benchmark/run.py` against the full 497-attack /
1,172-negative corpus. Submit your own via PR — see
[CONTRIBUTING.md](CONTRIBUTING.md#new-results).

| Tool              | Detection | FP rate | Precision | Recall  | F1      | Date       | Notes |
| ----------------- | --------- | ------- | --------- | ------- | ------- | ---------- | ----- |
| crawdad-v0.9.1    | 99.80%    | 0.00%   | 100.00%   | 99.80%  | 99.90%  | 2026-04-20 | Reference implementation. L1 patterns + L2 DeBERTa-small ML + L3 indirect injection + L5 code scanner + L6 PII/credential + typosquat-text. |

Raw JSON for each entry is in [`benchmark/results/`](benchmark/results/).

## Reading the numbers

- **Detection** — fraction of attacks blocked. Higher is better.
- **FP rate** — fraction of benign samples incorrectly blocked. Lower is
  better.
- **F1** — balance of precision and recall. Single-number summary.

A tool with 99% detection and 40% FP is strictly worse than one with
70% detection and 1% FP for production use. The benchmark will not
tell you which tool is "best" — it will tell you the tradeoffs each
one is making, and let you pick the point on the curve that matches
your deployment.

## Per-category breakdown (crawdad-v0.9.1)

### Attacks (496/497 blocked)

| Category                   | Blocked / Total | Rate    |
| -------------------------- | --------------- | ------- |
| credential_exfiltration    | 44 / 44         | 100.00% |
| encoding_obfuscation       | 40 / 40         | 100.00% |
| exfiltration               | 28 / 28         | 100.00% |
| exploitation_request       | 20 / 20         | 100.00% |
| indirect_injection         | 30 / 30         | 100.00% |
| jailbreak                  | 30 / 30         | 100.00% |
| pii_leakage                | 20 / 20         | 100.00% |
| prompt_injection           | 37 / 37         | 100.00% |
| role_switching             | 65 / 65         | 100.00% |
| supply_chain               | 40 / 40         | 100.00% |
| system_prompt_extraction   | 20 / 20         | 100.00% |
| tool_abuse                 | 53 / 53         | 100.00% |
| other                      | 69 / 70         |  98.57% |

### Negatives (0/1,172 false positives)

| Negative category     | Flagged / Total | FP rate |
| --------------------- | --------------- | ------- |
| hand_curated          |  0 / 57         |  0.00%  |
| conversational        |  0 / 10         |  0.00%  |
| developer_messages    |  0 / 1,075      |  0.00%  |
| security_discussion   |  0 / 30         |  0.00%  |

This is one tool's profile. A different tool may trade off the opposite
way — strong on one category, weak on another. The point of the
benchmark is to make those tradeoffs visible.
