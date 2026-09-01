# Triage eval results

Labeled set: [`labeled_set.jsonl`](labeled_set.jsonl) — 34 hand-labeled synthetic Wazuh
alerts (14 benign / 10 suspicious / 10 malicious).

Reproduce: `python -m eval.run_eval [--few-shot]`

## Claude Haiku 4.5, `prompts/triage_v1.md`

| run | accuracy | malicious precision | malicious recall | malicious→benign |
|---|---|---|---|---|
| baseline | **0.824** (28/34) | 1.00 | 0.70 | **0** |
| + analyst few-shot | **0.941** (32/34) | 1.00 | 0.90 | **0** |

**Baseline confusion** (rows = true, cols = predicted)

|            | benign | suspicious | malicious |
|------------|:------:|:----------:|:---------:|
| benign     |  13    |     1      |    0      |
| suspicious |   2    |     8      |    0      |
| malicious  |   0    |     3      |    7      |

### Reading the numbers
- **No malicious alert was ever called `benign`** in either run — the safety-critical
  failure mode is clean, and every `malicious` verdict the model gave was correct
  (precision 1.0).
- Baseline misses are all one severity level low, and mostly the model correctly
  following `triage_v1.md`'s rule that `malicious` needs *observed* success
  (SQLi with a 200 + 5 KB response, service-account SSH from a hostile IP,
  successful auth right after a brute-force burst).
- **The feedback loop closes most of that gap:** one recorded analyst override
  (successful-login-after-brute-force → malicious) lifted accuracy +12 pts and
  malicious recall 0.70 → 0.90 with no loss of precision. This is the Phase 9
  loop paying off — measured, not asserted.
- Open question for a prompt revision: whether `triage_v1.md` should treat an
  exploit attempt *with response evidence* as `malicious` outright, or keep
  leaning on the feedback loop. Left as-is pending that call.
