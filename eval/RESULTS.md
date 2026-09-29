# Triage eval results

Labeled set: [`labeled_set.jsonl`](labeled_set.jsonl) — 104 hand-labeled synthetic Wazuh
alerts (44 benign / 30 suspicious / 30 malicious), covering auth brute force (including
low-and-slow), web exploitation, privilege escalation, lateral movement, data staging,
exfiltration, ransomware precursors, identity/OAuth abuse, and a spread of routine benign
operational noise.

> **These numbers are directional, not a certified benchmark.** The set is synthetic and
> self-labeled by a single annotator, and the model runs at its default non-zero
> temperature, so a re-run lands near these figures but not digit-for-digit. A bigger set
> narrows the margin of error on any one percentage, but 104 examples with one annotator
> doesn't cross into "certified benchmark" territory, read these as an early, directional
> read from an internal test, not a validated accuracy claim.

Reproduce: `python -m eval.run_eval [--few-shot]`

## Claude Haiku 4.5, `prompts/triage_v1.md` — current run (104-alert set)

| run | accuracy | malicious precision | malicious recall | malicious→benign |
|---|---|---|---|---|
| baseline | **0.894** (93/104) | 0.955 | 0.700 | **0** |
| + analyst few-shot | **0.885** (92/104) | 0.913 | 0.700 | **0** |

**Baseline confusion** (rows = true, cols = predicted)

|            | benign | suspicious | malicious |
|------------|:------:|:----------:|:---------:|
| benign     |   44   |     0      |    0      |
| suspicious |    1   |     28     |    1      |
| malicious  |    0   |     9      |    21     |

### Reading the numbers
- **No malicious alert was ever called `benign`**, in either run, on this larger and more
  varied set either — the one failure mode that must stay at zero still does.
- Malicious recall (0.70) is unchanged from the original 34-alert run, but accuracy is
  higher overall (0.894 vs the old 0.824), largely because the added benign examples are
  all scored correctly (precision and recall both 1.0 on that class) and the new
  suspicious category is fuller and easier to call correctly than before.
- The 9 malicious→suspicious misses are the same shape as before: the model under-calling
  an exploit attempt or a credential-access technique as merely suspicious rather than
  outright malicious, one severity level low, not a wild miss.
- **The few-shot run here isn't actually exercising the feedback loop.** This eval reads
  real analyst corrections from the live database (`app.feedback.few_shot_block`), and
  that database currently has zero recorded corrections, `python -m eval.run_eval
  --few-shot` prints `few-shot: no analyst overrides on record` before running. So the two
  rows above differ only by the model's own sampling noise (non-zero temperature), not by
  any actual feedback-loop effect. Once a real analyst override exists, re-running this
  will show its real effect; until then, don't read the small baseline/few-shot gap above
  as the loop helping or hurting, it isn't doing anything yet.

## Claude Haiku 4.5, `prompts/triage_v1.md` — earlier run (original 34-alert set, kept for the record)

The very first eval, back when the labeled set was 34 alerts, deliberately paired with one
staged analyst correction to demonstrate the feedback loop end to end.

| run | accuracy | malicious precision | malicious recall | malicious→benign |
|---|---|---|---|---|
| baseline | 0.824 (28/34) | 1.00 | 0.70 | 0 |
| + analyst few-shot | 0.941 (32/34) | 1.00 | 0.90 | 0 |

One recorded analyst override (successful-login-after-brute-force → malicious) lifted
accuracy +12 points and malicious recall 0.70 → 0.90 with no loss of precision, a genuine,
measured demonstration that the feedback loop works when there's a real correction to
learn from. Superseded as the headline number by the 104-alert run above, kept here since
it's still the clearest illustration of the loop actually doing something.
