# D5: adversarial robustness check

The second-opinion classifier (D3/D4, TF-IDF + LogisticRegression) has never been
tested against a deliberately crafted input before. This runs a targeted evasion
attack from the [Adversarial Robustness Toolbox](https://github.com/Trusted-AI/adversarial-robustness-toolbox)
against it: starting from every eval-set alert the model currently calls
`malicious` or `suspicious` correctly, how small a nudge in its own TF-IDF
feature space is enough to flip the prediction specifically to `benign`, the
one flip that actually matters to an attacker?

Reproduce: `python -m eval.adversarial [--eps ...]`

## Result

| eps (L-inf, TF-IDF units) | flipped to benign | flip rate | mean \|delta\| |
|---|---|---|---|
| 0.005 | 0 / 36 | 0.0 | 0.0018 |
| 0.01 | 20 / 36 | 0.556 | 0.0036 |
| 0.015 | 36 / 36 | 1.0 | 0.0055 |
| 0.02 | 36 / 36 | 1.0 | 0.0073 |
| 0.05 | 36 / 36 | 1.0 | 0.0182 |
| 0.1 | 36 / 36 | 1.0 | 0.0362 |

> **Directional, not a certified benchmark.** Same caveats as every other number
> in this eval directory: 36 targets from a small, self-labeled synthetic set,
> one model version, one attack algorithm. A re-run after the next retrain will
> land near these figures, not reproduce them digit-for-digit.

## Reading the numbers

**The decision boundary has almost no margin.** A perturbation of just 0.015 in
L-infinity norm, moving each TF-IDF feature by about a hundredth of its own
typical value, is enough to flip every correctly-flagged malicious or suspicious
alert in the eval set to benign. That's not a large or exotic attack budget;
it's tiny relative to the feature scale (the eval set's own TF-IDF values top
out around 0.28). A linear model over a fairly small (56-alert) TF-IDF
vocabulary was never going to have a wide margin, so this isn't shocking, but
it hadn't actually been measured before now.

**What this does and doesn't prove.** This measures fragility in the model's
own *feature space* — it doesn't hand you a rewritten alert. Turning "move
these 2,050 TF-IDF weights by this vector" into "add these words to a log
line" is a separate, harder problem this check doesn't attempt (the
adversarial-ML literature calls this the feature-space-to-problem-space gap).
So the honest reading is "the classifier's margin is thin enough that a
motivated attacker probing it for wording changes that reduce the malicious
score would likely find one fairly quickly," not "here is a working evasion
string." Worth a red-team follow-up if this classifier's verdict is ever
treated as more than advisory.

**Why this doesn't change anything today.** D3's design already treats this
classifier as a nudge, not a gate (see `second_opinion.py`) — an analyst
glances at a stricter-than-primary second opinion, nothing more, so a fooled
classifier in normal operation degrades to "the second opinion agreed with a
fooled primary," not "an attack sailed through unnoticed." The one place this
finding matters more is the AI-detection-off nav toggle, where the classifier
*is* the primary verdict, and it inherits the same thin margin. Worth keeping
in mind if AI detection is ever left off for an extended period against real
adversarial traffic rather than as a stopgap.

**Not tested here**: D1's auth-log anomaly detector (PyOD ECOD). It's
unsupervised, no decision boundary in the same sense, and evading it means
mimicking the statistical shape of normal traffic rather than crossing a
classifier's line, a different kind of robustness question than the one ART's
mainstream evasion attacks are built for. Left for a future pass rather than
forced into the same harness.
