"""D5: adversarial robustness check for the second-opinion classifier.

Targets the currently-promoted (or D3-default) model with a targeted evasion
attack from the Adversarial Robustness Toolbox: starting from every eval-set
alert the model already correctly calls malicious or suspicious, how small a
perturbation in its own TF-IDF feature space is enough to flip the prediction
specifically to benign, the one flip an attacker actually wants?

    python -m eval.adversarial
    python -m eval.adversarial --eps 0.005 0.01 0.02 0.05 0.1

This measures the *mathematical* margin around the decision boundary in
feature space, not a proven text-editing recipe: an attacker still has to
find real words to add or remove that approximate this perturbation
direction, a separate, harder "problem-space" step this check doesn't
attempt. Read the numbers as "how thin is the margin," not "here is the
exploit." See eval/ADVERSARIAL.md for the recorded findings.
"""
from __future__ import annotations

import argparse
import warnings

import numpy as np

from app.triage.second_opinion import _model, eval_examples

_ATTACK_LABELS = ("suspicious", "malicious")  # the ones worth trying to hide as benign
_DEFAULT_EPS = [0.005, 0.01, 0.015, 0.02, 0.03, 0.05, 0.1]


def _correctly_flagged_examples() -> tuple[list[tuple[str, str]], object]:
    """Eval-set rows the model currently scores correctly as non-benign, plus
    the fitted pipeline. There's nothing to "evade" on a row it already
    misses, so only correct calls are meaningful attack targets."""
    pipe = _model()
    examples = [(t, l) for t, l in eval_examples() if l in _ATTACK_LABELS]
    preds = pipe.predict([t for t, _ in examples])
    return [(t, l) for (t, l), p in zip(examples, preds) if p == l], pipe


def run(eps_values: list[float] | None = None) -> dict:
    """Targeted FGM sweep, in the model's own TF-IDF feature space, aimed at
    the benign class. Returns a report dict; pure aside from loading the
    model and eval set, no DB writes, nothing else touched."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # ART's optional-backend import noise
        from art.attacks.evasion import FastGradientMethod
        from art.estimators.classification.scikitlearn import SklearnClassifier

    targets, pipe = _correctly_flagged_examples()
    if not targets:
        return {"n_targets": 0, "sweep": []}

    vec, clf = pipe.named_steps["tfidf"], pipe.named_steps["clf"]
    classes = list(clf.classes_)
    benign_idx = classes.index("benign")

    X = vec.transform([t for t, _ in targets]).toarray().astype(np.float32)
    y_target = np.zeros((len(targets), len(classes)), dtype=np.float32)
    y_target[:, benign_idx] = 1.0

    # clip_values wide open: TF-IDF weights are never negative and the eval
    # set's own max is well under 1, so this never actually clips a real value.
    art_clf = SklearnClassifier(model=clf, clip_values=(0.0, 100.0))

    sweep = []
    for eps in eps_values or _DEFAULT_EPS:
        attack = FastGradientMethod(estimator=art_clf, eps=float(eps), targeted=True, norm=np.inf)
        X_adv = attack.generate(x=X, y=y_target)
        preds_adv = clf.predict(X_adv)
        flipped = int(sum(1 for p in preds_adv if p == "benign"))
        sweep.append({
            "eps": eps,
            "n": len(targets),
            "flipped_to_benign": flipped,
            "flip_rate": round(flipped / len(targets), 3),
            "mean_abs_perturbation": round(float(np.mean(np.abs(X_adv - X))), 4),
        })
    return {"n_targets": len(targets), "sweep": sweep}


def report(res: dict) -> str:
    if res["n_targets"] == 0:
        return "no correctly-flagged malicious/suspicious examples to attack"
    lines = [
        f"targeted evasion (-> benign), {res['n_targets']} correctly-flagged "
        "malicious/suspicious example(s), FastGradientMethod (L-inf)",
        "",
        f"{'eps':>6}  {'flipped to benign':>18}  {'flip rate':>10}  {'mean |delta|':>13}",
    ]
    lines += [
        f"{r['eps']:>6}  {r['flipped_to_benign']:>18}  {r['flip_rate']:>10}  {r['mean_abs_perturbation']:>13}"
        for r in res["sweep"]
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--eps", type=float, nargs="+", default=None,
                    help="L-inf perturbation budgets to sweep, in TF-IDF feature units")
    args = ap.parse_args()
    print(report(run(args.eps)))


if __name__ == "__main__":
    main()
