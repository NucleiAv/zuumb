"""Triage eval harness: run the labeled set through triage, report the numbers.

    python -m eval.run_eval --offline      # keyword heuristic, no API cost
    python -m eval.run_eval                # real Claude (needs ANTHROPIC_API_KEY)
    python -m eval.run_eval --few-shot     # also prepend recent analyst overrides
    python -m eval.run_eval --limit 10
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

CLASSES = ["benign", "suspicious", "malicious"]
LABELED_SET = Path(__file__).parent / "labeled_set.jsonl"


def load_labeled(path: Path = LABELED_SET) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def _rate(num: float, den: float) -> float:
    return round(num / den, 3) if den else 0.0


def score(pairs: list[tuple[str, str]]) -> dict:
    """pairs = (true_label, predicted_label). Pure — no IO."""
    cm = {t: {p: 0 for p in CLASSES} for t in CLASSES}
    for true, pred in pairs:
        cm[true][pred] += 1
    correct = sum(cm[c][c] for c in CLASSES)

    per_class = {}
    for c in CLASSES:
        tp = cm[c][c]
        fp = sum(cm[t][c] for t in CLASSES if t != c)
        fn = sum(cm[c][p] for p in CLASSES if p != c)
        prec, rec = _rate(tp, tp + fp), _rate(tp, tp + fn)
        per_class[c] = {"precision": prec, "recall": rec,
                        "f1": _rate(2 * prec * rec, prec + rec), "support": tp + fn}

    return {
        "n": len(pairs),
        "accuracy": _rate(correct, len(pairs)),
        "confusion": cm,
        "per_class": per_class,  # malicious P/R here == "did we catch the bad stuff"
        "missed_as_benign": cm["malicious"]["benign"],  # the one failure mode that must stay 0
    }


def report(res: dict) -> str:
    cm = res["confusion"]
    out = ["", f"n={res['n']}   accuracy={res['accuracy']}", "",
           "confusion  (rows = true, cols = predicted)",
           f"{'':12}" + "".join(f"{c:>12}" for c in CLASSES)]
    out += [f"{t:12}" + "".join(f"{cm[t][p]:>12}" for p in CLASSES) for t in CLASSES]
    out += ["", f"{'class':12}{'precision':>11}{'recall':>9}{'f1':>7}{'support':>9}"]
    out += [f"{c:12}{m['precision']:>11}{m['recall']:>9}{m['f1']:>7}{m['support']:>9}"
            for c, m in res["per_class"].items()]
    mal = res["per_class"]["malicious"]
    out += ["", f"malicious detection: precision={mal['precision']}  recall={mal['recall']}"
                f"   (malicious mislabelled benign: {res['missed_as_benign']})"]
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true", help="keyword heuristic, no API")
    ap.add_argument("--few-shot", action="store_true", help="prepend recent analyst overrides")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    from app.ingestion.wazuh_client import normalize_alert
    from app.triage.agent import PROMPT_PATH, _alert_brief, _call_llm

    if args.offline:
        from app.triage.offline import offline_verdict as call
    else:
        call = _call_llm

    system = PROMPT_PATH.read_text(encoding="utf-8")
    if args.few_shot:
        from app.db.session import get_session
        from app.feedback.logger import few_shot_block
        with get_session() as s:
            block = few_shot_block(s)
        system += block
        print(f"few-shot: {'appended corrections' if block else 'no analyst overrides on record'}")

    items = load_labeled()
    if args.limit:
        items = items[: args.limit]

    pairs: list[tuple[str, str]] = []
    for i, item in enumerate(items, 1):
        alert = normalize_alert(item["alert"])
        pred = call(system, _alert_brief(alert))["verdict"]
        pairs.append((item["label"], pred))
        mark = " " if item["label"] == pred else "X"
        print(f" {mark} {i:>2}/{len(items)}  {item['alert']['id']:8} true={item['label']:10} pred={pred}")

    print(report(score(pairs)))


if __name__ == "__main__":
    main()
