from app.ingestion.wazuh_client import normalize_alert
from eval.run_eval import CLASSES, load_labeled, score


def test_score_perfect_predictions():
    pairs = [(c, c) for c in CLASSES for _ in range(3)]
    res = score(pairs)
    assert res["accuracy"] == 1.0
    assert all(m["precision"] == 1.0 and m["recall"] == 1.0 for m in res["per_class"].values())
    assert res["missed_as_benign"] == 0


def test_score_confusion_counts_and_rates():
    pairs = [
        ("malicious", "malicious"), ("malicious", "malicious"),
        ("malicious", "suspicious"),          # missed (not benign)
        ("malicious", "benign"),              # worst: called benign
        ("benign", "benign"), ("benign", "benign"),
        ("benign", "malicious"),              # false positive for malicious
        ("suspicious", "suspicious"),
    ]
    res = score(pairs)
    cm = res["confusion"]
    assert cm["malicious"]["malicious"] == 2
    assert cm["malicious"]["benign"] == 1
    assert cm["benign"]["malicious"] == 1
    # malicious: tp=2, fp=1 (benign->malicious), fn=2 (suspicious + benign preds)
    assert res["per_class"]["malicious"]["precision"] == round(2 / 3, 3)
    assert res["per_class"]["malicious"]["recall"] == round(2 / 4, 3)
    assert res["missed_as_benign"] == 1


def test_labeled_set_is_valid_and_sized():
    items = load_labeled()
    assert 30 <= len(items) <= 50
    assert {i["label"] for i in items} <= set(CLASSES)
    counts = {c: sum(i["label"] == c for i in items) for c in CLASSES}
    assert all(v >= 5 for v in counts.values()), counts  # every class represented
    for item in items:
        a = normalize_alert(item["alert"])  # must normalize without error
        assert a.rule_id and a.rule_description and a.timestamp
