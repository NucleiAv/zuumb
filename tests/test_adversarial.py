"""D5: the ART-based evasion check against the second-opinion classifier."""
from app.triage import second_opinion as so
from eval.adversarial import _correctly_flagged_examples, report, run


def _fresh():
    """_model() is process-cached (lru_cache); clear it so this test fits
    fresh against the current eval set instead of a model left over from an
    earlier test in the same pytest run."""
    so._model.cache_clear()


def test_correctly_flagged_examples_are_all_non_benign_and_actually_correct():
    _fresh()
    targets, pipe = _correctly_flagged_examples()
    assert targets  # the real eval set has plenty of these
    labels = {l for _, l in targets}
    assert labels <= {"suspicious", "malicious"}
    preds = pipe.predict([t for t, _ in targets])
    assert all(p == l for p, (_, l) in zip(preds, targets))  # every row really is a correct call


def test_run_sweeps_every_requested_epsilon_with_consistent_shape():
    _fresh()
    res = run([0.01, 0.05])
    assert res["n_targets"] > 0
    assert [r["eps"] for r in res["sweep"]] == [0.01, 0.05]
    for row in res["sweep"]:
        assert row["n"] == res["n_targets"]
        assert 0 <= row["flipped_to_benign"] <= row["n"]
        assert row["flip_rate"] == round(row["flipped_to_benign"] / row["n"], 3)
        assert row["mean_abs_perturbation"] >= 0


def test_a_larger_epsilon_flips_at_least_as_many_examples_to_benign():
    """Not strict monotonicity at every step (FGM's sign-step can be uneven),
    but a much larger budget should never flip fewer than a tiny one."""
    _fresh()
    res = run([0.001, 0.5])
    tiny, huge = res["sweep"]
    assert huge["flipped_to_benign"] >= tiny["flipped_to_benign"]


def test_a_large_enough_epsilon_evades_essentially_everything():
    """Regression for the actual D5 finding: the decision boundary has almost
    no margin in this feature space — a small perturbation is enough."""
    _fresh()
    res = run([0.1])
    row = res["sweep"][0]
    assert row["flip_rate"] == 1.0


def test_report_reads_the_sweep_back():
    text = report({"n_targets": 2, "sweep": [
        {"eps": 0.01, "n": 2, "flipped_to_benign": 1, "flip_rate": 0.5, "mean_abs_perturbation": 0.003},
    ]})
    assert "0.01" in text and "0.5" in text and "2" in text


def test_report_handles_no_targets_without_crashing():
    assert "no correctly-flagged" in report({"n_targets": 0, "sweep": []})
