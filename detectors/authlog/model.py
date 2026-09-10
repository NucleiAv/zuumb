"""D1 step 3: score per-window feature rows for anomalousness.

Unsupervised. `fit()` learns what "normal" auth-log windows look like from a
baseline period; `score()` returns an anomaly score per window (higher = more
unusual) plus a z-score against the baseline and a boolean flag. No labels, no
attack examples needed. A window with a sudden burst of one template (a
brute-force run) lands far in the tail and scores high.

Model: PyOD's ECOD. Chosen over Isolation Forest after testing — ECOD is
parameter-free, deterministic, and its score is a sum of per-feature tail
probabilities, so it grows with how extreme a window is instead of saturating
the moment a point looks unusual (which is what sank IForest here: a 240-event
burst scored the same as an 11-event window). Step 4 turns a flagged window
into an alert; this module only produces the score.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from pyod.models.ecod import ECOD

from detectors.authlog.features import FeatureRow, template_vocabulary

DEFAULT_Z = 4.0  # a window is flagged when its score is this many std-devs
                # above the mean baseline score


@dataclass(frozen=True)
class ScoredWindow:
    row: FeatureRow
    score: float       # ECOD anomaly score, higher = more anomalous
    z: float           # (score - baseline_mean) / baseline_std
    is_anomaly: bool    # z past the threshold set at fit() time


def _vectorize(rows, vocab: list[int]) -> np.ndarray:
    """FeatureRows -> fixed-width float matrix: three scalar features followed by
    one column per template id in `vocab` (its count in the window)."""
    out = [
        [r.n_events, r.n_distinct_templates, r.events_per_min,
         *(r.template_counts.get(tid, 0) for tid in vocab)]
        for r in rows
    ]
    return np.asarray(out, dtype=float)


class AuthLogAnomalyModel:
    """Fit on a baseline set of FeatureRows, then score any FeatureRows against it.

    The anomaly flag is a z-test of the ECOD score against the baseline's own
    score distribution, so the threshold adapts to how noisy the baseline is
    rather than being a fixed cutoff.
    """

    def __init__(self, *, z: float = DEFAULT_Z):
        self.vocab: list[int] = []
        self.z = z
        self._clf = ECOD()
        self._keep = None       # boolean mask: feature columns that vary in the baseline
        self._base_mean = 0.0
        self._base_std = 1e-9
        self._fitted = False

    def fit(self, rows) -> "AuthLogAnomalyModel":
        rows = list(rows)
        if len(rows) < 2:
            raise ValueError("need at least 2 baseline windows to fit")
        self.vocab = template_vocabulary(rows)
        X = _vectorize(rows, self.vocab)
        # drop columns that never move in the baseline: they carry no signal and
        # make ECOD's per-feature stats degenerate
        self._keep = X.std(axis=0) > 0
        if not self._keep.any():
            self._keep = np.ones(X.shape[1], dtype=bool)
        self._clf.fit(X[:, self._keep])
        train = self._clf.decision_scores_
        self._base_mean = float(np.mean(train))
        self._base_std = float(np.std(train)) or 1e-9
        self._fitted = True
        return self

    def score(self, rows) -> list[ScoredWindow]:
        if not self._fitted:
            raise RuntimeError("call fit() before score()")
        rows = list(rows)
        raw = self._clf.decision_function(_vectorize(rows, self.vocab)[:, self._keep])
        out = []
        for r, s in zip(rows, raw):
            z = (float(s) - self._base_mean) / self._base_std
            out.append(ScoredWindow(r, float(s), z, z > self.z))
        return out
