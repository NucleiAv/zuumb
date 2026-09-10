"""D1 steps 1-3: parsing + template mining + per-window features + anomaly scoring."""
from datetime import datetime, timedelta

from detectors.authlog import (
    Event,
    FeatureRow,
    iter_events,
    new_miner,
    parse_syslog_line,
    template_vocabulary,
    window_features,
)

_NOW = datetime(2026, 9, 10, 18, 0, 0)

_LINES = [
    "Sep 10 17:38:09 agent-lab-01 sshd[644]: Accepted password for deploy from 203.0.113.170 port 2866 ssh2",
    "Sep 10 17:38:42 agent-lab-01 sshd[644]: Failed password for invalid user deploy from 198.51.100.144 port 18172 ssh2",
    "Sep 10 17:39:36 agent-lab-01 sshd[644]: Failed password for invalid user oracle from 203.0.113.76 port 16321 ssh2",
    "Sep 10 17:40:10 agent-lab-01 sshd[644]: Failed password for invalid user admin from 192.0.2.84 port 49952 ssh2",
    "Sep 10 17:41:02 agent-lab-01 sshd[999]: Accepted password for deploy from 10.0.0.5 port 40001 ssh2",
    "Sep 10 17:41:45 agent-lab-01 sshd[644]: Connection closed by 198.51.100.69 port 54661 [preauth]",
]


def test_parse_syslog_line_splits_header_and_infers_year():
    ts, host, prog, msg = parse_syslog_line(_LINES[0], now=_NOW)
    assert (ts.year, ts.month, ts.day, ts.hour, ts.minute) == (2026, 9, 10, 17, 38)
    assert host == "agent-lab-01"
    assert prog == "sshd"
    assert msg.startswith("Accepted password for deploy from")


def test_parse_syslog_line_rolls_year_back_for_future_dates():
    # a December line seen in September must be last year, not next
    ts, *_ = parse_syslog_line(
        "Dec 31 23:59:00 h sshd[1]: Failed password for invalid user x from 1.1.1.1 port 2 ssh2",
        now=_NOW,
    )
    assert ts.year == 2025


def test_parse_syslog_line_returns_none_on_junk():
    assert parse_syslog_line("not a syslog line at all", now=_NOW) is None
    assert parse_syslog_line("", now=_NOW) is None


def test_failed_logins_collapse_to_one_template_regardless_of_user_ip_port():
    events = list(iter_events(_LINES, now=_NOW))
    assert len(events) == 6 and all(isinstance(e, Event) for e in events)

    failed = {e.template_id for e in events if e.message.startswith("Failed password for invalid user")}
    assert len(failed) == 1, "three failed-login lines should share one template"

    accepted = {e.template_id for e in events if e.message.startswith("Accepted password")}
    assert len(accepted) == 1
    assert accepted != failed, "accepted and failed must be distinct templates"

    # ip / port are masked, so they don't appear as literals in the mined template
    tmpl = next(e.template for e in events if e.message.startswith("Failed password for invalid user"))
    assert "198.51.100.144" not in tmpl and "18172" not in tmpl


def test_template_vocabulary_stays_small():
    events = list(iter_events(_LINES, now=_NOW))
    # 6 lines, 3 distinct message shapes (accepted / failed-invalid / conn-closed)
    assert len({e.template_id for e in events}) <= 3


def test_shared_miner_keeps_ids_stable_across_calls():
    miner = new_miner()
    first = list(iter_events(_LINES[:3], miner=miner, now=_NOW))
    second = list(iter_events(_LINES[3:], miner=miner, now=_NOW))
    fail_ids = {e.template_id for e in first + second
                if e.message.startswith("Failed password for invalid user")}
    assert len(fail_ids) == 1, "same template id before and after the split"


# --- step 2: per-window features -------------------------------------------------

def _ev(minute, host="h", tid=1):
    return Event(datetime(2026, 9, 10, 12, minute, 0), host, "sshd", "msg", tid, "<t>")


def test_events_split_across_the_window_boundary_into_separate_rows():
    rows = window_features([_ev(1), _ev(4), _ev(7)], window_seconds=300)  # 5-min windows
    assert [r.window_start.minute for r in rows] == [0, 5]
    assert [r.n_events for r in rows] == [2, 1]


def test_each_host_gets_its_own_row_in_the_same_window():
    rows = window_features([_ev(1, "a"), _ev(2, "b"), _ev(3, "a")], window_seconds=300)
    assert {(r.host, r.n_events) for r in rows} == {("a", 2), ("b", 1)}


def test_template_counts_sum_to_n_events_and_rate_is_per_minute():
    rows = window_features([_ev(0, tid=1), _ev(1, tid=1), _ev(2, tid=2)], window_seconds=300)
    (r,) = rows
    assert isinstance(r, FeatureRow)
    assert sum(r.template_counts.values()) == r.n_events == 3
    assert r.n_distinct_templates == 2
    assert r.events_per_min == round(3 / 5, 3)  # 3 events in a 5-minute window


def test_a_burst_window_has_a_higher_rate_than_a_quiet_one():
    burst = [_ev(0, tid=1) for _ in range(40)]
    quiet = [_ev(6, tid=1), _ev(7, tid=2)]
    rows = window_features(burst + quiet, window_seconds=300)
    assert rows[0].events_per_min > rows[1].events_per_min * 5


def test_template_vocabulary_is_the_sorted_union_across_rows():
    rows = window_features([_ev(0, tid=5), _ev(1, tid=2), _ev(6, tid=9)], window_seconds=300)
    assert template_vocabulary(rows) == [2, 5, 9]


# --- step 3: Isolation Forest anomaly scoring --------------------------------------

from detectors.authlog import AuthLogAnomalyModel, ScoredWindow  # noqa: E402


_BASE_TS = datetime(2026, 9, 10, 0, 0, 0)


def _row(host, slot, counts, window_seconds=300):
    n = sum(counts.values())
    return FeatureRow(
        host=host, window_start=_BASE_TS + timedelta(seconds=slot * window_seconds),
        n_events=n, n_distinct_templates=len(counts),
        events_per_min=round(n / (window_seconds / 60), 3), template_counts=counts,
    )


def _baseline(n=180):
    """Steady low-rate traffic with realistic jitter: ~4-12 events/window, mostly
    the failed-login template, a small number of accepted logins."""
    import random
    rng = random.Random(1)
    return [_row("h", i, {1: rng.randint(4, 12), 2: rng.randint(0, 2)}) for i in range(n)]


def test_model_needs_a_baseline_to_fit():
    import pytest
    with pytest.raises(ValueError):
        AuthLogAnomalyModel().fit([_baseline(1)[0]])


def test_baseline_windows_are_mostly_not_flagged():
    m = AuthLogAnomalyModel().fit(_baseline())
    scored = m.score(_baseline())
    assert all(isinstance(s, ScoredWindow) for s in scored)
    assert sum(s.is_anomaly for s in scored) <= len(scored) * 0.05  # a few at most


def test_a_brute_force_burst_scores_highest_and_is_flagged():
    m = AuthLogAnomalyModel().fit(_baseline())
    burst = _row("h", 500, {1: 240, 2: 1})          # 240 failed logins in 5 min
    scored = m.score(_baseline() + [burst])
    burst_scored = scored[-1]
    assert burst_scored.is_anomaly
    assert burst_scored.z > AuthLogAnomalyModel().z
    assert burst_scored.score == max(s.score for s in scored)


def test_a_quiet_normal_window_is_not_flagged_even_next_to_a_burst():
    m = AuthLogAnomalyModel().fit(_baseline())
    burst = _row("h", 500, {1: 240})
    normal = _row("h", 501, {1: 7, 2: 1})
    scored = {s.row.window_start: s for s in m.score([normal, burst])}
    assert scored[normal.window_start].is_anomaly is False
    assert scored[burst.window_start].is_anomaly is True


def test_scoring_is_deterministic():
    burst = _row("h", 500, {1: 200})
    a = AuthLogAnomalyModel().fit(_baseline()).score(_baseline() + [burst])
    b = AuthLogAnomalyModel().fit(_baseline()).score(_baseline() + [burst])
    assert [s.score for s in a] == [s.score for s in b]
