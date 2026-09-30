"""Human-confirmed manual links between incidents (app/correlation/manual_link.py).
A third, distinct layer from the deterministic correlation (engine.py) and the
advisory embedding similarity (similarity.py) — see that module's docstring."""
from sqlmodel import select

from app.correlation import manual_link
from app.db.models import Incident, ManualIncidentLink
from app.db.session import get_session


def _seed_two() -> tuple[int, int]:
    with get_session() as s:
        a = Incident(title="incident a", severity="high")
        b = Incident(title="incident b", severity="high")
        s.add(a)
        s.add(b)
        s.commit()
        s.refresh(a)
        s.refresh(b)
        return a.id, b.id


def test_confirm_records_who_and_the_optional_note():
    a, b = _seed_two()
    with get_session() as s:
        link = manual_link.confirm(s, a, b, "alice", "same attacker IP range, seen in raw logs")
    assert link.incident_a_id == a and link.incident_b_id == b
    assert link.linked_by == "alice"
    assert link.note == "same attacker IP range, seen in raw logs"


def test_confirming_twice_is_a_no_op_not_a_duplicate():
    a, b = _seed_two()
    with get_session() as s:
        first = manual_link.confirm(s, a, b, "alice")
        second = manual_link.confirm(s, a, b, "bob")  # same pair, confirmed again
    assert first.id == second.id
    assert second.linked_by == "alice"  # unchanged — the original confirmation stands
    with get_session() as s:
        assert len(s.exec(select(ManualIncidentLink)).all()) == 1


def test_confirming_the_reverse_order_is_the_same_pair():
    a, b = _seed_two()
    with get_session() as s:
        manual_link.confirm(s, a, b, "alice")
        again = manual_link.confirm(s, b, a, "bob")
    with get_session() as s:
        rows = s.exec(select(ManualIncidentLink)).all()
    assert len(rows) == 1
    assert again.linked_by == "alice"


def test_for_incident_reads_either_side_most_recent_first():
    from datetime import datetime

    a, b = _seed_two()
    with get_session() as s:
        c_row = Incident(title="incident c", severity="high")
        s.add(c_row)
        s.commit()
        s.refresh(c_row)
        c = c_row.id
    with get_session() as s:
        older = manual_link.confirm(s, a, b, "alice")
        newer = manual_link.confirm(s, c, a, "bob")
        # explicit, well-separated timestamps: real wall-clock calls this close
        # together can land in the same tick and make "most recent" ambiguous
        older.linked_at = datetime(2026, 1, 1, 0, 0, 0)
        newer.linked_at = datetime(2026, 1, 1, 0, 0, 1)
        s.add(older)
        s.add(newer)
        s.commit()
    with get_session() as s:
        hits = manual_link.for_incident(s, a)
    assert {h["incident"].id for h in hits} == {b, c}
    assert hits[0]["link"].linked_by == "bob"  # most recent first


def test_unlink_removes_the_row_and_is_not_permanent():
    a, b = _seed_two()
    with get_session() as s:
        link = manual_link.confirm(s, a, b, "alice")
    with get_session() as s:
        assert manual_link.unlink(s, link.id) is True
    with get_session() as s:
        assert manual_link.for_incident(s, a) == []


def test_unlink_missing_row_returns_false():
    with get_session() as s:
        assert manual_link.unlink(s, 999999) is False


def test_manual_link_has_no_downstream_effect_on_correlation_severity_or_chains():
    """Same verification standard as D3's second opinion and the advisory
    similarity layer: this module must never be referenced by the modules
    that actually decide incidents, severity, or attack chains."""
    import inspect

    from app.attack_chain import stitcher
    from app.correlation import engine

    for module in (engine, stitcher):
        src = inspect.getsource(module)
        assert "ManualIncidentLink" not in src
        assert "manual_link" not in src
