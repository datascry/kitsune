# tests/test_store — detector test module.
# Asserts behaviour and edge cases for the unit under test.

from __future__ import annotations

from pathlib import Path

from kitsune_detector.models import Session
from kitsune_detector.store import Store


def test_session_round_trip(human_session: Session) -> None:
    with Store() as store:
        store.save_session(human_session)
        loaded = store.get_session(human_session.session_id)
        assert loaded == human_session
        assert store.get_session("missing") is None


def test_verdict_round_trip(detector, human_session: Session, bot_session: Session) -> None:
    with Store() as store:
        for session in (human_session, bot_session):
            store.save_verdict(detector.score(session))

        assert store.get_verdict("missing") is None
        assert store.get_verdict("bot-001").label.value == "bot"
        listed = [v.session_id for v in store.list_verdicts()]
        assert set(listed) == {"human-001", "bot-001"}


def test_persists_to_file(tmp_path: Path, human_session: Session) -> None:
    db = tmp_path / "k.db"
    store = Store(db)
    store.save_session(human_session)
    store.close()
    assert db.exists()

    reopened = Store(db)
    assert reopened.get_session(human_session.session_id) == human_session
    reopened.close()
