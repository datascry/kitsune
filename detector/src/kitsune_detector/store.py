# detector/store — schema-versioned SQLite persistence for sessions and verdicts.
# Thread-safe JSON-blob storage; the schema_version column keeps history comparable.

"""Schema-versioned SQLite persistence for sessions and verdicts.

Sessions and verdicts are stored as JSON blobs (the wire format) plus a few indexed columns. SQLite
is deliberately the right amount of database for a lab — the *schema_version* column is what keeps
historical scoreboards valid as the contracts evolve.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from types import TracebackType

from .models import Session, Verdict

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    body           TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verdicts (
    session_id      TEXT PRIMARY KEY,
    schema_version  TEXT NOT NULL,
    score           REAL NOT NULL,
    label           TEXT NOT NULL,
    ruleset_version TEXT NOT NULL,
    scored_at       TEXT NOT NULL,
    body            TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:") -> None:
        # check_same_thread=False: the HTTP app runs sync handlers in a threadpool. A single lock
        # serialises access, which is the right amount of concurrency control for a lab.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)

    # -- context manager -------------------------------------------------
    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    # -- sessions --------------------------------------------------------
    def save_session(self, session: Session) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO sessions VALUES (?, ?, ?, ?, ?)",
                (
                    session.session_id,
                    session.schema_version,
                    session.first_seen.isoformat(),
                    session.last_seen.isoformat(),
                    session.model_dump_json(),
                ),
            )
            self._conn.commit()

    def get_session(self, session_id: str) -> Session | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return Session.model_validate_json(row["body"]) if row else None

    # -- verdicts --------------------------------------------------------
    def save_verdict(self, verdict: Verdict) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    verdict.session_id,
                    verdict.schema_version,
                    verdict.score,
                    verdict.label.value,
                    verdict.ruleset_version,
                    verdict.scored_at.isoformat(),
                    verdict.model_dump_json(),
                ),
            )
            self._conn.commit()

    def get_verdict(self, session_id: str) -> Verdict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM verdicts WHERE session_id = ?", (session_id,)
            ).fetchone()
        return Verdict.model_validate_json(row["body"]) if row else None

    def list_verdicts(self) -> list[Verdict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT body FROM verdicts ORDER BY scored_at, session_id"
            ).fetchall()
        return [Verdict.model_validate_json(row["body"]) for row in rows]
