# detector/__main__ — run the detector HTTP app.
# Serves the FastAPI app via uvicorn (python -m kitsune_detector).

"""Run the detector HTTP app: ``python -m kitsune_detector``."""

from __future__ import annotations

import os

import uvicorn

from .app import create_app
from .store import Store


def main() -> None:  # pragma: no cover - thin runtime entrypoint
    db_path = os.environ.get("KITSUNE_DB", "kitsune.db")
    app = create_app(store=Store(db_path))
    host = os.environ.get("KITSUNE_HOST", "127.0.0.1")
    port = int(os.environ.get("KITSUNE_PORT", "8080"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    main()
