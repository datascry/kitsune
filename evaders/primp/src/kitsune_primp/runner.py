# evaders/primp/runner — drive one request through the edge with a browser-impersonating TLS stack.
# primp (Rust/BoringSSL) sends a real Chrome ClientHello; the runner reads the verdict back.

"""primp evader runner.

``primp`` impersonates a current Chrome's TLS + HTTP/2 fingerprint — GREASE, the post-quantum key
share, the full ``Sec-*`` header set — but runs no JS engine. This runner drives one request through
the edge and reads the verdict by the ``ks_sid`` the edge minted. The HTTP client is injected as a
structural protocol so the flow is testable without the compiled primp wheel or a live network.
"""

from __future__ import annotations

import os
import re
from typing import Any, Protocol

NAME = "primp"
VERSION = "0.1.0"

# The Chrome profile primp impersonates by default — recent enough that its ClientHello carries the
# post-quantum key share, so it is *not* a stale template (the precise point of the evaluation).
DEFAULT_IMPERSONATE = "chrome_146"

_KS_SID = re.compile(r"ks_sid=([0-9a-f]+)")


class PrimpError(RuntimeError):
    """Raised when the live flow does not yield a correlated session."""


class Response(Protocol):
    """The minimal response surface the runner needs (primp's Response satisfies it)."""

    @property
    def headers(self) -> Any: ...

    def json(self) -> Any: ...


class Client(Protocol):
    """A get-only HTTP client (primp.Client satisfies it structurally)."""

    def get(self, url: str) -> Response: ...


def run_once(edge_url: str, detector_url: str, *, client: Client) -> dict[str, Any]:
    """Hit the edge, recover the ``ks_sid`` from Set-Cookie, fetch the detector's verdict."""
    resp = client.get(edge_url)
    match = _KS_SID.search(str(resp.headers.get("set-cookie", "")))
    if not match:
        raise PrimpError("edge did not set a ks_sid session cookie")
    session_id = match.group(1)
    verdict: dict[str, Any] = client.get(f"{detector_url}/verdict/{session_id}").json()
    return verdict


def select_impersonate() -> str:
    """The impersonated Chrome profile; override with ``KS_IMPERSONATE`` (default chrome_146)."""
    return os.environ.get("KS_IMPERSONATE", DEFAULT_IMPERSONATE)
