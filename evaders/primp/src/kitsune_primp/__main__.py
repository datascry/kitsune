# evaders/primp/__main__ — run the primp evader once against the live stack.
# Trusts the edge's self-signed cert, impersonates Chrome via primp, prints the verdict JSON.

from __future__ import annotations

import json
import os
import ssl
import tempfile

import primp

from .runner import run_once, select_impersonate


def main() -> None:  # pragma: no cover - thin CLI; needs the live edge + the compiled primp wheel
    edge = os.environ.get("KITSUNE_EDGE", "https://localhost:8443/healthz")
    detector = os.environ.get("KITSUNE_DETECTOR", "http://localhost:8080")
    host_port = edge.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = host_port.partition(":")
    # primp ignores verify=False for its impersonation backend, so trust the edge's self-signed cert
    # explicitly via ca_cert_file (the cert now covers the "edge" service name).
    pem = ssl.get_server_certificate((host, int(port or "443")))
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        ca = fh.name
    client = primp.Client(impersonate=select_impersonate(), ca_cert_file=ca)
    print(json.dumps(run_once(edge, detector, client=client), indent=2))


if __name__ == "__main__":  # pragma: no cover
    main()
