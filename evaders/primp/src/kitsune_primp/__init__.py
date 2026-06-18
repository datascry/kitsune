# evaders/primp — red-team: a Chrome-TLS-impersonating, JS-less HTTP client (Rust/BoringSSL).
# Wins the network fingerprint arms race; the package drives it against the live edge -> detector.

from .runner import NAME, VERSION, PrimpError, run_once, select_impersonate

__all__ = ["NAME", "VERSION", "PrimpError", "run_once", "select_impersonate"]
