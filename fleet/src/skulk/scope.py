# fleet/skulk/scope — authorization gate: Skulk only ever emits at targets the operator explicitly authorizes.
# The lab's ethics invariant in code — no run proceeds against an out-of-scope host. There is no bypass.

"""Authorization scope — the load-bearing ethics control.

Skulk emulates COORDINATED FLEETS to test whether a bot-detector catches them — an adversary-emulation /
detection-validation tool, the red half of a red⇄blue exercise. Like every responsible adversary-emulation
kit (Atomic Red Team, Caldera), it must only ever be pointed at infrastructure the operator OWNS or is
explicitly authorized to test. That invariant lives here, in code: every run resolves the target host against
an authorization scope and REFUSES anything outside it. The bundled default scope is Kitsune's own lab
(detector / edge / arena / localhost). An operator running an authorized engagement adds their in-scope hosts
(``--authorize`` / a scope file) AND affirms authorization (``--i-am-authorized``). There is no flag that
disables the check. Skulk emits benign coordination-shaped sessions to a detector's ingest surface; it is not,
and must not become, a flood/DoS, credential, or scraping tool.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

#: Kitsune's own lab surfaces — always in scope (what Skulk ships pointed at; needs no authorization affirmation).
_DEFAULT_HOSTS = frozenset({"detector", "edge", "arena", "localhost", "127.0.0.1", "::1"})


class AuthorizationError(RuntimeError):
    """Raised when Skulk is pointed at a target outside the authorized scope (or unaffirmed)."""


@dataclass
class Scope:
    """The set of authorized target hosts/networks. Every run must resolve its target into this set."""

    hosts: set[str] = field(default_factory=lambda: set(_DEFAULT_HOSTS))
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    affirmed: bool = False  # the operator affirmed they are authorized for the operator-added targets

    def authorize_host(self, host: str) -> None:
        self.hosts.add(host.strip().lower())

    def authorize_network(self, cidr: str) -> None:
        self.networks.append(ipaddress.ip_network(cidr, strict=False))

    def check(self, target_url: str) -> str:
        """Return the authorized host for ``target_url`` or raise :class:`AuthorizationError`.

        The bundled lab default hosts run with no affirmation; any operator-ADDED host additionally requires
        ``affirmed`` (the explicit "I am authorized to test this" acknowledgement). No path bypasses this.
        """
        host = (urlparse(target_url).hostname or "").lower()
        if not host:
            raise AuthorizationError(f"no host in target {target_url!r}")
        in_default = host in _DEFAULT_HOSTS
        in_scope = host in self.hosts or any(self._ip_in(host, n) for n in self.networks)
        if not in_scope:
            raise AuthorizationError(
                f"target host {host!r} is NOT in the authorized scope. Skulk only emits at hosts you own or are "
                f"authorized to test. Add it with `--authorize {host}` and affirm with `--i-am-authorized`."
            )
        if not in_default and not self.affirmed:
            raise AuthorizationError(
                f"target host {host!r} is operator-added — affirm you are authorized to test it with "
                f"`--i-am-authorized`. (This is a legal/ethics gate, not a nuisance: only test what you own or "
                f"have written authorization for.)"
            )
        return host

    @staticmethod
    def _ip_in(host: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
