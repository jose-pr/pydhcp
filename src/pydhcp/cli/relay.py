"""`pydhcp relay`: run a DHCP relay agent."""

from __future__ import annotations

import typing as _ty
import duho

from ..listener.spec import _split_host_port
from ..relay import DEFAULT_MAX_HOPS, DhcpRelay
from ..packet.enums import DhcpPort
from ._common import _Command


def _parse_server_address(value: str) -> "tuple[str, int]":
    """Split one `--server` argument into `(host, port)`, port 67 by default.

    Shares the listener's parser rather than repeating it. The hand-rolled one
    here split on a lone ':', which made `--server "[::1]:6767"` -- three colons
    -- fall through as a single opaque host string; the listener reads the same
    text as `("::1", 6767)`. Two parsers, two answers for the same syntax.

    An empty host is rejected here even though `_split_host_port` defaults it to
    `0.0.0.0`: the wildcard means "every local address" and is a reasonable
    thing to *listen* on, but as the address of an upstream server to forward
    *to* it is meaningless, so `--server :6767` is a typo worth reporting.
    """
    text = value.strip()
    if not text or (text.startswith(":") and not text.startswith("::")):
        raise ValueError(
            f"--server needs an upstream host address, got {value!r}; "
            "a bare port has no server to forward to"
        )
    host, port = _split_host_port(text)
    return host, int(DhcpPort.SERVER) if port is None else port


class Relay(_Command):
    """Start DHCP relay agent"""

    _parsername_ = "relay"

    listen: _ty.Optional[str] = None
    "Listen address/port spec, for example '*' or '127.0.0.1:6767,127.0.0.1:6768'"
    ("--listen", "-l")

    # A tuple, not a list: a mutable class-level default is shared by every
    # instance -- `a.server is b.server is Relay.server` -- so one command
    # appending to it would change the default every parser built afterwards
    # sees. duho copies at parser-build time, which hid it on the shipped path.
    server: _ty.Tuple[str, ...] = ()
    "Upstream DHCP server address, optionally host:port (repeatable)"
    ("--server", "-s")

    max_hops: int = DEFAULT_MAX_HOPS
    "Drop requests whose hop count exceeds this (RFC 1542 default 4, max 16)"
    ("--max-hops",)

    insert_relay_agent_info: bool = False
    "Add RELAY_AGENT_INFORMATION (option 82) to forwarded requests"
    ("--insert-relay-agent-info",)

    circuit_id: _ty.Optional[str] = None
    "Hex-encoded circuit ID sub-option (requires --insert-relay-agent-info)"
    ("--circuit-id",)

    remote_id: _ty.Optional[str] = None
    "Hex-encoded remote ID sub-option (requires --insert-relay-agent-info)"
    ("--remote-id",)

    per_interface: bool = False
    "Bind each interface separately instead of using wildcard packet-info routing"
    ("--per-interface",)

    def __call__(self) -> None:
        # The help text has always said these "require --insert-relay-agent-info",
        # and nothing enforced it: `_insert_relay_agent_info` returns early when
        # the flag is off, so `-s 10.0.0.1 --circuit-id 0a01` forwarded packets
        # with no option 82 and said nothing. Checked here rather than in
        # DhcpRelay because the library documents these as independent kwargs
        # and tests construct it that way -- raising there is an API break.
        ignored = [
            flag
            for flag, value in (
                ("--circuit-id", self.circuit_id),
                ("--remote-id", self.remote_id),
            )
            if value
        ]
        if ignored and not self.insert_relay_agent_info:
            raise ValueError(
                f"{' and '.join(ignored)} require --insert-relay-agent-info; "
                "without it no relay agent information option is added at all"
            )

        server_addresses = [_parse_server_address(addr) for addr in self.server]
        circuit_id = bytes.fromhex(self.circuit_id) if self.circuit_id else None
        remote_id = bytes.fromhex(self.remote_id) if self.remote_id else None

        if self.insert_relay_agent_info and not ignored:
            # An empty sub-option list inserts nothing, so the flag alone is a
            # no-op. A warning rather than an error: the flag is the library's
            # documented switch and a future sub-option could make it meaningful.
            self._logger_.warning(
                "--insert-relay-agent-info was given without --circuit-id or "
                "--remote-id, so no relay agent information option will be added"
            )

        # Construct first, announce second. The constructor is what validates
        # the upstream addresses and `max_hops`, so announcing first meant a bad
        # argument was reported *after* "Starting DHCP relay..." and read as a
        # runtime failure rather than as the argument error it is.
        relay = DhcpRelay(
            listen=self.listen or "*",
            server_addresses=server_addresses,
            max_hops=self.max_hops,
            insert_relay_agent_info=self.insert_relay_agent_info,
            circuit_id=circuit_id,
            remote_id=remote_id,
            per_interface=self.per_interface,
        )
        self._logger_.info(
            "Starting DHCP relay, listening on: %s, forwarding to: %s...",
            self.listen or "*",
            ", ".join(self.server),
        )
        try:
            relay.bind()
            relay.listen()
        except KeyboardInterrupt:
            self._logger_.info("Stopping relay...")
            relay.stop()
