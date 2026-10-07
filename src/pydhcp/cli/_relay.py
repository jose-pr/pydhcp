"""`pydhcp relay`: run a DHCP relay agent."""

from __future__ import annotations

import typing as _ty

from duho import Extend, Meta

from ..listener._spec import _split_host_port
from ..relay._core import DEFAULT_MAX_HOPS
from ..relay._sync import DHCPRelay
from ..packet._enums import DHCPPort
from ._common import _arguments, _Listening


def _parse_server_address(value: str) -> "tuple[str, int]":
    """Split one `--server` argument into `(host, port)`, port 67 by default.

    Shares the listener's parser rather than repeating it: splitting on a lone
    ':' would read `--server "[::1]:6767"` -- three colons -- as a single opaque
    host string, where the listener reads `("::1", 6767)`. One parser gives one
    answer for the same syntax.

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
    return host, int(DHCPPort.SERVER) if port is None else port


class Relay(_Listening):
    """Start DHCP relay agent"""

    _parsername_ = "relay"

    # A tuple, not a list: a mutable class-level default is shared by every
    # instance -- `a.server is b.server is Relay.server` -- so one command
    # appending to it would change the default every parser built afterwards
    # sees.
    server: _ty.Annotated[
        _ty.Tuple[str, ...],
        Extend(","),
        Meta(env="PYDHCP_RELAY_SERVER", required=True),
    ] = ()
    "Upstream DHCP server address, optionally host:port; repeat the option or separate with commas. Required"
    ("--server", "-s")

    max_hops: _ty.Annotated[int, Meta(env="PYDHCP_RELAY_MAX_HOPS")] = DEFAULT_MAX_HOPS
    "Drop requests whose hop count exceeds this (RFC 1542 default 4, max 16)"
    ("--max-hops",)

    insert_relay_agent_info: _ty.Annotated[
        bool, Meta(env="PYDHCP_RELAY_INSERT_RELAY_AGENT_INFO")
    ] = False
    "Add RELAY_AGENT_INFORMATION (option 82) to forwarded requests"
    ("--insert-relay-agent-info",)

    circuit_id: _ty.Annotated[
        _ty.Optional[str], Meta(env="PYDHCP_RELAY_CIRCUIT_ID")
    ] = None
    "Hex-encoded circuit ID sub-option (requires --insert-relay-agent-info). Default: none"
    ("--circuit-id",)

    remote_id: _ty.Annotated[_ty.Optional[str], Meta(env="PYDHCP_RELAY_REMOTE_ID")] = (
        None
    )
    "Hex-encoded remote ID sub-option (requires --insert-relay-agent-info). Default: none"
    ("--remote-id",)

    def __call__(self) -> None:
        # The ids are named by their flags here; the constructor refuses the same
        # combinations in the library's words.
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
        listen = "*" if self.listen is None else self.listen

        # Construct first, announce second. The constructor is what validates
        # the upstream addresses and `max_hops`, so announcing first would report
        # a bad argument *after* "Starting DHCP relay..." and read as a runtime
        # failure rather than as the argument error it is.
        with _arguments():
            relay = DHCPRelay(
                listen=listen,
                server_addresses=server_addresses,
                max_hops=self.max_hops,
                insert_relay_agent_info=self.insert_relay_agent_info,
                circuit_id=circuit_id,
                remote_id=remote_id,
                per_interface=self.per_interface,
            )
        self._logger_.info(
            "Starting DHCP relay, listening on: %s, forwarding to: %s...",
            listen,
            ", ".join(self.server),
        )
        self._serve(relay)
