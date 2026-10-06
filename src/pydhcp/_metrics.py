from __future__ import annotations

import typing as _ty


class DHCPMetrics:
    """Per-instance counters. Every listener/server/client/relay/capture owns one.

    The field list lives in `FIELDS` rather than being repeated by `__init__`,
    `reset` and `snapshot`: three copies of the same names is how a counter ends
    up incremented but absent from a snapshot, or reset everywhere but one.
    """

    #: Every counter, in the order `snapshot()` reports them.
    FIELDS: _ty.ClassVar[_ty.Tuple[str, ...]] = (
        "packets_received",
        "packets_sent",
        "leases_allocated",
        "leases_renewed",
        "leases_released",
        "leases_declined",
        "releases_ignored",
        "packets_dropped_hop_limit",
        "packets_dropped_untrusted",
        "packets_dropped_truncated",
        "packets_dropped_error",
        "replies_dropped_overflow",
        "packets_dropped_backlog",
        "packets_decoded_leniently",
        "packets_dropped_no_client_id",
        "packets_dropped_other_server",
        "addresses_refused",
        "replies_dropped_pin",
    )

    packets_received: int
    packets_sent: int
    leases_allocated: int
    leases_renewed: int
    leases_released: int
    #: DHCPDECLINEs. Counted apart from releases because they mean the
    #: opposite: the client found the address already in use, which is an
    #: address-conflict signal an operator needs to see, and folding it into
    #: `leases_released` made a conflict storm look like orderly shutdowns.
    leases_declined: int
    #: DHCPRELEASEs refused because the address named did not match the stored
    #: binding. Visible so "nobody is releasing" reads differently from
    #: "somebody is releasing addresses they do not hold".
    releases_ignored: int
    packets_dropped_hop_limit: int
    packets_dropped_untrusted: int
    #: Datagrams dropped before decoding because they did not fit
    #: `max_packet_size`. A sender that keeps exceeding it is a
    #: misconfiguration an operator can act on, which is why it is counted
    #: rather than only logged.
    packets_dropped_truncated: int
    #: Datagrams lost to an error anywhere in receive, decode or handle.
    packets_dropped_error: int
    #: Replies discarded because the client's reply queue was full.
    replies_dropped_overflow: int
    #: Datagrams the async listener's hand-off dropped unhandled: the
    #: backlog behind the handler was at its bound, or the listener
    #: was stopping and discarded what was queued.
    packets_dropped_backlog: int
    #: Datagrams that decoded because the decoder forgave something: an option
    #: cut short (what arrived is kept) or text that is not UTF-8 (its octets
    #: are kept). One per datagram, however many places in it. Option text is
    #: read when a handler asks for it, so a bad option string is not counted.
    packets_decoded_leniently: int
    #: Messages a server dropped because they carry neither a client
    #: identifier nor a hardware address.
    packets_dropped_no_client_id: int
    #: Messages other than a REQUEST that name another server's identifier.
    packets_dropped_other_server: int
    #: Requested addresses the server refused to lease (off the served
    #: network, its own, in use, quarantined).
    addresses_refused: int
    #: Broadcast replies dropped because they could not be pinned to the
    #: interface the request arrived on, with or without its index. Sent
    #: unpinned they could have left by another interface.
    replies_dropped_pin: int

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        for field in self.FIELDS:
            setattr(self, field, 0)

    def snapshot(self) -> _ty.Dict[str, int]:
        return {field: int(getattr(self, field)) for field in self.FIELDS}
