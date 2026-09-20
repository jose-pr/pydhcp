import typing as _ty


class DhcpMetrics:
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
        "replies_dropped_overflow",
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
    #: Replies discarded because the client's reply queue was full.
    replies_dropped_overflow: int

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        for field in self.FIELDS:
            setattr(self, field, 0)

    def snapshot(self) -> _ty.Dict[str, int]:
        return {field: int(getattr(self, field)) for field in self.FIELDS}
