import typing as _ty


class DhcpMetrics:
    def __init__(self) -> None:
        self.packets_received = 0
        self.packets_sent = 0
        self.leases_allocated = 0
        self.leases_renewed = 0
        self.leases_released = 0
        self.packets_dropped_hop_limit = 0

    def reset(self) -> None:
        self.packets_received = 0
        self.packets_sent = 0
        self.leases_allocated = 0
        self.leases_renewed = 0
        self.leases_released = 0
        self.packets_dropped_hop_limit = 0

    def snapshot(self) -> _ty.Dict[str, int]:
        return {
            "packets_received": self.packets_received,
            "packets_sent": self.packets_sent,
            "leases_allocated": self.leases_allocated,
            "leases_renewed": self.leases_renewed,
            "leases_released": self.leases_released,
            "packets_dropped_hop_limit": self.packets_dropped_hop_limit,
        }
