class DhcpMetrics:
    def __init__(self) -> None:
        self.packets_received = 0
        self.packets_sent = 0
        self.leases_allocated = 0
        self.leases_renewed = 0
        self.leases_released = 0

    def reset(self) -> None:
        self.packets_received = 0
        self.packets_sent = 0
        self.leases_allocated = 0
        self.leases_renewed = 0
        self.leases_released = 0


METRICS = DhcpMetrics()
