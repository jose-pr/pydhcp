import enum as _enum
class HardwareAddressType(_enum.IntEnum):
    NONE = 0
    ETHERNET = 1
    EXPERIMENTAL_ETHERNET = 2
    AX25 = 3
    PRONET = 4
    CHAOS = 5
    IEEE_802 = 6
    ARCNET = 7
    HYPERCHANNEL = 8
    LANSTAR = 9
    AUTONET = 10
    LOCALTALK = 11
    LOCALNET = 12

    def dumps(self, address: bytes):
        match self:
            case HardwareAddressType.ETHERNET:
                return address.hex(":", 1).upper()
            case _other:
                return f"{address}"