MAGIC_COOKIE = 0x63825363.to_bytes(4, "big")
"""The first four octets of the 'options' field of the DHCP message decimal values: 99, 130, 83 and 99"""

INIFINITE_LEASE_TIME = 0xFFFFFFFF
DHCP_MIN_LEGAL_PACKET_SIZE = 576


class Missing:
    ...


MISSING = Missing()
