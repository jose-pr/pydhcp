from pydhcp.client import DHCPClient
from pydhcp.options import DHCPOptionCode


def main() -> None:
    client = DHCPClient(listen=("127.0.0.1", 6768))
    discover = client.build_discover(
        b"\x00\x11\x22\x33\x44\x55",
        parameter_request_list=[
            DHCPOptionCode.SUBNET_MASK,
            DHCPOptionCode.ROUTER,
            DHCPOptionCode.DNS,
        ],
    )
    client.send(discover, destination="127.0.0.1", port=6767)
    print(f"sent DHCPDISCOVER xid={discover.xid:08X}")


if __name__ == "__main__":
    main()
