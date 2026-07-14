from pydhcp.capture import DhcpCapture
from pydhcp.packet.structured import dump_message


def on_capture(event) -> None:
    print(f"{event.captured_at.isoformat()} {event.message_type} {event.client_id}")
    print(dump_message(event.message, "json"))


def main() -> None:
    capture = DhcpCapture(
        listen=("127.0.0.1", 6767),
        packet_filter="msg_type=DHCPDISCOVER",
        hook=on_capture,
    )
    capture.listen()


if __name__ == "__main__":
    main()
