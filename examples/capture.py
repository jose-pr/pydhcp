from pydhcp.capture import DHCPCapture
from pydhcp.packet.structured import dump_message


def on_capture(event) -> None:
    print(f"{event.captured_at.isoformat()} {event.message_type} {event.client_id}")
    print(dump_message(event.message, "json"))


def main() -> None:
    capture = DHCPCapture(
        listen=("127.0.0.1", 6767),
        packet_filter="msg_type=DHCPDISCOVER",
        hook=on_capture,
    )
    with capture:
        try:
            capture.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
