"""Print each DHCPDISCOVER that reaches 127.0.0.1:6767, and write its record to standard output.

Needs the `pktcap` extra: pip install "pydhcp[pktcap]". Stop it with Ctrl-C.
"""

import sys

import pktcap

from pydhcp.capture import DHCPLayer, capture_dissector, sniff_dhcp

LISTEN = "127.0.0.1:6767"


def on_capture(frame: pktcap.DissectedFrame) -> None:
    layer = frame.layer(DHCPLayer)
    assert layer is not None
    print(f"{frame.time:.3f} {layer.message_type} {layer.client_id}", flush=True)


def main() -> None:
    # DHCP is read on 67, 68 and the port listened on; the filter knows its keys.
    dissector = capture_dissector((67, 68, 6767))
    wanted = pktcap.compile_capture_filter(
        "msg_type=DHCPDISCOVER", pktcap.frame_filter_for(dissector.registry)
    )
    frames = sniff_dhcp(LISTEN, dissector=dissector)
    with pktcap.CaptureWriter(sys.stdout.buffer, "json") as writer:
        try:
            pktcap.copy_frames(frames, writer, select=wanted, each=on_capture)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
