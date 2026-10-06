"""A reply that finds the socket's send buffer full is sent when there is room.

The asynchronous listener makes its sockets non-blocking and replies from its
worker thread, so a full send buffer raises `BlockingIOError` there. A failed
pin and a full buffer are different things: the reply must wait for room and go
out as it was, and not be read as a pin failure and retried somewhere else.
Judged by what crosses the client's segment.
"""

from __future__ import annotations

import pytest

from ._topo import single

REPLY = b"reply-sent-while-the-send-buffer-was-full"


@pytest.mark.parametrize(
    "destination", ["10.99.0.2", "255.255.255.255"], ids=["unicast", "broadcast"]
)
def test_a_reply_waits_for_a_full_send_buffer_and_arrives(lab, destination):
    net = single(lab, client_addr="10.99.0.2/24")
    tap = lab.tap(net.cli, "cv0", "client-segment")
    server = lab.python(net.srv, "full_buffer.py", destination, name="server")
    assert server.wait_for_text("serving"), server.text()

    lab.python_wait(
        net.cli,
        "emit.py",
        "discover",
        "--src",
        "10.99.0.2",
        "--dst",
        "10.99.0.1",
    )
    assert server.wait_for_text("full after", 10), server.text()
    arrived = tap.wait_for(
        lambda frames: any(f.sport == 67 and f.payload == REPLY for f in frames), 25
    )

    assert "the send buffer did not fill" not in server.text(), server.text()
    assert arrived, f"the reply was lost: {server.text()}"
    assert "sent after" in server.text(), server.text()
    reply = [f for f in tap.frames() if f.payload == REPLY][0]
    assert reply.src_ip == "10.99.0.1"
