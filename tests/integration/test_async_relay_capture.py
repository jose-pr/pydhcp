"""`AsyncDHCPRelay` / `AsyncDHCPCapture`: the parts a shared test cannot reach.

The forwarding, filter and hook *policy* is tested against both classes at once
by the `relay_class` / `capture_class` fixtures in `tests/test_relay.py` and
`tests/test_capture.py`. What is left, and lives here, is everything that needs
a real event loop and real sockets -- plus the structural guard that says the
async halves are a mixin and not a copy.

That guard is the point of this file. `AsyncDHCPServer` was originally written
as a copy of the sync constructor, `bind()` and receive path; a hardcoded
`_pktinfo = False` then left the async listener receiving *nothing at all* on
Linux while every unit test passed. A green suite is not evidence that the two
halves share a receive path -- so this measures it.
"""

from __future__ import annotations

import asyncio
import ast
import datetime as dt
import pathlib
import socket
import threading
import time
import typing as _ty

import pytest

from pydhcp import (
    AsyncDHCPCapture,
    AsyncDHCPRelay,
    DHCPCapture,
    DHCPMessage,
    DHCPOptions,
    DHCPRelay,
)
from ipaddress import IPv4Address as IPv4
from pydhcp.options import DHCPOptionCode
from pydhcp.packet import DHCPMessageType, DHCPFlags, HardwareAddressType, DHCPOpcode
from helpers import CHADDR, build_request
from pydhcp.listener import AsyncDHCPListener, DHCPListener

SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "pydhcp"


# --- The async halves must be a mixin, not a copy ----------------------------
#
# Measured, not read. Every check below is over the parsed source.


def _module(name: str) -> "tuple[ast.Module, list[str]]":
    text = (SRC / name).read_text(encoding="utf-8")
    return ast.parse(text), text.splitlines()


def _node(tree: ast.AST, path: str) -> ast.AST:
    """Find `Class.method` or a module-level `function` by dotted name."""
    node: _ty.Any = tree
    for part in path.split("."):
        for child in ast.iter_child_nodes(node):
            if getattr(child, "name", None) == part:
                node = child
                break
        else:  # pragma: no cover - a rename should fail loudly
            raise AssertionError(f"{path!r}: no {part!r}")
    return node


def _code_lines(node: ast.AST, lines: "list[str]") -> "set[str]":
    """The node's *statements*, with comments, docstrings and headers removed.

    `def`/`class` header lines are excluded deliberately. A constructor's
    parameter list is the public API and is bound to read the same on both
    halves -- `listen: ListenLike = None,` proves nothing. What must not be
    shared is a *statement*: a line that does work.
    """
    skip: set[int] = set()
    for child in ast.walk(node):
        body = getattr(child, "body", None)
        if not body or not isinstance(body, list):
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                skip.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            head = min([child.lineno] + [d.lineno for d in child.decorator_list])
            skip.update(range(head, first.lineno))
    out = set()
    start = node.lineno  # type: ignore[attr-defined]
    end = node.end_lineno or start  # type: ignore[attr-defined]
    for row in range(start, end + 1):
        if row in skip:
            continue
        line = lines[row - 1].strip()
        if not line or line.startswith("#"):
            continue
        out.add(line)
    return out


#: Every function that reads a datagram, builds its context, or opens a socket.
#: If any of these lines turns up inside an async class body, the mixin has
#: become a copy -- which is the defect this whole plan exists to avoid.
_RECEIVE_PATH = (
    "_pktinfo_supported",
    "_bind_sockets",
    "_arrival",
    "_iter_listen_bindings",
    "_close_socket",
    "_context_for",
    "_resolve_interface",
    "_parselisteners",
    "DHCPListener._loop",
    "_ListenerCore.bind",
    "_ListenerCore._dispatch",
    "AsyncDHCPListener._receive",
    "AsyncDHCPListener._dispatch_received",
    "AsyncDHCPListener._handle_datagram",
    "AsyncDHCPListener.start",
    "AsyncDHCPListener._begin_receiving",
    "AsyncDHCPListener._end_receiving",
)

#: The modules holding the core whose policy each async class inherits rather
#: than restates.
_CORE_MODULES = {
    "relay/_asyncio.py": ("relay/_core.py", "relay/_pending.py"),
    "capture/_asyncio.py": ("capture/_core.py",),
}

#: The policy each async class inherits rather than restates.
_POLICY = {
    "relay/_asyncio.py": (
        "_RelayCore.handle",
        "_RelayCore._forward_to_servers",
        "_RelayCore._forward_to_client",
        "_RelayCore._init_relay_state",
        "_RelayCore._client_transport",
        "_RelayCore._routed_transport",
        "_RelayCore._encode_for_forward",
        "_RelayCore._encode_request",
        "_RelayCore._added_option_82",
        "_RelayCore._is_own_address",
        "_PendingClients._record_pending",
        "_PendingClients._lookup_pending",
        "_PendingClients._expire_pending",
        "_PendingClients._pending_key",
    ),
    "capture/_asyncio.py": (
        "_CaptureCore.handle",
        "_CaptureCore._init_capture_state",
    ),
}


def _listener_code(path: str) -> "set[str]":
    """A receive-path definition's lines, from whichever `listener/` module
    holds it -- the package is split by responsibility."""
    for source in sorted((SRC / "listener").glob("*.py")):
        tree, lines = _module(str(source.relative_to(SRC)))
        try:
            return _code_lines(_node(tree, path), lines)
        except AssertionError:
            continue
    raise AssertionError(f"{path!r} is in no listener module")


def _shared_corpus(module: str) -> "set[str]":
    corpus: set[str] = set()
    for path in _RECEIVE_PATH:
        corpus |= _listener_code(path)
    parsed = [_module(core) for core in _CORE_MODULES[module]]
    for path in _POLICY[module]:
        for tree, lines in parsed:
            try:
                corpus |= _code_lines(_node(tree, path), lines)
                break
            except AssertionError:
                continue
        else:  # pragma: no cover - a rename should fail loudly
            raise AssertionError(f"{path!r} is in none of {_CORE_MODULES[module]}")
    return corpus


@pytest.mark.parametrize(
    "module, async_class",
    [
        ("relay/_asyncio.py", "AsyncDHCPRelay"),
        ("capture/_asyncio.py", "AsyncDHCPCapture"),
    ],
)
def test_the_async_class_copies_no_receive_path_or_policy_line(
    module: str, async_class: str
) -> None:
    """Not 'I read it and it looked fine' -- the lines are actually compared."""
    tree, lines = _module(module)
    body = _code_lines(_node(tree, async_class), lines)
    shared = _shared_corpus(module)

    # A bare `)` or `self,` says nothing; anything of substance that appears in
    # both places is a copy.
    copied = sorted(line for line in body & shared if len(line) >= 12)

    assert not copied, f"{async_class} repeats shared code:\n  " + "\n  ".join(copied)


@pytest.mark.parametrize(
    "module, async_class",
    [
        ("relay/_asyncio.py", "AsyncDHCPRelay"),
        ("capture/_asyncio.py", "AsyncDHCPCapture"),
    ],
)
def test_the_async_class_never_names_a_receive_path_helper(
    module: str, async_class: str
) -> None:
    """It must reach them only by inheriting them."""
    tree, lines = _module(module)
    node = _node(tree, async_class)
    named = {
        n.id
        for n in ast.walk(node)
        if isinstance(n, ast.Name) and n.id in _RECEIVE_PATH
    } | {
        n.attr
        for n in ast.walk(node)
        if isinstance(n, ast.Attribute) and n.attr in _RECEIVE_PATH
    }
    assert not named, f"{async_class} reimplements around {sorted(named)}"


@pytest.mark.parametrize(
    "module, async_class, state_init",
    [
        ("relay/_asyncio.py", "AsyncDHCPRelay", "_init_relay_state"),
        ("capture/_asyncio.py", "AsyncDHCPCapture", "_init_capture_state"),
    ],
)
def test_the_async_class_is_only_a_constructor_and_a_handle(
    module: str, async_class: str, state_init: str
) -> None:
    """A constructor and nothing else; the rules are inherited from the core.

    `__init__` must delegate its state to the same method the sync constructor
    calls -- the `_init_server_state` shape. Re-implementing the body is how
    `AsyncDHCPServer` lost `_declined` and made every DHCPDECLINE an
    AttributeError.
    """
    tree, _lines = _module(module)
    node = _ty.cast(ast.ClassDef, _node(tree, async_class))
    methods = [
        n.name
        for n in node.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    assert methods == ["__init__"], methods

    init = _ty.cast(ast.FunctionDef, _node(tree, f"{async_class}.__init__"))
    called = [
        n.func.attr
        for n in ast.walk(init)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    ]
    assert called == ["__init__", state_init], called


def test_the_two_constructors_accept_the_same_arguments() -> None:
    """Minus `poll_interval`, which is the sync receive loop's poll interval,
    plus `max_queued`, which bounds the async hand-off to the handler thread.

    A silently missing keyword is how an async class stops being a drop-in for
    its sync counterpart without anything failing.
    """
    import inspect

    for sync, asyncy in ((DHCPRelay, AsyncDHCPRelay), (DHCPCapture, AsyncDHCPCapture)):
        expected = [
            name
            for name in inspect.signature(sync.__init__).parameters
            if name != "poll_interval"
        ]
        actual = [
            name
            for name in inspect.signature(asyncy.__init__).parameters
            if name != "max_queued"
        ]
        assert actual == expected, f"{asyncy.__name__}: {actual} != {expected}"


@pytest.mark.parametrize(
    "sync, asyncy, kwargs",
    [
        (DHCPRelay, AsyncDHCPRelay, {"server_addresses": ["192.0.2.1"]}),
        (DHCPCapture, AsyncDHCPCapture, {}),
    ],
)
def test_the_async_class_holds_the_same_state_as_the_sync_one(
    sync: type, asyncy: type, kwargs: dict
) -> None:
    """The `test_async_server_has_the_same_state_as_the_sync_one` guard, here.

    Listener internals legitimately differ (a wake socket and a select loop
    against a worker and receive tasks), so this compares the policy layer.
    """
    missing = set(vars(sync(listen=("127.0.0.1", 0), **kwargs))) - set(
        vars(asyncy(listen=("127.0.0.1", 0), **kwargs))
    )
    sync_listener_only = set(vars(DHCPListener(listen=("127.0.0.1", 0)))) - set(
        vars(AsyncDHCPListener(listen=("127.0.0.1", 0)))
    )
    assert (
        missing <= sync_listener_only
    ), f"{asyncy.__name__} is missing {sorted(missing - sync_listener_only)}"


def test_the_async_relay_keeps_the_relays_ports_not_the_listeners() -> None:
    """`AsyncDHCPListener.DEFAULT_PORTS` comes first in the MRO.

    Left to it, an async relay would also bind the client port 68 and start
    relaying its own forwarded replies.
    """
    assert AsyncDHCPRelay.DEFAULT_PORTS == DHCPRelay.DEFAULT_PORTS
    assert AsyncDHCPRelay(server_addresses=["192.0.2.1"]).DEFAULT_PORTS == (67,)


@pytest.mark.parametrize(
    "asyncy, sync, kwargs",
    [
        (AsyncDHCPRelay, DHCPRelay, {"server_addresses": ["192.0.2.1"]}),
        (AsyncDHCPCapture, DHCPCapture, {}),
    ],
)
def test_the_async_class_agrees_about_the_receive_path(
    asyncy: type, sync: type, kwargs: dict
) -> None:
    """The exact check that caught the async listener's Linux deafness.

    A wildcard bind must take the packet-info path wherever the sync half does;
    expanding the wildcard instead is what loses every broadcast on Linux.
    """
    for spec in ("*", ("*", 10067), None):
        left = sync(listen=spec, **kwargs)
        right = asyncy(listen=spec, **kwargs)
        # private: the packet-info probe's result: no public view
        assert left._pktinfo == right._pktinfo, f"{spec!r}"
        # private: the parsed listen spec: `bound_addresses` is empty until the bind
        assert len(left._listen) == len(right._listen), f"{spec!r}"


# --- Phases 2 and 3: the real loop, real sockets -----------------------------


def _discover_bytes(xid: int = 0x5150F00D, chaddr: bytes = CHADDR) -> bytes:
    return bytes(
        build_request(DHCPMessageType.DHCPDISCOVER, xid=xid, chaddr=chaddr).encode()
    )


def _offer(xid: int, chaddr: bytes, giaddr: str) -> bytes:
    options = DHCPOptions()
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPOFFER
    return bytes(
        DHCPMessage(
            op=DHCPOpcode.BOOTREPLY,
            htype=HardwareAddressType.ETHERNET,
            hlen=6,
            hops=1,
            xid=xid,
            secs=dt.timedelta(seconds=0),
            flags=DHCPFlags.UNICAST,
            # ciaddr, so the relay unicasts back rather than broadcasting from a
            # loopback-bound socket -- which POSIX refuses outright.
            ciaddr=IPv4("127.0.0.1"),
            yiaddr=IPv4("127.0.0.1"),
            siaddr=IPv4("0.0.0.0"),
            giaddr=IPv4(giaddr),
            chaddr=chaddr,
            sname="",
            file="",
            options=options,
        ).encode()
    )


async def _recv(sock: socket.socket, timeout: float = 5.0) -> "tuple[bytes, tuple]":
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, sock.recvfrom, 4096), timeout=timeout
    )


def test_async_relay_forwards_a_request_and_its_reply_over_real_sockets() -> None:
    """The whole round trip on the event loop, not a hand-built context.

    This is the half a shared `handle()` test cannot reach: binding, the
    receive path (`add_reader` on POSIX, a `DatagramProtocol` on Windows'
    proactor loop) and the reply leaving by the tracked client port.
    """
    xid = 0x0BADF00D

    async def main() -> None:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind(("127.0.0.1", 0))  # deliberately not port 68
        relay = AsyncDHCPRelay(
            listen=("127.0.0.1", 0),
            server_addresses=[("127.0.0.1", upstream.getsockname()[1])],
        )
        await relay.start()
        relay_port = relay.bound_addresses[0].port
        try:
            client.sendto(_discover_bytes(xid=xid), ("127.0.0.1", relay_port))

            data, _addr = await _recv(upstream)
            forwarded = DHCPMessage.decode(data)
            assert forwarded.hops == 1, "the relay must count itself"
            assert forwarded.giaddr == IPv4("127.0.0.1"), forwarded.giaddr
            assert forwarded.xid == xid

            upstream.sendto(
                _offer(xid, CHADDR, str(forwarded.giaddr)),
                ("127.0.0.1", relay_port),
            )
            reply_data, _from = await _recv(client)
            reply = DHCPMessage.decode(reply_data)
            assert reply.op == DHCPOpcode.BOOTREPLY
            assert reply.xid == xid
            # The handler worker counts *after* its send returns, so the reply
            # can reach this thread first; give the increment a moment.
            # Measured on CI: read as 1 with the reply already in hand.
            deadline = time.monotonic() + 2.0
            while relay.metrics.packets_sent < 2 and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            assert relay.metrics.packets_sent == 2
        finally:
            await relay.aclose()
            upstream.close()
            client.close()

    asyncio.run(main())


def test_async_capture_records_a_packet_off_the_wire() -> None:
    events: list = []

    async def main() -> None:
        capture = AsyncDHCPCapture(
            listen=("127.0.0.1", 0),
            packet_filter="msg_type=DHCPDISCOVER",
            sink=events.append,
        )
        await capture.start()
        port = capture.bound_addresses[0].port
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(_discover_bytes(), ("127.0.0.1", port))
            sender.close()
            for _ in range(200):
                if events:
                    break
                await asyncio.sleep(0.02)
        finally:
            await capture.aclose()

    asyncio.run(main())

    assert len(events) == 1, "the datagram never reached the capture"
    assert events[0].message_type == "DHCPDISCOVER"


def test_async_capture_filter_rejects_on_the_wire_too() -> None:
    """A filter that matches nothing must not be mistaken for a quiet segment."""
    events: list = []
    handled = threading.Event()

    class Probe(AsyncDHCPCapture):
        def handle(self, msg, context):
            super().handle(msg, context)
            handled.set()

    async def main() -> None:
        capture = Probe(
            listen=("127.0.0.1", 0),
            packet_filter="msg_type=DHCPREQUEST",
            sink=events.append,
        )
        await capture.start()
        port = capture.bound_addresses[0].port
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.sendto(_discover_bytes(), ("127.0.0.1", port))
            sender.close()
            for _ in range(200):
                if handled.is_set():
                    break
                await asyncio.sleep(0.02)
        finally:
            await capture.aclose()

    asyncio.run(main())

    assert handled.is_set(), "the datagram never reached the capture"
    assert events == []


def test_async_capture_hook_fail_fast_actually_stops_the_loop() -> None:
    """The path the plan singles out, on a live loop.

    `hook_fail_fast` calls `shutdown()` from the handler *worker thread*, and
    `Event.set()` finishes through `loop.call_soon`, which queues a callback
    without waking the loop. Measured (a handler calling it on its worker):
    Linux's selector loop never woke and `await wait_closed()` blocked forever,
    while Windows' proactor loop returned in 7 ms. So the assertion is on the
    *elapsed time*, not merely on `wait_closed()` returning -- `wait_for`'s own timer wakes the loop at the deadline
    and makes a hang look like a pass.
    """
    elapsed: list = []

    def bad_hook(event):
        raise RuntimeError("boom")

    async def main() -> None:
        capture = AsyncDHCPCapture(
            listen=("127.0.0.1", 0), hook=bad_hook, hook_fail_fast=True
        )
        await capture.start()
        port = capture.bound_addresses[0].port
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.sendto(_discover_bytes(), ("127.0.0.1", port))
        sender.close()
        started = time.monotonic()
        assert await capture.wait_closed(10.0)
        elapsed.append(time.monotonic() - started)
        assert isinstance(capture.hook_error, RuntimeError)
        await capture.aclose()
        assert capture.bound_addresses == (), "the sockets are still open"

    asyncio.run(main())

    assert elapsed and elapsed[0] < 3.0, (
        f"shutdown() from the handler worker took {elapsed[0]:.2f}s to reach the "
        "loop -- it was not marshalled back onto it"
    )


def test_async_relay_state_is_only_touched_by_one_thread() -> None:
    """What keeps `_pending_clients` safe without a lock.

    It is an unguarded OrderedDict, read and written per datagram. The single
    handler worker is the whole guarantee -- a pool here would be a data race,
    not a speedup.
    """
    threads: set = set()
    seen = threading.Event()
    count = 12

    class Probe(AsyncDHCPRelay):
        def handle(self, msg, context):
            threads.add(threading.current_thread().ident)
            super().handle(msg, context)
            if len(self._pending_clients) >= count:
                seen.set()

    async def main() -> None:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream.bind(("127.0.0.1", 0))
        relay = Probe(
            listen=("127.0.0.1", 0),
            server_addresses=[("127.0.0.1", upstream.getsockname()[1])],
        )
        await relay.start()
        port = relay.bound_addresses[0].port
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for index in range(count):
                sender.sendto(
                    _discover_bytes(
                        xid=0xAA00 + index,
                        chaddr=bytes([0x02, 0, 0, 0, 0, index]),
                    ),
                    ("127.0.0.1", port),
                )
            sender.close()
            for _ in range(250):
                if seen.is_set():
                    break
                await asyncio.sleep(0.02)
            # private: the relay's pending table: its bound and eviction are the subject
            assert seen.is_set(), f"only {len(relay._pending_clients)} of {count}"
            assert len(threads) == 1, f"handlers ran on {len(threads)} threads"
            assert threading.current_thread().ident not in threads
        finally:
            await relay.aclose()
            upstream.close()

    asyncio.run(main())
