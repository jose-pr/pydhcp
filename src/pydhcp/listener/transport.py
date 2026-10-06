"""How a reply leaves: the plain UDP transport and the one that pins its source."""

from __future__ import annotations

import logging as _logging
import ipaddress as _ipaddress
import socket as _socket
import typing as _ty

import netimps as _netimps

from .. import _constants as _const

LOGGER = _logging.getLogger(__name__)

#: The all-ones address every DHCP client can be reached at before it has one of
#: its own (RFC 2131 s4.1).
BROADCAST_ADDRESS = "255.255.255.255"


class DHCPTransport:
    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _ipaddress.IPv4Address,
        port: int,
        client_mac: bytes,
    ) -> int:
        raise NotImplementedError()


def _dest_string(dest: _ipaddress.IPv4Address) -> str:
    """The address to actually send a reply to.

    0.0.0.0 in a DHCP header means "this client has no address yet", which on
    the wire is the limited broadcast (RFC 2131 s4.1) -- not a host called
    0.0.0.0, which is what `str()` would produce and what `sendto` would then
    reject or silently route nowhere.
    """
    return BROADCAST_ADDRESS if dest == _const.WILDCARD_V4 else str(dest)


class UDPTransport(DHCPTransport):
    def __init__(self, socket: _socket.socket):
        self.socket = socket

    def _send_to(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest_str: str,
        port: int,
    ) -> int:
        """One `sendto`, with no fallback of any kind."""
        return self.socket.sendto(data, (dest_str, port))

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _ipaddress.IPv4Address,
        port: int,
        client_mac: bytes,
    ) -> int:
        # No broadcast retry on failure. It was written for the case where a
        # unicast cannot reach a client that has no address yet -- "standard UDP
        # sockets can't target an L2 MAC if there is no ARP entry" -- but that
        # case does not raise: the kernel ARPs for an address nobody answers for
        # and drops the datagram silently, which is precisely how the original
        # POSIX no-reply defect went unnoticed. So the retry never fired for
        # what it was written for, and only ever fired for real socket errors --
        # EACCES, ENETUNREACH, a closed socket -- where a broadcast is both
        # useless and a disclosure: it puts a reply the caller deliberately
        # unicast onto the whole segment, carrying yiaddr, chaddr, the lease
        # options and any echoed option 82.
        #
        # Deciding *whether* a reply should be broadcast belongs to the caller
        # and is already made there: the server picks 255.255.255.255 for a
        # client with no address, `_dest_string` maps a 0.0.0.0 destination to
        # it, and a relay picks the client-facing address. The transport's job
        # is to send where it was told and report when it cannot.
        #
        # Future RawTransport can be plugged in here to craft L2 Ethernet frames
        # targeting client_mac, which is the real answer for an unconfigured
        # client on a segment where broadcast is unwanted.
        return self._send_to(data, _dest_string(dest), port)


class PktInfoUDPTransport(UDPTransport):
    """A transport that sends from a pinned interface and source address.

    For a wildcard socket: the reply leaves from the address and interface the
    request arrived on (``local_ip``, ``ifindex``), which the routing table
    alone would not choose on a multi-homed host. Pinning goes through
    `netimps.UDPEndpoint.send(src=...)`, which builds the per-platform control
    message -- Linux, macOS and Windows lay it out three different ways.
    """

    def __init__(
        self,
        socket: _socket.socket,
        endpoint: "_ty.Optional[_netimps.UDPEndpoint]" = None,
    ):
        super().__init__(socket)
        self.ifindex: int | None = None
        self.local_ip: _ipaddress.IPv4Address | None = None
        self.endpoint = endpoint or _netimps.UDPEndpoint(socket, pktinfo=False)

    def _source(self) -> _netimps.Interface:
        """The pin, as a netimps `Interface` holding exactly ``local_ip``.

        Not the bare address: netimps resolves an address to its interface by
        enumerating every adapter, measured at 1.29 ms per send against 0.04 ms
        for an `Interface` -- per reply, which is the per-packet enumeration
        cost this module has already removed once from the receive side. And not
        the receiving adapter's own `Interface`, which may hold several IPv4
        addresses: netimps would pick one, and the reply must come from the one
        the client addressed. An index of 0 means "unknown" and pins the address
        alone.
        """
        assert self.local_ip is not None
        return _netimps.Interface(
            name=f"ifindex {self.ifindex or 0}",
            index=self.ifindex or 0,
            ips=[_ipaddress.IPv4Interface(self.local_ip)],
        )

    def send(
        self,
        data: _ty.Union[bytes, bytearray, memoryview],
        dest: _ipaddress.IPv4Address,
        port: int,
        client_mac: bytes,
    ) -> int:
        dest_str = _dest_string(dest)
        if self.local_ip is not None and self.endpoint.has_src_pinning:
            try:
                # `_dest_string`, not `str(dest)`: this path took a yiaddr of
                # 0.0.0.0 -- the normal case for a client that has no address
                # yet -- and asked the kernel to send to host 0.0.0.0, which is
                # the one destination a reply to an unconfigured client must
                # never be.
                return int(
                    self.endpoint.send(bytes(data), dest_str, port, src=self._source())
                )
            except Exception as e:
                # This path's own failure modes -- a stale ifindex, a local_ip
                # no longer on that adapter -- used to propagate and lose the
                # reply outright. Retry without the pin, which is the thing that
                # went stale.
                #
                # Deliberately `_send_to` and not `super().send()`: the base
                # send answers a failed *unicast* with a broadcast to the whole
                # segment. That is right for a client with no address yet, and
                # wrong for one the server deliberately unicast to -- a
                # RENEWING client at its own ciaddr, or a relay at giaddr. Going
                # through it here would put yiaddr, chaddr, the lease options
                # and the echoed RELAY_AGENT_INFORMATION (RFC 3046 s2.2, whose
                # circuit-id identifies the subscriber's physical port) in front
                # of every host on the segment. Measured on the version this
                # replaces: sendmsg -> 192.0.2.50, sendto -> 192.0.2.50, sendto
                # -> 255.255.255.255. Same destination, one attempt, and the
                # error propagates if it fails.
                LOGGER.warning(
                    f"Pinned send from {self.local_ip} (ifindex {self.ifindex}) "
                    f"failed ({e.__class__.__name__} | {e}); retrying unpinned to "
                    f"{dest_str}."
                )
                return self._send_to(data, dest_str, port)
        return super().send(data, dest, port, client_mac)
