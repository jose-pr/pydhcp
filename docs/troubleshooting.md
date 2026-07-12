# Troubleshooting

This page covers the most common things that go sideways when bringing up a DHCP server.

## The server does not start

- Check whether another process is already bound to the UDP port.
- On Windows, verify the process has permission to open the socket.
- On Linux, confirm you are running with the privileges required for the binding mode you selected.

## No interfaces are listed

- Make sure the host has at least one IPv4 interface configured.
- In containers or sandboxes, interface enumeration may be limited by the runtime.
- If you are using a virtual adapter, confirm it exposes an address the library can resolve.

## Clients do not receive leases

- Confirm the server is bound to the interface that sees the client traffic.
- Verify the address pool overlaps the network on that interface.
- Check that the lease backend is writing allocations the way you expect.

## Packet decoding looks wrong

- Capture the raw packet and compare it against the DHCP header layout.
- Turn on debug logging to inspect the transaction ID and message type.
- Validate that any custom options implement the `DhcpOptionType` contract correctly.

## Wildcard listening behaves differently on Windows and Linux

- On Windows, wildcard listening uses one socket per interface so replies keep the correct source IP.
- On Linux, the same code path is the safe fallback; packet-info routing is only available on platforms that expose the needed socket APIs.
- If you need deterministic behavior while debugging, set `per_interface=True`.

## Useful commands

```bash
pydhcp interfaces
pydhcp server --help
pydhcp packet --help
```
