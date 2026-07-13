# Troubleshooting

This page covers the most common things that go sideways when bringing up a DHCP server.

## The server does not start

- Check whether another process is already bound to the UDP port.
- On Windows, verify the process has permission to open the socket.
- On Linux, confirm you are running with the privileges required for the binding mode you selected.
- Remember that the package is pure Python, but DHCP serving still depends on OS socket privileges and UDP broadcast behavior.

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

Decode packet hex to structured JSON when you want tooling-friendly output.

```bash
pydhcp packet --decode --stdin --json
```

Use summary output when you want a compact terminal view while troubleshooting captures.

```bash
pydhcp packet --decode --stdin --summary
```

If TOML packet encoding or decoding reports that TOML support is unavailable, install the
optional TOML extra for the environment running the CLI: `pip install pydhcp[toml]`.

## Wildcard listening behaves differently on Windows and Linux

- Packet-info routing is opportunistic and only used on platforms that expose the needed socket APIs.
- `per_interface=True` is the portable deterministic path when you need one socket per interface.
- Explicit endpoint lists avoid interface-enumeration surprises while debugging.

```bash
pydhcp server --listen 127.0.0.1:6767,127.0.0.1:6768 --log-level debug
```

## Useful commands

```bash
pydhcp interfaces
pydhcp server --help
pydhcp packet --help
```
