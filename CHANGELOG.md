# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **`pydhcp.exceptions`**, re-exported at the root: `DHCPError` (the base),
  `DHCPDecodeError` and `DHCPValueError` (each also a `ValueError`) and
  `NoClientIdentityError`. Every decoder raises `DHCPDecodeError` and nothing
  else for malformed octets: `DHCPMessage.decode` and each option codec used
  to raise a bare `ValueError` (or, for a short address, an
  `ipaddress.AddressValueError`, for a bad UTF-8 label a
  `UnicodeDecodeError`, for a destination with host bits set an `ipaddress`
  `ValueError`). `except ValueError` keeps working.
- **`pydhcp.__version__`**, read from the installed distribution's metadata.
- **`AsyncDHCPClient`** (`pydhcp` and `pydhcp.client`): `DHCPClient` on an event
  loop. `send`, `discover_offer` and `dora` are coroutines taking the same
  keywords as the synchronous client's and returning the same results, with the
  same retransmission schedule, `secs` and reply matching; `next_reply` is a
  coroutine and `drain_replies` and the `build_*` methods are plain methods. It
  uses the listener's lifecycle (`await start()`, `shutdown()`,
  `await wait_closed()`, `await aclose()`, `async with`). Cancelling a pending
  exchange abandons it and leaves no task, socket or accepted transaction behind,
  and several exchanges may be pending on one client. Its `on_reply` hook runs on
  the event loop, not on a worker thread. `import pydhcp` imports `asyncio` as it
  did before.

### Changed

- **Breaking: `NoClientIdentity` is now `pydhcp.NoClientIdentityError`**
  (`pydhcp.exceptions`), no longer importable from `pydhcp.packet.message`.
  No alias is kept. It is a `ValueError` as before.
- **The two listeners share one private base** for their configuration, binding
  and the handling of one datagram, and one is not the other's lookalike any more.
  Three differences between them are gone: `AsyncDHCPListener` no longer has the
  plain attributes `packets_dropped_truncated` and `packets_dropped_error`, which
  nothing ever incremented (the counts are on `.metrics`, as on the sync
  listener); `DHCPListener(max_packet_size=...)` defaults to `None`, as the
  header says, which means the largest UDP payload exactly as the old default
  constant did; and a listener that serves a wildcard through one socket per
  address (`per_interface=True`, or no packet info) lists the host's interfaces
  when `bind()` runs, not when it is constructed. The async listener's
  error record for a failing handler now reads like the sync one's.
- **Breaking: `AsyncDHCPServer` is no longer a subclass of `DHCPServer`.** The two
  are sibling drivers over one private core that holds the lease policy, the
  reply building and one handler per message type, and owns no socket, thread or
  clock. `isinstance(server, DHCPServer)` is false for an asynchronous server,
  and the methods it used to pick up from the synchronous listener are gone:
  `with AsyncDHCPServer(...)`, `.close()` (both raised `AttributeError` after
  closing the sockets) and `.start(cancellation_token)`. Subclass either driver
  and override the same hooks as before: `handle_discover`, `handle_request`,
  `handle_decline`, `handle_release`, `handle_inform`, `acquire_lease`,
  `release_lease`, `get_inform_options` and `get_lease_seconds`; each is an ordinary
  blocking method that runs on the one handler thread of either driver.
- **Breaking: `AsyncDHCPRelay` is no longer a subclass of `DHCPRelay`.** Same
  split as the server: one private core holds the forwarding rules, the
  pending-client table and the hop and relay-agent-information checks, and the two
  relays are sibling drivers over it. `isinstance(relay, DHCPRelay)` is false for
  an asynchronous relay, which has lost the synchronous listener's `with`,
  `close()` and `start(cancellation_token)` as the asynchronous server did. The
  pending table ages on the monotonic time stamped on each context, and
  `pydhcp.relay` is now a package (same import path and names; `PendingClient`
  is private); the relay's records are logged by `pydhcp.relay._core`.
- **Breaking: `AsyncDHCPCapture` is no longer a subclass of `DHCPCapture`**, on the
  same terms as the server and the relay: one private core holds the filter, sink
  and hook rules (`hook_fail_fast` included), and the two captures are sibling
  drivers over it. `isinstance(capture, DHCPCapture)` is false for an asynchronous
  capture, and `CaptureEvent.captured_at` is the time stamped on the context when the
  datagram arrived. `pydhcp.capture` is now a package (same import path and
  names); its hook-failure record is logged by `pydhcp.capture._core`.
- **Breaking: one lifecycle vocabulary on every listener and role**
  (`DHCPListener`, `DHCPServer`, `DHCPRelay`, `DHCPCapture`, `DHCPClient` and their
  asyncio counterparts). `listen()` is `serve_forever()`, `stop()` is `shutdown()`,
  `wait()` is `wait_closed(timeout=None)` (it returns `False` when the timeout passed
  first), and `start()` returns `None` and takes no cancellation token; no alias is
  kept for the old names. `shutdown()` never blocks and is safe from any thread and
  from a handler. The synchronous classes close with `close()` and a `with` block,
  the asynchronous ones with `await aclose()` and `async with`, neither starting to
  serve (the block binds). **Closed is final**: `start()`, `serve_forever()`,
  `bind()` and `with` after `close()` raise `RuntimeError`, where `start()` used to
  serve again. A second `start()` while serving raises `RuntimeError` too: on the
  asynchronous classes it added a second receive task per socket and stranded a
  pending `wait()`. `serve_forever()` no longer closes the sockets on its way out
  (`close()` does), and `start()` no longer returns the receive thread.
- **`close()` on a running thread-based listener ends it cleanly.** It shuts the
  loop down through a wake-up socket, waits for the receive thread (up to five
  seconds) and then releases the sockets; called on the receive thread itself, from
  a handler, it shuts down and returns, and the loop releases the sockets as it
  ends. On Windows the receive thread used to die with an uncaught `ValueError` or
  `OSError`; on Linux it never ended, `wait()` blocked and `start()` returned
  nothing. `shutdown()` ends the wait at once instead of after the poll interval.
- **The library installs no signal handler.** `DHCPListener.start()` no longer
  claims `SIGINT` for the process, and `close()` no longer gives it back. Ctrl-C
  reaches `serve_forever()` as `KeyboardInterrupt`; the `pydhcp server`, `relay`
  and `capture` commands catch it, log the same line and exit with status 0, as
  before.
- **Breaking: constructors take `listen` (and, for the relays, `server_addresses`)
  positionally and every other option by keyword.** This applies to `DHCPListener`,
  `DHCPServer`, `DHCPRelay`, `DHCPCapture`, `DHCPClient` and the asyncio
  counterparts; a seventh positional argument is a `TypeError`. The same position
  meant different things on the two drivers (`select_timeout` against
  `max_packet_size`), and the shipped header's `DHCPRelay` signature omitted
  `trust_client_relay_agent_info`, so a positional `select_timeout` written from it
  turned that trust on. `select_timeout` is now **`poll_interval`** on the
  synchronous classes (how often a wait looks at the shutdown flag; a shutdown no
  longer waits for it). `reuse_address` and `receive_buffer_size` are new
  keywords; each defaults to the `REUSE_ADDRESS` / `RECEIVE_BUFFER_SIZE` class
  attribute, which still works.
- **Constructors perform no I/O.** A listener no longer asks a socket whether the
  platform has packet info, and no longer lists adapters, until `bind()`.
  `FileLeaseBackend(filepath)` now requires its path (the default `leases.json` in
  the current directory is gone) and reads nothing: `open()` reads the file once,
  and the first lease operation or `with` calls it, so a missing file creates
  nothing and an unreadable one is not set aside until then.
- **Breaking: `SocketAddress(sock)` is `SocketAddress.from_socket(sock)`**, and
  `SocketAddress(ip, port)` needs both arguments (`TypeError` otherwise, where it
  was `ValueError`).
- **`pydhcp.client` is a package** (same import path and names). The message
  builders, the reply matching and the retransmission schedule are one private
  core under `DHCPClient` and `AsyncDHCPClient`, so `DHCPClient`'s behaviour on
  the wire is unchanged. A record the client logs (an OFFER without a server
  identifier) is named `pydhcp.client._core`, and a test that patches
  `pydhcp.client.UDPTransport` patches `pydhcp.client._sync.UDPTransport`.
- **`pydhcp.server.handlers`, `pydhcp.server.policy` and `pydhcp.server.reply`
  are gone** (they exported nothing); the layers are private modules of
  `pydhcp.server`, so a record they log is named `pydhcp.server._handlers` and so on.
- **`DHCPRequestContext` carries the time its datagram arrived**: two new
  trailing fields, `received_at` (timezone-aware UTC) and `received_monotonic`
  (`time.monotonic()` seconds), stamped by the listener. A context built by hand
  has `None` for both and a hook then reads the driver's clock, so a test that
  builds contexts keeps working. `quarantine_address(ip, *, now=None)` accepts the
  monotonic time; called with `ip` alone, as before, it reads the driver's clock.
- **`DHCPClient.discover_offer()` and `.dora()` name the keywords they
  forward** (`xid`, `client_identifier`, `parameter_request_list` and, for
  `discover_offer`, `broadcast`) instead of taking `**discover_kwargs`. The same
  calls work; an unknown keyword is now a `TypeError` at the call.
- **Breaking: `acquire_lease` takes a keyword `commit` and runs on the server
  itself.** The signature is `acquire_lease(client_id, server_id, msg, *, commit=True)`:
  an override must accept `commit` (one that does not raises `TypeError` for every
  DISCOVER). DHCPDISCOVER makes one call with `commit=False`, DHCPREQUEST makes two,
  `commit=False` to decide and `commit=True` to commit the ACK, and the override must do
  nothing that extends or creates a binding when `commit` is false. The call used to run
  on a throwaway copy of the server for the first of those, so an address pool that kept
  its next free host in an attribute (`self.next_host += 1`) gave every client the same
  address; the attribute is now the server's own. `self.lease_backend` inside an
  override is the real backend on both calls; only the base implementation reads through
  a view that does not extend a binding when `commit` is false.
- **Requires netimps 0.4.0** (`netimps>=0.4.0,<0.5`, was `>=0.3.3,<0.4`).
  netimps renamed its public names without an alias, so no range covers both
  series.
- **Breaking: `pydhcp.network.APIPA` is now `pydhcp.network.LINK_LOCAL_V4`**,
  following the name netimps gave the same network (`169.254.0.0/16`). No alias
  is kept: replace `APIPA` with `LINK_LOCAL_V4`. Its type is `IPv4Network`
  rather than the v4/v6 union. `host_ip_interfaces()`'s default filter is
  unchanged.
- **Breaking: `pydhcp.network.MACAddress.as_str()` is gone**, with the netimps
  method it came from; use `.format(sep=":", *, upper=False)`. `str(mac)` is
  still `00-11-22-33-44-55`, and `f"{mac}"` and `"%s" % mac` agree with it.
  Instances are now read-only, `copy` and `pickle` keep the subclass, a bad
  value raises `netimps.NetimpsValueError` (still a `ValueError`) and
  `MACAddress.try_parse()` raises `TypeError` for a non-`str`.
- **`host:port` text is read strictly.** In `listen=`, `--listen` and each
  `pydhcp relay --server`, the port is ASCII digits only and square brackets
  may enclose only an IPv6 literal. `"127.0.0.1:+6767"`, `"127.0.0.1: 6767"`,
  `"127.0.0.1:8_0"` and `"[127.0.0.1]:6767"` were read as a port or an address
  before; they now raise `ValueError` (netimps' `NetimpsValueError`), and the
  message names the port or the brackets.
- `host_ip_interfaces(family=)` accepts `socket.AF_INET` and `socket.AF_INET6`
  as well as `4` and `6`.
- A socket-buffer shortfall is now reported twice: by pydhcp at INFO, naming the
  address, and by netimps at WARNING, once per process for each distinct
  request and grant.
- **On Windows a disconnected adapter no longer lists a 169.254 address**
  (netimps leaves out an address Windows marks tentative or duplicate), so
  `host_ip_interfaces(filter=False)` can return fewer entries there.
- **Deployments: `NETIMPS_NO_SOCKET_PATCH` is now an error.** With it set,
  `import pydhcp` raises `ValueError` at import; use `NETIMPS_SOCKET_PATCH=0`
  to disable the `socket` patch.

- **Breaking: `pydhcp.network` holds only pydhcp's own types** (`HardwareAddressType`,
  `NetworkInterface`, `SocketAddress`, `host_ip_interfaces`). `IPv4`, `IPv6`, `IP`,
  `IPv4Network`, `IPv6Network`, `IPNetwork`, `IPv4Interface`, `LINK_LOCAL_V4` and
  `SocketOption` are gone from it: import `ipaddress.IPv4Address` and the others from
  `ipaddress`, and `LINK_LOCAL_V4` and `SocketOption` from `netimps`. `WILDCARD_V4` is
  not public: write `ipaddress.IPv4Address("0.0.0.0")`. No alias is kept.
- **Breaking: `NetworkInterface.mac` is a `netimps.MACAddress`, and `pydhcp.MACAddress` is
  gone** (import it from `netimps`). `str(mac)` is now `aa:bb:cc:dd:ee:ff` where it was `AA-BB-CC-DD-EE-FF`; `pydhcp
  interfaces` still prints the hyphenated upper-case form, through `mac.format("-",
  upper=True)`.
- **Breaking: `SocketAddress.listen()` is gone.** The listener calls `netimps.bind()`
  directly with the arguments it always passed (`broadcast=True`, `connreset=False`, an
  exclusive address unless `reuse_address` is set), so what a bound socket does on the wire
  is unchanged; the method's own `connreset=True` default was never reached.
- **A failed bind raises netimps' own error, with its own message.** The suggestions
  "try port N+1000" and "Try 6767 for testing" are no longer appended to it.
- **An adapter holding loopback and routable addresses answers from the routable one.**
  The address a reply is sent from, when the request's destination names none of the
  adapter's addresses, is `Interface.primary_ip()` (routable, then loopback,
  link-local last); it was the first address in the adapter's order that was not
  link-local. Only an adapter listing both kinds (Linux `lo` with an address added to
  it) is affected.
- **A request received without an arrival interface is judged by `Datagram.is_unicast`.**
  A destination that is the subnet broadcast of an adapter this host holds is now treated
  like the limited broadcast (no local address is taken from it); only the limited
  broadcast and multicast were before.

- **Breaking: every module that is not an import path of its own is private.**
  `pydhcp.log`, `.config`, `.constants`, `.metrics`, `.nvt` and `.network` are
  `pydhcp._log`, `._config`, `._constants`, `._metrics`, `._nvt` and `._network`;
  `pydhcp.packet.enums` and `.message` are `pydhcp.packet._enums` and `._message`;
  `pydhcp.options.code`, `.registry` and `.type` are `pydhcp.options._codes`,
  `._registry` and `._codecs` (and `options/base.py` joined `_codes.py`), each codec
  module under it with a leading underscore; the `pydhcp.listener` modules (`sync`,
  `aio`, `binding`, `interfaces`, `receive`, `spec`, `transport`) are `_sync`,
  `_asyncio`, `_binding`, `_interfaces`, `_receive`, `_spec` and `_transport`; the
  `pydhcp.cli` command modules are `_capture`, `_capture_hook`, `_interfaces`,
  `_packet`, `_relay` and `_server`. `pydhcp._utils` is split into `_generic` and
  `_missing`. No module is left behind to re-export from its old path. Import a name
  from `pydhcp`, `pydhcp.packet`, `pydhcp.options`, `pydhcp.listener` or the other
  public modules; `pydhcp.log.LOGGER` is `logging.getLogger("pydhcp")`.
- **A module's logger is named for its module,** so the records of a moved module
  change name: `pydhcp.log`, `pydhcp.config` and `pydhcp.metrics` become
  `pydhcp._log`, `pydhcp._config` and `pydhcp._metrics`, `pydhcp.listener.binding`
  and the other listener modules `pydhcp.listener._binding` and so on, and
  `pydhcp.cli.capture_hook` and the other command modules `pydhcp.cli._capture_hook`
  and so on. A `--loglevel` or a filter naming one of them follows; one naming
  `pydhcp` or `pydhcp.listener` is unaffected.

- **Breaking: the root exports the packet enums and no longer exports the address
  aliases or the specialised codec families.** `pydhcp.DHCPMessageType`,
  `pydhcp.DHCPOpcode`, `pydhcp.DHCPFlags` and `pydhcp.DHCPPort` are new (the same
  objects as `pydhcp.packet`'s). Each name below is gone from `pydhcp`, no alias is
  kept; import it from where it is listed:

| Was | Now |
| --- | --- |
| `pydhcp.IPv4` | `ipaddress.IPv4Address` |
| `pydhcp.IPv4Interface` | `ipaddress.IPv4Interface` |
| `pydhcp.IPv4Network` | `ipaddress.IPv4Network` |
| `pydhcp.MACAddress` | `netimps.MACAddress` |
| `pydhcp.CCCOption` | `pydhcp.options.CCCOption` |
| `pydhcp.CCCSubOption` | `pydhcp.options.CCCSubOption` |
| `pydhcp.CCCPrimaryDHCPServerAddress` | `pydhcp.options.CCCPrimaryDHCPServerAddress` |
| `pydhcp.CCCSecondaryDHCPServerAddress` | `pydhcp.options.CCCSecondaryDHCPServerAddress` |
| `pydhcp.CCCProvisioningServerAddress` | `pydhcp.options.CCCProvisioningServerAddress` |
| `pydhcp.CCCProvisioningServerFQDN` | `pydhcp.options.CCCProvisioningServerFQDN` |
| `pydhcp.CCCKerberosRealmName` | `pydhcp.options.CCCKerberosRealmName` |
| `pydhcp.CCCASBackoffRetry` | `pydhcp.options.CCCASBackoffRetry` |
| `pydhcp.CCCAPBackoffRetry` | `pydhcp.options.CCCAPBackoffRetry` |
| `pydhcp.CCCTicketGrantingServerUtilization` | `pydhcp.options.CCCTicketGrantingServerUtilization` |
| `pydhcp.CCCProvisioningTimer` | `pydhcp.options.CCCProvisioningTimer` |
| `pydhcp.CCCSecurityTicketControl` | `pydhcp.options.CCCSecurityTicketControl` |
| `pydhcp.CCCKDCServerAddressList` | `pydhcp.options.CCCKDCServerAddressList` |
| `pydhcp.CCCPrimaryDHCPServerAddressSubOption` | `pydhcp.options.CCCPrimaryDHCPServerAddressSubOption` |
| `pydhcp.CCCSecondaryDHCPServerAddressSubOption` | `pydhcp.options.CCCSecondaryDHCPServerAddressSubOption` |
| `pydhcp.CCCProvisioningServerAddressSubOption` | `pydhcp.options.CCCProvisioningServerAddressSubOption` |
| `pydhcp.CCCASBackoffRetrySubOption` | `pydhcp.options.CCCASBackoffRetrySubOption` |
| `pydhcp.CCCAPBackoffRetrySubOption` | `pydhcp.options.CCCAPBackoffRetrySubOption` |
| `pydhcp.CCCKerberosRealmNameSubOption` | `pydhcp.options.CCCKerberosRealmNameSubOption` |
| `pydhcp.CCCTicketGrantingServerUtilizationSubOption` | `pydhcp.options.CCCTicketGrantingServerUtilizationSubOption` |
| `pydhcp.CCCProvisioningTimerSubOption` | `pydhcp.options.CCCProvisioningTimerSubOption` |
| `pydhcp.CCCSecurityTicketControlSubOption` | `pydhcp.options.CCCSecurityTicketControlSubOption` |
| `pydhcp.CCCKDCServerAddressSubOption` | `pydhcp.options.CCCKDCServerAddressSubOption` |
| `pydhcp.VIVendorSpecificInformationRecord` | `pydhcp.options.VIVendorSpecificInformationRecord` |
| `pydhcp.VIVendorSpecificInformation` | `pydhcp.options.VIVendorSpecificInformation` |
| `pydhcp.VIVendorClassRecord` | `pydhcp.options.VIVendorClassRecord` |
| `pydhcp.VIVendorClass` | `pydhcp.options.VIVendorClass` |
| `pydhcp.MoSIPv4AddressRecord` | `pydhcp.options.MoSIPv4AddressRecord` |
| `pydhcp.MoSFQDNRecord` | `pydhcp.options.MoSFQDNRecord` |
| `pydhcp.MoSIPv4AddressList` | `pydhcp.options.MoSIPv4AddressList` |
| `pydhcp.MoSFQDNList` | `pydhcp.options.MoSFQDNList` |

- **Every public module declares `__all__`.** `pydhcp.options`, `.client`, `.relay`,
  `.capture`, `.lease`, `.packet.structured` and `.server.handlers`, `.policy` and
  `.reply` (the last three export nothing) gained one; a name outside it is not API.
  No `__all__` lists a type variable, a logger or an underscore name: `pydhcp.cli.LOGGER`
  leaves `pydhcp.cli.__all__`, and `pydhcp.options.T` and `.C` (type variables that
  `from pydhcp.options import *` used to bring in) are gone.
- **Breaking: `pydhcp.listener` and `pydhcp.cli` no longer re-export underscore names**
  (`_bind_sockets`, `_arrival`, `_TruncatedDatagram`, `_split_host_port`,
  `_load_capture_hook`, `_write_capture_record` and the rest). They are in the private
  modules that define them.
- **Breaking: `DHCPOptionCode.ensure_registered()` is gone.** The built-in codecs are
  bound to the standard option codes when `pydhcp.options` is imported, so a lookup
  never depends on an earlier call; there is no alias to call. A codec registered with
  `register_type` afterwards replaces the built-in one, as before. `DHCPMessageType` is
  defined in the options package (`pydhcp.packet.DHCPMessageType` and
  `pydhcp.DHCPMessageType` are the same object).
- **`DHCPMetrics` is `pydhcp.listener.DHCPMetrics`**, where it was
  `pydhcp.metrics.DHCPMetrics` and then a private module's. `pydhcp.options` exports
  `MIN_OPTION_CODE`, `MAX_OPTION_CODE` and every option codec in one list, and
  `from pydhcp.server import DHCPLease` is not API (it is `pydhcp.lease.DHCPLease`).
- **Option codecs are values.** The record codecs (`ClasslessRoute`,
  `ClientFQDN`, `StatusCode`, `SIPServers`, `RDNSSSelection`, `TLVOption`, the
  `VI*`, `MoS*` and `CCC*` records) are read-only: assigning or deleting an
  attribute raises `AttributeError`, and a list a record holds is a read-only
  copy (`TypeError` on any change), so a record put in a set keeps its hash.
  `SIPServers.values` is a tuple. `Flag() == other` returns `NotImplemented` for
  another type, as the rest do.
- **`repr()` of a codec is the constructor call that rebuilds it.** It was the
  display text: `repr(IPv4AddressOption("192.0.2.1"))` was `192.0.2.1` and
  `repr(DHCPMessageType.DHCPACK)` was `DHCPACK`; they are
  `IPv4AddressOption('192.0.2.1')` and `DHCPMessageType.DHCPACK`, and a list is
  `List[IPv4AddressOption]([IPv4AddressOption('192.0.2.1')])`. `repr()` of an
  empty `ClientIdentifier` no longer raises. What `DHCPMessage.dumps()`, the
  command and the capture formats print is unchanged.
- **Every list codec normalizes on every change**: `append`, `extend`, `insert`,
  `+=`, item assignment and slice assignment. A refused item raises
  `DHCPValueError` (or `TypeError` for a wrong type) and leaves the list as it
  was. The classes `List[...]` builds are named `List[IPv4AddressOption]` and
  belong to the module of `List`.
- **Breaking: `DHCPLease` is a value, not a tuple.** `DHCPLease(ip, expires=None,
  options=None)` is read-only, hashable and equal by content, and it no longer
  unpacks or indexes. `ip` is required (`None` raises `TypeError`, `0.0.0.0`
  raises `DHCPValueError`). `expires` is a timezone-aware `datetime` or `None`
  for a lease that never ends; a naive `datetime` raises `DHCPValueError` and
  `math.inf` or any other type raises `TypeError`, so an `acquire_lease`
  override or a `LeaseBackend` that built `DHCPLease(ip, datetime.now() + ttl,
  options)` or `DHCPLease(ip, math.inf, options)` builds
  `datetime.now(timezone.utc) + ttl` or `None`. `None` was a lease with no time
  left on the reply path and an infinite one in the reply; it is infinite
  throughout. `options` is copied in and read-only (`TypeError` on any change;
  `lease.options.copy()` is a bag to change), so a lease a backend stored cannot
  be altered through the one it handed out. The stock backends hold UTC
  instants, and `FileLeaseBackend` writes them with an offset and still loads
  a file that holds the naive local times it wrote before.
- **A DHCPINFORM is answered from its options.** The ACK is built without a
  lease (it used to be built from one with the wildcard address and an infinite
  expiry, and then had its address and lease time removed); what the client
  receives is unchanged.

- **Breaking: one name per conversion.**
  - `DHCPMessage.summary()` is the display `dumps()` was; nothing reads it back,
    and `dumps` now means only what `json.dumps` means. `HardwareAddressType.dumps`
    is `format_address`.
  - A structured document is `DHCPMessage.from_text(text, format)` and
    `message.to_text(format)`. `pydhcp.packet.structured` holds `loads(text,
    format)` and `dumps(data, format)` for a mapping; `load_message`,
    `dump_message`, `load_mapping` and `dump_mapping` are gone, from
    `pydhcp.packet` as well. The four formats are the same: a file the capture
    command wrote with an earlier version loads unchanged.
  - `DHCPMessage.encode()` returns `bytes`, not `bytearray`, and `bytes(message)`
    works. Write `bytearray(message.encode())` to patch an octet.
  - `DHCPOptions.decode(data)` is a classmethod that returns the options; it no
    longer fills an instance, takes a `base_offset` or returns the unconsumed tail.
  - `SocketAddress.compat()` is `to_tuple()`.
  - `DHCPMessage.client_id(func=None)` is `get_client_id(func=None)` and
    `DHCPServer.lease_seconds(msg)` (a hook) is `get_lease_seconds(msg)`.
  - `DHCPClient.send` and `AsyncDHCPClient.send` take the message and then
    keywords: `send(message, *, dst=..., port=...)` (`destination` is `dst`).
    `DHCPTransport.send(data, dst, *, port, client_mac)` takes its destination as
    `dst` and the port and hardware address as keywords; a transport a caller
    wrote accepts the same call.
  - `Bytes(value=None)` is built from bytes only (its keyword was `src`); hex
    text goes through `Bytes.parse(text)`. A structured document still writes
    and reads octets as hex.
- **Breaking: the contracts a caller implements are `typing.Protocol`s, and the
  codec contract has public names.**
  - `OptionCodec` (`pydhcp.options`) is the protocol of an option payload codec;
    `DHCPOptionType` is the base class that supplies its defaults. A codec writes
    its constructor, `unpack_from(option) -> (value, octets taken)` and
    `pack_into(buffer) -> octets written`, and may set `fixed_size()`, `to_json()`
    and `display_text()`; `Codec.unpack(data)` and `value.pack()` are built on
    those. The old spellings are gone: `_dhcp_read`, `_dhcp_write`,
    `_dhcp_len_hint`, `_dhcp_decode`, `_dhcp_encode`, `__json__` (now `to_json`)
    and the display hook `_display_text` (now `display_text`). The contract is
    `pack`/`unpack` and not `encode`/`decode` because `Bytes` is a `bytes` and
    `String` a `str`, which already have `decode` and `encode`.
  - `register_type` accepts any class with the methods of `OptionCodec`, not
    only a `DHCPOptionType` subclass, and `options[code] = value` builds the
    codec of the code from `value` as before.
  - `DHCPTransport` is a protocol: anything with `send(data, dst, *, port,
    client_mac)` is a transport (it was a class whose `send` raised
    `NotImplementedError`). `OptionCode` is the protocol of a code enum
    (`DHCPOptions(codemap=...)`); `BaseDHCPOptionCode` is its base class.
- **Breaking: `DHCPMessage` takes its `op` and keywords.** Every header field but
  `op` has a default (Ethernet, zeros, the wildcard address, no names, a fresh
  option bag) and is keyword-only, so `DHCPMessage(DHCPOpcode.BOOTREQUEST)` is a
  message that encodes to a legal 300-octet datagram. `hlen` is the length of
  `chaddr` when it is left out and must equal it when given: `DHCPValueError` at
  construction, and from `encode()` for a message changed since. `decode()` stays
  liberal and keeps the `hlen` the sender wrote, whatever the hardware type, so a
  relay still forwards what it received.
- **Text a value type accepts is `Type.parse(text)`** (and `Type.try_parse(text,
  default=None)`, which answers `default` for text that does not parse): on
  `SocketAddress` (`"192.0.2.1:67"`, what `str()` writes), `ClasslessRoute`
  (`"10.0.0.0/8 via 192.0.2.1"`), `StatusCode` (`"2 message"`), `ClientFQDN` (the
  name, then `[flags=0x05 rcode1=0 rcode2=0 partial]` when any of those is set)
  and `Bytes` (hex). Each raises `DHCPValueError` for text that is not a value
  of the type and `TypeError` for an argument that is not text, and
  `parse(str(value)) == value`. `str()` of a `ClasslessRoute`, `StatusCode` and
  `ClientFQDN` is now that text.
- **`DHCPMessage.message_type`** is option 53 read once: the
  `DHCPMessageType` member, or `None` when there is no option 53 or its payload is
  not one octet. The server, the client's reply matching and
  `CaptureEvent.message_type` read it there.
- **Named aliases for what a function accepts**, exported and listed in the
  headers: `IPv4AddressLike` (`pydhcp`), `ListenLike` (`pydhcp.listener`, was
  `ListenSpec`), `ServerAddressLike` (`pydhcp.relay`, was `ServerAddress`),
  `ClientIdentifierLike` (`pydhcp.client`) and `PacketFilterLike`
  (`pydhcp.capture`). `ListenAddress`, `ListenBinding` and `ListenPort` are no
  longer exported.
- **Codecs read what real peers send.** Each reading is an RFC allowance, and
  what is written is as strict as before.
  - Option 120 (`SIPServers`) reads compressed names (RFC 3361 section 3.1:
    clients MUST support them), with the bounds of the search list (255 octets
    a name, 127 pointers); a pointer counts from the encoding octet. It still
    writes uncompressed names.
  - A classless route (121, 249) whose destination has host bits set is read
    with them zeroed (RFC 3442 section 3); one such route no longer costs the
    whole option. `ClasslessRoute(...)` stays strict.
  - A static route (33) to `0.0.0.0` is read; building or writing one still
    raises.
  - Option 146 (`RDNSSSelection`) keeps the root name that marks the default
    RDNSS (RFC 6731 section 4.3), which `"."` spells as well as `""`, and
    ignores the six reserved bits of `flags`. It and option 124
    (`VIVendorClass`) are built from the form their `to_json` emits.
  - Option 82 (`RelayAgentInformation`) reads sub-options 0 and 255 as codes
    (RFC 3046 section 2.0 defines no pad and no end); before, they ended or
    skipped the option.
- **`DHCPMessageType` has an unnamed member for every octet** that names no
  type: `DHCPMessageType(99)` has no `.name`, `.label()` is `TYPE_99`, and
  `DHCPMessage.message_type` returns it, so a relay forwards what it received.
  `message_type` is `None` only for an option 53 that is not one octet.
  `CaptureEvent.message_type` is `TYPE_<n>` for one, where it was `UNKNOWN`, and
  the server logs that name. A number over 255 still raises `ValueError`.
- **The `flags` field keeps its reserved bits.** `DHCPFlags` is an `IntFlag`; a
  decoded message holds the sixteen bits it received and `encode` writes them
  back, where a decode cleared the fifteen reserved ones (a relay changed the
  field it forwarded). `DHCPMessage.broadcast` tests the bit that is assigned,
  `DHCPFlags.label()` names a value, and `to_mapping` writes a number for a value
  with a reserved bit set. A comparison `message.flags is DHCPFlags.BROADCAST`
  is true only when no other bit is set: use `broadcast`.
- **`DHCPOptions` compares raw payloads.** `==` is true for the same codes with
  the same octets in any order, and nothing is decoded: it no longer raises for a
  truncated payload, two decodes of one datagram are equal (so are two
  `DHCPMessage`s), and octets that read alike (`b"abc\x00junk"` and `b"abc"` under
  option 12) are different. Against another type, a `dict(bag)` included, it is
  `NotImplemented`; a lease's frozen bag compares the same way.
- **`DHCPOptions.append` is atomic**, as `__setitem__` is: a value its codec
  refuses leaves the bag as it was, where an absent code was left present and
  empty. `setdefault` answers the stored `bytearray` whether or not the code was
  there. A refused value now says which option and what kind of value
  (`option 12 (HOSTNAME) cannot hold a NoneType: ...`), with the same exception
  class.
- **Breaking: a text option takes text.** `String(None)`, `String(5)` and
  `options[12] = ["a"]` raise `TypeError`, where `str()` of the value was stored
  (`b"None"`); octets are read as text. Delete an option to leave it out.
- **Breaking: integer codecs hold exactly their range and whole numbers.**
  `I32(2**31)` raises `DHCPValueError` when built, where it was built and failed
  at `encode()` with `OverflowError`; `U8(1.9)` raises `TypeError`, where it was
  `U8(1)`.
- **`CCCKerberosRealmName` read from the wire keeps the case it arrived in**; a
  realm built by hand is still upper-cased. A `DomainList` encoded past 16,383
  octets writes a name in full where a compression pointer could not reach the
  suffix it shares, and a summary names an unnamed hardware type `HTYPE_<n>`.
- **`DHCPMessage.encode` lays the options out in one pass.** It no longer copies the
  option bag and encodes it twice for a message that fits the options field, and
  the overload layouts are tried only when it does not. A message that fits
  encodes to the same octets as before, and so does one that needed `sname` or
  `file` and fitted when the options were written in order (the recorded
  conversations re-encode unchanged); `parse.encode_reply`, a twelve-option ACK,
  joins `parse.encode_packet` in the benchmark suite.
- **A message the encoder used to refuse now encodes when a layout exists.**
  - A decoded message whose option 66 or 67 is longer than its field (a UEFI
    HTTP boot URL in option 67, say) encodes again, and so does one with a
    `sname` or `file` set that long: the name travels as option 66 or 67, the
    field it would have filled carries options, and `decode` reads it back.
  - A message whose options fit the three fields only with each option placed
    whole (the round-trip property test's saved example needs 494 octets of 497)
    encodes: when writing the options in order does not hold them, each is
    placed in the field with room for it. Option 53 and then option 52 lead the
    options field, then a relocated option 66 and 67, and every field keeps the
    order the options were set in.
- **`encode` at the smallest sizes.** `max_packetsize` is a datagram, so a message
  is padded to 300 octets or to `max_packetsize - 28`, whichever is smaller:
  `encode(280)` is 252 octets, where it was 280 and its datagram 308. Option 52
  stays in the options field, so a receiver learns that `sname` holds options; a
  message that cannot hold options 53 and 52 (a datagram under 275) is refused.
  Between 269 and 271 an option that does not fit raises the `OverflowError` the
  documentation names, where it raised a `ValueError` about a word size.
- **A refusal names what did not fit.** The `OverflowError` says which option did
  not fit and by how many octets the room is short. A `sname` or `file` that must
  travel as option 66 or 67 while that option holds other octets raises
  `DHCPValueError` naming both, where the name was dropped without a word.
- **`encode` writes `SUBNET_MASK` before `ROUTER`** when both are set, whatever the
  order they were set in (RFC 2132 section 3.3).
- **Codecs refuse on write what the wire cannot hold, and name it.** A `TLVOption`
  (relay agent and encapsulated sub-options) with a code outside 0 to 255 or a
  value over 255 octets, and a `PCPServerList` entry of more than 63 addresses,
  raise `DHCPValueError` when built, where `bytearray` said `byte must be in
  range(0, 256)`. A `ClientIdentifier` of one octet and an empty `SIPServers`
  raise `DHCPValueError` when written; both still decode.
- **`from_mapping` reads a value once.** The second reading of a value its codec
  refused, as bare hex, is gone: `"SUBNET_MASK": "dead"` loaded as a two-octet
  mask and `"IP_ADDRESS_LEASE_TIME": "abcd"` as a two-octet lease time, and
  `"255.255.255.0/24"` reported the hex parser's complaint. A value the codec
  refuses raises `TypeError` or `ValueError` naming the option and the kind of
  value (`option 1 (SUBNET_MASK) cannot hold a str: ...`). Octets are read from
  `{"hex": "..."}` for any option, and as hex text only for an option whose codec
  is opaque bytes (`VENDOR_SPECIFIC_INFORMATION`, an unnamed code); a number for
  such an option is a `TypeError`, where `Bytes(5)` was five zero octets. A missing
  header field is a `ValueError` naming it, where it was a bare `KeyError`; an
  option name nobody knows is a `ValueError` naming it.
  **Breaking** for a document that relied on bare hex for a typed option: write
  `{"hex": "..."}`.
- **`from_mapping` and `from_text` take `codemap=`**, the code map `to_mapping`
  named the options with (default `DHCPOptionCode`).
- **`sname` and `file` are byte-exact through the mapping and every format.**
  A name that is not UTF-8 is written as `{"hex": "..."}` (it was text with U+FFFD
  for each such octet, so `from_mapping(to_mapping())` changed it, and a name
  taken from JSON or YAML changed too); a name that is UTF-8 is still text.
  `from_mapping` also takes `bytes` and the hex form for either field. A document
  written before still loads, with the U+FFFD text it holds.
- **`decode` accepts a missing END marker**, as it always did: the documentation
  said it raised `DHCPDecodeError`, and the check could not fire. A message that
  stops after a complete option, inside one, or after the cookie decodes and
  keeps what arrived.

### Renamed

**Breaking.** Every public class name spells its acronyms in capitals, and the
generic names take the `DHCP` prefix. No alias is kept: an old name is not
importable. Replace each name in the left column with the one beside it.

| Was | Now |
| --- | --- |
| `DhcpListener` | `DHCPListener` |
| `AsyncDhcpListener` | `AsyncDHCPListener` |
| `DhcpServer` | `DHCPServer` |
| `AsyncDhcpServer` | `AsyncDHCPServer` |
| `DhcpClient` | `DHCPClient` |
| `DhcpRelay` | `DHCPRelay` |
| `AsyncDhcpRelay` | `AsyncDHCPRelay` |
| `DhcpCapture` | `DHCPCapture` |
| `AsyncDhcpCapture` | `AsyncDHCPCapture` |
| `DhcpMessage` | `DHCPMessage` |
| `DhcpOptions` | `DHCPOptions` |
| `DhcpOption` | `DHCPOption` |
| `DhcpOptionCode` | `DHCPOptionCode` |
| `DhcpOptionCodes` | `DHCPOptionCodes` |
| `DhcpOptionType` | `DHCPOptionType` |
| `BaseDhcpOptionCode` | `BaseDHCPOptionCode` |
| `DhcpMetrics` | `DHCPMetrics` |
| `DhcpMessageType` | `DHCPMessageType` |
| `DhcpPort` | `DHCPPort` |
| `DhcpLease` | `DHCPLease` |
| `OpCode` | `DHCPOpcode` |
| `Flags` | `DHCPFlags` |
| `RequestContext` | `DHCPRequestContext` |
| `UdpTransport` | `UDPTransport` |
| `PktInfoUdpTransport` | `PktInfoUDPTransport` |
| `Transport` | `DHCPTransport` |
| `pydhcp.options.type.IPv4Address` (the option codec) | `IPv4AddressOption`; `IPv4Address` is only the address type |
| `TlvOption` | `TLVOption` |
| `UriList` | `URIList` |
| `RdnssSelection` | `RDNSSSelection` |
| `ClientFqdn` | `ClientFQDN` |
| `SipServers` | `SIPServers` |
| `PcpServerList` | `PCPServerList` |
| `ViVendorClass` | `VIVendorClass` |
| `ViVendorClassRecord` | `VIVendorClassRecord` |
| `ViVendorSpecificInformation` | `VIVendorSpecificInformation` |
| `ViVendorSpecificInformationRecord` | `VIVendorSpecificInformationRecord` |
| `MoSIpv4AddressRecord` | `MoSIPv4AddressRecord` |
| `MoSIpv4AddressList` | `MoSIPv4AddressList` |
| `MoSFqdnRecord` | `MoSFQDNRecord` |
| `MoSFqdnList` | `MoSFQDNList` |
| `CccOption` | `CCCOption` |
| `CccSubOption` | `CCCSubOption` |
| `CccPrimaryDhcpServerAddress` | `CCCPrimaryDHCPServerAddress` |
| `CccPrimaryDhcpServerAddressSubOption` | `CCCPrimaryDHCPServerAddressSubOption` |
| `CccSecondaryDhcpServerAddress` | `CCCSecondaryDHCPServerAddress` |
| `CccSecondaryDhcpServerAddressSubOption` | `CCCSecondaryDHCPServerAddressSubOption` |
| `CccProvisioningServerAddress` | `CCCProvisioningServerAddress` |
| `CccProvisioningServerAddressSubOption` | `CCCProvisioningServerAddressSubOption` |
| `CccProvisioningServerFqdn` | `CCCProvisioningServerFQDN` |
| `CccKerberosRealmName` | `CCCKerberosRealmName` |
| `CccKerberosRealmNameSubOption` | `CCCKerberosRealmNameSubOption` |
| `CccTicketGrantingServerUtilization` | `CCCTicketGrantingServerUtilization` |
| `CccTicketGrantingServerUtilizationSubOption` | `CCCTicketGrantingServerUtilizationSubOption` |
| `CccProvisioningTimer` | `CCCProvisioningTimer` |
| `CccProvisioningTimerSubOption` | `CCCProvisioningTimerSubOption` |
| `CccSecurityTicketControl` | `CCCSecurityTicketControl` |
| `CccSecurityTicketControlSubOption` | `CCCSecurityTicketControlSubOption` |
| `CccKdcServerAddressList` | `CCCKDCServerAddressList` |
| `CccKdcServerAddressSubOption` | `CCCKDCServerAddressSubOption` |
| `CccAsReqAsRepBackoffRetry` | `CCCASBackoffRetry` |
| `CccAsReqAsRepBackoffRetrySubOption` | `CCCASBackoffRetrySubOption` |
| `CccApReqApRepBackoffRetry` | `CCCAPBackoffRetry` |
| `CccApReqApRepBackoffRetrySubOption` | `CCCAPBackoffRetrySubOption` |
| `pydhcp.network.WILDCARD_IPv4` | `WILDCARD_V4` |
| `HardwareAddressType.IP_ARP_over_ISO_7816_3` | `HardwareAddressType.IP_ARP_OVER_ISO_7816_3` |
| `DHCPOptionCode.GRD` (option 212) | `DHCPOptionCode.SIXRD`; `GRD` stays as an alias member, so `DHCPOptionCode(212).name` is now `SIXRD` |
| `DHCPMessage.dumps()` | `DHCPMessage.summary()` |
| `HardwareAddressType.dumps(address)` | `HardwareAddressType.format_address(address)` |
| `load_message(text, format)`, `dump_message(message, format)` | `DHCPMessage.from_text(text, format)`, `message.to_text(format)` |
| `load_mapping(text, format)`, `dump_mapping(data, format)` | `pydhcp.packet.structured.loads(text, format)`, `.dumps(data, format)` |
| `SocketAddress.compat()` | `SocketAddress.to_tuple()` |
| `DHCPMessage.client_id()` | `DHCPMessage.get_client_id()` |
| `DHCPServer.lease_seconds(msg)` | `DHCPServer.get_lease_seconds(msg)` |
| `ListenSpec` | `ListenLike` |
| `ServerAddress` | `ServerAddressLike` |
| `send(..., destination=...)`, `DHCPTransport.send(..., dest, ...)` | `dst` |
| `Bytes(src=...)` | `Bytes(value=...)` |
| `_dhcp_read`, `_dhcp_write`, `_dhcp_len_hint`, `_dhcp_decode`, `_dhcp_encode` | `unpack_from`, `pack_into`, `fixed_size`, `unpack`, `pack` |
| `__json__`, `_display_text` | `to_json`, `display_text` |

### Fixed

- **Every public annotation resolves with `typing.get_type_hints` on Python
  3.9.** `X | Y` in a signature, a `typing_extensions.Self` imported only
  under `TYPE_CHECKING` and names a function could not see failed there with a
  `TypeError` or `NameError` (28 of 242 public callables). Signatures use
  `Optional` and `Union`, `Self` is a bound `TypeVar` per class, and every
  module has `from __future__ import annotations`; `typing_extensions` is no
  longer imported.
- **Each module logs on its own logger.** Records from the listener, server, relay,
  client, lease store and the rest were emitted on `pydhcp` itself, so a level set
  on `pydhcp.server` silenced nothing. A record is now named for its module
  (`pydhcp.server.handlers`, `pydhcp.listener.receive`, `pydhcp.cli.capture_hook`);
  a handler or level on `pydhcp` still sees all of them, since children propagate.
- **`pydhcp capture --hook ./name` runs the file it names.** The command was started by
  the name with its `./` dropped, which POSIX looks up on `PATH` only: the hook was not
  found (a traceback per packet) or a program of the same name on `PATH` ran instead.
  The hook is now resolved to an absolute path when the capture starts, so `./name` is the
  file in the working directory on every platform and survives a later change of
  directory, and a bare `name` is looked up on `PATH` (a bare name that is only a file in
  the working directory is refused, naming `./name`). A command hook that is not
  executable is refused at start-up on POSIX. The help text says which is which.
- **Address-bound listening is documented as it behaves, and warns.** A socket bound to
  an address (`per_interface=True`, or a `listen` that names one) hears no broadcast on
  Linux (measured: 0 of 3 limited and 0 of 3 subnet broadcasts, against 3 of 3 for the
  wildcard; macOS and the BSDs are expected to match, unmeasured), so an unconfigured
  client is served only through the wildcard there. The documentation called
  `per_interface=True` the portable deterministic path and `examples/listener.py` used
  it; both now say this and `examples/listener.py` listens on the wildcard. Binding a
  non-wildcard, non-loopback address on a platform other than Windows logs one WARNING
  per process.
- **The async listener's queue behind its handler is bounded.** Every
  datagram was queued for the one worker thread with no limit, so a slow
  handler (a lease-file write) let a flood grow memory by tens of MiB a
  second. `AsyncDHCPListener`, `AsyncDHCPServer`, `AsyncDHCPRelay` and
  `AsyncDHCPCapture` take `max_queued` (default 1024 datagrams): the
  datagram that finds the backlog full is dropped, counted in the new
  `metrics.packets_dropped_backlog` and reported at WARNING at most once a
  minute. `stop()` discards what is still queued, counted in the same
  counter, instead of letting the worker log one ERROR with a traceback
  for each queued datagram; the handler already running finishes. The
  per-datagram `getsockname()` for the DEBUG log is skipped when DEBUG is
  off.
- **`DHCPListener.start()` raises when the bind fails.** It used to return the
  receive thread, whose bind error reached only `threading.excepthook`, leaving
  the listener "started": `wait()` blocked for ever and a second `start()`
  returned `None`. `start()` now binds on the caller's thread and raises what
  `bind()` raised (`AddressInUseError`, `PermissionError`), with nothing bound
  and the listener startable again; `listen()` clears its token when its own
  bind fails.
- **A `bind()` that fails partway no longer keeps the sockets it had opened**
  (`DHCPListener(listen=[good, bad]).bind()`, `with` on such a listener): they
  are closed before the error is raised, so the ports are not held.
- **The Client FQDN option (81) reads every form RFC 4702 defines.** A partial
  name (no terminating label) and an empty Domain Name field used to raise
  `ValueError`, and so did a flags octet with a reserved bit set, which the RFC
  says receivers MUST ignore; `options.get(81)` now returns the value, with the
  reserved bits dropped from `flags`. `ClientFQDN` gains `partial` (a keyword
  argument and an attribute, also in its mapping form) so a partial name is
  encoded without the terminator it was received without, and an empty field is
  encoded as empty. Constructing with a reserved flag bit set now raises
  `ValueError`, as the RFC requires senders to clear them.
- **A domain list can no longer cost a datagram's worth of CPU and memory.**
  Decoding options 119, 141, 88 and 146 followed compression pointers with no
  limit, so one 60 KB datagram of chained pointers took 15 s and 112 MB to
  read. A decoded name is now at most 255 octets (RFC 1035 s2.3.4), a name
  follows at most 127 pointers, and a pointer must point strictly backwards to
  the start of a label of an earlier name; otherwise the option raises
  `ValueError` (the same datagram is now refused in 0.06 s). A last name left
  unfinished at the end of the option is discarded (RFC 3397 s3) rather than
  kept, and a final octet that starts a pointer no longer raises `IndexError`.
- Re-binding a started `AsyncDHCPListener` whose listen list shrank retires the
  dropped socket's receive task cleanly; it used to wait for ever.
- `SocketAddress` refuses a port outside 0-65535 with `DHCPValueError`; `str()` of one
  with a port such as 70000 used to raise.
- `options.get(code)` of a list option (`ROUTER`, `DNS`, `PARAMETER_REQUEST_LIST` and
  the others) pickles, copies and deep-copies to an equal value, and so do a
  `DHCPOptions` bag and a `DHCPMessage` holding them; `pickle.dumps` of one
  raised `PicklingError`. `insert`, `+=` and slice assignment on a list codec
  stored items un-normalized (`StaticRoute[0] = (...)` skipped the
  default-destination check).

## [0.7.0] - 2026-10-03

### Changed

- **Requires netimps 0.3.3** (`netimps>=0.3.3,<0.4`, was `>=0.3.1`): it uses
  `supports_pktinfo`, the interface cache (`cache=`, `clear_interface_cache`),
  `AddressInUseError`, `UdpEndpoint.arecv()`, `backoff_delays(jitter_seconds=)`
  and `Datagram.truncated`, all added in that release.
- **A taken port raises `netimps.AddressInUseError`** from `DhcpListener.bind()`
  and `SocketAddress.listen()` — an `OSError` subclass, so `except OSError`
  still catches it, but never a `PermissionError`. Windows reports a port held
  exclusively elsewhere as WSAEACCES, which Python maps to `PermissionError`
  on 3.12+ and to a plain `OSError` on 3.9.
- `SocketAddress.listen()` takes keyword-only `broadcast`,
  `allow_address_takeover` and `connreset`, forwarded to `netimps.bind()`.
  `REUSE_ADDRESS=True` now means `allow_address_takeover=True`; the exclusive
  default is netimps' on every platform.
- `pydhcp.network.SocketOption` is `netimps.SocketOption` (same three fields).
- **Host-address lookups use netimps' enumeration cache** (one-second TTL),
  cleared on every bind, in place of pydhcp's own two per-bind caches. Same
  cost bound — measured, a 1000-datagram burst cost 2 enumerations — and an
  address the host gains or loses is now noticed within a second instead of
  only at the next bind. `host_ip_interfaces()` gains a keyword-only `cache`.
- `MACAddress.hex()` is inherited from netimps (identical behaviour) rather
  than overridden, and `str(SocketAddress)` is built with `netimps.join_host`.
- **`DhcpClient`'s retransmission schedule comes from
  `netimps.backoff_delays(jitter_seconds=1.0)`.** Two deliberate differences
  from the hand-rolled one, both closer to RFC 2131 §4.1: the ±1 s jitter is
  applied after the 64 s cap, so a backed-off wait is 63–65 s instead of
  clamped one-sidedly below 64 (which re-synchronises clients exactly where
  they spend their time), and the amplitude is capped at the current delay
  rather than a quarter of it.

### Removed

- **`pydhcp.network.SocketSession`**, which nothing in pydhcp used and which
  duplicated `UdpTransport`'s rule that a `0.0.0.0` destination means the
  limited broadcast. Send through a `Transport` instead.

### Fixed

- **A burst of requests overflowed the socket buffer on Windows.** Its 64 KiB
  default holds about 220 typical DHCP datagrams; measured, a 1000-datagram
  burst at a wildcard server delivered 220 and the kernel dropped the rest.
  Listeners now ask for a 1 MiB receive buffer (`RECEIVE_BUFFER_SIZE`, a new
  class attribute; `0` keeps the OS default) through
  `netimps.set_buffer_size`, logging any shortfall the OS imposes. The same
  burst now delivers all 1000.
- **`DhcpMessage.encode()` refused messages it could encode.** The overload
  field was chosen from how far the options overshot, ignoring whether it was
  free: one octet over meant `sname`, so a reply with a set `sname` moved it
  into option 66, overflowed, and raised `OverflowError` while an empty `file`
  would have held everything — a PXE-shaped reply, lost. Each overload choice
  is now tried, cheapest first, and an occupied field is relocated only when
  nothing cheaper fits. Found by the round-trip property test.
- **A wildcard listener did not know which interface a datagram arrived on**
  on CPython 3.9–3.11 anywhere (`socket.IP_PKTINFO` only exists from 3.12), on
  macOS (which zero-fills the field the old code read) and on Windows (whose
  packet-info layout differs). The server then resolved a synthetic
  `0.0.0.0/32` interface and, measured, received a DISCOVER and allocated and
  sent nothing. Receiving now goes through `netimps.UdpEndpoint`, which
  handles every platform and interpreter; a broadcast is answered from the
  receiving interface's own address.
- **`listen="0.0.0.0:67"` and `"*:67"` were not treated as wildcards**: they
  skipped packet info and bound one socket per address, which on Linux hears
  no broadcast DISCOVER (measured: 0 of 3, against 3 of 3 for
  `("0.0.0.0", 67)`). Wildcard-ness is now decided on the parsed host.
- **The async listener had no packet info on Windows' default proactor
  loop**, where it fell back to a `DatagramProtocol`. It now receives with
  `UdpEndpoint.arecv()` on every loop type.
- **A client that went away cost the server an ERROR on Windows.** An ICMP
  port-unreachable provoked by a reply surfaced as `ConnectionResetError` on
  the next, unrelated receive, logged with a traceback and counted as a dropped
  datagram. Listener sockets are now bound with netimps' `connreset=False`.
- **Replies were only pinned to the receiving address on Linux 3.12+.**
  `PktInfoUdpTransport` packed the POSIX control message by hand, behind the
  same `IP_PKTINFO` feature test. It now sends through
  `netimps.UdpEndpoint.send(src=...)` on every platform, and takes an optional
  `endpoint` argument.

## [0.6.1] - 2026-09-28

### Changed

- `duho` floor raised to `>=0.6.0,<0.7` (was `>=0.5.0,<0.6`). No pydhcp code
  change was needed: the three duho-0.6 regressions found against a
  pre-release snapshot (`sys.exit` return typing, an unconditional stderr
  handler, and logger levels pinned on descendant loggers) are fixed in the
  release. `duho` 0.6 also added an MCP-over-stdio launch mode, triggered by
  setting `PYDHCP_MCP=stdio` in the environment; the `pydhcp` CLI (`App`) is
  left at that default (no opt-out) rather than disabling it.

## [0.6.0] - 2026-09-21

The 0.5.2 review remediation: 122 commits closing all 339 findings of a multi-agent
review, verified per-commit on Windows and Linux and against ISC dhclient on a
veth pair.

### Added

- `AsyncDhcpRelay` and `AsyncDhcpCapture`, completing async parity. Mixed onto
  `AsyncDhcpListener` rather than copied, so the `IP_PKTINFO` receive path and every
  fix it gains are shared; a test parses both classes and fails if any receive-path
  line is duplicated. Verified with ISC dhclient over a veth pair.
- `DhcpListener.bound_addresses` / `AsyncDhcpListener.bound_addresses` — what a
  listener is actually bound to, read from the sockets. This is how a caller that
  passed port 0 learns the port it was given.
- `FileLeaseBackend.SAVE_INTERVAL_SECONDS`, with `flush()`, `close()` and context-manager
  support: opt-in write coalescing. **Off by default** — coalescing trades a property
  the operator cannot see going wrong (leases lost on a crash) for one they can already
  measure, which is the wrong way round for a default.
- `pydhcp server --lease-file PATH` (also `lease_file` under `[server]` in a config
  file). `docs/deployment.md` had always told operators to mount lease storage; until
  now the CLI had no way to write to it, so the volume stayed empty and every client
  renumbered on restart.
- `pydhcp server --per-interface` and `pydhcp relay --per-interface` — both classes
  already took the argument; only the CLI could not reach it.
- `python -m pydhcp` as an entry point.
- `UncompressedDomainList`, and `RecordList[T]` for codecs whose entries are records.

### Fixed

**The one that mattered most.** On Linux and macOS the default wildcard server received
nothing at all: the `IP_PKTINFO` path discarded the local address and interface index at
the line that needed them, so the server answered with identifier `0.0.0.0` and no
client ever completed a DORA. Measured against ISC dhclient 4.4.3: retransmitting
DISCOVER until it gave up, before; bound, after.

- **Server (RFC 2131).** A DHCPDISCOVER no longer extends the lease it is only probing,
  and a REQUEST about to be NAKed no longer renews the address it is refusing. Replies
  carry the server's `siaddr`/`sname`/`file` instead of echoing the client's — a client
  could nominate its own next-server and boot file, which is the pair a PXE client acts
  on. A DHCPRELEASE is checked against `ciaddr` before it frees anything. Option 54 is
  compared against every address this host holds, so a second socket on the same segment
  no longer deletes the binding the first just granted. Option 57 below the RFC 2132
  minimum is floored rather than making `encode` raise and the client get nothing. A
  lease with no time left produces no OFFER and NAKs a REQUEST rather than ACKing an
  empty reply. Lease length is the server's policy, honouring the RFC 2132 infinity
  sentinel. The base server no longer claims to be the network's router and resolver.
- **Wire format.** Every encoded packet leads with the message type on both encode
  paths. `sname`, `file` and `chaddr` raise instead of being silently truncated, and
  `hlen` is bounded to what `decode` accepts. Domain labels are measured in octets, not
  characters — every non-ASCII name was going out corrupt. Options 88 and 146 encode
  uncompressed, as RFC 4280 §4.6 and RFC 6731 require; 119 and 141 still compress, as
  theirs require. Outgoing messages are padded to the 300-octet BOOTP minimum. Six
  option codecs match the wire forms their RFCs define. An option-overloaded message
  now round-trips: `decode` consumes options 52, 66 and 67 — the framing that says
  `sname`/`file` hold option fragments, and the two options the encoder parked the
  real values in — instead of handing them back alongside the fields it restored
  them into. A decoded message no longer claims an overload it is not carrying, nor
  reports its server name and boot file twice under two spellings.
- **Relay.** A request is dropped only when its hop count *exceeds* the threshold
  (RFC 1542 §4.1.1) — it was refused one hop early — and the default is now the RFC's 4
  rather than its ceiling of 16. A relayed exchange is identified by client as well as
  transaction, so a forged xid cannot redirect an OFFER.
- **Client.** Retransmissions back off with jitter instead of repeating one interval,
  and carry a real `secs`. Replies match on `(xid, chaddr)`, so two exchanges on one
  client no longer consume each other's replies.
- **Async.** `stop()` called from a handler no longer hangs the loop on Linux — nothing
  it touched was thread-safe, and the selector loop never woke.
- **Lease store.** Bounded, so a forged-identity flood cannot exhaust it. The file
  survives a crash and no longer loses leases silently.
- **Capture and CLI.** Filter keywords match whatever their case — an uppercase `AND`
  compiled, matched nothing and reported nothing. Filter values are checked once at
  startup instead of raising per packet. A per-capture filename pattern is validated
  before binding. A capture run cannot create unbounded files per client identifier.
  The CLI calls itself `pydhcp`.
- **Registry.** A subscripted generic is the same class every time. A user's
  `register_type()` is no longer overwritten by the lazy registry load, and a failed
  load is retried rather than leaving every code as `Bytes`.

### Changed

- `DhcpServer.release_lease()` returns `bool` and no longer touches metrics — an orderly
  release, a DECLINE reporting an address conflict, and a reclaim after the client chose
  another server all arrive there, and only the caller knows which.
- `DhcpMetrics` gains `leases_declined` and `releases_ignored`. DECLINE used to count as
  a release, so an address-conflict storm read as orderly shutdowns.
- `DhcpRelay(max_hops=...)` defaults to 4 and must be 0..16.
- `DhcpClient(timeout=...)` is the *initial* retransmission interval, so a default call
  now takes up to ~14 s rather than ~6 s before giving up.
- The package installs a `NullHandler` and logs under `pydhcp.<module>`. With logging
  otherwise unconfigured this **silences** the WARNING-and-above that `logging.lastResort`
  used to print; configure a handler to see them.
- `DhcpOptions` rejects codes 0 and 255 on assignment — they are structural markers, not
  options. Receive stays liberal.
- Both import cycles removed; `HardwareAddressType` now lives in `pydhcp.network` and is
  re-exported from `pydhcp.packet`.
- **`netimps` is now required as `>=0.3.1,<0.4`** (was `>=0.2.2`). The floor is
  0.3.1 rather than 0.3.0 for one reason: 0.3.0's `bind_error_hint` read a
  Windows `WSAEACCES` as POSIX `EACCES` and called a taken port a privilege
  problem — "permission denied binding port 64514", plus advice to become
  Administrator, on a platform that has no privileged ports. pydhcp carried its
  own interception for that; 0.3.1 fixes it upstream, so the workaround is gone
  and the diagnosis is made in one place again. A port held by another socket is
  still reported as in use and not as a privilege failure, and still suggests an
  alternative port; only the wording moves.

  The six entry points this package uses — `normalize_host`, `bind`,
  `bind_error_hint`, `iter_addresses`, `APIPA`, `MACAddress` — keep their
  signatures across 0.2.x → 0.3.1. Several of 0.3.0's documented breaks *are*
  real (`MACAddress` no longer compares equal to its own string spelling, mixed
  MAC separators are rejected, `normalize_host` raises on an ambiguous
  multi-colon host); none is reachable from this package, which was checked
  rather than assumed. pydhcp never compares a hardware address to a string —
  leases and capture filters key on `str` client identifiers on both sides — and
  the `normalize_host` inputs that now raise used to fail a step later in
  `IPv4()` anyway, so the CLI reports a better message for them rather than a
  worse one. The upper bound is the pre-1.0 rule that a minor bump means the
  documented API broke.

### Removed

**These are the breaking changes in this release**, and the reason it needs a
MINOR bump rather than a patch: pre-1.0, MINOR means the documented API broke.
Nothing else here is breaking.

- **`pydhcp.IPv4Address`, `pydhcp.List`, `pydhcp.Bytes`, `pydhcp.String` and
  `pydhcp.Boolean`** are no longer re-exported from the top level. They are
  option *codecs*, and their bare names did not say so — `pydhcp.IPv4Address`
  was the codec rather than `ipaddress.IPv4Address`, so
  `isinstance(interface.ip, pydhcp.IPv4Address)` was **False** while looking
  exactly like the check you meant to write. Import them from
  **`pydhcp.options.type`**, where they have always lived. The stdlib address
  type remains `pydhcp.IPv4`.

  The other 49 codecs stay, including `U8`/`U16`/`U32` and the `Ccc*`/`MoS*`/
  `Vi*` families: nothing in the stdlib or `typing` is called any of those, so
  the bare name already says it is a pydhcp type.

- **`pydhcp.constants.MISSING` / `pydhcp.constants.Missing`** are gone.
  `constants.py` holds protocol constants — packet sizes, port numbers, the
  infinite-lease sentinel — and this is a Python idiom for "argument not
  supplied where `None` is itself a value". It now lives in `pydhcp._utils` and
  is private; nothing outside the package needed it.

No deprecation aliases were left behind for either, which is this project's
convention: a name that still resolves is a name nobody migrates off.

### Documentation

- The option code registry — 163 RFC-documented members — reaches the API reference for
  the first time.
- A repo-root `AGENTS.md`, which two shipped headers already cited.
- README and CHANGELOG links that only resolved inside a checkout, and CHANGELOG compare
  links naming three tags that never existed.

## [0.5.2] - 2026-08-16

### Changed

- **`duho` is now required as `>=0.5.0,<0.6`** (was `>=0.4.1`). The old floor
  predated duho 0.5.0, which changed how a `list`/`set`/`tuple` field used as an
  option parses: `--x a b` used to accumulate both values in one occurrence
  (`nargs="*"`), and an option field now takes one value per occurrence. The CLI
  declares `server: List[str]` as `--server`/`-s` on the `relay` subcommand and
  documents it as "(repeatable)", so a resolver was free to install a duho where
  that flag did not behave the way its own help text describes. The upper bound
  is the pre-1.0 rule that a minor bump means the documented API broke.
- **`netimps` is now required as `>=0.2.0,<0.3`** (was `>=0.2.2`), normalising it
  to the same minor-series form. Nothing this package calls (`normalize_host`,
  `bind`, `bind_error_hint`, `iter_addresses`, `APIPA`, `MACAddress`) was added
  after 0.2.0, so the exact-patch floor was stricter than the code justified.

## [0.5.1] - 2026-08-16

### Added

- **`DhcpOptions.copy()`** — returns an independent container: the codemap is
  preserved and every payload is copied into a fresh `bytearray`, so neither
  structural edits nor in-place mutation of a payload obtained from
  `get(..., decode=False)` can write through to the original.

### Changed

- The `netimps` requirement floor is raised to `>=0.2.2`. The previous
  `>=0.0.1` predated the API this package actually calls (`normalize_host`,
  `bind`, `bind_error_hint`, `iter_addresses`, `APIPA`, `MACAddress`), so a
  resolver was free to install a release that could not satisfy it.

### Fixed

- **Server responses no longer mutate the stored lease.**
  `DhcpServer._create_response` assigned `resp.options = lease.options`, so the
  response and the lease backend shared one `DhcpOptions` object. Everything the
  response pipeline did to it edited the allocation store: `IP_ADDRESS_LEASE_TIME`,
  `SERVER_IDENTIFIER`, `DHCP_MESSAGE_TYPE` and the echoed
  `RELAY_AGENT_INFORMATION` (option 82) were injected into the lease;
  `PARAMETER_REQUEST_LIST` filtering **permanently deleted** from the lease every
  option the client did not ask for; and `handle_inform` stripped the lease time.
  `InMemoryLeaseBackend.renew` carries the same object across renewals and
  `FileLeaseBackend` persisted the damage to disk. The response now takes
  `lease.options.copy()`.
- **`DhcpRelay._pending_clients` is bounded.** The `xid -> original client
  address` map grew without limit for xids whose replies never arrived, leaking
  memory in a long-running relay. It is now capped at
  `DhcpRelay.MAX_PENDING_CLIENTS` (1024) entries, oldest evicted first; an
  evicted entry only costs the port-68 fallback a real client listens on.
- `MACAddress.hex()` carries the real `bytes.hex` signature it forwards to
  (it had untyped `*args, **kwargs`, which also left its body unchecked).
- Removed two dead `isinstance(e, KeyboardInterrupt)` re-raise branches in
  `listener.py`: `KeyboardInterrupt` does not subclass `Exception`, so neither
  could ever run. The interrupt already propagates to the outer handler.
- `listener.py`'s socket-close bare `except:` is now `except Exception:`.
- `DhcpMessage.dumps()` printed `siaddr` twice, as "Server Address" and "Next
  Server"; it is one field and now prints once as "Next Server (siaddr)".

## [0.5.0] - 2026-07-24

### Changed

- **`cli.py` is rewritten on [`duho`](https://pypi.org/project/duho/)**, a
  declarative CLI framework, replacing hand-built `argparse`. Each subcommand
  (`interfaces`, `server`, `relay`, `packet`, `capture`) is now a `duho.Cmd`
  class with annotated fields instead of `add_argument` calls. Behavior and
  flags are preserved, with additions:
  - `pydhcp --version` now works (resolved from installed package metadata).
  - Per-subcommand `--log-level` is replaced by duho's shared verbosity
    scheme: `-v`/`-q` (repeatable) and `--loglevel KEY=VALUE`.
  - New short flags: `packet` gains `-i`/`-o`/`-f` (`--input`/`--output`/
    `--format`); `capture` gains `-l`/`-o`/`-f`/`-c` (`--listen`/`--output`/
    `--format`/`--count`); `server` and `relay` gain `-l` (`--listen`);
    `relay` also gains `-s` (`--server`).
  - `--help` now shows `(default: X)` next to any option with a non-empty
    default.
- Added `duho` as a runtime dependency.

## [0.4.1] - 2026-07-22

### Changed

- **Network enumeration now comes from `netimps`.** `network/platform.py` --
  503 lines of ctypes (`GetAdaptersInfo`, `getifaddrs` with hand-written
  sockaddr structs, plus `ipconfig`/`ip addr` text-scraping fallbacks) -- is
  deleted. Every address the old code found is still found, with identical
  prefixes and MACs, verified against a captured baseline before switching.
  - Adapter names are now **human-readable** (`"Wi-Fi"`) rather than Windows
    GUIDs.
  - **Loopback is now enumerated**, so a loopback-bound socket resolves to a
    real interface with its true `/8` instead of falling through to a
    synthetic `/32`.
  - `host_ip_interfaces()` gains `family=4` as the default, preserving the
    IPv4-only behaviour callers relied on.
- `MACAddress` is now a `netimps.MACAddress` subclass. The uppercase-hyphenated
  rendering is unchanged; it is no longer a `bytes` subclass, so use `.packed`
  for raw bytes (`.hex()` is kept as a passthrough). It gains `.oui`,
  `.is_multicast`, `.is_local` and ordering.
- `SocketAddress.listen()` delegates to `netimps.bind()`, which closes the
  socket before any exception propagates.
- Bind failures use `netimps.bind_error_hint`, which recognises the POSIX
  errnos *and* the Windows `WinError` codes. The DHCP-specific suggestions are
  appended rather than replacing the diagnosis.

### Fixed

- `_split_host_port` mis-parsed IPv6 listen specs: `"[::1]:67"` returned
  `("[::1]:67", None)`, silently dropping the port. It now delegates to
  `netimps.normalize_host`.

## [0.4.0] - 2026-07-14

### Added
- Added a basic listener-based `DhcpClient` for building, sending, and collecting DHCP client packets without configuring OS interfaces.
- Added reusable DHCP capture primitives and a `pydhcp capture` CLI with safe `and` filters, structured output streams/files/per-capture files, and trusted Python or command hooks.
- `pydhcp.config.load_config` (and `pydhcp server --config`) now accepts YAML and TOML in addition to JSON and INI, matching the formats already supported by `pydhcp.packet.structured`.
- Added `DhcpClient.discover_offer()` and `DhcpClient.dora()` to run a full DISCOVER/OFFER/REQUEST/ACK exchange (with retries and a timeout) in a single call, instead of hand-building each message.
- `DhcpServer` now echoes `RELAY_AGENT_INFORMATION` (option 82) unchanged from request to reply per RFC 3046 §2.2, when a relay agent includes it.
- Added Hypothesis-based property round-trip tests for the core option codecs (`U8`/`U16`/`U32`/`I32`, `Boolean`, `String`, `Bytes`, `List[IPv4Address]`, `DomainList`, `ClasslessRoute`) in `tests/test_property_roundtrip.py`, plus `hypothesis` as a `dev` extra.
- Documented `pydhcp.client`, `pydhcp.capture`, `pydhcp.packet`, `pydhcp.network`, and `pydhcp.lease` on the API reference site, and added FAQ entries for running a DORA handshake and picking a config file format.
- Added `DhcpRelay`, an RFC 1542 / RFC 2131 §4.1 / RFC 3046 DHCP relay agent: forwards client broadcasts to one or more configured upstream servers (stamping `giaddr`, incrementing `hops`, dropping packets past a configurable `max_hops`) and forwards server replies back to the original client, with optional `RELAY_AGENT_INFORMATION` (option 82) circuit-id/remote-id tagging. Includes a `pydhcp relay` CLI subcommand.

### Changed
- Reorganized package internals into clearer `packet`, `options`, and `network` subpackages; `DhcpOptionCode` now lives under `pydhcp.options`, and option codec classes live under `pydhcp.options.type`.
- Moved the message-level enums (`DhcpMessageType`, `OpCode`, `Flags`, `DhcpPort`, `HardwareAddressType`) from `pydhcp.enum` to `pydhcp.packet.enums`, re-exported from `pydhcp.packet`; the `pydhcp.enum` package is gone.
- Renamed the misspelled `pydhcp.constants.INIFINITE_LEASE_TIME` constant to `INFINITE_LEASE_TIME`.
- Split the 1,252-line `pydhcp.options.type` module into a subpackage (`base`, `net`, `scalar`, `vendor`, `mos` submodules); the public import path `pydhcp.options.type` and every name it exposes are unchanged.
- **Breaking**: removed the global mutable `pydhcp.metrics.METRICS` singleton. `DhcpListener` (and `DhcpServer`/`DhcpClient`) now own a per-instance `self.metrics: DhcpMetrics`, so counters no longer leak across independent listeners/servers in the same process (e.g. in tests). Added `DhcpMetrics.snapshot() -> dict[str, int]`.
- Precompiled the DHCP fixed-header `struct.Struct` in `pydhcp.packet.message` instead of re-parsing the format string on every encode/decode call, roughly 5x faster packet parsing (see structured JSON benchmark reports in `benchmarks/README.md`).
- **Breaking**: standardized the `pydhcp packet` CLI on the same conventions `capture` already used: `--input <path>` and `--output <path>` each accept `-` for stdin/stdout (POSIX convention) and default to `-`, and the five separate `--json`/`--yaml`/`--toml`/`--ini`/`--summary` flags collapsed into one `--format <fmt>` flag (default `json`). Removed `--stdin`, `--input-file`, `--output-file`, and inline `--input <text>` (unused/undocumented) — use `--input -` for stdin and a path for files.

### Fixed
- `mypy --strict` now passes cleanly across the whole package (was 40 errors in 8 files), surfacing and fixing one real bug along the way: a synthetic DHCPINFORM lease built with `expires=None` instead of the established "does not expire" sentinel `math.inf`.
- Fixed `DomainList` decoding silently dropping domains that follow a compression-pointer-terminated domain in the same option (affects `DOMAIN_SEARCH` and any other option backed by `DomainList`); found by the new Hypothesis property tests.

## [0.3.0] - 2026-07-13

### Added
- Added CCC option codec coverage and registered `DhcpOptionCode.CCC` for typed round trips.
- Clarified `DhcpServer` customization hooks, added DHCPINFORM option-only responses, and
  repaired examples so they match the current lease API.
- Made TOML packet support optional at import time, with clear `NotImplementedError` messages
  when `tomli` or `tomli-w` is unavailable.
- Added stricter short-packet diagnostics and `pydhcp packet --decode --summary` for compact
  DHCP capture inspection.
- Added multi-endpoint listener parsing for host:port strings, comma-separated CLI listen specs, and
  one-address/many-port tuples, plus `per_interface` constructor parity on sync and async servers.
- Added optional JSON benchmark report output for `benchmarks/bench_options.py` and uploaded the
  opt-in CI benchmark run as a workflow artifact for easier comparison across iterations.
- Added optional JSON benchmark report output for `benchmarks/bench_parse.py` so both benchmark
  entry points now share the same local artifact pattern.
- Extended the opt-in benchmark workflow to archive both parse and options benchmark JSON reports.
- Added the repo-local `benchmarks/run.py` wrapper so maintainers can choose `parse` or `options`
  benchmarks and optionally write structured JSON output without expanding the released package CLI.
- Added structured packet I/O for `pydhcp packet` with JSON, YAML, TOML, and INI round trips plus
  explicit stdin, inline, file, and output-file handling.

### Fixed
- Removed the stale `pydhcp packet --encode` CLI flag and replaced it with a real packet encoding
  mode backed by structured packet helpers.

## 0.2.1-rc.1 - 2026-07-12

### Added
- Expanded DHCP option-type registrations so common well-defined options decode to typed values.
- Added a "Common DHCP Options" docs page with typed examples and updated the custom-options example to prefer typed assignment.
- Added stricter option-type validation and `ClasslessRoute` truncation checks.
- Added wildcard listener `per_interface` support and exported `PktInfoUdpTransport`.
- Added typed codecs and registrations for policy filters, static routes, user classes, encapsulated vendor/relay sub-options, name service search, subnet selection, and RDNSS selection.

### Fixed
- Made `DhcpMessage.encode()` idempotent and tolerant of reserved flag bits during decode.
- Corrected `DhcpMessage.dumps()` field labels and `secs` packing behavior.

## 0.2.0 - 2026-07-12

### Added
- Created `benchmarks/bench_parse.py` packet parsing and serialization performance benchmarks.
- Added `benchmarks/README.md` documenting performance baselines.
- Added `AsyncDhcpListener` and `AsyncDhcpServer` classes implementing asyncio-based event loop integration.
- Added integration tests for async server in `tests/test_async.py`.
- Configured MkDocs documentation with Material theme and `mkdocstrings` auto-generated API references.
- Added `Transport`, `UdpTransport`, and `RequestContext` classes for structured transport-layer abstraction and Interface tracking.
- Added comprehensive unit testing coverage for packet deserialization and type-safe dictionary operations in `test_message.py` and `test_options.py`.
- Added integration tests verifying standard client DORA sequences and RFC 2131 routing logic in `tests/integration/test_dora.py`.
- Added missing `ALL_VPNS` option (Tag 254) to `DhcpOptionCode` after comparing against the latest IANA registry.
- Populated default `ROUTER` and `DNS` lease options in `DhcpServer.acquire_lease` using the server's interface IP.
- Added pluggable lease backend API (`LeaseBackend`) and implementations (`InMemoryLeaseBackend`, `FileLeaseBackend`) for state preservation and persistence.
- Added unit and integration tests for lease backends in `tests/test_lease_backend.py` and `tests/integration/test_dora.py`.
- Added validation checks for hardware address length (hlen <= 16) during packet decoding.
- Added socket binding error diagnostics that offer actionable suggestions for permission and address-in-use errors.
- Added unit tests for binding error handling and malformed packet input in `tests/test_permissions.py` and `tests/test_malformed_packets.py`.
- Added command-line interface (CLI) with `interfaces`, `server`, `packet`, and `bench` subcommands.
- Added JSON-based configuration loading support in `config.py`.
- Added in-process metrics counters (`packets_received`, `packets_sent`, etc.) in `metrics.py` to support observability.
- Added option parsing and lease allocation performance benchmarks in `benchmarks/bench_options.py`.
- Added async DHCP server concurrency stress tests under `tests/test_async_concurrency.py`.

### Changed
- Configured strict typechecking configuration in `pyproject.toml` and resolved all mypy type-checking errors across the library.
- Refactored `DhcpMessageType` and `OptionOverload` to implement the `DhcpOptionType` interface directly and avoid PEP 561 / type conflicts with `BaseFixedLengthInteger` and Enums.
- Refactored `DhcpServer.handle` to accept `RequestContext` instead of `SocketSession`, split processing into message-type specific handlers (`handle_discover`, etc.), and comply strictly with RFC 2131 routing paths.
- Enriched `NetworkInterface` and `host_ip_interfaces()` to yield fully detailed adapter metadata.
- Refactored `DhcpServer` and `AsyncDhcpServer` to accept and delegate lease lifecycle events (allocate, lookup, renew, release) to a configurable `lease_backend`.
- Refactored options parsing in `DhcpOptions.decode` to handle truncated option lengths gracefully by logging a warning and parsing remaining bytes instead of crashing.
- Added debug-level logging for packet arrival and lease allocation including client XIDs.
- Renamed misspelled `contants.py` to `constants.py` and updated all internal references.
- Added strict `__all__` public exports list to `src/pydhcp/__init__.py`.

### Fixed
- Fixed bug in `ClasslessRoute` destination descriptor parsing/serialization that caused incorrect length calculations for CIDR/8.
- Fixed forward reference type resolution issue for `DhcpOption` in `_options.py`.
- Fixed options encoding `OverflowError` when option size limit is infinite.
- Fixed `BaseDhcpOptionCode.__int__` returning constant zero, correcting enum integer conversion for option codes.

## 0.1.0 - 2026-07-11

### Added

- Initial release.

[Unreleased]: https://github.com/jose-pr/pydhcp/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/jose-pr/pydhcp/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/jose-pr/pydhcp/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/jose-pr/pydhcp/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/jose-pr/pydhcp/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/jose-pr/pydhcp/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/jose-pr/pydhcp/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/jose-pr/pydhcp/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/jose-pr/pydhcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jose-pr/pydhcp/compare/5d1f19e7bac784c926966eaf8561a3c588b2f5f2...v0.3.0
