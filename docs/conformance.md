# Conformance

The server and the relay are compared with **dnsmasq 2.92** (the relay with `--dhcp-relay`) and the
client with **ISC dhclient 4.4.3-P1**. Each case is an exchange written by hand: what a client or a
server sends, and what the role under test is configured with. Its golden is what the reference
answered, recorded on a real network link and never edited. The suite replays every case against
this library's role cores with no socket and no peer installed, so it runs on every platform.

What the comparison covers is stated once, in the
[README](https://github.com/jose-pr/pydhcp#differences-from-dnsmasq-and-isc-dhclient), together
with the differences from the references.

## Coverage

What each role does, whether this library does it, and the recorded cases that ask. A row with no
case is not recorded: the reference cannot produce it, or no case asks it yet. Option codecs are in
[Common DHCP Options](options.md).

<!-- coverage-table:begin -->
| Role | Feature | RFC | Implemented | Cases | Note |
| --- | --- | --- | --- | --- | --- |
| server | DHCPDISCOVER answered with an OFFER | RFC 2131 s4.3.1 | yes | `server-discover` | The address comes from `acquire_lease`; the case gives the client a static address. |
| server | OFFER to a client with no address and the broadcast flag clear | RFC 2131 s4.1 | yes | `server-discover-no-broadcast-flag` | Broadcast, unless `UNICAST_TO_UNCONFIGURED_CLIENT` is set. |
| server | DISCOVER through a relay (giaddr set, option 82 present) | RFC 2131 s4.1, RFC 3046 | yes | `server-discover-relayed` | The option 82 is echoed last. |
| server | An offered address held for its client | RFC 2131 s4.3.1 | yes | `server-offer-hold` | A second client is left unanswered while the only address is on offer. |
| server | REQUEST in SELECTING answered with an ACK | RFC 2131 s4.3.2 | yes | `server-request-selecting` |  |
| server | REQUEST for another address than the one offered, answered with a NAK | RFC 2131 s4.3.2 | yes | `server-request-selecting-other-address` |  |
| server | REQUEST in INIT-REBOOT | RFC 2131 s4.3.2 | yes | `server-request-init-reboot` |  |
| server | INIT-REBOOT from a client the server knows nothing about | RFC 2131 s4.3.2 | yes | `server-request-unknown-client` | Silence. |
| server | INIT-REBOOT for an address on another network, answered with a NAK | RFC 2131 s4.3.2 | yes | `server-request-wrong-subnet` |  |
| server | REQUEST in RENEWING | RFC 2131 s4.3.2 | yes | `server-request-renewing` |  |
| server | The port a renewal's ACK goes to | RFC 1542 s5.4 | yes | `server-request-renewing-from-another-port` | Port 68 in the default strict mode. |
| server | REQUEST in REBINDING | RFC 2131 s4.3.2 | yes |  | Answered like RENEWING; no case asks the broadcast shape. |
| server | The client's host name (option 12) in the ACK | RFC 2132 s3.14 | no | `server-request-selecting-host-name` | Not echoed. |
| server | DHCPINFORM answered with an ACK that carries no address | RFC 2131 s4.3.5 | yes | `server-inform` |  |
| server | DHCPRELEASE | RFC 2131 s4.3.4 | yes | `server-release` |  |
| server | DHCPDECLINE of an address the sender holds | RFC 2131 s4.3.3 | yes | `server-decline` | The address is quarantined. |
| server | DHCPDECLINE from a sender that holds no lease | RFC 2131 s4.3.3 | yes | `server-decline-without-a-lease` | The address is quarantined whoever sent it; `DECLINE_REQUIRES_LEASE` restores the stricter rule. |
| server | Renewal and rebinding times (options 58 and 59) in OFFER and ACK | RFC 2131 s4.4.5 | yes |  | Half and seven eighths of the lease time in the same reply, without fuzz; every server case compares both options. |
| server | An address pool | RFC 2131 s4.3.1 | no |  | The stock server has no pool: a subclass supplies leases through `acquire_lease`. |
| server | Static host-to-address assignments | RFC 2131 s4.3.1 | no |  | Through a subclass, as for a pool. |
| server | BOOTP clients with no message type option | RFC 951, RFC 1542 | no |  | The server dispatches on the message type option. |
| server | Rapid commit | RFC 4039 | no |  | The option is decoded; the two-message exchange is not served. |
| server | PXE and proxy DHCP |  | no |  | The boot file and server name fields are carried; no PXE logic. |
| server | Lease persistence |  | yes |  | `FileLeaseBackend` writes a JSON file; no recorded case. |
| server | DHCPv6 | RFC 8415 | no |  | Out of scope. |
| client | DHCPDISCOVER | RFC 2131 s4.4.1 | yes | `client-discover` |  |
| client | REQUEST in SELECTING after an OFFER | RFC 2131 s4.4.1 | yes | `client-request-selecting` |  |
| client | REQUEST in INIT-REBOOT | RFC 2131 s4.4.2 | yes | `client-request-init-reboot` |  |
| client | DHCPRELEASE | RFC 2131 s4.4.6 | yes | `client-release` |  |
| client | DHCPDECLINE | RFC 2131 s4.4.1 | yes | `client-decline` |  |
| client | DHCPINFORM | RFC 2131 s4.4.3 | yes |  | dhclient sends none, so there is nothing to record. |
| client | REQUEST in RENEWING and REBINDING, with lease timers | RFC 2131 s4.4.5 | no |  | The caller builds the REQUEST; the client keeps no lease timers. |
| client | Configuring the network interface with the lease |  | no |  | The client does not change the host's addresses. |
| client | DHCPv6 | RFC 8415 | no |  | Out of scope. |
| relay | A client's DISCOVER relayed to the server | RFC 1542 s4.1.1 | yes | `relay-discover` | giaddr stamped, hops incremented. |
| relay | A server's OFFER relayed to the client | RFC 1542 s4.1.2 | yes | `relay-offer` |  |
| relay | The hop limit | RFC 1542 s4.1.1 | yes | `relay-discover-over-hop-limit` | Requests above 4 hops are dropped by default; `max_hops` sets it. |
| relay | A request another relay already stamped | RFC 1542 s4.1.1 | yes | `relay-request-already-relayed` | giaddr is kept. |
| relay | Relay agent information (option 82) inserted | RFC 3046 | yes |  | Opt-in (`insert_relay_agent_info`); no recorded case. |
<!-- coverage-table:end -->

## Differences

Each is deliberate, and asserted by the suite as this library behaves. The last column is the RFC
text that backs it, or says that the RFCs decide nothing and the choice is the project's.

<!-- differences-table:begin -->
| Difference | What differs | Authority |
| --- | --- | --- |
| `siaddr-left-zero` | dnsmasq 2.92 writes its own address in 'siaddr' of every reply; this library leaves it 0.0.0.0, because the field names the next bootstrap server and this library supplies none. | RFC 2131 s2: 'A DHCP server may return its own address in the 'siaddr' field, if the server is prepared to supply the next bootstrap service'; the server's own address travels in the server identifier option. |
| `server-option-order` | The server lists its options in another order than dnsmasq 2.92 (this library: message type, subnet mask, broadcast address, router, then lease time, renewal and rebinding times and server identifier); the order carries no meaning. | RFC 2131 and RFC 2132 define no order for the options of a reply beyond RFC 2132 s3.3 ('If both the subnet mask and the router option are specified in a DHCP reply, the subnet mask option MUST be first'), which both keep; this library's order is the project's own choice. |
| `offer-broadcast-without-address` | To a client with no address whose broadcast flag is clear, dnsmasq 2.92 unicasts the OFFER to the offered address; this library broadcasts it, because a plain UDP socket cannot deliver to an address the client does not own yet (set `UNICAST_TO_UNCONFIGURED_CLIENT` for a transport that can). | RFC 2131 s4.1: 'If the BROADCAST bit is cleared to 0, the message SHOULD be sent as an IP unicast to the IP address specified in the 'yiaddr' field and the link-layer address specified in the 'chaddr' field. If unicasting is not possible, the message MAY be sent as an IP broadcast'; the same in RFC 1542 s5.4. |
| `reply-port-68` | A renewal sent from a port other than 68 is answered by dnsmasq 2.92 to that port; this library answers to port 68 (its lenient mode, `STRICT_REPLY_PORTS = False`, answers to the sender's port). | RFC 1542 s5.4: 'The UDP destination port MUST be set to BOOTPC (68).' |
| `offer-held` | While the only address is on offer to one client, dnsmasq 2.92 offers it again to a second client that asks; this library holds it for the first and leaves the second unanswered until the hold ends. | RFC 2131 s4.3.1: 'the server SHOULD NOT reuse the selected network address before the client responds to the server's DHCPOFFER message.' |
| `relayed-reply-hops-zero` | In the reply to a relayed request dnsmasq 2.92 echoes the request's 'hops'; this library sends 0. | RFC 2131 s4.3.1, Table 3: 'hops' is 0 in DHCPOFFER, DHCPACK and DHCPNAK. |
| `host-name-not-echoed` | dnsmasq 2.92 echoes the client's host name (option 12) in the ACK when the client lists it among the parameters it asks for; this library holds no value for it and does not send one. | RFC 2131 s4.3.1: for a requested parameter the server has no configured value for and no Host Requirements default, 'The server MUST NOT return a value for that parameter'; Table 3 ('All others MAY') permits echoing the client's name but does not require it. |
| `client-broadcast-flag` | ISC dhclient 4.4.3-P1 leaves the broadcast flag clear in DISCOVER, REQUEST and DECLINE; this library's client sets it (`broadcast=True`, the default), because a plain UDP socket cannot receive a unicast reply before the host holds the address. | RFC 2131 s4.1: 'A client that cannot receive unicast IP datagrams until its protocol software has been configured with an IP address SHOULD set the BROADCAST bit in the 'flags' field to 1 in any DHCPDISCOVER or DHCPREQUEST messages that client sends.' |
| `client-option-order` | ISC dhclient 4.4.3-P1 lists the message type, then the server identifier, then the requested address in REQUEST and DECLINE; this library lists the requested address before the server identifier; the order carries no meaning. | RFC 2131 and RFC 2132 define no order for the options of a client message; this library's order is the project's own choice. |
| `relay-hop-limit` | A request whose 'hops' is 5 is relayed by dnsmasq 2.92 and dropped by this library, whose limit is 4 and is set by `max_hops`. | RFC 1542 s4.1.1: 'The relay agent MUST silently discard BOOTREQUEST messages whose 'hops' field exceeds the value 16.' and 'The default setting for a configurable threshold SHOULD be 4.' |
<!-- differences-table:end -->

## Recording again

On Linux, as root, with `dnsmasq`, `dhclient` and `busybox` installed (the real-peer lab of
`tests/interop`):

```bash
sudo python tests/conformance/record.py            # write every golden.json
sudo python tests/conformance/record.py --check    # re-record in memory and report drift
python docs/conformance_table.py --check           # this page agrees with the data
```

`--check` exits 0 when nothing differs, and also when it differs on another version or another
distribution than the golden's (the difference is printed); it exits 1 for a difference on the
system that recorded the golden and 2 when the lab or a case cannot run.
