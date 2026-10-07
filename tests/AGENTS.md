# tests — running and writing the suite

How to run the tests of `pydhcp`, what each platform skips, what lives where and the
traps a new test meets. The repository's layout and conventions are in the root
`AGENTS.md`; the API a test checks is in the shipped headers (`src/pydhcp/AGENTS.md`
and the ones it lists).

## Running

```bash
python -m pip install -e ".[dev,docs]"
python -m pytest -q -rs                     # the suite, with every skip's reason
python -m mypy src                          # strict; also on the other platform
python -m black --check src tests benchmarks examples
python -m mkdocs build --strict             # the docs site
```

Run it on **3.9 (the floor) and on the latest Python**, each in its own venv named
`.venv/<version>-<os>-<arch>`; the architecture is what the interpreter was built for, not
what the host is (an emulated x64 CPython on an ARM64 host is `win-amd64`). Run one suite at
a time on a machine: the tests share loopback and a second run's ports collide.

`dev` is `pydhcp[cli,yaml,toml]` plus the tooling, so a development install runs every test
that needs an extra; without them those tests skip (read `-rs`, a green run with the
`yaml`, `toml` or `cli` tests skipped verifies nothing about them). A test of a missing
extra hides the module inside the test (`sys.modules[name] = None`) and never uninstalls.
`pyproject.toml` sets `pythonpath = ["src", "tests"]`, so a test imports helpers by name
(`from helpers import ...`), `filterwarnings = ["error"]` with no exception, and
`xfail_strict = true`.

The benchmark tests (`test_benchmarks_*.py`, `integration/test_benchmarks_suites.py`) are
collected only where `benchmarks/` exists: the sdist leaves it out.

To run the suite against an older `src`, `PYTHONPATH` is not enough (`pythonpath` puts
`src` first): `-o "pythonpath=<old src> tests"`, with forward slashes.

On FreeBSD the `dev` extra does not install (the current `hypothesis` builds a Rust
component and no toolchain is present): install `pytest` and `hypothesis==6.112.0` by name
and the project with `--no-deps`.

## Expected skips

A run is verified against these counts; the tests that decide at run time say so.

| Platform | Skipped | Which |
| --- | --- | --- |
| Windows, either interpreter | 45, or 47 | 32 of `interop/` (network namespaces need Linux), 4 of `test_lease_durability.py` (no `time.tzset`), 3 of `integration/test_documented_commands.py` (`--help` exits before the parser reports an unknown option), 4 of `integration/test_cli.py` (a bare name is searched in the working directory; a script needs `PATHEXT`; no executable bit), 2 of `test_value_laws.py`; the 2 more are `integration/test_listener_transport.py` pin tests, skipped when this Windows build refuses a source pin from the unassigned `127.0.0.2` |
| Linux without root | 7, plus `interop/` | 3 documented commands, 2 value laws, 2 of `integration/test_listener_binding.py` (Windows-only socket options) |
| macOS runner with the loopback aliases CI adds | 44 | |
| macOS without them (an Intel host) | 54 | |
| FreeBSD 16 (Python 3.11) | 56 | |

The tests that need a second loopback address (`127.0.0.2`, `.3`, `.50`) skip where a probe
(`helpers.LOOPBACK_ALIAS_BINDABLE`) says it cannot be bound: macOS and the BSDs have none
until `ifconfig lo0 alias` adds it, which `test.yml` does for the macOS runners.

## What is where

| Where | What |
| --- | --- |
| `conftest.py` | fixtures only: the autouse network guard and `allow_off_host_destination`, `network_escapes`, `fake_adapters`, `enumerations` |
| `helpers.py` | what tests import: `build_request`, `wait_bound`, `running`, `FixedLeaseServer`, `wait_until`, `await_until`, `LOOPS`, `run_on`, the two probes |
| `cli_process.py`, `command_run.py`, `hook_programs.py` | the command as a process (`run_cli`, `Running`, `free_port`), as a call to `main(argv)` on port 0 (`run_command`), and real hook programs (`alive`, `kill`) |
| `driving.py`, `capture_input.py`, `value_samples.py` | running a role on each loop type and counting threads and tasks; the recorded datagrams a capture reads; one sample value of every codec |
| `integration/` | real sockets on loopback, or the command as a process |
| `conformance/` | the RFC octets (`rfc_vectors.py`), property and fuzz tests of the decoders, recorded real-peer exchanges |
| `interop/` | real DHCP clients and servers in network namespaces (below) |
| `data/` | fixtures: files the code wrote before a change, the capture-output expectations; `-text`, never rewritten to make a test pass |
| the rest of `tests/` | one module per source area |

Unit modules by area:

| Area | Modules |
| --- | --- |
| the message and the wire | `test_message.py`, `test_message_defaults.py`, `test_message_hex.py`, `test_message_mapping.py`, `test_mapping_contract.py`, `test_structured_packet.py`, `test_encode_layout.py`, `test_malformed_packets.py`, `test_truncated_option_containment.py`, `test_decode_errors.py`, `test_property_roundtrip.py`, `test_send_side_checks.py`, `test_rfc_compliance.py` |
| options and codecs | `test_options.py`, `test_options_codes.py`, `test_options_container.py`, `test_options_domain_lists.py`, `test_options_registry.py`, `test_option_types.py`, `test_option_display.py`, `test_domain_name_octets.py`, `test_custom_codec.py`, `test_conversions.py`, `test_value_laws.py` |
| leases | `test_lease_backend.py`, `test_lease_contract.py`, `test_lease_durability.py`, `test_lease_value.py` |
| the listener | `test_listen_grammar.py`, `test_listener_core.py`, `test_listener_listen_specs.py`, `test_listener_apipa_resolution.py`, `test_listener_address_cache.py`, `test_log_limits.py`, `test_network_types.py`, `test_platform_interfaces.py` |
| the roles | `test_server_apipa_not_servable.py`, `test_server_customization.py`, `test_server_extension_contract.py`, `test_server_extension_point.py`, `test_server_malformed_input.py`, `test_server_non_committing_paths.py`, `test_server_offered_state.py`, `test_server_release_and_decline.py`, `test_server_reply_header.py`, `test_server_request_states.py`, `test_server_size_and_expiry.py`, `test_relay.py`, `test_role_cores.py`, `test_constructors.py` |
| capture | `test_capture.py`, `test_capture_payload.py`, `test_capture_writer.py`, `test_dissector.py` |
| the command line and configuration | `test_cli_contract.py`, `test_cli_lease_file.py`, `test_config.py`, `test_extras.py` |
| the package itself | `test_surface.py`, `test_import_structure.py`, `test_type_hints.py`, `test_exceptions.py`, `test_error_messages.py`, `test_permissions.py`, `test_manifest.py`, `test_examples.py`, `test_readme.py`, `test_comments.py`, `test_shipped_headers.py`, `test_private_reach.py`, `test_network_guard.py` |
| benchmarks | `test_benchmarks_options.py`, `test_benchmarks_parse.py`, `test_benchmarks_run.py` |

`integration/`: `test_async.py`, `test_async_backlog.py`, `test_async_client.py`, `test_async_concurrency.py`, `test_async_relay_capture.py`, `test_benchmarks_suites.py`, `test_capture_command_hook.py`, `test_capture_drivers.py`, `test_capture_file.py`, `test_capture_file_output.py`, `test_capture_output.py`, `test_cli.py`, `test_cli_capture_bounds.py`, `test_cli_commands.py`, `test_cli_interrupt.py`, `test_cli_logging.py`, `test_cli_settings.py`, `test_client.py`, `test_documented_commands.py`, `test_dora.py`, `test_examples_run.py`, `test_listen_command.py`, `test_listen_interface.py`, `test_listener_binding.py`, `test_listener_lifecycle.py`, `test_listener_pktinfo_receive.py`, `test_listener_transport.py`, `test_relay_dora.py`, `test_relay_drivers.py`, `test_roles_run_clean.py`, `test_server_drivers.py`, `test_server_reply_ports.py` (as `integration/<name>`).

`conformance/`: `rfc_vectors.py`, `test_decoders_fuzz.py`, `test_decoders_property.py`, `test_liberal_receive.py`, `test_recorded_cases.py`, `test_reserved_values.py`, `test_rfc_vectors.py`, `test_rfc3397_names.py`, `test_rfc4702_client_fqdn.py` (as `conformance/<name>`; `cases/` holds the recorded exchanges).

`interop/`: `conftest.py`, `_lab.py`, `_peers.py`, `_topo.py`, the scenarios `test_addrbound.py`, `test_capture.py`, `test_dhclient_relay.py`, `test_dhclient_server.py`, `test_dnsmasq.py`, `test_full_buffer.py`, `test_listen_interface.py`, `test_reboot_and_nak.py`, `test_two_segments.py`, `test_udhcpc.py`, and the programs they start under `interop/roles/` (`addrbound_listen.py`, `capture.py`, `client_dora.py`, `emit.py`, `full_buffer.py`, `pool_server.py`, `relay.py`, `tap.py`).

## The network guard

An autouse fixture in `conftest.py` refuses a `socket` `sendto`, `connect` or `connect_ex`, a
`netimps` endpoint `send` or `asend` and a name lookup that is not loopback, unspecified or an
address literal. The refusal is recorded and fails the test again at teardown, so code that
swallows the exception cannot hide one. A test that must address something else requests
`allow_off_host_destination` and says why in its docstring; `interop/conftest.py` lifts it for
every real-peer test, which send between namespaces. A limited broadcast (`255.255.255.255`)
is refused: use `127.255.255.255`, after a probe says the host delivers it to a wildcard
socket. `test_network_guard.py` proves what is refused and what passes.

## Loopback rules

- **A test binds port 0** and reads the port back (`bound_addresses`, `wait_bound`); a fixed
  port collides under `WSAEACCES` on Windows. Do not probe a port from the test and then give
  it to the command: the command's bind then fails. Name a `free_port()`, wait for the
  `Bound:` record, give the bind a second.
- **A DORA over loopback passes `broadcast=False`** to `dora()`, `discover_offer()` and
  `build_discover()`: a socket bound to `127.0.0.1` cannot originate a broadcast on POSIX
  (Windows allows it). The server answers a loopback client by unicast, so the reply direction
  needs nothing. **Judge reply delivery on Linux, never on Windows alone.**
- A client or relay on an ephemeral port: set `server.REPLY_TO_CLIENT_PORT` (or
  `REPLY_TO_RELAY_PORT`) on the server, since a reply goes to 68 or 67.
- A test that needs **a real interface** says which properties it needs. A host may list
  `10.255.255.254/32` first (no room in its network, so a pool is refused as off-subnet) or
  transient APIPA adapters that `host_ip_interfaces()` filters and the other enumeration does
  not: `_servable_interface()` of `test_server_customization.py` requires a prefix of at most
  29 bits, `_a_real_interface()` of `test_listener_listen_specs.py` membership in both
  enumerations. Count adapter enumerations with the `enumerations` fixture, listed after any
  fixture that itself enumerates.
- Time is injected (`listener._read_clock`, the clients' `_monotonic`, a stepped backend
  clock); a test that asserts a loop stopped asserts **elapsed time**, because a timer wakes
  the loop at its deadline and a hang looks like a pass.

## Warnings are errors

An unclosed socket, pipe or loop is reported by the garbage collector in whichever later test
it runs in, so the failing test is rarely the leaking one: run with `-X tracemalloc=10` and
read the `ResourceWarning` text. A command interrupted between its bind and its receive loop
leaks the wake socketpair: `command_run.run_command` waits `settle` before it interrupts.

## Private reach

`test_private_reach.py` fails for a statement that reaches an underscored attribute, module,
imported name or patch target with no comment on the line above (or earlier in the same
function with the same reason). A test patches a name where the code reads it
(`pydhcp.cli._server.DHCPServer`, `pydhcp.server._policy._servable_interface`). The seams kept
on purpose are the host's adapters, the `_netimps` and `_net` names in the modules that read
them, `DHCPMessage.decode` raising a non-decode error, the clients' `_wait_for`, `_monotonic`
and `_retransmit_intervals` (no test waits real seconds).

## The real-peer tests

`interop/` runs ISC dhclient, BusyBox udhcpc and dnsmasq against the server, relay, capture
and `DHCPClient`, in network namespaces the tests create and remove (both veth ends are made
inside a namespace, so the default one is untouched, and each test ends by asserting nothing is
left). It needs Linux, root, `ip netns` and the peers; a missing one skips with its reason.

```bash
sudo python -m pytest -q -rs tests/interop
```

`PYDHCP_INTEROP_LOGS=<dir>` keeps each test's process logs and the frames on each segment;
`PYDHCP_RECORD_CASES=1` rewrites `conformance/cases/` (compare the old and new case option by
option, and zero the transaction id before comparing bytes: udhcpc draws a new one each run);
`PYDHCP_INTEROP_REQUIRE=1` (CI) turns a skip into a failure. The baseline is 32 passed with no
expected failure. Traps of the peers: dhclient sends no client identifier by default;
`udhcpc -r` sends a DISCOVER with a requested address, not an INIT-REBOOT; dnsmasq needs
`--no-ping` or each OFFER is delayed by its conflict ping and the client retransmits; an
`ETH_P_IP` packet socket sees only incoming frames (the tap uses `ETH_P_ALL`); a namespace with
an address and no route cannot broadcast from a plain UDP socket, so scripted senders bind to
the device. A capture and a server cannot both bind `*:67` on one host. Run them after any
change to a decode, send, receive, server, relay or client path.

## Writing a test

- It asserts behaviour through the public API, and is seen to fail without the change it covers.
- A codec fix gets the RFC's own wire example as a vector in `conformance/rfc_vectors.py`
  (`pending` makes a direction a strict xfail); a new codec fails
  `test_every_exported_codec_has_a_sample` until `value_samples.py` has one, and
  `test_every_structured_codec_the_registry_binds_has_a_vector` until it has a row.
- Ground truth comes from the wire or the platform, never from the code under test; a fake
  that re-implements the thing proves nothing.
- A test that must run on 3.9 does not use `Path.write_text(newline=)` (3.10 and later):
  `write_bytes`.
- A public name added or removed changes its list in `test_surface.py` in the same commit, and
  its header (`test_shipped_headers.py` names every `__all__` entry, every printed signature and
  every public class constant).
- A comment, docstring or header line states the code as it is: `test_comments.py` fails
  on history wording ("used to", "previously", "no longer", "now") and on a reference to
  anything outside the repository, over `src/`, every shipped header and `pyproject.toml`.
  A phrase that is a fact and not history goes in its `_ALLOWED` list with the reason.
