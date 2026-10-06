"""The `listen` grammar, as a table: every accepted form, every refused one.

The same parser reads the constructors' argument, `pydhcp server --listen`, and
the `listen` key of a JSON, YAML, TOML or INI configuration file, so the table is
run through each of those too.
"""

from __future__ import annotations

import ipaddress
import json
import typing as ty

import netimps
import pytest

from pydhcp import AsyncDHCPListener, DHCPListener, SocketAddress
from pydhcp._config import load_config
from pydhcp.cli import Server, main
from pydhcp.server import DHCPServer

# the listen-argument parser is not public
from pydhcp.listener._spec import _interface_limits, _parselisteners

IPv4 = ipaddress.IPv4Address
DEFAULTS = (67,)


def _addresses(*pairs: "tuple[str, int]") -> "list[SocketAddress]":
    return [SocketAddress(ip, port) for ip, port in pairs]


#: spec -> the addresses it names, with 67 as the default port.
ACCEPTED: "list[tuple[ty.Any, list[SocketAddress]]]" = [
    # nothing, and the wildcard in every spelling
    (None, _addresses(("0.0.0.0", 67))),
    ("*", _addresses(("0.0.0.0", 67))),
    ("0.0.0.0", _addresses(("0.0.0.0", 67))),
    ("*:6767", _addresses(("0.0.0.0", 6767))),
    (":6767", _addresses(("0.0.0.0", 6767))),
    ("0.0.0.0:6767", _addresses(("0.0.0.0", 6767))),
    (IPv4("0.0.0.0"), _addresses(("0.0.0.0", 67))),
    ((None, 6767), _addresses(("0.0.0.0", 6767))),
    (("", 6767), _addresses(("0.0.0.0", 6767))),
    (("*", 6767), _addresses(("0.0.0.0", 6767))),
    ((None, None), _addresses(("0.0.0.0", 67))),
    ([None], _addresses(("0.0.0.0", 67))),
    # text
    ("127.0.0.1", _addresses(("127.0.0.1", 67))),
    ("127.0.0.1:6767", _addresses(("127.0.0.1", 6767))),
    (" 127.0.0.1:6767 ", _addresses(("127.0.0.1", 6767))),
    (
        "127.0.0.1:6767,127.0.0.2:6768",
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    ("127.0.0.1:6767, ,127.0.0.1:6767", _addresses(("127.0.0.1", 6767))),
    ("127.0.0.1:0", _addresses(("127.0.0.1", 0))),
    ("127.0.0.1:65535", _addresses(("127.0.0.1", 65535))),
    # an address object
    (IPv4("127.0.0.1"), _addresses(("127.0.0.1", 67))),
    # a pair, as a tuple and as the list a configuration file delivers
    (("127.0.0.1", 6767), _addresses(("127.0.0.1", 6767))),
    (["127.0.0.1", 6767], _addresses(("127.0.0.1", 6767))),
    (("127.0.0.1", "6767"), _addresses(("127.0.0.1", 6767))),
    (["127.0.0.1", "6767"], _addresses(("127.0.0.1", 6767))),
    ((IPv4("127.0.0.1"), 6767), _addresses(("127.0.0.1", 6767))),
    (("127.0.0.1", None), _addresses(("127.0.0.1", 67))),
    (("127.0.0.1:6767", None), _addresses(("127.0.0.1", 6767))),
    (("127.0.0.1:6767", 6767), _addresses(("127.0.0.1", 6767))),
    (("127.0.0.1", 0), _addresses(("127.0.0.1", 0))),
    # a pair with several ports
    (
        ("127.0.0.1", [6767, 6768]),
        _addresses(("127.0.0.1", 6767), ("127.0.0.1", 6768)),
    ),
    (
        ["127.0.0.1", ["6767", 6768]],
        _addresses(("127.0.0.1", 6767), ("127.0.0.1", 6768)),
    ),
    (("127.0.0.1", (6767,)), _addresses(("127.0.0.1", 6767))),
    # a sequence of bindings, of every kind, in order and without repeats
    (
        [("127.0.0.1", 6767), ("127.0.0.2", 6768)],
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        [["127.0.0.1", 6767], ["127.0.0.2", 6768]],
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        ["127.0.0.1:6767", "127.0.0.2:6768"],
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        ("127.0.0.1:6767", "127.0.0.2:6768"),
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        ["127.0.0.1", "127.0.0.2"],
        _addresses(("127.0.0.1", 67), ("127.0.0.2", 67)),
    ),
    (
        ["127.0.0.1", ["127.0.0.2", 6768], "127.0.0.3:6769,127.0.0.4"],
        _addresses(
            ("127.0.0.1", 67),
            ("127.0.0.2", 6768),
            ("127.0.0.3", 6769),
            ("127.0.0.4", 67),
        ),
    ),
    (
        [("127.0.0.1", 6767), ("127.0.0.1", 6767), "127.0.0.1:6767"],
        _addresses(("127.0.0.1", 6767)),
    ),
]

#: spec -> (the exception class, a word in its message).
REFUSED: "list[tuple[ty.Any, type, str]]" = [
    # names no address
    ("", ValueError, "names no address"),
    ("  ", ValueError, "names no address"),
    (" , ", ValueError, "names no address"),
    ([], ValueError, "names no address"),
    ((), ValueError, "names no address"),
    ([""], ValueError, "names no address"),
    (("127.0.0.1", []), ValueError, "names no port"),
    # a bool or a bare number is not an address, and a bool is not a port
    (True, TypeError, "bool"),
    (6767, TypeError, "int"),
    (6767.0, TypeError, "float"),
    ([6767], TypeError, "int"),
    (("127.0.0.1", True), TypeError, "bool"),
    (("127.0.0.1", False), TypeError, "bool"),
    (["127.0.0.1", True], TypeError, "bool"),
    (("127.0.0.1", 6767.5), TypeError, "float"),
    (b"127.0.0.1", TypeError, "bytes"),
    ({"host": "127.0.0.1"}, TypeError, "dict"),
    (["127.0.0.1", 6767, 1], TypeError, "int"),
    # a port out of range, malformed, or written twice and different
    (("127.0.0.1", 70000), ValueError, "out of range"),
    (("127.0.0.1", -1), ValueError, "out of range"),
    ("127.0.0.1:70000", ValueError, "out of range"),
    ("127.0.0.1:+6767", ValueError, "invalid port"),
    ("127.0.0.1: 6767", ValueError, "invalid port"),
    ("127.0.0.1:8_0", ValueError, "invalid port"),
    ("127.0.0.1:port", ValueError, "invalid port"),
    (("127.0.0.1", "+67"), ValueError, "invalid port"),
    (("127.0.0.1", " 67"), ValueError, "invalid port"),
    (("127.0.0.1", ""), ValueError, "invalid port"),
    (("127.0.0.1:+6767", 67), ValueError, "invalid port"),
    (("127.0.0.1", ["67", 70000]), ValueError, "out of range"),
    (("*:6767", 6868), ValueError, "two ports"),
    (("127.0.0.1:6767", 6868), ValueError, "two ports"),
    # brackets and IPv6 are not IPv4 addresses
    ("[127.0.0.1]:6767", ValueError, "bracketed"),
    ("::", ipaddress.AddressValueError, "Expected 4 octets"),
    ("[::1]:67", ipaddress.AddressValueError, "Expected 4 octets"),
    ("127.0.0.1:67:68", ValueError, "colon"),
]


def _ids(table: "list[ty.Any]") -> "list[str]":
    return [repr(row[0] if isinstance(row, tuple) else row) for row in table]


@pytest.mark.parametrize("spec, expected", ACCEPTED, ids=_ids(ACCEPTED))
def test_an_accepted_form_names_exactly_these_addresses(
    spec: ty.Any, expected: "list[SocketAddress]"
) -> None:
    assert _parselisteners(spec, DEFAULTS, False) == expected


@pytest.mark.parametrize("spec, error, word", REFUSED, ids=_ids(REFUSED))
def test_a_refused_form_is_refused_with_the_right_error(
    spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error) as raised:
        _parselisteners(spec, DEFAULTS, False)
    assert word in str(raised.value), str(raised.value)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
@pytest.mark.parametrize("spec, error, word", REFUSED, ids=_ids(REFUSED))
def test_every_constructor_refuses_what_the_table_refuses(
    driver: type, spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error):
        driver(listen=spec)


@pytest.mark.parametrize("spec, expected", ACCEPTED, ids=_ids(ACCEPTED))
def test_a_constructor_stores_what_the_table_says(
    spec: ty.Any, expected: "list[SocketAddress]"
) -> None:
    listener = DHCPListener(listen=spec)
    stored = listener._listen
    # The default ports of a listener are 67 and 68: one binding per default.
    assert [a for a in stored if a in expected] == [a for a in expected if a in stored]
    assert set(expected) <= set(stored)


def test_the_default_ports_follow_a_binding_without_one() -> None:
    assert DHCPListener(listen="127.0.0.1")._listen == _addresses(
        ("127.0.0.1", 67), ("127.0.0.1", 68)
    )
    assert DHCPListener(listen=None)._listen == _addresses(
        ("0.0.0.0", 67), ("0.0.0.0", 68)
    )


# -- what the forms bind -------------------------------------------------------


@pytest.mark.parametrize(
    "spec",
    [("127.0.0.1", "0"), ["127.0.0.1", 0], ("127.0.0.1", ["0"]), "127.0.0.1:0"],
    ids=repr,
)
def test_a_pair_binds_one_socket_on_that_port(spec: ty.Any) -> None:
    listener = DHCPListener(listen=spec)
    listener.bind()
    try:
        assert len(listener.bound_addresses) == 1
        assert str(listener.bound_addresses[0].ip) == "127.0.0.1"
    finally:
        listener.close()


@pytest.mark.parametrize("spec", [("127.0.0.1", "6767"), ["127.0.0.1", 6767]], ids=repr)
def test_a_text_or_listed_port_is_one_port_not_digits(spec: ty.Any) -> None:
    assert DHCPListener(listen=spec)._listen == _addresses(("127.0.0.1", 6767))


def test_a_refused_spec_binds_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    bound: "list[object]" = []
    monkeypatch.setattr(
        "pydhcp.listener._binding._netimps.bind",
        lambda *a, **k: bound.append(a),
    )
    for spec in [("127.0.0.1", True), "", ["127.0.0.1", 6767.5]]:
        with pytest.raises((TypeError, ValueError)):
            DHCPListener(listen=spec).bind()
    assert bound == []


# -- the command line and the configuration file --------------------------------


class _Recorded(DHCPServer):
    """A real server that opens no socket and records what it would bind."""

    seen: "list[list[SocketAddress]]" = []

    def __enter__(self) -> "_Recorded":
        _Recorded.seen.append(list(self._listen))
        return self

    def serve_forever(self) -> None:
        raise KeyboardInterrupt


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> "list[list[SocketAddress]]":
    _Recorded.seen = []
    monkeypatch.setattr("pydhcp.cli._server.DHCPServer", _Recorded)
    return _Recorded.seen


def _command(listen: ty.Any = None, config: ty.Optional[str] = None) -> Server:
    command = Server()
    command.listen = listen
    command.config = config
    return command


@pytest.mark.parametrize(
    "spec, expected",
    [r for r in ACCEPTED if isinstance(r[0], str)],
    ids=_ids(ACCEPTED[:0] + [r for r in ACCEPTED if isinstance(r[0], str)]),
)
def test_the_listen_flag_reads_the_same_text(
    spec: str, expected: "list[SocketAddress]", recorded: "list[list[SocketAddress]]"
) -> None:
    _command(listen=spec)()
    assert set(expected) <= set(recorded[0])


@pytest.mark.parametrize(
    "spec", [r[0] for r in REFUSED if isinstance(r[0], str)], ids=repr
)
def test_the_listen_flag_refuses_the_same_text(
    spec: str, recorded: "list[list[SocketAddress]]"
) -> None:
    with pytest.raises((TypeError, ValueError)):
        _command(listen=spec)()
    assert recorded == []


def test_an_empty_listen_flag_is_an_error_not_the_wildcard(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    recorded: "list[list[SocketAddress]]",
) -> None:
    monkeypatch.delenv("PYDHCP_TRACEBACK", raising=False)
    monkeypatch.setattr("sys.argv", ["pydhcp", "server", "--listen", ""])
    with pytest.raises(SystemExit) as exit_info:
        main()
    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("pydhcp: error:") and "names no address" in err
    assert "Traceback" not in err
    assert recorded == []


def _write(path: ty.Any, name: str, text: str) -> str:
    target = path / name
    target.write_text(text, encoding="utf-8")
    return str(target)


#: One value of the `listen` key in each file format, and what it must name.
FILES: "list[tuple[str, str, str, list[SocketAddress]]]" = [
    (
        "json",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", 6767]}}),
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "json text port",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", "6767"]}}),
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "json list of pairs",
        "c.json",
        json.dumps({"server": {"listen": [["127.0.0.1", 6767], ["127.0.0.2", 6768]]}}),
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        "json ports",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", [6767, 6768]]}}),
        _addresses(("127.0.0.1", 6767), ("127.0.0.1", 6768)),
    ),
    (
        "json null host",
        "c.json",
        json.dumps({"server": {"listen": [None, 6767]}}),
        _addresses(("0.0.0.0", 6767)),
    ),
    (
        "yaml",
        "c.yaml",
        "server:\n  listen: [127.0.0.1, 6767]\n",
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "yaml text",
        "c.yaml",
        "server:\n  listen: 127.0.0.1:6767\n",
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "yaml block list",
        "c.yaml",
        "server:\n  listen:\n    - 127.0.0.1:6767\n    - [127.0.0.2, 6768]\n",
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
    (
        "toml",
        "c.toml",
        '[server]\nlisten = ["127.0.0.1", 6767]\n',
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "toml text",
        "c.toml",
        '[server]\nlisten = "127.0.0.1:6767"\n',
        _addresses(("127.0.0.1", 6767)),
    ),
    (
        "ini",
        "c.ini",
        "[server]\nlisten = 127.0.0.1:6767,127.0.0.2:6768\n",
        _addresses(("127.0.0.1", 6767), ("127.0.0.2", 6768)),
    ),
]

BAD_FILES: "list[tuple[str, str, str]]" = [
    ("json empty", "c.json", json.dumps({"server": {"listen": ""}})),
    ("json empty list", "c.json", json.dumps({"server": {"listen": []}})),
    (
        "json bool port",
        "c.json",
        json.dumps({"server": {"listen": ["127.0.0.1", True]}}),
    ),
    ("json bare number", "c.json", json.dumps({"server": {"listen": 6767}})),
    ("yaml bool port", "c.yaml", "server:\n  listen: [127.0.0.1, true]\n"),
    ("yaml bare number", "c.yaml", "server:\n  listen: 6767\n"),
    ("yaml empty", "c.yaml", "server:\n  listen: ''\n"),
    ("toml bool port", "c.toml", '[server]\nlisten = ["127.0.0.1", true]\n'),
    ("toml empty", "c.toml", '[server]\nlisten = ""\n'),
    ("toml bad port", "c.toml", '[server]\nlisten = ["127.0.0.1", 70000]\n'),
    ("ini bad port", "c.ini", "[server]\nlisten = 127.0.0.1:+67\n"),
]


def _skip_without_the_format(name: str) -> None:
    if name.endswith(".yaml"):
        pytest.importorskip("yaml")
    if name.endswith(".toml"):
        pytest.importorskip("tomli" if _needs_tomli() else "tomllib")


def _needs_tomli() -> bool:
    import sys

    return sys.version_info < (3, 11)


@pytest.mark.parametrize(
    "label, name, text, expected", FILES, ids=[f[0] for f in FILES]
)
def test_a_configuration_file_listen_reaches_the_listener_as_the_table_says(
    label: str,
    name: str,
    text: str,
    expected: "list[SocketAddress]",
    tmp_path: ty.Any,
    recorded: "list[list[SocketAddress]]",
) -> None:
    _skip_without_the_format(name)
    path = _write(tmp_path, name, text)
    # What the loader returns is what the command hands the constructor.
    assert load_config(path)["server"]["listen"] is not None
    _command(config=path)()
    assert set(expected) <= set(recorded[0])


@pytest.mark.parametrize("label, name, text", BAD_FILES, ids=[f[0] for f in BAD_FILES])
def test_a_configuration_file_with_a_refused_listen_fails_before_binding(
    label: str,
    name: str,
    text: str,
    tmp_path: ty.Any,
    recorded: "list[list[SocketAddress]]",
) -> None:
    _skip_without_the_format(name)
    path = _write(tmp_path, name, text)
    with pytest.raises((TypeError, ValueError)):
        _command(config=path)()
    assert recorded == []


def test_the_flag_beats_a_list_in_the_file(
    tmp_path: ty.Any, recorded: "list[list[SocketAddress]]"
) -> None:
    path = _write(
        tmp_path, "c.json", json.dumps({"server": {"listen": ["127.0.0.1", 6767]}})
    )
    _command(listen="127.0.0.2:6768", config=path)()
    assert recorded[0] == _addresses(("127.0.0.2", 6768))


# -- an interface ----------------------------------------------------------------

MAC = netimps.MACAddress("aa:bb:cc:dd:ee:ff")
ADAPTER = netimps.Interface("aabbccddeeff", 7, mac=None, ips=[])
WILD = SocketAddress("0.0.0.0", 6767)

#: spec -> (the sockets it names, the interfaces each is limited to).
#: Text that is no IPv4 address is read as a MAC, then as an adapter name; a host
#: name is never resolved.
INTERFACES: (
    "list[tuple[ty.Any, list[SocketAddress], dict[SocketAddress, tuple[ty.Any, ...]]]]"
) = [
    # an adapter name, with and without a port
    ("eth1", [SocketAddress("0.0.0.0", 67)], {SocketAddress("0.0.0.0", 67): ("eth1",)}),
    ("eth1:6767", [WILD], {WILD: ("eth1",)}),
    (" eth1:6767 ", [WILD], {WILD: ("eth1",)}),
    ("eth1:0", [SocketAddress("0.0.0.0", 0)], {SocketAddress("0.0.0.0", 0): ("eth1",)}),
    ("Wi-Fi 2:6767", [WILD], {WILD: ("Wi-Fi 2",)}),
    ("vEthernet (WSL):6767", [WILD], {WILD: ("vEthernet (WSL)",)}),
    ("eth0.100:6767", [WILD], {WILD: ("eth0.100",)}),
    ("lo:6767", [WILD], {WILD: ("lo",)}),
    # a name that is also a host name, or looks like one, is still an adapter
    ("localhost:6767", [WILD], {WILD: ("localhost",)}),
    ("example.com:6767", [WILD], {WILD: ("example.com",)}),
    ("1.2.3:6767", [WILD], {WILD: ("1.2.3",)}),
    ("123456:6767", [WILD], {WILD: ("123456",)}),
    # a name with a trailing colon-number is a port: `eth0:1` is eth0 on port 1
    ("eth0:1", [SocketAddress("0.0.0.0", 1)], {SocketAddress("0.0.0.0", 1): ("eth0",)}),
    # a MAC in every spelling, the colon one without a port in text
    (
        "aa:bb:cc:dd:ee:ff",
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (MAC,)},
    ),
    (
        "AA:BB:CC:DD:EE:FF",
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (MAC,)},
    ),
    (
        "aa-bb-cc-dd-ee-ff",
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (MAC,)},
    ),
    ("aa-bb-cc-dd-ee-ff:6767", [WILD], {WILD: (MAC,)}),
    ("AA-BB-CC-DD-EE-FF:6767", [WILD], {WILD: (MAC,)}),
    (
        "aabb.ccdd.eeff",
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (MAC,)},
    ),
    ("aabb.ccdd.eeff:6767", [WILD], {WILD: (MAC,)}),
    ("aa.bb.cc.dd.ee.ff:6767", [WILD], {WILD: (MAC,)}),
    (
        "aabbccddeeff",
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (MAC,)},
    ),
    ("aabbccddeeff:6767", [WILD], {WILD: (MAC,)}),
    # objects
    (MAC, [SocketAddress("0.0.0.0", 67)], {SocketAddress("0.0.0.0", 67): (MAC,)}),
    (
        ADAPTER,
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): (ADAPTER,)},
    ),
    # pairs, as a tuple and as the list a configuration file delivers
    (("eth1", 6767), [WILD], {WILD: ("eth1",)}),
    (["eth1", 6767], [WILD], {WILD: ("eth1",)}),
    (["eth1", "6767"], [WILD], {WILD: ("eth1",)}),
    (("eth1:6767", None), [WILD], {WILD: ("eth1",)}),
    (
        ("eth1", None),
        [SocketAddress("0.0.0.0", 67)],
        {SocketAddress("0.0.0.0", 67): ("eth1",)},
    ),
    (("aa:bb:cc:dd:ee:ff", 6767), [WILD], {WILD: (MAC,)}),
    (["aa:bb:cc:dd:ee:ff", "6767"], [WILD], {WILD: (MAC,)}),
    ((MAC, 6767), [WILD], {WILD: (MAC,)}),
    ((ADAPTER, 6767), [WILD], {WILD: (ADAPTER,)}),
    (
        ("eth1", [6767, 6768]),
        [WILD, SocketAddress("0.0.0.0", 6768)],
        {WILD: ("eth1",), SocketAddress("0.0.0.0", 6768): ("eth1",)},
    ),
    # several interfaces share one socket; the wildcard on that port or an
    # address does not, and a wildcard named plainly has no limit
    ("eth1:6767,eth2:6767", [WILD], {WILD: ("eth1", "eth2")}),
    (["eth1:6767", ("eth2", 6767), (MAC, 6767)], [WILD], {WILD: ("eth1", "eth2", MAC)}),
    (["eth1:6767", "eth1:6767"], [WILD], {WILD: ("eth1",)}),
    (
        "eth1:6767,127.0.0.1:6768",
        [WILD, SocketAddress("127.0.0.1", 6768)],
        {WILD: ("eth1",)},
    ),
    ("eth1:6767,*:6767", [WILD], {}),
    ("*:6767,eth1:6767", [WILD], {}),
    ("0.0.0.0:6767,eth1:6767", [WILD], {}),
    (
        "eth1:6767,eth2:6768",
        [WILD, SocketAddress("0.0.0.0", 6768)],
        {WILD: ("eth1",), SocketAddress("0.0.0.0", 6768): ("eth2",)},
    ),
]

REFUSED_INTERFACES: "list[tuple[ty.Any, type, str]]" = [
    ("eth1:", ValueError, "invalid port"),
    ("eth1:70000", ValueError, "out of range"),
    ("eth1:port", ValueError, "invalid port"),
    ("eth0:1:67", ValueError, "colon"),
    ("aa:bb:cc:dd:ee:ff:67", ValueError, "colon"),
    ("eth/1", ValueError, "not an interface name"),
    ("eth1/24", ValueError, "not an interface name"),
    (("eth1", True), TypeError, "bool"),
    (("eth1", 6767.5), TypeError, "float"),
    (("eth1", 70000), ValueError, "out of range"),
    (("eth1", []), ValueError, "names no port"),
    (("eth1:6767", 6868), ValueError, "two ports"),
    (("aa:bb:cc:dd:ee:ff", True), TypeError, "bool"),
    # an IPv6 address is not an interface
    ("::1", ipaddress.AddressValueError, "Expected 4 octets"),
    ("fe80::1%eth0", ipaddress.AddressValueError, "Expected 4 octets"),
    ("[fe80::1]:67", ipaddress.AddressValueError, "Expected 4 octets"),
]


def _interface_ids(table: "list[ty.Any]") -> "list[str]":
    return [repr(row[0]) for row in table]


@pytest.mark.parametrize(
    "spec, sockets, limits", INTERFACES, ids=_interface_ids(INTERFACES)
)
def test_an_interface_form_names_one_wildcard_socket_limited_to_it(
    spec: ty.Any,
    sockets: "list[SocketAddress]",
    limits: "dict[SocketAddress, tuple[ty.Any, ...]]",
) -> None:
    assert _parselisteners(spec, DEFAULTS, False) == sockets
    assert _interface_limits(spec, DEFAULTS) == limits


@pytest.mark.parametrize(
    "spec, error, word", REFUSED_INTERFACES, ids=_interface_ids(REFUSED_INTERFACES)
)
def test_an_interface_form_that_is_malformed_is_refused(
    spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error) as raised:
        _parselisteners(spec, DEFAULTS, False)
    assert word in str(raised.value), str(raised.value)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
@pytest.mark.parametrize(
    "spec, sockets, limits", INTERFACES, ids=_interface_ids(INTERFACES)
)
def test_every_constructor_reads_an_interface_without_asking_the_host(
    driver: type,
    spec: ty.Any,
    sockets: "list[SocketAddress]",
    limits: "dict[SocketAddress, tuple[ty.Any, ...]]",
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whether the interface exists is checked by `bind()`: a constructor
    performs no I/O."""

    def refuse(*args: ty.Any, **kwargs: ty.Any) -> ty.NoReturn:
        raise AssertionError("the constructor asked the host about its adapters")

    monkeypatch.setattr(netimps, "iter_interfaces", refuse)
    monkeypatch.setattr(netimps, "get_interfaces", refuse)
    listener = driver(listen=spec)
    assert set(sockets) <= set(listener._listen)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
@pytest.mark.parametrize(
    "spec, error, word", REFUSED_INTERFACES, ids=_interface_ids(REFUSED_INTERFACES)
)
def test_every_constructor_refuses_a_malformed_interface(
    driver: type, spec: ty.Any, error: type, word: str
) -> None:
    with pytest.raises(error):
        driver(listen=spec)


@pytest.mark.parametrize("driver", [DHCPListener, AsyncDHCPListener])
def test_an_interface_cannot_be_combined_with_one_socket_per_address(
    driver: type,
) -> None:
    with pytest.raises(ValueError, match="per_interface cannot be combined"):
        driver(listen="eth1", per_interface=True)


def test_an_unknown_interface_is_refused_by_bind_and_binds_nothing() -> None:
    listener = DHCPListener(listen="no-such-adapter-7:0")
    with pytest.raises(ValueError, match="no interface matches 'no-such-adapter-7'"):
        listener.bind()
    assert listener._sockets == [] and listener.bound_addresses == ()


def test_a_host_name_is_an_adapter_name_and_is_never_resolved() -> None:
    """`localhost` resolves, and that is not what `listen` asks: the name is
    looked for among the adapters, and the refusal says what a name is."""
    if any(a.name == "localhost" for a in netimps.get_interfaces()):
        pytest.skip("this host has an adapter named localhost")
    listener = DHCPListener(listen="localhost:0")
    with pytest.raises(ValueError, match="host name is never resolved"):
        listener.bind()
    assert listener._sockets == []


def test_an_interface_is_found_by_name_by_mac_and_as_an_object() -> None:
    adapter = _an_adapter()
    by_name = DHCPListener(listen=f"{adapter.name}:0")
    by_object = DHCPListener(listen=(adapter, 0))
    for listener in (by_name, by_object):
        listener.bind()
        try:
            (socket_,) = listener._sockets
            assert listener._allowed[socket_] >= {adapter.index}
            assert str(listener.bound_addresses[0].ip) == "0.0.0.0"
        finally:
            listener.close()
    if adapter.mac is not None:
        by_mac = DHCPListener(listen=(adapter.mac, 0))
        by_mac.bind()
        try:
            (socket_,) = by_mac._sockets
            assert adapter.index in by_mac._allowed[socket_]
        finally:
            by_mac.close()


def _an_adapter() -> netimps.Interface:
    """An adapter with an index, a MAC, an IPv4 address and a name `listen` can
    spell: none of the characters that mean a port, a network or a MAC."""
    for adapter in netimps.get_interfaces():
        if (
            adapter.index
            and adapter.mac is not None
            and adapter.ipv4
            and ":" not in adapter.name
            and "/" not in adapter.name
            and netimps.MACAddress.try_parse(adapter.name) is None
        ):
            return adapter
    pytest.skip("this host has no adapter with a MAC, an IPv4 address and a plain name")
