"""What a codec refuses to write, and what it says when it does.

Each refusal names the option, the value and the limit; before them the first
two surfaced as `byte must be in range(0, 256)` from `bytearray.append`.
"""

from __future__ import annotations

import pytest

from pydhcp import DHCPOptions, DHCPValueError
from pydhcp.options import (
    ClientIdentifier,
    PCPServerList,
    SIPServers,
    TLVOption,
)


def test_a_sub_option_longer_than_255_octets_is_refused_by_name() -> None:
    with pytest.raises(DHCPValueError, match=r"sub-option 7.*300 octets.*255"):
        TLVOption(7, bytes(300))
    assert len(TLVOption(7, bytes(255)).value) == 255


def test_a_sub_option_code_outside_one_octet_is_refused_by_name() -> None:
    with pytest.raises(DHCPValueError, match=r"sub-option code 300.*0 to 255"):
        TLVOption(300, b"x")
    with pytest.raises(DHCPValueError, match="sub-option code -1"):
        TLVOption(-1, b"x")
    assert TLVOption(255, b"x").code == 255


def test_a_relay_agent_option_names_the_sub_option_that_does_not_fit() -> None:
    options = DHCPOptions()
    with pytest.raises(DHCPValueError, match=r"option 82 .*sub-option 1.*300 octets"):
        options[82] = [(1, bytes(300))]
    assert 82 not in options


def test_a_pcp_entry_of_64_addresses_is_refused_by_name() -> None:
    addresses = [f"10.0.0.{n}" for n in range(1, 65)]
    with pytest.raises(DHCPValueError, match=r"64 addresses.*at most 63"):
        PCPServerList([addresses])
    assert len(PCPServerList([addresses[:63]])[0]) == 63


def test_a_pcp_entry_cannot_be_changed_past_the_checks() -> None:
    """An entry held as a list took `entry.append(...)` in place: a 64th address, or
    text that is no address, which then failed only when the option was packed."""
    servers = PCPServerList(["192.0.2.1"])
    entry = servers[0]
    assert entry == ("192.0.2.1",)
    with pytest.raises(AttributeError):
        entry.append("not an address")  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        entry[0] = "not an address"  # type: ignore[index]
    servers[0] = ["192.0.2.2", "192.0.2.3"]
    assert servers == [("192.0.2.2", "192.0.2.3")]


def test_a_client_identifier_of_one_octet_is_refused_when_written() -> None:
    # RFC 2132 section 9.14: a type octet and at least one more.
    with pytest.raises(DHCPValueError, match=r"ClientIdentifier.*at least 2"):
        ClientIdentifier(b"\x01").pack()
    options = DHCPOptions()
    with pytest.raises(DHCPValueError, match=r"option 61 \(CLIENT_IDENTIFIER\)"):
        options[61] = ClientIdentifier(b"\x01")
    assert 61 not in options
    assert ClientIdentifier(b"\x01\x02").pack() == b"\x01\x02"


def test_a_client_identifier_error_of_the_decoder_is_a_decode_error() -> None:
    from pydhcp import DHCPDecodeError

    with pytest.raises(DHCPDecodeError, match="ClientIdentifier"):
        ClientIdentifier.unpack(b"\x01")


def test_an_empty_sip_server_list_is_refused_when_written() -> None:
    # RFC 3361 section 3: at least one name or address follows the encoding.
    with pytest.raises(DHCPValueError, match=r"SIPServers.*at least one"):
        SIPServers().pack()
    assert SIPServers(["192.0.2.1"]).pack() == b"\x01\xc0\x00\x02\x01"
    assert SIPServers().values == ()  # still constructible, and still decodes
    assert SIPServers.unpack(b"\x01").values == ()
