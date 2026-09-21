"""Regression tests for the error-message and dead-code nits fixed on this branch.

The point of each assertion is that the exception says *something* a caller can
act on: every site below used to raise a bare `ValueError()` or a context-free
string, which reaches a user as an empty message with only a traceback for
context.
"""

from __future__ import annotations


import pytest

from pydhcp import config
from pydhcp.network import SocketAddress
from pydhcp.options import DhcpOptionCode, DhcpOptions
from pydhcp.options.type import DomainList, OptionOverload
from pydhcp.options.type.base import DhcpOptionCodes
from pydhcp.options.type.ccc import CccProvisioningServerAddress
from pydhcp.options.type.net import IPv4Address
from pydhcp.options.type.scalar import U32
from pydhcp.packet import DhcpMessageType
from pydhcp.packet import message as _message
from pydhcp.packet import structured


def _message_of(exc: pytest.ExceptionInfo[BaseException]) -> str:
    return str(exc.value)


def test_socket_address_without_a_port_explains_itself() -> None:
    with pytest.raises(ValueError) as exc:
        SocketAddress("127.0.0.1")
    assert "port" in _message_of(exc)


def test_option_code_over_one_octet_names_the_value() -> None:
    # Reached only through a codemap whose constructor rejects the value:
    # `DhcpOptionCode(256)` raises, so `_normalize` falls through to the
    # one-octet range check. Measured, not assumed -- a `DhcpOptionCodes[int]`
    # returns early on `isinstance(256, int)` and never reaches the branch.
    DhcpOptionCode.ensure_registered()
    codes = DhcpOptionCodes[DhcpOptionCode]  # type: ignore[index]
    with pytest.raises(ValueError) as exc:
        codes._normalize(256)
    assert "256" in _message_of(exc)


def test_domain_list_reserved_length_prefix_names_the_octet() -> None:
    # 0x80 sets one high bit: neither a label (00) nor a pointer (11).
    with pytest.raises(ValueError) as exc:
        DomainList._dhcp_decode(bytes([0x80, 0x00]))
    assert "0x80" in _message_of(exc)


def test_fixed_length_integer_names_its_width() -> None:
    with pytest.raises(ValueError) as exc:
        U32._dhcp_read(memoryview(bytes(2)))
    assert "4" in _message_of(exc) and "2" in _message_of(exc)


def test_option_overload_empty_payload_is_described() -> None:
    with pytest.raises(ValueError) as exc:
        OptionOverload._dhcp_read(memoryview(b""))
    assert _message_of(exc).strip() != ""


def test_message_type_empty_payload_is_described() -> None:
    with pytest.raises(ValueError) as exc:
        DhcpMessageType._dhcp_read(memoryview(b""))
    assert _message_of(exc).strip() != ""


def test_wrong_option_size_names_the_codec_and_both_lengths() -> None:
    # Was the context-free "Wrong option size".
    with pytest.raises(ValueError) as exc:
        U32._dhcp_decode(bytes(3))
    text = _message_of(exc)
    assert "U32" in text and "4" in text and "3" in text


def test_trailing_octets_message_is_spelled_correctly() -> None:
    # Was the misspelled "Couldnt decode whole option".
    with pytest.raises(ValueError) as exc:
        IPv4Address._dhcp_decode(bytes(5))
    text = _message_of(exc)
    assert "Couldnt" not in text
    assert "IPv4Address" in text


@pytest.mark.parametrize(
    "kwargs, needle, offender",
    [
        ({"word_size": 0}, "word size", "0"),
        ({"word_size": -1}, "word size", "-1"),
        ({"maxsize": 3}, "max size", "3"),
    ],
)
def test_partial_encode_errors_name_the_offending_value(
    kwargs: dict[str, object], needle: str, offender: str
) -> None:
    # Both sites were placeholder-free f-strings ("Invalid Options Word Size"),
    # which named the condition but never the value that tripped it.
    options = DhcpOptions()
    call = {"maxsize": 576, "word_size": 1}
    call.update(kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError) as exc:
        options.partial_encode(**call)  # type: ignore[arg-type]
    text = _message_of(exc)
    assert needle in text.lower()
    assert offender in text


def test_ccc_address_narrows_its_except_to_valueerror() -> None:
    # A non-address string is still classified as an FQDN...
    assert CccProvisioningServerAddress("boot.example.com").kind == "fqdn"
    assert CccProvisioningServerAddress("10.0.0.1").kind == "ipv4"

    # ...but a non-ValueError raised inside the try must propagate rather than
    # being silently reclassified. A bare `except Exception` swallowed it.
    def _explode(_value: object) -> object:
        raise RuntimeError("codec defect")

    import pydhcp.options.type.ccc as ccc

    original = ccc.IPv4Address
    ccc.IPv4Address = _explode  # type: ignore[assignment]
    try:
        with pytest.raises(RuntimeError, match="codec defect"):
            CccProvisioningServerAddress("boot.example.com")
    finally:
        ccc.IPv4Address = original  # type: ignore[assignment]


def test_dead_helpers_are_gone() -> None:
    assert not hasattr(_message, "_decode_option_value")
    assert not hasattr(structured, "_StructuredFormat")


def test_toml_guard_lives_in_one_place() -> None:
    """`structured` sources its TOML probes from `config`, not its own ladder."""
    assert structured._tomllib is config._tomllib or (
        structured._tomllib is None and config._tomllib is None
    )
    assert config._import_toml_reader() is structured._tomllib
    assert config._import_toml_writer() is structured._tomli_w


@pytest.mark.parametrize(
    "factory_name, needle",
    [
        ("_toml_reader_unavailable", "tomli"),
        ("_toml_writer_unavailable", "tomli-w"),
    ],
)
def test_toml_unavailable_messages_are_built_from_one_template(
    factory_name: str, needle: str
) -> None:
    factory = getattr(config, factory_name)
    error = factory("TOML thing", "INI")
    assert isinstance(error, NotImplementedError)
    text = str(error)
    assert text.startswith("TOML thing requires")
    assert needle in text
    assert "use INI as a stdlib fallback" in text
