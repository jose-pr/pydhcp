"""The value-type laws, checked over every option codec.

Each law is a parametrised test over `SAMPLES` (`value_samples.py`), which holds
a value of every class the codec package exports plus the generated list
classes the registry binds. A class added to the package without a sample fails
the completeness test, so a new codec cannot skip the laws.
"""

from __future__ import annotations

import copy
import enum
import ipaddress
import multiprocessing
import pickle
import typing as _ty

import pytest

from helpers import build_request
from pydhcp import DHCPMessage, DHCPOptions, DHCPValueError
from pydhcp.options import DHCPOptionCode
from pydhcp.options import _codecs as codecs
from pydhcp.options._codecs import *  # noqa: F401,F403
from pydhcp.options._codecs import _addresses, _mos, _vendor
from pydhcp.packet import DHCPMessageType
from value_samples import ALT_SPELLINGS, ITEMS, NOT_VALUES, SAMPLES, label, make

IPv4Address = ipaddress.IPv4Address

BUILTIN_BASES = (list, int, str, bytes, ipaddress.IPv4Address, enum.Enum)

ALL = list(SAMPLES)

#: The names a `repr` may use: the package's, the private helper classes a
#: nested value names, and the standard library's address types.
EVAL_NAMESPACE = {
    **vars(_addresses),
    **vars(_mos),
    **vars(_vendor),
    **vars(codecs),
    "DHCPMessageType": DHCPMessageType,
    "DHCPOptionCode": DHCPOptionCode,
    "IPv4Address": IPv4Address,
    "ipaddress": ipaddress,
}


def _records() -> list[type]:
    return [cls for cls in SAMPLES if not issubclass(cls, BUILTIN_BASES)]


def _lists() -> list[type]:
    return [cls for cls in SAMPLES if issubclass(cls, list)]


def test_every_exported_codec_has_a_sample() -> None:
    exported = {name: getattr(codecs, name) for name in codecs.__all__}
    missing = [
        name
        for name, cls in exported.items()
        if name not in NOT_VALUES and cls not in SAMPLES
    ]
    assert missing == []
    assert all(name in exported for name in NOT_VALUES)


def test_every_codec_the_registry_binds_has_a_sample() -> None:
    bound = set()
    for code in DHCPOptionCode:
        try:
            bound.add(code.get_type())
        except Exception:
            continue
    assert [cls for cls in bound if cls not in SAMPLES and cls is not bytes] == []


@pytest.mark.parametrize("cls", ALL, ids=label)
def test_equal_values_are_equal_and_hash_equal(cls: type) -> None:
    first, second = make(cls), make(cls)
    assert first == second
    assert not first != second
    if isinstance(first, list):
        with pytest.raises(TypeError):
            hash(first)
    else:
        assert hash(first) == hash(second)
        assert len({first, second}) == 1
    for spelling in (ALT_SPELLINGS.get(cls),):
        if spelling is not None:
            alt = cls(*spelling)
            assert alt == first
            if not isinstance(first, list):
                assert hash(alt) == hash(first)


@pytest.mark.parametrize(
    "cls", [c for c in ALL if SAMPLES[c][1] is not None], ids=label
)
def test_different_values_are_unequal(cls: type) -> None:
    first, other = make(cls), make(cls, 1)
    assert first != other
    assert not first == other
    assert type(first) is cls and type(other) is cls


@pytest.mark.parametrize("cls", ALL, ids=label)
def test_comparison_with_another_type_does_not_raise_or_match(cls: type) -> None:
    value = make(cls)
    stranger = object()
    assert (value == stranger) is False
    assert (value != stranger) is True
    assert value.__eq__(stranger) is NotImplemented


@pytest.mark.parametrize("cls", _records(), ids=label)
def test_a_record_is_read_only(cls: type) -> None:
    value = make(cls)
    before = hash(value)
    attributes = [
        name
        for name in dir(value)
        if not name.startswith("_") and not callable(getattr(value, name))
    ]
    for name in attributes:
        with pytest.raises(AttributeError):
            setattr(value, name, 1)
        with pytest.raises(AttributeError):
            delattr(value, name)
    with pytest.raises(AttributeError):
        value.invented = 1  # type: ignore[attr-defined]
    assert hash(value) == before


@pytest.mark.parametrize("cls", _records(), ids=label)
def test_a_record_holds_no_list_that_can_change(cls: type) -> None:
    value = make(cls)
    snapshot = copy.deepcopy(value)
    for name in dir(value):
        if name.startswith("_"):
            continue
        held = getattr(value, name)
        if isinstance(held, list):
            for mutate in (
                lambda: held.append(held[0]),
                lambda: held.extend(held),
                lambda: held.insert(0, held[0]),
                lambda: held.pop(),
                lambda: held.__setitem__(0, held[0]),
                lambda: held.__delitem__(0),
                lambda: held.clear(),
                lambda: held.reverse(),
            ):
                with pytest.raises(TypeError):
                    mutate()
    assert value == snapshot
    assert hash(value) == hash(snapshot)


@pytest.mark.parametrize("cls", ALL, ids=label)
def test_repr_is_a_constructor_call_and_evaluates(cls: type) -> None:
    value = make(cls)
    text = repr(value)
    if isinstance(value, enum.Enum):
        assert text == f"{cls.__name__}.{value.name}"
    else:
        assert text.startswith(f"{cls.__name__}(")
        assert text.endswith(")")
    rebuilt = eval(text, dict(EVAL_NAMESPACE))
    assert rebuilt == value
    assert type(rebuilt) is type(value)


def test_repr_never_raises_on_an_empty_or_short_value() -> None:
    for value in (
        ClientIdentifier(b""),
        ClientIdentifier(b"\x01"),
        Bytes(b""),
        String(""),
        DomainList(),
        List[IPv4AddressOption](),
        UserClass(),
        PCPServerList(),
    ):
        assert repr(value).startswith(type(value).__name__)
        assert isinstance(str(value), str)


@pytest.mark.parametrize("cls", ALL, ids=label)
@pytest.mark.parametrize("protocol", range(2, pickle.HIGHEST_PROTOCOL + 1))
def test_a_value_pickles_to_an_equal_value_of_the_same_class(
    cls: type, protocol: int
) -> None:
    value = make(cls)
    again = pickle.loads(pickle.dumps(value, protocol))
    assert again == value
    assert type(again) is type(value)


@pytest.mark.parametrize("cls", ALL, ids=label)
def test_a_value_copies_to_an_equal_value_of_the_same_class(cls: type) -> None:
    value = make(cls)
    for twin in (copy.copy(value), copy.deepcopy(value)):
        assert twin == value
        assert type(twin) is type(value)
    if isinstance(value, list):
        assert copy.copy(value) is not value
        assert copy.deepcopy(value) is not value


def test_the_generated_list_classes_have_a_name_that_reads_and_pickles() -> None:
    generated = List[IPv4AddressOption]
    assert generated.__name__ == "List[IPv4AddressOption]"
    assert generated.__module__ == List.__module__
    assert pickle.loads(pickle.dumps(generated)) is generated
    assert generated is List[IPv4AddressOption]
    assert pickle.loads(pickle.dumps(DHCPOptionCodes[DHCPOptionCode])) is (
        DHCPOptionCodes[DHCPOptionCode]
    )


def test_every_decoded_option_of_a_message_pickles_with_its_bag_and_message() -> None:
    options = DHCPOptions()
    options[DHCPOptionCode.ROUTER] = ["192.0.2.1"]
    options[DHCPOptionCode.CLASSLESS_STATIC_ROUTE] = [("192.0.2.1", "10.0.0.0/8")]
    options[DHCPOptionCode.PARAMETER_REQUEST_LIST] = [1, 3, 6]
    options[DHCPOptionCode.DHCP_MESSAGE_TYPE] = DHCPMessageType.DHCPACK
    for code in (
        DHCPOptionCode.ROUTER,
        DHCPOptionCode.CLASSLESS_STATIC_ROUTE,
        DHCPOptionCode.PARAMETER_REQUEST_LIST,
        DHCPOptionCode.DHCP_MESSAGE_TYPE,
    ):
        decoded = options.get(code)
        assert pickle.loads(pickle.dumps(decoded)) == decoded
        assert copy.deepcopy(decoded) == decoded
    assert pickle.loads(pickle.dumps(options)).encode() == options.encode()
    message = DHCPMessage.decode(build_request(options=options).encode())
    again = pickle.loads(pickle.dumps(message))
    assert again.encode() == message.encode()
    assert again.options.get(DHCPOptionCode.ROUTER) == [IPv4Address("192.0.2.1")]


def test_values_cross_a_process_boundary() -> None:
    values = [make(cls) for cls in ALL]
    context = multiprocessing.get_context("spawn")
    with context.Pool(1) as pool:
        returned = pool.map(copy.deepcopy, values)
    assert returned == values
    assert [type(item) for item in returned] == [type(item) for item in values]


# --- the list codecs -------------------------------------------------------


def _normalised(items: _ty.Iterable[_ty.Any], cls: type) -> bool:
    return all(
        type(cls._normalize(item)) is type(item) and cls._normalize(item) == item  # type: ignore[attr-defined]
        for item in items
    )


@pytest.fixture(params=list(ITEMS), ids=label)
def listing(request: pytest.FixtureRequest) -> tuple[type, _ty.Any, _ty.Any]:
    cls = request.param
    good, bad = ITEMS[cls]
    return cls, good, bad


def test_every_list_codec_is_covered_by_the_mutator_tests() -> None:
    assert set(_lists()) - set(ITEMS) == set()


def test_each_mutator_leaves_only_normalised_items(listing) -> None:  # type: ignore[no-untyped-def]
    cls, good, _bad = listing
    operations: list[_ty.Callable[[_ty.Any], _ty.Any]] = [
        lambda lst: lst.append(good),
        lambda lst: lst.extend([good, good]),
        lambda lst: lst.insert(0, good),
        lambda lst: lst.__iadd__([good]),
        lambda lst: lst.__imul__(2),
        lambda lst: lst.__setitem__(0, good),
        lambda lst: lst.__setitem__(slice(0, 1), [good, good]),
        lambda lst: lst.__setitem__(slice(0, 0), [good]),
        lambda lst: lst.sort(key=repr),
        lambda lst: lst.reverse(),
    ]
    for operation in operations:
        target = make(cls)
        operation(target)
        assert _normalised(target, cls), operation
        assert isinstance(target, cls)


def test_a_bad_item_is_refused_and_leaves_the_list_unchanged(listing) -> None:  # type: ignore[no-untyped-def]
    cls, good, bad = listing
    if bad is None:
        pytest.skip("this codec accepts anything str() accepts")
    refusals = (DHCPValueError, TypeError)
    operations: list[_ty.Callable[[_ty.Any], _ty.Any]] = [
        lambda lst: lst.append(bad),
        lambda lst: lst.extend([good, bad]),
        lambda lst: lst.insert(0, bad),
        lambda lst: lst.__iadd__([good, bad]),
        lambda lst: lst.__setitem__(0, bad),
        lambda lst: lst.__setitem__(slice(0, 1), [good, bad]),
    ]
    for operation in operations:
        target = make(cls)
        before = list(target)
        with pytest.raises(refusals):
            operation(target)
        assert list(target) == before, operation


def test_a_constructor_refuses_a_bad_item_with_the_value_error(listing) -> None:  # type: ignore[no-untyped-def]
    cls, good, bad = listing
    if bad is None:
        pytest.skip("this codec accepts anything str() accepts")
    with pytest.raises((DHCPValueError, TypeError)):
        cls([good, bad])


# --- what stays as it was --------------------------------------------------


def test_the_builtin_subclass_codecs_keep_equality_with_their_builtin() -> None:
    """The recorded exception to "do not subclass a builtin to carry meaning".

    A decoded lease time compares with the number it carries and an address
    with the address it names, so `options.get(51) == 86400` and
    `address in network` work. A change to these makes them fail.
    """
    assert U32(86400) == 86400
    assert String("a") == "a"
    assert Bytes(b"ab") == b"ab"
    assert IPv4AddressOption("192.0.2.1") == IPv4Address("192.0.2.1")
    assert IPv4AddressOption("192.0.2.1") in ipaddress.ip_network("192.0.2.0/24")
    assert Boolean(1) == U8(1)
    options = DHCPOptions()
    options[DHCPOptionCode.IP_ADDRESS_LEASE_TIME] = 86400
    assert options.get(DHCPOptionCode.IP_ADDRESS_LEASE_TIME) == 86400
