"""The exception hierarchy: each class's bases, where it lives, and that it
survives a copy and a pickle (multiprocessing and `copy` both rely on it).
"""

from __future__ import annotations

import copy
import pathlib
import pickle

import pytest

import pydhcp
from pydhcp import exceptions
from pydhcp.exceptions import (
    DHCPDecodeError,
    DHCPError,
    DHCPValueError,
    NoClientIdentityError,
)

#: Each class with its direct bases, in declaration order.
_BASES = [
    (DHCPError, (Exception,)),
    (DHCPDecodeError, (DHCPError, ValueError)),
    (DHCPValueError, (DHCPError, ValueError)),
    (NoClientIdentityError, (DHCPError, ValueError)),
]
_IDS = [cls.__name__ for cls, _ in _BASES]


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
def test_each_exception_has_exactly_its_documented_bases(cls, bases) -> None:
    """A dropped builtin co-parent silently breaks every caller's `except`."""
    assert cls.__bases__ == bases


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
def test_every_exception_is_exported_from_the_root(cls, bases) -> None:
    assert getattr(pydhcp, cls.__name__) is cls
    assert cls.__name__ in pydhcp.__all__
    assert cls.__name__ in exceptions.__all__


@pytest.mark.parametrize("cls, bases", _BASES, ids=_IDS)
def test_every_exception_copies_and_pickles(cls, bases) -> None:
    """One constructor shape: a message. It round-trips by value."""
    error = cls("the message")
    for clone in (
        copy.copy(error),
        copy.deepcopy(error),
        pickle.loads(pickle.dumps(error)),
    ):
        assert type(clone) is cls
        assert clone.args == ("the message",)
        assert str(clone) == "the message"


def test_every_exception_class_is_defined_in_one_module() -> None:
    """A class defined elsewhere is a second home for a name the root re-exports."""
    src = pathlib.Path(pydhcp.__file__).parent
    homes = set()
    for path in src.rglob("*.py"):
        for line in path.read_text(encoding="utf-8").splitlines():
            head = line.split("(")[0]
            if line.startswith("class ") and head.endswith("Error"):
                homes.add(path.relative_to(src).as_posix())
    assert homes == {"exceptions.py"}


def test_the_old_name_is_gone() -> None:
    assert not hasattr(pydhcp, "NoClientIdentity")
    assert not hasattr(exceptions, "NoClientIdentity")


def test_a_decode_error_is_a_value_error_and_a_package_error() -> None:
    for catches in (ValueError, DHCPError):
        with pytest.raises(catches):
            pydhcp.DhcpMessage.decode(b"\x00" * 10)
