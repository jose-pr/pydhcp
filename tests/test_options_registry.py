"""The option-type registry: loaded with the options package, and who wins.

Importing `pydhcp.options._codes` binds every standard option code to its
codec, so no lookup depends on an earlier call. A codec the caller registers
afterwards replaces the built-in one.

The load-at-import test runs in a subprocess on purpose: by the time this file
is collected the registry has long been imported, so a pristine interpreter is
the only place "nothing else imported it first" can be observed.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap

import pytest

import pydhcp
from pydhcp.options import Bytes, DHCPOptionCode

#: The tree under test, so a subprocess imports the same one pytest did rather
#: than whatever an editable install happens to point at.
SRC = str(pathlib.Path(pydhcp.__file__).resolve().parent.parent)


def _run(script: str) -> str:
    env = dict(os.environ, PYTHONPATH=SRC)
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def test_every_standard_code_is_bound_the_moment_the_package_is_imported() -> None:
    """No call but the import makes the registry load.

    The codec table is read directly, with no lookup in between: a lookup that
    loads the registry would hide a registry that is not loaded yet.
    """
    out = _run("""
        import pydhcp.options._codes as codes
        from pydhcp.options import Bytes

        bound = sum(1 for codec in codes._CODEMAP if codec is not Bytes)
        print(codes._CODEMAP[6] is not Bytes, bound > 100)
        """)
    assert out == "True True", out


def test_a_registration_made_after_import_replaces_the_built_in_codec() -> None:
    class MyDnsCodec(Bytes):
        pass

    original = DHCPOptionCode.DNS.get_type()
    try:
        DHCPOptionCode.DNS.register_type(MyDnsCodec)
        assert DHCPOptionCode.DNS.get_type() is MyDnsCodec
    finally:
        DHCPOptionCode.DNS.register_type(original)


def test_registering_a_non_codec_still_raises_before_anything_is_written() -> None:
    """The type check stays ahead of the registry load and of `_CODEMAP`."""
    before = DHCPOptionCode.DOMAIN_NAME.get_type()
    with pytest.raises(TypeError):
        DHCPOptionCode.DOMAIN_NAME.register_type(int)  # type: ignore[arg-type]
    assert DHCPOptionCode.DOMAIN_NAME.get_type() is before
