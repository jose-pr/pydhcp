"""The lazy option-type registry: load ordering, retry, and who wins.

`DhcpOptionCode.ensure_registered()` imports `options/registry.py` the first
time a codec is looked up. The three properties pinned here are the ones the
obvious implementation does not have, and all three were measured failing:

* the "loaded" flag must not be visible to another thread until the registry
  really is loaded;
* a registry import that *fails* must be retried, not remembered as done;
* a codec the caller registered must not be silently replaced by the built-in
  when the lazy load finally fires.

The last two run in a subprocess on purpose. The registry is a module-level
singleton loaded at most once per interpreter, and by the time this file is
collected pytest has already triggered it -- so a pristine interpreter is the
only place the pre-load window still exists.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import textwrap

import pytest

import pydhcp
import pydhcp.options as _options
import pydhcp.options.registry as _registry
from pydhcp.options import code as _code
from pydhcp.options.code import DhcpOptionCode

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


def test_a_failed_registry_import_is_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    """A registry import that raises must leave the registry un-loaded.

    The flag used to be set *before* the import, so an import that raised --
    a broken third-party codec module, an `ImportError` from a partially
    installed dependency -- left it `True` with `_CODEMAP` still full of the
    `Bytes` placeholder. Nothing ever retried, so every later `get_type()`
    quietly answered `Bytes` for every option in the packet, and the only
    symptom was undecoded payloads.

    `None` in `sys.modules` is CPython's "this import is halted" marker; the
    package attribute has to go too, or `from . import registry` finds the
    already-bound submodule and never consults `sys.modules` at all.
    """
    monkeypatch.setattr(_code, "_REGISTRY_LOADED", False)
    monkeypatch.setattr(_code, "_REGISTRY_LOADING", False)
    monkeypatch.setitem(sys.modules, "pydhcp.options.registry", None)
    monkeypatch.delattr(_options, "registry")

    with pytest.raises(ImportError):
        DhcpOptionCode.ensure_registered()
    assert _code._REGISTRY_LOADED is False, "a failed import was recorded as loaded"
    assert _code._REGISTRY_LOADING is False, "the in-progress guard was not cleared"

    monkeypatch.setitem(sys.modules, "pydhcp.options.registry", _registry)
    monkeypatch.setattr(_options, "registry", _registry, raising=False)
    DhcpOptionCode.ensure_registered()
    assert _code._REGISTRY_LOADED is True, "the retry did not take"


def test_the_loaded_flag_is_not_published_while_the_registry_runs() -> None:
    """Nothing may observe "loaded" until `registry.py` has finished.

    This is the race, made deterministic: every `register_type` call the
    registry makes is a moment when another thread could be inside
    `get_type()`, and at each of them the flag must still be `False`. With the
    flag set first, a concurrent reader was measured getting `Bytes` for a
    code whose real codec was already on its way in.
    """
    out = _run("""
        import sys
        import pydhcp.options as opts
        from pydhcp.options import code as c
        from pydhcp.options.code import DhcpOptionCode

        seen = []
        original = DhcpOptionCode.register_type

        def spy(self, optiontype):
            seen.append(c._REGISTRY_LOADED)
            return original(self, optiontype)

        DhcpOptionCode.register_type = spy
        DhcpOptionCode.ensure_registered()
        print(len(seen), any(seen), c._REGISTRY_LOADED)
        """)
    count, published_early, loaded_after = out.split()
    assert int(count) > 100, "the registry did not run: nothing was registered"
    assert published_early == "False", "the flag was visible while registry.py ran"
    assert loaded_after == "True", "the flag was never set"


def test_a_registration_made_before_the_lazy_load_survives_it() -> None:
    """The caller's codec wins, whenever they registered it.

    `register_type` wrote straight into `_CODEMAP`. A caller who registered
    before anything triggered the lazy load therefore had their codec undone
    by it: the built-in `List[IPv4Address]` was written over their class by
    `registry.py` the moment the first `get_type()` fired, with no error and
    no warning. Registering the built-ins first makes the caller's write the
    later one.
    """
    out = _run("""
        from pydhcp.options import code as c
        from pydhcp.options.code import DhcpOptionCode
        from pydhcp.options.type import Bytes

        class MyDnsCodec(Bytes):
            pass

        assert not c._REGISTRY_LOADED, "the registry loaded too early to test this"
        DhcpOptionCode.DNS.register_type(MyDnsCodec)
        print(DhcpOptionCode.DNS.get_type().__name__)
        """)
    assert out == "MyDnsCodec", f"the lazy load replaced the caller's codec: {out}"


def test_registering_a_non_codec_still_raises_before_anything_is_written() -> None:
    """The type check stays ahead of the registry load and of `_CODEMAP`."""
    before = DhcpOptionCode.DOMAIN_NAME.get_type()
    with pytest.raises(TypeError):
        DhcpOptionCode.DOMAIN_NAME.register_type(int)  # type: ignore[arg-type]
    assert DhcpOptionCode.DOMAIN_NAME.get_type() is before
