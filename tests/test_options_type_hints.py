"""`get_type_hints` works on the option bag (`cli-surface-28`).

`pydhcp/options/__init__.py` does `from .type import *`, and importing that
submodule binds it as the module's global `type` — shadowing the builtin. So a
bare `type[X]` annotation in that file resolves to a *module* at runtime, and
anything that evaluates the annotations fails:

    TypeError: 'module' object is not subscriptable

That is not hypothetical tidiness: `typing.get_type_hints` is what
documentation generators, runtime validators, dependency injectors and
`dataclasses` use. The file already imports `builtins as _builtins` for exactly
this shadowing, and the annotations now use it.
"""

import typing

import pytest

from pydhcp.options import DhcpOptions


@pytest.mark.parametrize("member", ["__init__", "get", "items"])
def test_the_annotations_can_be_evaluated(member) -> None:
    hints = typing.get_type_hints(getattr(DhcpOptions, member))
    assert hints, f"{member} resolved to no hints at all"


def test_the_submodule_really_does_shadow_the_builtin() -> None:
    """The premise, pinned — so nobody 'simplifies' `_builtins.type` back.

    If this ever stops being true (the submodule renamed, or the star-import
    dropped), the qualification becomes unnecessary rather than wrong, and this
    test is where that shows up.
    """
    import pydhcp.options as options_module

    assert options_module.type is not type
    assert options_module.type.__name__ == "pydhcp.options.type"
