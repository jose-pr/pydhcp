"""Every shipped example must at least import.

`examples/dhcpd.py` imported `pydhcp.netutils`, which was renamed to
`pydhcp.network` long before this test existed, so the example a reader is
pointed at failed on its first line. Nothing in the suite touched the examples,
so nothing noticed.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

EXAMPLES = sorted(
    (pathlib.Path(__file__).resolve().parents[1] / "examples").glob("*.py")
)


def test_there_are_examples_to_check():
    """Guards the glob itself: an empty list would make the suite below vacuous."""
    assert EXAMPLES, "no examples found to import"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_imports(path):
    """Import the module body.

    These examples define classes and a `main()` guarded by `__main__`, so
    importing exercises every import and class definition without binding a
    socket. An example that calls `SystemExit` on import is still fine.
    """
    spec = importlib.util.spec_from_file_location(f"_example_{path.stem}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        pass
