"""Where `pydhcp` logs.

One logger per module -- `LOGGER = logging.getLogger(__name__)` -- all of them
children of the package logger `pydhcp`, so an application can turn the whole
library up or down through `logging.getLogger("pydhcp")` and still silence one
noisy module by name.
"""

from __future__ import annotations

import logging as _logging

#: The package logger. Every module logger is a child of it, so setting its
#: level (which is what `pydhcp <cmd> -v` and `--loglevel pydhcp:DEBUG` do)
#: reaches all of them.
LOGGER = _logging.getLogger("pydhcp")

# With no handler anywhere on the chain, `logging.lastResort` prints WARNING and
# above to stderr, onto the console of an embedding application that never
# configured logging. A `NullHandler` stops that (the standard library's
# "Configuring Logging for a Library"); an application sees records once it
# configures a handler, and the command line installs one.
LOGGER.addHandler(_logging.NullHandler())
