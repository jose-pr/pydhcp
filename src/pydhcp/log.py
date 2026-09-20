"""Where `pydhcp` logs.

One logger per module -- `LOGGER = logging.getLogger(__name__)` -- all of them
children of the package logger `pydhcp`, so an application can turn the whole
library up or down through `logging.getLogger("pydhcp")` and still silence one
noisy module by name.
"""

import logging as _logging

#: The package logger. Every module logger is a child of it, so setting its
#: level (which is what `pydhcp <cmd> -v` and `--loglevel pydhcp:DEBUG` do)
#: reaches all of them.
LOGGER = _logging.getLogger("pydhcp")

# A library must not decide where its records go. With no handler anywhere on
# the chain, `logging.lastResort` prints WARNING and above straight to stderr,
# so a warning from deep in the receive path landed on the console of an
# embedding application that had never configured logging. A `NullHandler` is
# the stdlib's answer to exactly this ("Configuring Logging for a Library"),
# and it is a deliberate behaviour change: an embedder relying on that
# `lastResort` output now sees nothing until it configures a handler. The CLI
# is unaffected -- duho installs a real one.
LOGGER.addHandler(_logging.NullHandler())
