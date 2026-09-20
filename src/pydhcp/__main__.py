"""Entry point for `python -m pydhcp`.

The console script installed by `[project.scripts]` is the usual way in, but it
is only on PATH after an install. `python -m` works from a source checkout, in a
container without the scripts directory on PATH, and when several interpreters
are present and the choice has to be explicit -- which is exactly when someone
is debugging and least wants a second problem.
"""

from .cli import main

if __name__ == "__main__":
    main()
