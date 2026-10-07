"""Run a listening command in this process, from an argument vector, and stop it.

`pydhcp.cli.main(argv)` is the entry point a console script calls. A command that
listens blocks until it is interrupted, which is what Ctrl-C does to it: the
helper waits for the command's own `Bound: ...` records (the state the caller
needs), runs what the test wants done while it is serving, and then interrupts
the main thread the way a terminal would. Nothing of the project is replaced.
"""

from __future__ import annotations

import _thread
import logging
import select
import threading
import typing as _ty

from pydhcp.cli import main


class Ran(_ty.NamedTuple):
    status: int
    #: The messages the command logged, in order.
    records: "list[str]"
    #: The addresses of its `Bound: ...` records, in order.
    bound: "list[str]"
    #: What `during` returned, or the exception it raised.
    result: _ty.Any


class _Collector(logging.Handler):
    def __init__(self, want: int, ready: threading.Event) -> None:
        super().__init__(logging.DEBUG)
        self.records: "list[str]" = []
        self.bound: "list[str]" = []
        self._want = want
        self._ready = ready

    def emit(self, record: logging.LogRecord) -> None:
        text = record.getMessage()
        self.records.append(text)
        if text.startswith("Bound"):
            self.bound.append(text.split(": ", 1)[1])
            if len(self.bound) >= self._want:
                self._ready.set()


def run_command(
    argv: "_ty.Sequence[str]",
    *,
    bound: int = 1,
    during: "_ty.Optional[_ty.Callable[[list[str]], _ty.Any]]" = None,
    ends: bool = False,
    timeout: float = 30.0,
) -> Ran:
    """`main(argv)`, interrupted once it has logged `bound` bound addresses.

    `during(addresses)` runs on another thread after that and before the
    interrupt, unless `ends`: the command is expected to end by itself (a
    `--count`), and is interrupted only after `timeout` seconds so that a
    command that does not end fails the test instead of hanging it. A command
    that ends by itself (a refused argument, a failed bind)
    returns without ever being interrupted. `argv` carries `-v`, so the
    records are logged at all.

    The `Bound` record is the last thing the command logs before it receives.
    The interrupt waits for the receive loop's first `select.select()` as well,
    so it lands in a command that is receiving and not in the instructions of
    start-up, where a Ctrl-C is handled too but is not what these tests are
    about. A test that needs the command serving sends it a datagram in
    `during` and waits for what that causes.
    """
    ready = threading.Event()
    waiting = threading.Event()
    finished = threading.Event()
    real_select = select.select

    def announcing_select(*args: _ty.Any, **kwargs: _ty.Any) -> _ty.Any:
        waiting.set()
        return real_select(*args, **kwargs)

    collector = _Collector(bound, ready)
    outcome: "dict[str, _ty.Any]" = {}

    def interrupter() -> None:
        waited = 0.0
        while not ((ready.wait(0.05) and waiting.wait(0.05)) or finished.is_set()):
            waited += 0.05
            if waited >= timeout:  # never bound as many as asked: end it, and fail
                _thread.interrupt_main()
                return
        if finished.is_set():
            return
        try:
            if during is not None:
                outcome["result"] = during(list(collector.bound))
        except BaseException as error:  # reported to the test, not lost here
            outcome["result"] = error
        if ends and finished.wait(timeout):
            return
        if not finished.is_set():
            _thread.interrupt_main()

    watcher = threading.Thread(target=interrupter, daemon=True)
    logger = logging.getLogger("pydhcp")
    logger.addHandler(collector)
    select.select = announcing_select
    watcher.start()
    status = None
    try:
        status = main(list(argv))
    finally:
        select.select = real_select
        finished.set()
        # An interrupt already on its way lands here, not in the test.
        while True:
            try:
                watcher.join(timeout)
                break
            except KeyboardInterrupt:
                continue
        logger.removeHandler(collector)
    assert status is not None
    return Ran(status, collector.records, collector.bound, outcome.get("result"))
