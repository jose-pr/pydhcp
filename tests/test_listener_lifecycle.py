"""Stopping a listener has to actually let go of things.

`tests-6` (`close()` was reachable only from `__exit__`, so `stop()` leaked
every socket), `tests-5` (the receive thread was non-daemon, so a process that
forgot to stop hung instead of exiting), `transport-33` (a handler's `stop()`
was ignored for the rest of the ready set) and `transport-27` (`wait()` read
`_cancellation_token` twice per turn while the receive thread was nulling it).
"""

from __future__ import annotations

import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time

import pytest

from conftest import LOOPBACK_ALIAS_BINDABLE, build_request, running, wait_bound
from pydhcp.listener import DhcpListener

# --- tests-6: the receive loop releases its sockets ---


def test_the_receive_loop_closes_its_sockets_on_the_way_out() -> None:
    """`close()` was called only from `__exit__`; `listen()`'s `finally` just
    nulled the cancellation token. Measured across three test modules before
    the fix: 7 sockets still open at the end of the session, every one of them
    holding a UDP port a later bind could not have."""
    listener = DhcpListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    thread = listener.start()
    assert thread is not None
    wait_bound(listener)
    # The private list on purpose: the claim is that the OS sockets were
    # closed, and `bound_addresses` can only report that they stopped being
    # listed -- which is also what a leak that merely cleared the list looks
    # like.
    sockets = list(listener._sockets)
    assert sockets

    listener.stop()
    thread.join(5)
    assert not thread.is_alive()

    for sock in sockets:
        assert sock.fileno() == -1, "the receive loop left a socket open"
    assert listener.bound_addresses == ()
    listener.close()


def test_a_closed_listener_can_be_started_again() -> None:
    """Closing on the way out must not make the listener single-use."""
    listener = DhcpListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    with running(listener):
        first = listener.bound_addresses[0]
    assert listener.bound_addresses == ()

    with running(listener):
        assert listener.bound_addresses
        assert listener.bound_addresses[0].ip == first.ip


def test_the_receive_thread_does_not_strand_the_sigint_handler() -> None:
    """The other half of `tests-6`.

    `listen()`'s teardown now runs on the receive thread, and `signal.signal`
    raises off the main thread -- so a naive `close()` there would fail the
    restore *and* clear the bookkeeping, leaving the process-wide handler
    pointing at a listener that is no longer listening and no later `close()`
    able to give it back. Ctrl-C would then be swallowed by a dead listener.
    """
    original = signal.getsignal(signal.SIGINT)
    listener = DhcpListener(listen=("127.0.0.1", 0), select_timeout=0.05)
    thread = listener.start()
    assert thread is not None
    installed = signal.getsignal(signal.SIGINT)
    assert installed is not original

    listener.stop()
    thread.join(5)
    assert not thread.is_alive()
    # Still installed, and still restorable: the receive thread deliberately
    # left it alone rather than failing the swap and forgetting about it.
    assert signal.getsignal(signal.SIGINT) is installed
    assert listener._sigint_handler is installed

    listener.close()
    assert signal.getsignal(signal.SIGINT) is original


# --- tests-5: a forgotten listener must not hold the process open ---

_FORGETFUL = """
import sys
sys.path.insert(0, {src!r})
from pydhcp.listener import DhcpListener

listener = DhcpListener(listen=("127.0.0.1", 0), select_timeout=0.05)
listener.start()
print("started", flush=True)
"""


def test_a_started_listener_does_not_keep_the_process_alive() -> None:
    """Measured before the fix: this process was still running after 8 s and
    had to be killed. The receive loop never ends on its own, so a non-daemon
    thread running it is an interpreter that never exits."""
    source = textwrap.dedent(_FORGETFUL).format(src=str(_src_dir()))
    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, "-c", source],
        capture_output=True,
        text=True,
        # Generous on purpose. The defect was a process that never exits, so
        # `TimeoutExpired` here IS the assertion -- an unbounded hang is caught
        # by any bound. A tight one would instead measure how loaded the
        # machine is, which is not the property under test and which failed
        # this suite once on a box running three other pytest runs.
        timeout=60,
    )
    elapsed = time.monotonic() - started

    assert "started" in completed.stdout
    assert completed.returncode == 0, completed.stderr
    # Reported, not asserted: see the timeout note above. The pass/fail signal
    # is "did it exit at all", and `subprocess.run` already provides it.
    print(f"forgetful listener process exited in {elapsed:.1f}s")


def _src_dir():
    import pydhcp
    import pathlib

    return pathlib.Path(pydhcp.__file__).resolve().parent.parent


# --- transport-33: a handler's stop() ends the turn, not just the loop ---


class StoppingListener(DhcpListener):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.handled = 0

    def handle(self, msg, context) -> None:
        self.handled += 1
        self.stop()


@pytest.mark.skipif(
    not LOOPBACK_ALIAS_BINDABLE,
    reason="needs three loopback addresses; macOS aliases only 127.0.0.1",
)
def test_a_handler_that_stops_is_not_called_again_in_the_same_turn() -> None:
    """`for socket in rlist:` had no cancellation check, so every socket that
    was already readable in the same `select()` was still serviced after the
    handler asked to stop. Measured: `capture --count 1` wrote 3 records in 3
    of 3 trials, on a wildcard bind whose three sockets went ready together.

    Three *distinct* local addresses are the point -- one select() must report
    several sockets ready at once -- so this cannot fall back to three ports on
    127.0.0.1, and it is skipped where the loopback has no aliases.
    """
    listener = StoppingListener(
        listen=[("127.0.0.1", 0), ("127.0.0.2", 0), ("127.0.0.3", 0)],
        select_timeout=0.05,
    )
    listener.bind()
    ports = [(str(a.ip), a.port) for a in listener.bound_addresses]
    assert len(ports) == 3

    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = build_request().encode()
    for address in ports:
        sender.sendto(payload, address)
    sender.close()
    # Give all three datagrams time to land, so one select() reports all three
    # sockets ready -- which is the condition the defect needs.
    time.sleep(0.3)

    thread = threading.Thread(target=listener.listen, daemon=True)
    thread.start()
    thread.join(5)
    assert not thread.is_alive()

    assert listener.handled == 1, "kept draining the ready set after stop()"


# --- transport-27: wait() reads the token once per turn ---


class _VanishingToken(DhcpListener):
    """A listener whose token disappears between two reads.

    The real window is the receive thread executing `listen()`'s
    `finally: self._cancellation_token = None` between `wait()`'s `is not
    None` test and its `.wait()` call -- microseconds wide and not reliably
    reproducible by timing. Making the attribute itself vanish on the second
    read reproduces it every time.
    """

    _reads = 0

    @property
    def _cancellation_token(self):
        type(self)._reads += 1
        return self._token if type(self)._reads == 1 else None

    @_cancellation_token.setter
    def _cancellation_token(self, value) -> None:
        self._token = value


def test_wait_survives_the_token_being_nulled_underneath_it() -> None:
    """Old: `AttributeError: 'NoneType' object has no attribute 'wait'`, out of
    the one call whose entire job is to block until shutdown."""
    listener = _VanishingToken(listen=("127.0.0.1", 0), select_timeout=0.01)
    listener._token = threading.Event()
    type(listener)._reads = 0

    listener.wait()  # must return, not raise

    assert type(listener)._reads >= 2, "the second read never happened"
