"""A throwaway network lab: namespaces, veth pairs, processes and recorded frames.

Everything the interoperability tests do to the network happens inside network
namespaces this module creates and removes. Both ends of every veth pair are
created directly in a namespace, so the default namespace never holds an
interface, an address, a route or a firewall rule of the lab's. `Lab.close()`
runs on every exit path: it stops every process the lab started, deletes every
namespace, and asserts that nothing is left.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import secrets
import shutil
import signal
import subprocess
import sys
import time
import typing as _ty

HERE = pathlib.Path(__file__).resolve().parent
ROLES = HERE / "roles"
SRC = HERE.parents[1] / "src"

_SBIN = "/usr/sbin:/sbin:/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"


def which(name: str) -> _ty.Optional[str]:
    """Locate a program, including the system directories sudo may drop."""
    return shutil.which(name, path=os.environ.get("PATH", "") + os.pathsep + _SBIN)


def unavailable() -> _ty.Optional[str]:
    """Why the lab cannot run here, or None when it can."""
    if not sys.platform.startswith("linux"):
        return "network namespaces need Linux"
    if os.geteuid() != 0:
        return "needs root (run the tests under sudo)"
    ip = which("ip")
    if ip is None:
        return "the `ip` program is not installed"
    probe = "pdi-probe-" + secrets.token_hex(3)
    try:
        made = subprocess.run([ip, "netns", "add", probe], capture_output=True)
    except OSError as error:
        return f"cannot run `ip netns`: {error}"
    if made.returncode != 0:
        return (
            "`ip netns add` is refused: " + made.stderr.decode(errors="replace").strip()
        )
    subprocess.run([ip, "netns", "del", probe], capture_output=True)
    return None


def _links() -> _ty.List[str]:
    out = subprocess.run(
        [which("ip") or "ip", "-o", "link", "show"], capture_output=True, text=True
    ).stdout
    return sorted(line.split(":")[1].strip().split("@")[0] for line in out.splitlines())


def _resolv_digest() -> str:
    try:
        return hashlib.sha256(pathlib.Path("/etc/resolv.conf").read_bytes()).hexdigest()
    except OSError:
        return "absent"


class Proc:
    """A process the lab started: its own session, its output in a file."""

    def __init__(self, popen: "subprocess.Popen[bytes]", log: pathlib.Path) -> None:
        self.popen = popen
        self.log = log

    def text(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")

    def alive(self) -> bool:
        return self.popen.poll() is None

    def wait_for_text(self, text: str, timeout: float = 15) -> bool:
        """Wait until the process has printed `text`; False if it exits or times out."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if text in self.text():
                return True
            if not self.alive():
                return text in self.text()
            time.sleep(0.05)
        return text in self.text()

    def stop(self, wait: float = 3.0) -> None:
        if self.popen.poll() is None:
            try:
                os.killpg(self.popen.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.popen.wait(wait)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.popen.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.popen.wait(5)


class Frame(_ty.NamedTuple):
    """One UDP datagram on port 67 or 68 as it crossed a segment."""

    seq: int
    kind: str  # host | broadcast | multicast | otherhost | outgoing
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    sport: int
    dport: int
    payload: bytes

    def message(self) -> _ty.Any:
        from pydhcp import DHCPMessage

        return DHCPMessage.decode(self.payload)

    def type_name(self) -> str:
        from pydhcp.options import DHCPOptionCode

        value = self.message().options.get(DHCPOptionCode.DHCP_MESSAGE_TYPE)
        return getattr(value, "name", str(value))


class Tap:
    """Frames seen on one interface, written by a process inside its namespace."""

    def __init__(self, proc: Proc, out: pathlib.Path, label: str) -> None:
        self.proc = proc
        self.out = out
        self.label = label

    def frames(self) -> _ty.List[Frame]:
        if not self.out.exists():
            return []
        found = []
        for line in self.out.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            item["payload"] = bytes.fromhex(item["payload"])
            found.append(Frame(**item))
        return found

    def of_type(self, name: str) -> _ty.List[Frame]:
        return [f for f in self.frames() if f.type_name() == name]

    def wait_for(
        self, predicate: _ty.Callable[[_ty.List[Frame]], bool], timeout: float
    ) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate(self.frames()):
                return True
            time.sleep(0.1)
        return predicate(self.frames())


class Lab:
    """Namespaces, links and processes, all removed by `close()`."""

    def __init__(self, workdir: pathlib.Path) -> None:
        self.ip = which("ip") or "ip"
        self.work = workdir
        self.work.mkdir(parents=True, exist_ok=True)
        self.tag = "pdi-" + secrets.token_hex(3)
        self.namespaces: _ty.List[str] = []
        self.procs: _ty.List[Proc] = []
        self._links_before = _links()
        self._resolv_before = _resolv_digest()
        self._counter = 0
        self.closed = False

    # -- topology ---------------------------------------------------------

    def netns(self, role: str) -> str:
        name = f"{self.tag}-{role}"
        self._run([self.ip, "netns", "add", name])
        self.namespaces.append(name)
        self.run(name, [self.ip, "link", "set", "lo", "up"])
        self.run(
            name,
            [
                which("sysctl") or "sysctl",
                "-q",
                "-w",
                "net.ipv4.conf.all.rp_filter=0",
                "net.ipv4.conf.default.rp_filter=0",
            ],
            check=False,
        )
        return name

    def veth(
        self,
        ns1: str,
        if1: str,
        ns2: str,
        if2: str,
        *,
        mac1: str,
        mac2: str,
        addr1: _ty.Optional[str] = None,
        addr2: _ty.Optional[str] = None,
    ) -> None:
        self._run(
            [
                self.ip,
                "link",
                "add",
                if1,
                "netns",
                ns1,
                "address",
                mac1,
                "type",
                "veth",
                "peer",
                "name",
                if2,
                "netns",
                ns2,
                "address",
                mac2,
            ]
        )
        for ns, iface, addr in ((ns1, if1, addr1), (ns2, if2, addr2)):
            if addr:
                self.run(ns, [self.ip, "addr", "add", addr, "dev", iface])
            self.run(ns, [self.ip, "link", "set", iface, "up"])
            self.run(
                ns,
                [
                    which("sysctl") or "sysctl",
                    "-q",
                    "-w",
                    f"net.ipv4.conf.{iface}.rp_filter=0",
                ],
                check=False,
            )

    def route(self, ns: str, *args: str) -> None:
        self.run(ns, [self.ip, "route", "add", *args])

    # -- running things ---------------------------------------------------

    @staticmethod
    def _run(argv: _ty.Sequence[str]) -> "subprocess.CompletedProcess[str]":
        done = subprocess.run(list(argv), capture_output=True, text=True)
        if done.returncode != 0:
            raise RuntimeError(f"{' '.join(argv)}: {done.stderr.strip()}")
        return done

    def run(
        self,
        ns: str,
        argv: _ty.Sequence[str],
        *,
        check: bool = True,
        timeout: float = 30,
    ) -> "subprocess.CompletedProcess[str]":
        done = subprocess.run(
            [self.ip, "netns", "exec", ns, *argv],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if check and done.returncode != 0:
            raise RuntimeError(f"[{ns}] {' '.join(argv)}: {done.stderr.strip()}")
        return done

    def spawn(
        self,
        ns: str,
        argv: _ty.Sequence[str],
        name: str,
        env: _ty.Optional[_ty.Dict[str, str]] = None,
    ) -> Proc:
        self._counter += 1
        log = self.work / f"{self._counter:02d}-{name}.log"
        handle = open(log, "wb")
        merged = dict(os.environ)
        merged["PYTHONPATH"] = str(SRC) + os.pathsep + merged.get("PYTHONPATH", "")
        merged["PYTHONUNBUFFERED"] = "1"
        merged["PYTHONDONTWRITEBYTECODE"] = "1"
        if env:
            merged.update(env)
        popen = subprocess.Popen(
            [self.ip, "netns", "exec", ns, *argv],
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            env=merged,
            cwd=str(self.work),
        )
        handle.close()
        proc = Proc(popen, log)
        self.procs.append(proc)
        return proc

    def python(
        self, ns: str, role: str, *args: str, name: _ty.Optional[str] = None
    ) -> Proc:
        """Start a role script from `roles/` inside `ns`."""
        return self.spawn(
            ns, [sys.executable, str(ROLES / role), *args], name or role.split(".")[0]
        )

    def python_wait(self, ns: str, role: str, *args: str, timeout: float = 30) -> str:
        """Run a role script to completion and return its output."""
        proc = self.python(ns, role, *args)
        try:
            proc.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            proc.stop()
            raise
        return proc.text()

    def tap(self, ns: str, iface: str, label: str) -> Tap:
        out = self.work / f"tap-{label}.jsonl"
        ready = self.work / f"tap-{label}.ready"
        proc = self.python(
            ns, "tap.py", iface, str(out), str(ready), name=f"tap-{label}"
        )
        end = time.monotonic() + 10
        while not ready.exists():
            if time.monotonic() > end or not proc.alive():
                raise RuntimeError(f"tap {label} did not start: {proc.text()}")
            time.sleep(0.05)
        return Tap(proc, out, label)

    def wait_file(self, path: pathlib.Path, timeout: float = 15) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if path.exists():
                return True
            time.sleep(0.05)
        return path.exists()

    # -- tear-down --------------------------------------------------------

    def close(self) -> None:
        """Stop every process, delete every namespace, assert nothing is left."""
        if self.closed:
            return
        self.closed = True
        for proc in reversed(self.procs):
            proc.stop()
        leftovers = []
        for ns in reversed(self.namespaces):
            subprocess.run([self.ip, "netns", "del", ns], capture_output=True)
        listed = subprocess.run(
            [self.ip, "netns", "list"], capture_output=True, text=True
        ).stdout
        leftovers += [ns for ns in self.namespaces if ns in listed]
        after = _links()
        problems = []
        if leftovers:
            problems.append(f"namespaces left behind: {leftovers}")
        if after != self._links_before:
            problems.append(
                f"links changed: before {self._links_before}, after {after}"
            )
        if _resolv_digest() != self._resolv_before:
            problems.append("/etc/resolv.conf changed")
        alive = [p.popen.pid for p in self.procs if p.alive()]
        if alive:
            problems.append(f"processes still running: {alive}")
        if problems:
            raise AssertionError("lab tear-down: " + "; ".join(problems))
