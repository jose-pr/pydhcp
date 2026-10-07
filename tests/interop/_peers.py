"""Stock DHCP software started inside a lab namespace.

Each starter confines its peer to the namespace and the lab's work directory:
a client gets a script of its own (so the system's resolver files and
interfaces outside the namespace are never touched), lease and pid files in the
work directory, and a made-up host name. What the client was given is read back
from the file its script writes.
"""

from __future__ import annotations

import pathlib
import time
import typing as _ty

from ._lab import Lab, Proc, which

HOSTNAME = "lab-client"

_DHCLIENT_SCRIPT = """#!/bin/sh
# Records the lease and configures the address inside this namespace only.
OUT='{out}'
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT)
    {{ echo "reason=$reason"; env | grep '^new_' | sort; echo '--'; }} >> "$OUT/events"
    [ {status} -eq 0 ] || exit {status}
    '{ip}' addr flush dev "$interface" 2>/dev/null
    '{ip}' addr add "$new_ip_address/$new_subnet_mask" dev "$interface"
    ;;
  *)
    echo "reason=$reason" >> "$OUT/other"
    ;;
esac
exit 0
"""

_UDHCPC_SCRIPT = """#!/bin/sh
# Records the lease and configures the address inside this namespace only.
OUT='{out}'
case "$1" in
  bound|renew)
    {{ echo "reason=$1"; echo "ip=$ip"; echo "mask=$mask"; echo "router=$router";
       echo "dns=$dns"; echo "domain=$domain"; echo "mtu=$mtu"; echo "serverid=$serverid";
       echo "lease=$lease"; echo '--'; }} >> "$OUT/events"
    '{ip_tool}' addr flush dev "$interface" 2>/dev/null
    '{ip_tool}' addr add "$ip/$mask" dev "$interface"
    ;;
  *)
    echo "reason=$1" >> "$OUT/other"
    ;;
esac
exit 0
"""


class Lease(_ty.NamedTuple):
    """What a client reported it was given."""

    reason: str
    fields: _ty.Dict[str, str]


def _write(path: pathlib.Path, text: str) -> None:
    """Write LF text; `Path.write_text(newline=)` exists only from Python 3.10."""
    path.write_bytes(text.encode("utf-8"))


def read_events(path: pathlib.Path) -> _ty.List[Lease]:
    """The leases a client script recorded: blocks of `key=value` lines ending in `--`."""
    if not path.exists():
        return []
    found: _ty.List[Lease] = []
    current: _ty.Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "--":
            found.append(Lease(current.pop("reason", ""), current))
            current = {}
        elif "=" in line:
            key, _, value = line.partition("=")
            current[key.replace("new_", "")] = value
    return found


class Client:
    """A client process and what it reported."""

    def __init__(self, lab: Lab, proc: Proc, out: pathlib.Path, started: float) -> None:
        self.lab = lab
        self.proc = proc
        self.out = out
        self.started = started

    @property
    def events_path(self) -> pathlib.Path:
        return self.out / "events"

    def leases(self) -> _ty.List[Lease]:
        return read_events(self.events_path)

    def wait_bound(self, timeout: float) -> _ty.Optional[Lease]:
        """The first lease the client reports, or None after `timeout`."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            leases = self.leases()
            if leases:
                self.bound_after = time.monotonic() - self.started
                return leases[0]
            if not self.proc.alive():
                leases = self.leases()
                return leases[0] if leases else None
            time.sleep(0.1)
        return None

    bound_after: float = 0.0


def dhclient(
    lab: Lab,
    ns: str,
    iface: str,
    name: str = "dhclient",
    *,
    extra_conf: str = "",
    lease_file: _ty.Optional[str] = None,
    reboot_seconds: int = 10,
    timeout_seconds: int = 20,
    send_host_name: bool = True,
    script_status: int = 0,
    release: bool = False,
) -> Client:
    """ISC dhclient, one attempt, in the foreground, confined to `ns`.

    `send_host_name=False` leaves the host name out of what it sends,
    `script_status` is the exit status of its script on a lease (non-zero makes
    it send a DHCPDECLINE) and `release=True` runs `dhclient -r`, which
    releases the lease its lease file holds and exits.
    """
    binary = which("dhclient")
    assert binary is not None
    out = lab.work / f"{name}-out"
    out.mkdir(parents=True, exist_ok=True)
    script = out / "script.sh"
    _write(script, _DHCLIENT_SCRIPT.format(out=out, ip=lab.ip, status=script_status))
    script.chmod(0o755)
    conf = out / "dhclient.conf"
    # The option list is stated: a distribution's built-in default differs
    # (Debian's dhclient does not ask for the interface MTU, Fedora's does).
    _write(
        conf,
        (f'send host-name "{HOSTNAME}";\n' if send_host_name else "")
        + "request subnet-mask, broadcast-address, routers, domain-name,\n"
        "    domain-name-servers, host-name, interface-mtu;\n"
        f"timeout {timeout_seconds};\nreboot {reboot_seconds};\n"
        "retry 5;\nselect-timeout 0;\n" + extra_conf,
    )
    lease = out / "dhclient.leases"
    _write(lease, lease_file or "")
    started = time.monotonic()
    proc = lab.spawn(
        ns,
        [
            binary,
            "-d",
            "-r" if release else "-1",
            "-v",
            "-cf",
            str(conf),
            "-lf",
            str(lease),
            "-pf",
            str(out / "dhclient.pid"),
            "-sf",
            str(script),
            iface,
        ],
        name,
    )
    return Client(lab, proc, out, started)


def udhcpc(
    lab: Lab,
    ns: str,
    iface: str,
    name: str = "udhcpc",
    *,
    extra: _ty.Sequence[str] = (),
) -> Client:
    """BusyBox udhcpc, quitting once it holds a lease, confined to `ns`."""
    busybox = which("busybox")
    assert busybox is not None
    out = lab.work / f"{name}-out"
    out.mkdir(parents=True, exist_ok=True)
    script = out / "script.sh"
    _write(script, _UDHCPC_SCRIPT.format(out=out, ip_tool=lab.ip))
    script.chmod(0o755)
    started = time.monotonic()
    proc = lab.spawn(
        ns,
        [
            busybox,
            "udhcpc",
            "-i",
            iface,
            "-f",
            "-q",
            "-n",
            "-t",
            "4",
            "-T",
            "2",
            "-s",
            str(script),
            "-p",
            str(out / "udhcpc.pid"),
            "-x",
            f"hostname:{HOSTNAME}",
            *extra,
        ],
        name,
    )
    return Client(lab, proc, out, started)


def dnsmasq(
    lab: Lab,
    ns: str,
    iface: str,
    dhcp_range: _ty.Optional[str],
    name: str = "dnsmasq",
    *,
    extra: _ty.Sequence[str] = (),
) -> Proc:
    """dnsmasq as a DHCP-only server on `iface`, confined to `ns`.

    `dhcp_range=None` gives no range (a relay has none) and `extra` is appended
    to the command line. It is ready once port 67 is bound in `ns` and, with a
    range, the range is logged.
    """
    binary = which("dnsmasq")
    assert binary is not None
    out = lab.work / f"{name}-out"
    out.mkdir(parents=True, exist_ok=True)
    proc = lab.spawn(
        ns,
        [
            binary,
            "--no-daemon",
            "--conf-file=/dev/null",
            "--port=0",
            "--no-resolv",
            "--no-hosts",
            "--no-ping",
            "--user=root",
            "--group=root",
            "--bind-interfaces",
            f"--interface={iface}",
            *([f"--dhcp-range={dhcp_range}"] if dhcp_range else []),
            f"--dhcp-leasefile={out / 'leases'}",
            f"--pid-file={out / 'pid'}",
            f"--log-facility={out / 'log'}",
            "--log-dhcp",
            *extra,
        ],
        name,
    )
    end = time.monotonic() + 5
    log = out / "log"
    while time.monotonic() < end:
        logged = log.exists() and (
            not dhcp_range or "DHCP, IP range" in log.read_text(errors="replace")
        )
        if (
            logged
            and lab.run(ns, ["ss", "-Hlun", "sport = :67"], check=False).stdout.strip()
        ):
            break
        if not proc.alive():
            raise RuntimeError(f"dnsmasq exited: {proc.text()}")
        time.sleep(0.1)
    return proc
