"""Record what dnsmasq and ISC dhclient answer to each conformance case. Development only.

    sudo python tests/conformance/record.py              # write every golden.json
    sudo python tests/conformance/record.py --check      # re-record in memory, report drift
    sudo python tests/conformance/record.py NAME ...     # only these cases

The references play in network namespaces of the real-peer lab (``tests/interop``):
dnsmasq 2.92 is the server and, with ``--dhcp-relay``, the relay; ISC dhclient is the
client. A scripted end (``player.py``) sends a case's steps or answers as a server
would. A golden is the exchange as the taps saw it, with the reference's version and
the system it ran on, and is never edited by hand: ``test_conformance.py`` replays the
goldens and needs neither this script nor the references.

Exit status: 0 for no drift, and for drift measured on another version or distribution
than the golden's (printed, not an error); 1 for drift on the recording system itself;
2 when the lab or a reference cannot run, or a case does not play.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import os
import pathlib
import platform
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import exchange  # noqa: E402
import player  # noqa: E402
from interop import _lab, _peers, _topo  # noqa: E402

PLAYER = str(HERE / "player.py")
#: What a dhclient message needs before it is given up on, in seconds.
CLIENT_WAIT = 40.0
LEASE = """lease {{
  interface "cv0";
  fixed-address {address};
  option subnet-mask {mask};
  option routers {server};
  option dhcp-lease-time 600;
  option dhcp-message-type 5;
  option dhcp-server-identifier {server};
  renew 0 2037/1/1 00:00:00;
  rebind 0 2037/1/1 00:00:00;
  expire 0 2037/1/1 00:00:00;
}}
"""


class CannotPlay(Exception):
    """The lab or a reference did not do what the case needs."""


def _version(program: str) -> str:
    found = _lab.which(program)
    if found is None:
        raise CannotPlay("%s is not installed" % program)
    done = subprocess.run([found, "--version"], capture_output=True, text=True)
    first = (done.stdout + done.stderr).strip().splitlines()[0]
    return first.split("  Copyright")[0].split(" (")[0]


def _distribution() -> str:
    found: Dict[str, str] = {}
    try:
        for line in (
            pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        ):
            key, _, value = line.partition("=")
            found[key] = value.strip('"')
    except OSError:
        pass
    return "%s %s" % (found.get("ID", "unknown"), found.get("VERSION_ID", "unknown"))


def _reference(role: str) -> Dict[str, str]:
    program = "dhclient" if role == "client" else "dnsmasq"
    return {
        "name": program,
        "version": _version(program),
        "distribution": _distribution(),
        "machine": platform.machine(),
        "recorded": datetime.date.today().isoformat(),
    }


def _write_json(path: pathlib.Path, document: Any) -> None:
    path.write_bytes((json.dumps(document, indent=1) + "\n").encode("utf-8"))


def _dnsmasq_arguments(config: Dict[str, Any]) -> List[str]:
    mask = config["mask"]
    seconds = config["lease_seconds"]
    served = ipaddress.IPv4Interface("%s/%d" % (config["server"], config["prefix"]))
    if config["range"]:
        first, last = config["range"]
        arguments = ["--dhcp-range=%s,%s,%s,%d" % (first, last, mask, seconds)]
    else:
        arguments = [
            "--dhcp-range=%s,static,%s,%d"
            % (served.network.network_address, mask, seconds)
        ]
    arguments += ["--dhcp-host=%s,%s" % pair for pair in config["hosts"].items()]
    arguments.append("--dhcp-option=3,%s" % config["router"])
    if config["authoritative"]:
        arguments.append("--dhcp-authoritative")
    return arguments


def _needs(*names: str) -> None:
    missing = [name for name in names if _lab.which(name) is None]
    if missing:
        raise CannotPlay("not installed: " + ", ".join(missing))


def _scripted_server(
    lab: _lab.Lab, ns: str, iface: str, replies: Dict[str, Any]
) -> None:
    (lab.work / "replies.json").write_bytes(json.dumps(replies).encode("utf-8"))
    ready = lab.work / "answer.ready"
    lab.spawn(
        ns,
        [
            sys.executable,
            PLAYER,
            "answer",
            iface,
            str(lab.work / "replies.json"),
            str(ready),
        ],
        "answer",
    )
    if not lab.wait_file(ready, 10):
        raise CannotPlay("the scripted server did not start")


def _send(
    lab: _lab.Lab, ns: str, iface: str, steps: List[Dict[str, Any]]
) -> List[Tuple[str, float]]:
    (lab.work / "steps.json").write_bytes(json.dumps(steps).encode("utf-8"))
    progress = lab.work / "progress.jsonl"
    proc = lab.spawn(
        ns,
        [
            sys.executable,
            PLAYER,
            "send",
            iface,
            str(lab.work / "steps.json"),
            str(progress),
        ],
        "send",
    )
    try:
        proc.popen.wait(len(steps) * (player.SILENCE + 3) + 15)
    except subprocess.TimeoutExpired:
        raise CannotPlay("the scripted client did not finish: " + proc.text()) from None
    if proc.popen.returncode != 0:
        raise CannotPlay("the scripted client failed: " + proc.text())
    return [
        (row["step"], row["t"])
        for row in map(json.loads, progress.read_text(encoding="utf-8").splitlines())
    ]


def _frames(taps: List[_lab.Tap]) -> List[_lab.Frame]:
    return sorted((f for tap in taps for f in tap.frames()), key=lambda f: f.t)


def _entries(
    frames: List[_lab.Frame], roles: Dict[str, str], step_of: Any
) -> List[Dict[str, Any]]:
    found = []
    for frame in frames:
        sender = roles.get(frame.src_mac)
        if sender is None:
            raise CannotPlay("a frame from an unlabelled sender: " + frame.src_mac)
        found.append(
            {
                "step": step_of(frame, sender),
                "sender": sender,
                "src": "%s:%d" % (frame.src_ip, frame.sport),
                "dst": "%s:%d" % (frame.dst_ip, frame.dport),
                "payload": frame.payload.hex(),
            }
        )
    return found


def _by_progress(progress: List[Tuple[str, float]]) -> Any:
    def step_of(frame: _lab.Frame, sender: str) -> str:
        name = progress[0][0]
        for step, started in progress:
            if frame.t >= started - 0.05:
                name = step
        return name

    return step_of


def _record_server(lab: _lab.Lab, case: Dict[str, Any]) -> List[Dict[str, Any]]:
    _needs("dnsmasq")
    config = case["config"]
    if case["topology"] == "single":
        net = _topo.single(lab)
        tap = lab.tap(net.cli, "cv0", "client-segment")
        roles, sender_ns, sender_iface = _topo.ROLES_SINGLE, net.cli, "cv0"
        iface = "sv0"
        server_ns = net.srv
    else:
        net2 = _topo.relayed(lab)
        tap = lab.tap(net2.srv, "sv0", "server-segment")
        roles, sender_ns, sender_iface = _topo.ROLES_RELAYED, net2.rly, "rs0"
        iface = "sv0"
        server_ns = net2.srv
    _peers.dnsmasq(lab, server_ns, iface, None, extra=_dnsmasq_arguments(config))
    progress = _send(lab, sender_ns, sender_iface, case["steps"])
    return _entries(_frames([tap]), roles, _by_progress(progress))


def _record_relay(lab: _lab.Lab, case: Dict[str, Any]) -> List[Dict[str, Any]]:
    _needs("dnsmasq")
    config = case["config"]
    net = _topo.relayed(lab)
    client_tap = lab.tap(net.cli, "cv0", "client-segment")
    server_tap = lab.tap(net.srv, "sv0", "server-segment")
    _scripted_server(lab, net.srv, "sv0", config["replies"])
    _peers.dnsmasq(
        lab,
        net.rly,
        "ra0",
        None,
        extra=[
            "--interface=rs0",
            "--dhcp-relay=%s,%s" % (config["local"], config["server"]),
        ],
    )
    progress = _send(lab, net.cli, "cv0", case["steps"])
    return _entries(
        _frames([client_tap, server_tap]), _topo.ROLES_RELAYED, _by_progress(progress)
    )


def _record_client(lab: _lab.Lab, case: Dict[str, Any]) -> List[Dict[str, Any]]:
    _needs("dhclient")
    config = case["config"]
    dhclient = config["dhclient"]
    held = config["holds"]
    net = _topo.single(lab, client_addr=("%s/24" % held) if held else None)
    tap = lab.tap(net.cli, "cv0", "client-segment")
    _scripted_server(lab, net.srv, "sv0", config["replies"])
    lease = dhclient["lease"]
    peer = _peers.dhclient(
        lab,
        net.cli,
        "cv0",
        lease_file=LEASE.format(**lease) if lease else None,
        send_host_name=dhclient["send_host_name"],
        script_status=dhclient["script_status"],
        release=dhclient["release"],
        reboot_seconds=5,
    )
    wanted = config["messages"]
    ended = time.monotonic() + CLIENT_WAIT
    while (
        time.monotonic() < ended
        and len([f for f in tap.frames() if f.src_mac == _topo.CLIENT_MAC]) < wanted
    ):
        if not peer.proc.alive() and not tap.frames():
            raise CannotPlay("dhclient ended without a message: " + peer.proc.text())
        time.sleep(0.2)
    time.sleep(player.SILENCE)
    peer.proc.stop()
    names = [step["name"] for step in case["steps"]]
    frames = _frames([tap])
    sent = [f for f in frames if f.src_mac == _topo.CLIENT_MAC]
    if len(sent) < wanted:
        raise CannotPlay(
            "dhclient sent %d of the %d messages the case needs" % (len(sent), wanted)
        )
    if len(sent) > wanted:
        frames = [f for f in frames if f.t < sent[wanted].t]
    counted = []

    def step_of(frame: _lab.Frame, sender: str) -> str:
        counted.append(sender == "client")
        return names[max(sum(counted) - 1, 0)]

    return _entries(frames, _topo.ROLES_SINGLE, step_of)


def _screen(entries: List[Dict[str, Any]]) -> None:
    """Refuse a golden that holds this machine's names or an address that is not private."""
    names = {platform.node(), platform.node().split(".")[0]}
    for variable in ("USER", "LOGNAME", "SUDO_USER", "USERNAME"):
        value = os.environ.get(variable)
        if value and value != "root":
            names.add(value)
    blob = json.dumps(entries).encode()
    for name in names:
        if len(name) >= 3 and name.encode() in blob:
            raise CannotPlay("a golden would hold a name from this machine")
    for entry in entries:
        for end in (entry["src"], entry["dst"]):
            address = ipaddress.ip_address(end.rsplit(":", 1)[0])
            if not (address.is_private or str(address) == "255.255.255.255"):
                raise CannotPlay(
                    "a golden would hold an address that is not private: " + end
                )


def record(case_directory: pathlib.Path) -> Dict[str, Any]:
    """One case against a fresh lab: the reference and the exchange as the taps saw it."""
    case = exchange.load(case_directory)
    role = case["role"]
    with tempfile.TemporaryDirectory() as work:
        lab = _lab.Lab(pathlib.Path(work) / "lab")
        try:
            run = {
                "server": _record_server,
                "relay": _record_relay,
                "client": _record_client,
            }[role]
            entries = run(lab, case)
        finally:
            lab.close()
    _screen(entries)
    return {"reference": _reference(role), "exchange": entries}


def _by_step(
    entries: List[Dict[str, Any]],
) -> Dict[str, Dict[str, List[exchange.Datagram]]]:
    grouped: Dict[str, Dict[str, List[exchange.Datagram]]] = {}
    for entry in entries:
        senders = grouped.setdefault(entry["step"], {})
        senders.setdefault(entry["sender"], []).append(
            (bytes.fromhex(entry["payload"]), entry["dst"])
        )
    return grouped


def drift(case: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """What the two exchanges differ in, outside the aspects the case leaves out as chance."""
    notes = []
    before, after = _by_step(old["exchange"]), _by_step(new["exchange"])
    order = [s["name"] for s in case["steps"]]
    for step in sorted(
        set(before) | set(after),
        key=lambda s: order.index(s) if s in order else len(order),
    ):
        left_out = [e["aspect"] for e in case["not_compared"] if e["step"] == step]
        for sender in sorted(set(before.get(step, {})) | set(after.get(step, {}))):
            for found in exchange.differences(
                before.get(step, {}).get(sender, []),
                after.get(step, {}).get(sender, []),
                left_out,
            ):
                notes.append(
                    "%s %s: %s %s -> %s"
                    % (step, sender, found.aspect, found.reference, found.ours)
                )
    return notes


def main(argv: List[str]) -> int:
    check = "--check" in argv
    names = [a for a in argv if not a.startswith("--")]
    reason = _lab.unavailable()
    if reason is not None:
        print("cannot record: " + reason)
        return 2
    status = 0
    for directory in exchange.cases():
        if names and directory.name not in names:
            continue
        started = time.monotonic()
        try:
            golden = record(directory)
        except CannotPlay as error:
            print("%-44s does not play: %s" % (directory.name, error))
            return 2
        path = directory / "golden.json"
        old: Optional[Dict[str, Any]] = (
            json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        )
        case = exchange.load(directory)
        notes = drift(case, old, golden) if old else ["no golden"]
        same_system = bool(old) and all(
            old["reference"][k] == golden["reference"][k]
            for k in ("version", "distribution")
        )
        if check:
            print(
                "%-44s %s (%.0f s)"
                % (
                    directory.name,
                    "; ".join(notes) or "no drift",
                    time.monotonic() - started,
                )
            )
            if notes and (same_system or not old):
                status = max(status, 1)
        elif not notes and same_system:
            print(
                "%-44s unchanged, %d datagrams (%.0f s)"
                % (directory.name, len(golden["exchange"]), time.monotonic() - started)
            )
        else:
            _write_json(path, golden)
            print(
                "%-44s recorded %d datagrams (%.0f s)"
                % (directory.name, len(golden["exchange"]), time.monotonic() - started)
            )
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
