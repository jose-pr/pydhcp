"""This library's answers held to what dnsmasq and ISC dhclient answered, with no peer installed.

Each directory under ``cases/`` holds ``case.json``, what is sent and the question, and
``golden.json``, what the reference answered, recorded by ``record.py``. The replay drives the
role cores with the same input (no socket) and compares, per step, the datagrams sent, their
header fields, each option's octets and order, the padding and the destination. A difference
is one of two things: a deviation (``deviations.json``: deliberate, asserted present in
exactly its cases) or a divergence (``divergences.json``: a strict expected failure, so the
fix that closes it forces the marker out). An aspect a case leaves out is named, with its
reason, in the case's ``not_compared``.

A divergence or a deviation names an aspect as ``"<step> <aspect>"``.
"""

from __future__ import annotations

import ipaddress
import json
import re

import pytest

import exchange
import replay

HERE = exchange.HERE
DEVIATIONS = json.loads((HERE / "deviations.json").read_text(encoding="utf-8"))
DIVERGENCES = {
    entry["case"]: entry
    for entry in json.loads((HERE / "divergences.json").read_text(encoding="utf-8"))
}
CASES = exchange.cases()
SERVING = [d for d in CASES if exchange.load(d)["role"] in ("server", "relay")]
REFERENCES = {"server": "2.92", "relay": "2.92", "client": "4.4.3-P1"}
_PLAYED: dict = {}


def _key(step, difference):
    return "%s %s" % (step, difference.aspect)


def _remaining(directory, driver="sync"):
    """Every difference of a case outside its ``not_compared`` and the deviations."""
    if (directory.name, driver) not in _PLAYED:
        _PLAYED[(directory.name, driver)] = [
            (step, d)
            for step, d in replay.compare(directory, driver)
            if not any(
                directory.name in deviation["cases"]
                and _key(step, d) in deviation["aspects"]
                for deviation in DEVIATIONS
            )
        ]
    return _PLAYED[(directory.name, driver)]


def _golden(directory):
    return json.loads((directory / "golden.json").read_text(encoding="utf-8"))


def _case(directory, driver="sync"):
    divergent = directory.name in DIVERGENCES
    marks = (
        [pytest.mark.xfail(strict=True, reason=DIVERGENCES[directory.name]["reason"])]
        if divergent
        else []
    )
    return pytest.param(
        directory, driver, id=directory.name + "-" + driver, marks=marks
    )


def test_there_are_cases_with_goldens():
    assert len(CASES) >= 15
    assert [d.name for d in CASES if not (d / "golden.json").is_file()] == []


@pytest.mark.parametrize("directory", CASES, ids=lambda d: d.name)
def test_a_golden_says_what_recorded_it(directory):
    golden = _golden(directory)
    reference = golden["reference"]

    assert set(golden) == {"reference", "exchange"}
    assert REFERENCES[exchange.load(directory)["role"]] in reference["version"]
    assert reference["name"] in ("dnsmasq", "dhclient")
    assert reference["distribution"] and reference["machine"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", reference["recorded"])


@pytest.mark.parametrize("directory", CASES, ids=lambda d: d.name)
def test_a_golden_holds_only_private_addresses_and_locally_administered_hardware(
    directory,
):
    for entry in _golden(directory)["exchange"]:
        for end in (entry["src"], entry["dst"]):
            address = ipaddress.ip_address(end.rsplit(":", 1)[0])
            assert address.is_private or str(address) == "255.255.255.255", end
        assert int(exchange.read(bytes.fromhex(entry["payload"]))["chaddr"][:2], 16) & 2


@pytest.mark.parametrize("directory", SERVING, ids=lambda d: d.name)
def test_the_input_of_a_golden_is_what_the_case_spells(directory):
    """The datagrams the scripted end sent are the case's, octet for octet: no golden depends on the code under test."""
    role = exchange.load(directory)["role"]
    spelled = [
        (step["name"], exchange.build(step["message"]))
        for step in exchange.load(directory)["steps"]
    ]
    sent = [
        (entry["step"], bytes.fromhex(entry["payload"]))
        for entry in _golden(directory)["exchange"]
        if (
            entry["sender"] != "server"
            if role == "server"
            else entry["sender"] == "client"
        )
    ]

    assert sent == spelled


@pytest.mark.parametrize("directory", CASES, ids=lambda d: d.name)
def test_a_golden_names_only_steps_of_its_case(directory):
    names = {s["name"] for s in exchange.load(directory)["steps"]}

    assert {e["step"] for e in _golden(directory)["exchange"]} <= names


@pytest.mark.parametrize(
    "directory, driver",
    [_case(d) for d in CASES] + [_case(d, "async") for d in SERVING],
)
def test_this_library_says_what_the_reference_said(directory, driver):
    found = _remaining(directory, driver)

    assert found == [], "\n".join(
        "%s: %s %s -> %s" % (step, d.aspect, d.reference, d.ours) for step, d in found
    )


@pytest.mark.parametrize("directory", CASES, ids=lambda d: d.name)
def test_the_divergences_of_a_case_are_exactly_what_still_differs(directory):
    entry = DIVERGENCES.get(directory.name)
    listed = sorted(entry["aspects"]) if entry else []

    assert sorted({_key(step, d) for step, d in _remaining(directory)}) == listed


@pytest.mark.parametrize("directory", SERVING, ids=lambda d: d.name)
def test_the_two_drivers_of_a_role_differ_alike(directory):
    assert [_key(s, d) for s, d in _remaining(directory, "async")] == [
        _key(s, d) for s, d in _remaining(directory)
    ]


def test_every_divergence_names_a_case_and_says_why():
    names = {d.name for d in CASES}

    assert set(DIVERGENCES) <= names
    for entry in DIVERGENCES.values():
        assert set(entry) == {"case", "aspects", "reason"}
        assert entry["aspects"] and entry["reason"]


def test_every_deviation_is_one_difference_with_its_authority():
    names = {d.name for d in CASES}

    assert len({d["id"] for d in DEVIATIONS}) == len(DEVIATIONS)
    for entry in DEVIATIONS:
        assert set(entry) == {"id", "aspects", "cases", "difference", "authority"}
        assert entry["difference"].endswith(".") and entry["authority"]
        assert entry["cases"] and set(entry["cases"]) <= names


def test_a_deviation_shows_in_exactly_its_cases():
    shown = {}
    for directory in CASES:
        found = {_key(step, d) for step, d in replay.compare(directory)}
        for entry in DEVIATIONS:
            if found & set(entry["aspects"]):
                shown.setdefault(entry["id"], set()).add(directory.name)

    assert shown == {entry["id"]: set(entry["cases"]) for entry in DEVIATIONS}
