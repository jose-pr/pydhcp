"""Domain-name option codecs: search lists (RFC 3397), and a single name."""

from __future__ import annotations

import typing as _ty
from .base import DhcpOptionType
from .domain import decode_domain_name, encode_domain_name, split_domain_name
from collections.abc import Iterable

if _ty.TYPE_CHECKING:
    from typing_extensions import Self


class DomainList(DhcpOptionType, list[str]):
    """RFC 1035 domain-name list with compression support.

    Normalizes like `List[T]` does, and for the same reason. With no
    `__init__` this inherited `list`'s, where a `str` argument is an
    *iterable of characters*: `DomainList("corp")` was `["c", "o", "r", "p"]`
    and `options[119] = "corp"` silently offered the client four
    single-letter search domains. A bare name is one entry; pass a list for
    several.
    """

    def __init__(self, *items: _ty.Any) -> None:
        # Same rule as `List.__init__`: a list/tuple argument is a sequence of
        # entries, anything else is a single entry.
        for group in items:
            self.extend(group if isinstance(group, (tuple, list)) else (group,))

    @staticmethod
    def _normalize(item: _ty.Any) -> str:
        if not isinstance(item, str):
            raise TypeError(
                f"domain-list entries must be str, not {type(item).__name__}"
            )
        return item

    def __setitem__(self, idx: _ty.Any, item: str) -> None:  # type: ignore[override]
        list.__setitem__(self, idx, self._normalize(item))

    def append(self, item: str) -> None:
        list.append(self, self._normalize(item))

    def extend(self, __iterable: Iterable[str]) -> None:
        list.extend(self, [self._normalize(item) for item in __iterable])

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        view = memoryview(option)
        self = cls()
        if not option:
            return self, 0
        # offset -> (kind, value, offset of the next component)
        #   kind "label": value is the decoded text
        #   kind "root" : value is None (a 0x00 terminator)
        #   kind "ptr"  : value is the target offset
        components: dict[int, tuple[str, _ty.Any, int]] = _ty.OrderedDict()
        domains: list[int] = [0]
        id = 0
        size = len(view)
        while id < size:
            start = id
            ptr_or_len = view[id]
            id += 1
            if ptr_or_len == 0x00:
                components[start] = ("root", None, id)
                if id < size:
                    domains.append(id)
                continue
            is_ptr = ptr_or_len & 0xC0
            if is_ptr:
                if is_ptr != 0xC0:
                    raise ValueError(
                        f"search list octet {ptr_or_len:#04x} at offset {start} sets a "
                        "reserved label-length prefix; RFC 1035 s4.1.4 defines only "
                        "00 (label) and 11 (compression pointer)"
                    )
                components[start] = (
                    "ptr",
                    ((0x3F & ptr_or_len) << 8) | view[id],
                    id + 1,
                )
                id += 1
                if id < size:
                    domains.append(id)
            else:
                dc = view[id : ptr_or_len + id]
                if len(dc) != ptr_or_len:
                    raise ValueError(
                        f"search list is truncated: a label declares {ptr_or_len} "
                        f"octets but only {len(dc)} remain"
                    )
                label = dc.tobytes().decode()
                if "." in label:
                    # Same reason as `domain.decode_domain_name`: these names
                    # are joined with ".", so a label already containing one
                    # re-encodes as a different number of labels than arrived.
                    raise ValueError(
                        f"search list has a label containing '.' ({label!r}), "
                        "which cannot be represented unambiguously in dotted form"
                    )
                components[start] = ("label", label, id + ptr_or_len)
                id += ptr_or_len

        def get_dn(start: int) -> list[str]:
            """Resolve one name by walking the component chain.

            Iterative, and every offset is visited at most once per name: a
            self-referential or mutually-referential compression pointer is a
            decode error, not a RecursionError, and the work is proportional to
            the name actually produced. The previous implementation rescanned
            every component for each name, which made decoding O(n^2) in the
            payload length and, since packets are decoded on the receive path,
            an unauthenticated CPU exhaustion vector.
            """
            result: list[str] = []
            seen: set[int] = set()
            offset = start
            while True:
                if offset in seen:
                    raise ValueError(
                        f"Cyclic domain-name compression pointer at offset {offset}"
                    )
                seen.add(offset)
                component = components.get(offset)
                if component is None:
                    break
                kind, value, nxt = component
                if kind == "root":
                    break
                if kind == "ptr":
                    offset = value
                    continue
                result.append(value)
                offset = nxt
            return result

        for domain in domains:
            self.append(".".join(get_dn(domain)))
        return self, len(option)

    def _dhcp_write(self, _data: bytearray) -> int:
        components: list[tuple[list[str], int]] = []
        data = bytearray()
        for domain_str in self:
            # Same rules as every other name in the package, even though the
            # encoding below is compressed and theirs is not: without this an
            # over-long label's length prefix sets the pointer flag bits and
            # this encoder emits bytes its own decoder rejects.
            domain = split_domain_name(domain_str, "search-list entry", allow_root=True)
            unique = domain
            parent: _ty.Optional[tuple[int, int]] = None
            for cn, cidx in components:
                pair = 1
                while pair < len(domain):
                    if domain[-pair:] != cn[-pair:]:
                        break
                    pair += 1
                pair -= 1
                if pair:
                    if parent:
                        _, _pair = parent
                        if pair <= _pair:
                            continue
                    for n in cn[:-pair]:
                        # Octets, not characters. A compression pointer is a
                        # byte offset into the option, so counting characters
                        # here aimed every pointer past a non-ASCII label at the
                        # wrong byte.
                        cidx += 1 + len(n.encode())

                    parent = cidx, pair
                    unique = domain[:-pair]

            components.append((domain, len(data)))
            for comp in unique:
                # RFC 1035 3.1: a label's length octet counts OCTETS. This
                # counted characters, so `bücher.example` declared 6 for a
                # 7-octet label: the wire bytes were corrupt, and this encoder's
                # own decoder either raised a bare ValueError or read the
                # remainder as different labels entirely -- measured,
                # ['éé.x.com', 'y.x.com'] came back as ['<0xef><0xbf><0xbd>',
                # 'x.com', 'y']. `split_domain_name` validates in octets, so the
                # length check and the length written now agree.
                encoded = comp.encode()
                data.append(len(encoded))
                data.extend(encoded)
            if parent is None:
                data.append(0x00)
            else:
                data.extend((0xC000 | parent[0]).to_bytes(2, byteorder="big"))
        _data.extend(data)
        return len(data)


class UncompressedDomainList(DomainList):
    """A domain-name list for the options that forbid DNS name compression.

    RFC 3397's search list (option 119) is compressed on purpose. Two other
    options carrying a name list are not, and both were registered as plain
    `DomainList`, so pydhcp emitted a `0xC0` pointer into payloads whose own
    RFCs forbid one:

    * option 88, BCMCS controller domain names -- RFC 4280 §4.6: "The domain
      names MUST be concatenated and encoded using the technique described in
      Section 3.3 of [RFC1035]. DNS name compression MUST NOT be used."
    * option 146, RDNSS selection -- RFC 6731 §4.3 defers to RFC 3315 §8: "A
      domain name, or list of domain names, in DHCP MUST NOT be stored in
      compressed form, as described in section 4.1.4 of RFC 1035."

    Measured before the split, `["a.example.com", "b.example.com"]` encoded as
    `01 61 07 example 03 com 00 01 62 c0 02` for option 88 -- the second name
    ending in a pointer a conforming receiver is not required to follow.

    **Encode only.** Decoding stays `DomainList`'s: a pointer that arrives
    resolves unambiguously inside the option, and the receive path in this
    package is deliberately liberal, so refusing one would turn a readable
    packet from a non-conforming peer into a decode failure. The RFCs
    constrain what is sent, and that is what changes here.
    """

    def _dhcp_write(self, data: bytearray) -> int:
        written = 0
        for domain in self:
            # The shared encoder in `type/domain.py`, exactly as options 81,
            # 120, 122, 139 and 140 use it -- one set of name rules for the
            # whole package. `allow_root` keeps `DomainList`'s treatment of an
            # empty entry as the root name, a single zero octet.
            encoded = encode_domain_name(domain, "domain-list entry", allow_root=True)
            data.extend(encoded)
            written += len(encoded)
        return written


class DomainName(DhcpOptionType, str):
    """A single uncompressed RFC 1035 name, as an option payload.

    Options 147 (RFC 8973 s5.2) and 213 (RFC 5986 s3.2) carry a label sequence,
    not dotted text. Registered as `String` they decoded to the raw label bytes
    rather than to `example.com`, and emitted dotted text that a conforming
    receiver cannot parse.
    """

    @classmethod
    def _dhcp_read(cls, option: memoryview) -> tuple[Self, int]:
        name, read = decode_domain_name(option, 0, cls.__name__)
        return cls(name), read

    def _dhcp_write(self, data: bytearray) -> int:
        encoded = encode_domain_name(str(self), type(self).__name__, allow_root=True)
        data.extend(encoded)
        return len(encoded)

    def __json__(self) -> str:
        return str(self)
