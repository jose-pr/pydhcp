"""The options a handler acts on, checked once before any handler runs."""

from __future__ import annotations

import logging as _logging
import typing as _ty

from ..exceptions import DHCPDecodeError
from ..listener._limit import _brief
from ..listener._receive import DHCPRequestContext
from ..options._codes import DHCPOptionCode
from ..options import _codecs as _type
from ..packet._message import DHCPMessage
from ._state import _ServerState

__all__: list[str] = []

LOGGER = _logging.getLogger(__name__)

#: Octets of an unusable value a log line shows.
_SHOWN_OCTETS = 16

#: The options the handlers and the lease policy read, with the codec each is
#: read with and what an unusable value costs: the message (options 50 and 54
#: say which address and which server, so a message that cannot say is one the
#: server cannot answer) or only the option, which is then treated as absent
#: (51 and 57 are hints the server has a default for).
_ACTED_ON: _ty.Tuple[_ty.Tuple[DHCPOptionCode, _ty.Any, bool], ...] = (
    (DHCPOptionCode.SERVER_IDENTIFIER, _type.IPv4AddressOption, True),
    (DHCPOptionCode.REQUESTED_IP, _type.IPv4AddressOption, True),
    (DHCPOptionCode.IP_ADDRESS_LEASE_TIME, _type.U32, False),
    (DHCPOptionCode.MAXIMUM_DHCP_MESSAGE_SIZE, _type.U16, False),
)


class _InputGuard(_ServerState):
    """Decides, before any handler runs, whether the message can be handled at all."""

    def _acted_on_options_usable(
        self, msg: DHCPMessage, client_id: str, context: DHCPRequestContext
    ) -> bool:
        """Whether `msg` may go on to a handler; False when it is dropped.

        Each option of `_ACTED_ON` is decoded here. An unusable option 50 or 54
        drops the message; an unusable 51 or 57 is removed from it, so every
        later reader of `msg.options` sees it absent. Either is counted and
        logged through the rate limit, with the XID and the client.
        """
        for code, codec, drops in _ACTED_ON:
            if code not in msg.options:
                continue
            try:
                msg.options.get(code, decode=codec)
                continue
            except DHCPDecodeError:
                pass
            raw = bytes(msg.options.get(code, decode=False) or b"")
            shown = raw[:_SHOWN_OCTETS].hex() + (
                "..." if len(raw) > _SHOWN_OCTETS else ""
            )
            now = self._instant(context).monotonic
            if drops:
                self.metrics.packets_dropped_malformed_option += 1
                self._log_limit.log(
                    LOGGER,
                    _logging.WARNING,
                    f"unusable option {int(code)}",
                    "[XID=%08x] Dropping a message from %s|%s: option %d (%s) is "
                    "unusable (%d octets: %s)",
                    msg.xid,
                    context.client,
                    _brief(client_id),
                    int(code),
                    code.label(),
                    len(raw),
                    shown,
                    now=now,
                )
                return False
            del msg.options[code]
            self.metrics.options_ignored_malformed += 1
            self._log_limit.log(
                LOGGER,
                _logging.WARNING,
                f"unusable option {int(code)}",
                "[XID=%08x] Ignoring option %d (%s) from %s|%s: unusable "
                "(%d octets: %s); treating it as absent",
                msg.xid,
                int(code),
                code.label(),
                context.client,
                _brief(client_id),
                len(raw),
                shown,
                now=now,
            )
        return True
