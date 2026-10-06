# API Reference

This section provides references for the primary classes in the `pydhcp` package.

## DHCPMessage

::: pydhcp.packet.DHCPMessage
    options:
      # Defined in layers in pydhcp.packet (fields, decode, encode, mapping,
      # display); without this the page would show nothing inherited.
      inherited_members: true

## DHCPOptions

::: pydhcp.options.DHCPOptions

## DHCPOptionCode

The standard IANA option-code registry: an `IntEnum` whose members carry, in their own
docstrings, the RFC text that defines each option. Codes without a member resolve to an
opaque pseudo-member (`get_type()` returns `Bytes`, `label()` reports `UNKNOWN`) rather
than raising, so an unknown code never costs a client its lease.

::: pydhcp.options.DHCPOptionCode
    options:
      # Load-bearing, measured 2026-09-20: without it only the 82 members that carry an
      # RFC docstring render and the other 81 codes vanish from the registry listing.
      members: true

## BaseDHCPOptionCode

The base any custom code map subclasses; pass one to `DHCPOptions(codemap=...)` to
serve a private or vendor option space instead of the IANA registry above.

::: pydhcp.options.BaseDHCPOptionCode
    options:
      # Same reason as DHCPOptionCode: nothing on this class carries a docstring, so
      # without `members: true` the heading renders with no body at all.
      members: true

## DHCPOption

::: pydhcp.options.DHCPOption
    options:
      members: true

## Option Types

::: pydhcp.options
    options:
      # The classes above have sections of their own; the rest of `__all__` is
      # the option codecs.
      filters:
        - "!^(DHCPOptions|DHCPOptionCode|BaseDHCPOptionCode|DHCPOption)$"

## DHCPServer

::: pydhcp.server.DHCPServer
    options:
      # The server is composed of layered classes in pydhcp.server; without this
      # the page would show only __init__.
      inherited_members: true

## DHCPClient

::: pydhcp.client.DHCPClient
    options:
      # The message builders and the reply matching live in a private base.
      inherited_members: true

## AsyncDHCPClient

::: pydhcp.client.AsyncDHCPClient
    options:
      inherited_members: true

## DHCPRelay

::: pydhcp.relay.DHCPRelay

## DHCPCapture

::: pydhcp.capture.DHCPCapture

## CaptureEvent

::: pydhcp.capture.CaptureEvent

## DHCPCaptureWriter

::: pydhcp.capture.DHCPCaptureWriter

## AsyncDHCPServer

::: pydhcp.server.AsyncDHCPServer
    options:
      # The server is composed of layered classes in pydhcp.server; without this
      # the page would show only __init__.
      inherited_members: true

## AsyncDHCPRelay

::: pydhcp.relay.AsyncDHCPRelay

## AsyncDHCPCapture

::: pydhcp.capture.AsyncDHCPCapture

## DHCPListener

::: pydhcp.listener.DHCPListener

## AsyncDHCPListener

::: pydhcp.listener.AsyncDHCPListener

## DHCPMetrics

Every `DHCPListener` (and therefore `DHCPServer`, `DHCPClient`) owns its own `metrics: DHCPMetrics`
instance — counters are per-instance, not global, so running multiple listeners in one process
(e.g. in tests) never cross-contaminates counts. Call `.snapshot()` for a plain `dict[str, int]`.

::: pydhcp.listener.DHCPMetrics

## pydhcp.client

::: pydhcp.client

## pydhcp.capture

::: pydhcp.capture

## pydhcp.packet

::: pydhcp.packet

## SocketAddress

::: pydhcp.SocketAddress

## NetworkInterface

::: pydhcp.NetworkInterface

## pydhcp.lease

::: pydhcp.lease
