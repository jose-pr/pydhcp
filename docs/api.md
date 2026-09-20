# API Reference

This section provides references for the primary classes in the `pydhcp` package.

## DhcpMessage

::: pydhcp.packet.message.DhcpMessage

## DhcpOptions

::: pydhcp.options.DhcpOptions

## DhcpOptionCode

The standard IANA option-code registry: an `IntEnum` whose members carry, in their own
docstrings, the RFC text that defines each option. Codes without a member resolve to an
opaque pseudo-member (`get_type()` returns `Bytes`, `label()` reports `UNKNOWN`) rather
than raising, so an unknown code never costs a client its lease.

::: pydhcp.options.DhcpOptionCode
    options:
      # Load-bearing, measured 2026-09-20: without it only the 82 members that carry an
      # RFC docstring render and the other 81 codes vanish from the registry listing.
      members: true

## BaseDhcpOptionCode

The base any custom code map subclasses; pass one to `DhcpOptions(codemap=...)` to
serve a private or vendor option space instead of the IANA registry above.

::: pydhcp.options.BaseDhcpOptionCode
    options:
      # Same reason as DhcpOptionCode: nothing on this class carries a docstring, so
      # without `members: true` the heading renders with no body at all.
      members: true

## DhcpOption

::: pydhcp.options.DhcpOption
    options:
      members: true

## Option Types

::: pydhcp.options.type

## DhcpServer

::: pydhcp.server.DhcpServer

## DhcpClient

::: pydhcp.client.DhcpClient

## DhcpRelay

::: pydhcp.relay.DhcpRelay

## DhcpCapture

::: pydhcp.capture.DhcpCapture

## CaptureEvent

::: pydhcp.capture.CaptureEvent

## AsyncDhcpServer

::: pydhcp.server.AsyncDhcpServer

## DhcpListener

::: pydhcp.listener.DhcpListener

## AsyncDhcpListener

::: pydhcp.listener.AsyncDhcpListener

## DhcpMetrics

Every `DhcpListener` (and therefore `DhcpServer`, `DhcpClient`) owns its own `metrics: DhcpMetrics`
instance — counters are per-instance, not global, so running multiple listeners in one process
(e.g. in tests) never cross-contaminates counts. Call `.snapshot()` for a plain `dict[str, int]`.

::: pydhcp.metrics.DhcpMetrics

## pydhcp.client

::: pydhcp.client

## pydhcp.capture

::: pydhcp.capture

## pydhcp.packet

::: pydhcp.packet

## pydhcp.network

::: pydhcp.network

## pydhcp.lease

::: pydhcp.lease
