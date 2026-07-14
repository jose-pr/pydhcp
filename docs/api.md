# API Reference

This section provides references for the primary classes in the `pydhcp` package.

## DhcpMessage

::: pydhcp.packet.message.DhcpMessage

## DhcpOptions

::: pydhcp.options.DhcpOptions

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
