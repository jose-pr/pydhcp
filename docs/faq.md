# FAQ

## Why does the server use a synthetic interface on loopback?

In sandboxed or minimal environments, interface enumeration may not return a matching `NetworkInterface` record for `127.0.0.1`. The server falls back to a synthetic interface so tests and local demos still work.

## Why are some clients sent broadcast replies?

If the server cannot send a direct unicast packet to the requested address, it falls back to broadcast delivery. That keeps local development usable even when the requested lease address is not reachable from the host network.

## Why are the docs split into several short pages?

The project has a few different operational concerns now: API reference, examples, deployment, and troubleshooting. Keeping them separate makes it easier to find the right piece without scrolling through a giant wall of text.
