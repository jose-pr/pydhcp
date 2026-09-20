# Deployment

`pydhcp` is a pure-Python library, so deployment is mostly about running it with the right permissions and network layout. Packet parsing and structured packet tooling are portable; DHCP serving depends on the host OS allowing the needed UDP binds and broadcasts.

## Production checklist

1. Run the server under a dedicated service account.
2. Make sure the host can bind the DHCP ports you expect to use.
3. Confirm the selected interface has the address range you want to serve.
4. Pass `--lease-file /var/lib/pydhcp/leases.json` if you need stable client
   assignment across restarts. Without it the server keeps leases in memory
   only, and every client renumbers when the process restarts.
5. Implement address-pool policy in a `DhcpServer` subclass or custom lease backend before serving a real network.

The built-in server is a base implementation, not a full IPAM system. It is useful for
simple deployments, tests, and custom services, but production pools, reservations, and
site policy should live in your own subclass or backend.

## systemd

For Linux services, run the server from a unit that starts the CLI entry point directly.

```ini
[Unit]
Description=pydhcp server
After=network-online.target

[Service]
ExecStart=/opt/pydhcp/.venv/bin/pydhcp server --config /etc/pydhcp/server.yaml
Restart=on-failure
User=pydhcp
Group=pydhcp

[Install]
WantedBy=multi-user.target
```

The CLI accepts JSON, YAML, TOML and INI configuration files through `--config` (TOML needs Python 3.11+ or the `pydhcp[toml]` extra). An explicit `--listen` overrides whatever the file says.

Port 67 is privileged: run the unit as root, or grant the interpreter the capability once with
`sudo setcap 'cap_net_bind_service=+ep' /opt/pydhcp/.venv/bin/python3` and keep `User=pydhcp`. Without one of the two the service fails to bind, which pydhcp reports as a `PermissionError` naming the port.

## Docker

The server can also run inside a container if the container is allowed to bind the needed UDP ports and see the host network.

- Prefer host networking for real DHCP service.
- Mount configuration and lease storage explicitly, and point `--lease-file`
  at the mounted path — a mounted volume stays empty unless the server is
  told to write to it.
- Keep logs on stdout/stderr so orchestrators can collect them.

## Operational notes

- Use the CLI `interfaces` command to confirm interface detection before serving traffic.
- If you are debugging packet flow, raise the level (`-v`, repeatable, or
  `--loglevel pydhcp:DEBUG`) and look for the transaction ID — every packet
  line carries `[XID=...]`. Components log under `pydhcp.<module>`, so
  `--loglevel pydhcp.listener:DEBUG` narrows it to the receive path.
- After a restart, check the lease file is being written: `FileLeaseBackend`
  rewrites it on every mutation by default, and a deployment that raises
  `SAVE_INTERVAL_SECONDS` to coalesce writes trades up to one interval of
  leases on a crash.
