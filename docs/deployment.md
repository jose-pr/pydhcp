# Deployment

`pydhcp` is a pure-Python library, so deployment is mostly about running it with the right permissions and network layout.

## Production checklist

1. Run the server under a dedicated service account.
2. Make sure the host can bind the DHCP ports you expect to use.
3. Confirm the selected interface has the address range you want to serve.
4. Keep lease persistence enabled if you need stable client assignment across restarts.

## systemd

For Linux services, run the server from a unit that starts the CLI entry point directly.

```ini
[Unit]
Description=pydhcp server
After=network-online.target

[Service]
ExecStart=/opt/pydhcp/.venv/bin/pydhcp server --help
Restart=on-failure
User=pydhcp
Group=pydhcp

[Install]
WantedBy=multi-user.target
```

Replace `--help` with the server arguments you actually want in production. The CLI accepts JSON or INI configuration files through `--config`.

## Docker

The server can also run inside a container if the container is allowed to bind the needed UDP ports and see the host network.

- Prefer host networking for real DHCP service.
- Mount configuration and lease storage explicitly.
- Keep logs on stdout/stderr so orchestrators can collect them.

## Operational notes

- Use the CLI `interfaces` command to confirm interface detection before serving traffic.
- If you are debugging packet flow, turn on debug logging and look for the transaction ID in the output.
- Keep an eye on lease backend state after restarts if you are not using the in-memory backend.
