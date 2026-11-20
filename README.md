# Doorward

Doorward is an authentication gateway in front of MCP servers hosted anywhere. An admin decides which people may use which servers, and every request is checked before it reaches a server. It ships as one binary with one config file and one SQLite database.

Status: under construction.

## Run with Docker

Two Compose files are in this repository. Copy `.env.example` to `.env` and set
`DOORWARD_PUBLIC_URL`. Then follow [docs/DOCKER.md](docs/DOCKER.md).

- `compose.caddy.yaml` runs Caddy in front of the gateway, with automatic HTTPS.
- `compose.yaml` runs the gateway alone, on the host's loopback address, for a proxy or
  tunnel you already run.

The first start prints a setup code in the logs. The first person to sign up with it
becomes the owner.

## License

Licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
