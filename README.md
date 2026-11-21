# Doorward

Doorward is an authentication gateway in front of MCP servers hosted anywhere. People sign
in with an email and a password, an admin decides who may use which server and which tool,
and every request is checked before it reaches a server. It ships as one binary with one
SQLite database.

Status: pre-release (0.1.0).

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/overview-dark.png">
  <img src="docs/images/overview-light.png" alt="The Doorward admin panel: the navigation on the left, a warning about two servers that answer without the gateway, counts of servers, users, invitations and rules, and the latest activity" width="720">
</picture>

## What it does

- **One address per server.** Each MCP server you add gets a path, `https://gateway.example.com/<slug>`.
  A combined endpoint, `/mcp`, offers the tools of every server a person may use, named
  `<path>__<tool>`.
- **Its own OAuth server.** MCP clients discover it, send the person to the gateway's own
  sign-in and consent pages, and get tokens that only work at the gateway. The upstream
  servers never see them.
- **Invitations.** The first person to sign up owns the instance. Everyone else comes in
  through a one-time link that expires, and sets or resets their own password by email.
- **Access rules.** Servers are assigned to people. Allow and deny rules cover all tools,
  one server, or one exact tool. A denied tool is left out of the tool list and refused
  when called.
- **Activity log.** Every sign-in, admin change and tool call is recorded with the person
  who made it.
- **Mail.** Raw SMTP, Resend or Mailgun, set from the admin panel.
- **Both protocol generations.** The session form and the stateless form of MCP over HTTP
  are both served.

## Run with Docker

Two Compose files are in this repository. Copy `.env.example` to `.env`, set
`DOORWARD_PUBLIC_URL`, and follow [docs/DOCKER.md](docs/DOCKER.md).

- `compose.caddy.yaml` runs Caddy in front of the gateway, with automatic HTTPS.
- `compose.yaml` runs the gateway alone, on the host's loopback address, for a proxy or
  tunnel you already run.

## Run the binary

The gateway runs on Linux; Windows is not supported. Build it with Rust 1.89 or newer:

```sh
cargo build --release
```

Write a config file. Four settings are enough to start. `doorward.example.toml` shows the
main settings; the settings table in [docs/DOCKER.md](docs/DOCKER.md#settings) lists all of
them, and every setting can also come from an environment variable.

```toml
public_url = "https://gateway.example.com"
listen = "127.0.0.1:8717"
database = "/var/lib/doorward/doorward.db"
trusted_proxies = ["127.0.0.1", "::1"]
```

`trusted_proxies` names the proxy in front; the two loopback addresses fit a proxy on the same host.
The directory of `database` must exist and be writable by the gateway.

Start it. The config file is read only from `--config` or `DOORWARD_CONFIG`.

```sh
./target/release/doorward --config doorward.toml
```

The first start prints a setup code on standard error. Open `/setup`, enter the code, and
the account you create becomes the owner. The code stops working once an owner exists.
The admin panel is at `/admin`; an admin's account page links to it.

Set up mail in the panel before you need it. A lost password, the owner's included, is
reset by email only: there is no command that sets one.

The encryption key for stored secrets is created next to the database, as a file readable
only by its owner. Back it up with the database: one is useless without the other.

Two more commands exist: `doorward unlock` clears a sign-in block for an account, and
`doorward health` checks a running gateway.

## Put HTTPS in front

The gateway speaks plain HTTP and expects a proxy that terminates TLS: Caddy, nginx, a
tunnel, or a load balancer.

- `public_url` must be `https` unless it is a loopback address.
- Set `trusted_proxies` to the addresses of the proxies you run. The gateway then reads the
  visitor's address from `X-Forwarded-For`, which sign-in throttling and rate limits need.
- With an `https` address and no trusted proxy the gateway refuses to start and says why.
  `shared_client_address = true` accepts that every visitor shares one address instead.

Caddy needs nothing more than the address. It gets the certificate, sends
`X-Forwarded-For` and passes event streams through as they arrive:

```
gateway.example.com {
	reverse_proxy 127.0.0.1:8717
}
```

nginx buffers answers and closes a connection that is silent for 60 seconds unless told
otherwise, which breaks event streams. Inside the `server` block that holds your
certificate:

```
location / {
    proxy_pass http://127.0.0.1:8717;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_buffering off;
    proxy_read_timeout 1h;
}
```

## Add a server and lock it down

In the admin panel, add a server with a name, a path and its upstream address. Then make sure
the server only answers the gateway:

1. Give the server a secret header (a name and a value) and configure the server to refuse
   any request without it. The gateway adds the header to every request it forwards and
   removes the visitor's own credentials.
2. Press "Check lock-down" on the server page. The gateway calls the server without the
   secret and shows one of three states. "Locked down" means the server refused a request
   without the secret. "Answers without the gateway" means anyone who can reach its address
   can use it, gateway or not. "Not checked" means the check has not run yet, or the server
   did not answer the check.
3. Where you can, also restrict the server's network so that only the gateway reaches it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/servers-dark.png">
  <img src="docs/images/servers-light.png" alt="The servers page: each server with its path, tool count, user count and lock-down state" width="720">
</picture>

The gateway never follows redirects from a server, and only relays the answers an MCP
server is expected to give.

Two things to know about server addresses. An admin can point a server at any address the
gateway can reach, one on your private network included, so give the admin role only to
people you would give that reach. And an `http` address carries the secret header
unencrypted between the gateway and the server: use `https` unless the server runs on the
same host or on a network you trust.

## Give people access

Invite a person from the invitations page of the admin panel (`/admin/invitations`). Assign
servers to them from their page or from the server's page. An admin can do this for
anyone, the owner and other admins included; only the owner changes roles and mail
settings. With no matching deny rule, every tool of an assigned server is allowed. Rules
allow or deny all tools, one server, or one exact tool, for one person or for everyone.

## Connect a client

Give the client the address of one server (`https://gateway.example.com/<slug>`) or the
combined endpoint (`https://gateway.example.com/mcp`). Any MCP client that supports
streamable HTTP and OAuth should work: it finds the sign-in pages by itself, and both
client registration methods are supported.

Claude Code:

```sh
claude mcp add --transport http <name> https://gateway.example.com/<slug>
claude mcp login <name>
```

Codex:

```sh
codex mcp add <name> --url https://gateway.example.com/<slug>
codex mcp login <name>
```

The browser opens the gateway's sign-in page, then a consent page that names the client,
the server and the signed-in person. Approve only a sign-in you started yourself.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/consent-dark.png">
  <img src="docs/images/consent-light.png" alt="The consent page on a phone: where the sign-in will be sent, a warning about the client's name, the server, the signed-in person, Approve and Deny" width="320">
</picture>

Each person sees their connected clients on their account page and can disconnect one
there. Claude Code, Codex and the Cursor command line client were run against 0.1.0.

## Limits worth knowing

- Five wrong passwords for one account from one address block further tries on that
  account from that address for 15 minutes. Other limits and all defaults are in
  [docs/DOCKER.md](docs/DOCKER.md#rate-limits).
- A browser page on another origin cannot call the MCP paths unless its origin is listed
  in `allowed_origins`.
- A server's answer larger than `tools_list_bytes` (4 MiB by default) is refused with a
  `502`, whether it is a tool list, a tool result or one event of a stream.
- Access tokens last 60 minutes and refresh tokens rotate. A refresh token presented again
  within 30 seconds gets the same new pair, which covers a lost answer; presented later, it
  ends that client's connection.

## Run the tests

`./check.sh` runs formatting, lints, every test, the dependency audits and the repository
hygiene scan, and prints `CHECK PASS` when all of them pass.

The proof scripts (`scripts/prove-*.sh`, with helpers in `scripts/prove/`) drive real clients
and real HTTP against a throwaway gateway. [CONTRIBUTING.md](CONTRIBUTING.md) describes them.

## Questions and bugs

Bugs and questions go to the repository's issue tracker. Security reports do not: see
[SECURITY.md](SECURITY.md) for how to make one.

## More

- [docs/DOCKER.md](docs/DOCKER.md): containers, every setting, backups, upgrades.
- [docs/DESIGN.md](docs/DESIGN.md): how the gateway is built and why.
- [docs/INTERFACE.md](docs/INTERFACE.md): every page and endpoint.
- [docs/TESTS.md](docs/TESTS.md): the test catalogue.
- [SECURITY.md](SECURITY.md): how to report a vulnerability.
- [CONTRIBUTING.md](CONTRIBUTING.md): how a change is made and checked.

## License

Licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
