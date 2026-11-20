# Run Doorward with Docker

This page covers the image, the two Compose files, the Caddyfile and every setting. Run the
commands from the repository root.

## Choose a variant

- `compose.caddy.yaml` puts Caddy in front of the gateway. Caddy gets a certificate for your
  address and serves HTTPS on ports 80 and 443. The gateway publishes no port on the host.
- `compose.yaml` runs the gateway alone. It is published on the host's loopback address only
  (`127.0.0.1:8717`). Use it when you already run a proxy or a tunnel on the same host.

Without Caddy, the proxy on the host must send an `X-Forwarded-For` header with the client
address. Any process on that host can send that header too, so any process on the host can
choose the address the gateway counts. Run only software you trust on that host.

The gateway has no header-read timeout of its own. Keep a proxy in front of it in both
variants.

## Quick start with Caddy

1. Copy the example file: `cp .env.example .env`
2. Edit `.env` and set `DOORWARD_PUBLIC_URL`, for example `https://doorward.example.com`.
   The name must point to this host, and ports 80 and 443 must reach it from the internet,
   so that Caddy can get a certificate.
3. Build the image: `docker compose -f compose.caddy.yaml build`
4. Start the stack: `docker compose -f compose.caddy.yaml up -d`
5. Read the setup code: `docker compose -f compose.caddy.yaml logs doorward`. Look for the
   line `doorward setup code: <code>`.
6. Open `<DOORWARD_PUBLIC_URL>/setup` in a browser and sign up with the setup code. The first
   person to sign up becomes the owner. After that, only invitations open new accounts.

To use another HTTPS port, set `HTTPS_PORT` in `.env` and put the same port in
`DOORWARD_PUBLIC_URL`, for example `https://doorward.example.com:8443`. The two must match,
because Caddy listens on the port in the address and the host publishes that same number.

The Compose file follows the `caddy:2.11` tag, so patch releases with security fixes arrive
on `docker compose -f compose.caddy.yaml pull`. A person who wants a frozen image can append
`@sha256:<digest>` to the `image: caddy:2.11` line.

## Quick start without Caddy

1. Copy the example file: `cp .env.example .env`
2. Edit `.env` and set `DOORWARD_PUBLIC_URL` to the address your proxy serves, with `https`.
3. Build the image: `docker compose -f compose.yaml build`
4. Start the gateway: `docker compose -f compose.yaml up -d`
5. Point your proxy at `http://127.0.0.1:8717` and make it send `X-Forwarded-For`.
6. Read the setup code with `docker compose -f compose.yaml logs doorward`, then sign up in
   the browser at `<DOORWARD_PUBLIC_URL>/setup`.

Plain `http` is accepted only for `localhost` and other loopback hosts, for a test on the
host itself.

## Settings

Every setting is an environment variable named `DOORWARD_` followed by the setting's name in
capitals, with the sections joined by `_`. The containers read only environment variables;
no config file is mounted. An empty value means not set. Lists are comma separated.
Booleans are `true` or `false`.

An unknown `DOORWARD_` name, or a value that does not parse, stops the gateway at start. The
message names the variable and never prints the value.

| Variable | Default | Meaning |
|---|---|---|
| `DOORWARD_PUBLIC_URL` | required | Public address: `https`, a host name, and a port only when it is not 443. Mail links use it. |
| `DOORWARD_LISTEN` | `127.0.0.1:8717` | Address and port the gateway listens on. The containers set `0.0.0.0:8717`. |
| `DOORWARD_DATABASE` | required | Path of the SQLite database file. The containers set `/data/doorward.db`. |
| `DOORWARD_KEY_FILE` | (none) | File that holds the encryption key. When unset, the key file is the database path with `.key` added. |
| `DOORWARD_TRUSTED_PROXIES` | (none) | Addresses or CIDR ranges of proxies whose `X-Forwarded-For` is believed. A range that holds every address (prefix 0) refuses the start. See Client addresses. |
| `DOORWARD_SHARED_CLIENT_ADDRESS` | `false` | Set to `true` to accept that every visitor shares one address when no trusted proxy is set. |
| `DOORWARD_ALLOWED_ORIGINS` | (none) | Comma separated origins, other than the public address, that may call the MCP paths, for a browser client served from another origin such as an extension. Each entry is `scheme://host[:port]` and is compared exactly. |
| `DOORWARD_LIFETIMES_INVITATION_DAYS` | `7` | Days an invitation link works. |
| `DOORWARD_LIFETIMES_RESET_MINUTES` | `60` | Minutes a password reset link works. |
| `DOORWARD_LIFETIMES_SESSION_HOURS` | `12` | Hours a browser session lasts. |
| `DOORWARD_LIFETIMES_AUTH_REQUEST_MINUTES` | `10` | Minutes a sign-in request for a client stays usable. |
| `DOORWARD_LIFETIMES_AUTH_CODE_SECONDS` | `60` | Seconds an authorization code works, once. |
| `DOORWARD_LIFETIMES_ACCESS_TOKEN_MINUTES` | `60` | Minutes an access token works. |
| `DOORWARD_LIFETIMES_REFRESH_TOKEN_DAYS` | `30` | Days a refresh token works. |
| `DOORWARD_LIFETIMES_FAMILY_DAYS` | `90` | Days one client connection (a token family) may last. |
| `DOORWARD_LIFETIMES_REFRESH_REPLAY_SECONDS` | `30` | Seconds in which a just-used refresh token may be presented again. `0` turns this off. |
| `DOORWARD_LIMITS_BODY_BYTES` | `1048576` | Largest request body in bytes. Caddy uses the same limit. |
| `DOORWARD_LIMITS_TOOLS_LIST_BYTES` | `4194304` | Largest answer in bytes that a server may send in one piece: a tool list, any other JSON answer such as a tool result, or one event of a stream. A larger one is refused with `502`. |
| `DOORWARD_LIMITS_UPSTREAM_TIMEOUT_SECONDS` | `300` | Seconds an upstream server may stay silent before the call ends. At most `86400` (one day); a larger value refuses the start. |
| `DOORWARD_LIMITS_ACCOUNT_FAILURES` | `5` | Wrong passwords for one account from one client address, inside `DOORWARD_LIMITS_BLOCK_MINUTES`, after which a sign-in to that account from that address answers `429`, right password included. Other addresses are not affected. |
| `DOORWARD_LIMITS_ACCOUNT_CEILING` | `50` | Wrong passwords for one account from all client addresses together, inside `DOORWARD_LIMITS_BLOCK_MINUTES`, that block the account for every address. Must be at least `DOORWARD_LIMITS_ACCOUNT_FAILURES`. |
| `DOORWARD_LIMITS_ADDRESS_FAILURES` | `30` | More than this many wrong passwords from one client address, for any accounts, inside `block_minutes` make that address answer `429`. |
| `DOORWARD_LIMITS_BLOCK_MINUTES` | `15` | Minutes a wrong password stays counted. Each one stops counting this long after it was made. |
| `DOORWARD_LIMITS_DCR_PER_HOUR` | `60` | Client registrations per client address per hour. |
| `DOORWARD_LIMITS_UNUSED_REGISTRATIONS` | `10000` | Most registered clients that have never completed a sign-in. At the bound the oldest such client is dropped to make room; a client that has completed a sign-in is never dropped for this. Must be at least 1. |
| `DOORWARD_LIMITS_GENERAL_BURST` | `240` | General class, per address: requests allowed at once. |
| `DOORWARD_LIMITS_GENERAL_PER_MINUTE` | `600` | General class, per address: sustained requests per minute. |
| `DOORWARD_LIMITS_OAUTH_BURST` | `60` | OAuth class, per address: requests allowed at once. |
| `DOORWARD_LIMITS_OAUTH_PER_MINUTE` | `120` | OAuth class, per address: sustained requests per minute. |
| `DOORWARD_LIMITS_CREDENTIALS_BURST` | `20` | Credentials class, per address: requests allowed at once. |
| `DOORWARD_LIMITS_CREDENTIALS_PER_MINUTE` | `20` | Credentials class, per address: sustained requests per minute. |
| `DOORWARD_LIMITS_MCP_BURST` | `240` | MCP class, per user: requests allowed at once. |
| `DOORWARD_LIMITS_MCP_PER_MINUTE` | `600` | MCP class, per user: sustained requests per minute. |
| `DOORWARD_LIMITS_MCP_OPEN` | `64` | Most MCP requests and streams one user may have open at the same time. |
| `DOORWARD_LIMITS_RATE_TABLE_KEYS` | `100000` | Most addresses and users the rate limiter keeps counters for at once. |
| `DOORWARD_LIMITS_AUTH_REQUESTS_MAX` | `10000` | Most pending sign-in requests kept at once. Past it the oldest are dropped, so a flood from many addresses can make a person who is in the middle of a sign-in start again. |
| `DOORWARD_LIMITS_CATALOG_REFRESH_SECONDS` | `30` | Least seconds between two refreshes of one server's tool list that a call for a tool missing from the list starts. A call that finds a refresh running waits for it. Must be at least `1`. |
| `DOORWARD_LIMITS_ACTIVITY_DAYS` | `90` | Days an activity row is kept. The housekeeping run deletes older rows. Must be at least `1`. |
| `DOORWARD_MAIL_SMTP_CA_FILE` | (none) | PEM file with extra trusted roots for SMTP over TLS. |

Names that are not settings:

| Name | Meaning |
|---|---|
| `DOORWARD_KEY` | The encryption key itself, as 64 hexadecimal characters. Use a key file instead. Do not put it in `.env`. |
| `DOORWARD_CONFIG` | Path of a TOML config file. The containers do not use one. |

Mail settings, the setup code, the first owner and upstream secrets are not environment
settings. Set mail and upstream secrets in the admin panel.

## Hardening keys

Each key in the Compose files, and what it is for:

| Key | What it is for |
|---|---|
| `read_only: true` | The root file system is read-only, so a process cannot change the program or other files. |
| `cap_drop: [ALL]` | No Linux capabilities: no raw network access, no mounts, no ownership changes. |
| `security_opt: no-new-privileges:true` | A process cannot gain privileges, for example through a setuid binary. |
| `user: "65532:65532"` | The gateway runs as a fixed user that is not root. The image sets the same user. |
| `pids_limit: 1024` | Caps processes and threads, so a fork loop cannot exhaust the host. |
| `mem_limit: 512m` | Caps memory. |
| `cpus: 2` | Caps CPU time. |
| `ulimits.nofile: 65536` | Caps open files and sockets. |
| `stop_grace_period: 15s` | Time for requests to finish before a forced stop. |
| `logging` with `max-size` and `max-file` | Caps the disk space the container logs use. |
| `restart: unless-stopped` | Starts the container again after a crash or a reboot, but not after a manual stop. |
| `tmpfs: /tmp` | Scratch space for SQLite, in memory and small; it is empty after each restart. |
| `internal: true` on `proxy` | The proxy network has no route out, so only Caddy and the gateway are on it. |
| `ipv4_address` and `ipam` subnets | Fixed addresses, so the gateway trusts exactly one proxy address. |
| `ports: 127.0.0.1:8717:8717` | The gateway port is published on loopback only. |
| `enable_ipv6: true` on `edge` | IPv6 for Caddy's public side. Remove it on a host without IPv6. |

Caddy keeps the image's default user. All its capabilities are still dropped.

## Data: database, key file and backups

The database and its key file are one unit. The key file sits next to the database in the
volume, `/data/doorward.db.key`, and holds the key that encrypts mail and upstream secrets.
A database without its exact key will not start. There is no recovery command for a lost key.

The volume is `doorward-data`. Caddy keeps its certificates in `caddy-data`.

### Backup

A backup holds the key, so treat the archive as a secret. Stop the stack first, so the
database is not written during the copy. The archive is private and owned by you:

```
docker compose -f compose.caddy.yaml stop
mkdir -p backup
docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v doorward-data:/data:ro -v "$PWD/backup:/backup" busybox sh -c \
  'umask 077 && tar -C /data -czf /backup/doorward-data.tar.gz . && chown "$HOST_UID:$HOST_GID" /backup/doorward-data.tar.gz'
docker compose -f compose.caddy.yaml start
```

For `compose.yaml`, use the same commands with that file name.

### Restore

A restore replaces everything in the volume. Stop the stack first:

```
docker compose -f compose.caddy.yaml stop
docker run --rm -v doorward-data:/data -v "$PWD/backup:/backup:ro" busybox \
  sh -c 'rm -rf /data/* /data/.[!.]* ; tar -C /data -xzf /backup/doorward-data.tar.gz'
docker compose -f compose.caddy.yaml start
```

### Upgrade

Back up first. Update the sources, build the image again, and start the stack. The gateway
migrates its database by itself at start.

```
docker compose -f compose.caddy.yaml build
docker compose -f compose.caddy.yaml up -d
```

### Separate key file

By default the key lives in the volume beside the database. You can keep it outside the
volume instead, as a file that the container reads through a bind mount:

1. Create a key with 64 hexadecimal characters: `openssl rand -hex 32 > doorward.key`
2. Make the file owned by user 65532 and private: `sudo chown 65532:65532 doorward.key`
   and `chmod 600 doorward.key`. The gateway refuses a key file that others can read.
3. Set `DOORWARD_KEY_FILE=/run/secrets/doorward.key` in `.env`.
4. Mount the file read-only into the `doorward` service, under its `volumes:` key:
   `- ./doorward.key:/run/secrets/doorward.key:ro`

If the file is missing on the host, Docker creates a directory in its place. Create the
file before the first start.

## Unlock an account

A sign-in block ends by itself: each wrong password stops counting
`DOORWARD_LIMITS_BLOCK_MINUTES` after it was made. A block is for one account from one
client address, unless the account reached `DOORWARD_LIMITS_ACCOUNT_CEILING` wrong
passwords from all addresses together: then it is blocked for everyone. A password reset
by mail ends every block of the account. To end them now without mail, run the gateway's
own `unlock` command in the running container.
The image has no shell, but the binary runs directly:

```
docker compose -f compose.caddy.yaml exec doorward /usr/local/bin/doorward unlock user@example.com
```

It prints `unlocked user@example.com` and exits 0, and the unlock is written to the activity
log. When no account has that address it exits 1 with
`doorward: no account has that email address` and changes nothing. When the database file
does not exist it exits 1 with `doorward: no database at <path>` and creates nothing. For
`compose.yaml`, use that file name.

## Rate limits

The gateway limits request rates itself, so the limits are the same with or without Caddy.

| Class | Counted per | Covers | Default burst / per minute |
|---|---|---|---|
| general | client address | Everything not listed, and anonymous or refused requests on MCP paths | 240 / 600 |
| oauth | client address | `POST /oauth/token`, `POST /oauth/register`, `GET /oauth/authorize` | 60 / 120 |
| credentials | client address | Sign-in, setup, forgot password, invitation, reset, password change, disconnect pages | 20 / 20 |
| mcp | user | Every request that passed the bearer check | 240 / 600 |
| mcp_open | user | MCP requests and streams open at the same time | 64 |

IPv6 clients are counted by their /64. A caller that passed the bearer check is counted per
user, not per address, so users of one shared client address do not share a bucket.

A limited client gets `429` with an integer `Retry-After` in seconds. The answer has
`Cache-Control: no-store` and no `WWW-Authenticate`. Token and registration endpoints answer
JSON with the error `too_many_requests`. MCP paths answer JSON-RPC error `-32029`. A limited
request changes no state and reaches no upstream.

Counters live in memory and reset on restart. Password guessing stays covered by the
database throttle, which survives restarts. A flood of failing requests from one shared
address can block that address for everyone behind it.

## Client addresses

The gateway counts requests by client address. It takes the address from the socket peer,
unless the peer is in `DOORWARD_TRUSTED_PROXIES`. Then it takes the last `X-Forwarded-For`
entry that is not itself a trusted proxy.

- `DOORWARD_TRUSTED_PROXIES` takes addresses or CIDR ranges, comma separated. Keep it to the
  proxies you run. A `/0` entry trusts every peer and must never be used.
- The gateway refuses to start when `DOORWARD_PUBLIC_URL` is `https` and no trusted proxy is
  set. The message says how to fix it. `DOORWARD_SHARED_CLIENT_ADDRESS=true` accepts the
  refusal instead: the gateway then starts, logs one warning, and every visitor shares one
  address for sign-in throttling and rate limits.
- Rootless Docker and Docker Desktop do not pass client addresses. The gateway logs a
  warning once. Use `DOORWARD_SHARED_CLIENT_ADDRESS=true`, or a proxy on the host.
- On an IPv4-only edge network, IPv6 clients show as the bridge gateway address and share
  one bucket.
- The shipped Compose files trust one exact address each: `10.213.87.2` for Caddy in
  `compose.caddy.yaml`, and `10.213.87.9` for the host's bridge in `compose.yaml`.
- Hosts without IPv6 must remove `enable_ipv6: true` from the `edge` network in
  `compose.caddy.yaml`.

## Health

The image's health check runs `doorward health` every 30 seconds. It asks `/healthz` on the
listen address, which reads the database: the check passes only while the database answers.
A failing check exits 1 with one line on standard error, and the gateway's own line
`doorward: health check failed: <error>` names the cause.

## Logs

The gateway writes to standard error. A failure inside it writes one line, in one of these
shapes:

- `doorward: <what> failed: <error>`, for example `doorward: sign-in failed: database error: database is locked`.
  The page or answer the request gets is unchanged, except a bearer check that cannot read
  the database, which answers `503`.
- `doorward: upstream <slug> failed: <phrase>`, when an upstream answer cannot be used. The phrase is one
  fixed text, such as `no answer in time`; only the server's slug is written.
- `doorward: tool list failed: tools/list: <slug> ...`, when a tool list leaves tools or a server out. It
  names the server's slug and a count, never a tool.
- `doorward: token refused: <reason>`, when a code or refresh token that exists is refused.
  The reason is one fixed phrase, such as `the verifier does not match`. A code or token
  that matches no row writes nothing.
- `doorward: client metadata for <host> failed: <error>`, when a client metadata document
  cannot be fetched. Only the host of the client ID is written, never its path or query.
- `doorward: health check failed: <error>`, when `/healthz` cannot read the database.
- At start-up, a file that cannot be used exits 2 with the file's path and the cause:
  `doorward: cannot read the config file <path>: <error>`,
  `doorward: cannot open the database <path>: <error>`,
  `doorward: cannot read the key file <path>: <error>` or
  `doorward: cannot create the key file <path>: <error>`.

No failure line holds a password, an email address, a token, a code, a cookie, a request
body or a full URL. The setup code printed at first start is the one secret line, and it is
unchanged.
