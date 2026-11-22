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

`IMAGE` sets the name of the image that both Compose files build and run. Compose reads it from
`.env` to fill the `image:` line; the gateway does not read it, so it is not in the settings
table. When it is unset, the image is `doorward:local`, built from this repository.

To use another HTTPS port, set `HTTPS_PORT` in `.env` and put the same port in
`DOORWARD_PUBLIC_URL`, for example `https://doorward.example.com:8443`. The two must match,
because Caddy listens on the port in the address and the host publishes that same number.

The Compose file pins `caddy:2.11` by digest, so `docker compose -f compose.caddy.yaml pull`
does not fetch a newer Caddy release. Caddy security fixes reach the stack only when the pin
changes. To update Caddy, change both the tag and the digest on the
`image: caddy:2.11@sha256:...` line.

### What the Caddyfile does

- The admin API is off (`admin off`), so nothing can change the running configuration.
- Request bodies over `DOORWARD_LIMITS_BODY_BYTES` get `413` at Caddy, before the gateway sees
  them. The default is `1048576` bytes, the same limit the gateway uses.
- Streamed answers pass through unbuffered (`flush_interval -1`), so event streams are not held
  back.
- For `/oauth/token` and `/oauth/register` only, an error with status 502 to 504, such as an
  unreachable gateway, is answered with `503`, `Content-Type: application/json` and the body
  `{"error":"temporarily_unavailable"}`. Other paths and other statuses keep their own status.

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
| `DOORWARD_SHARED_CLIENT_ADDRESS` | `false` | Set to `true` to accept that every visitor shares one address when no trusted proxy is set. Every visitor then shares one set of address rate limits and one sign-in block, so anyone on the internet can lock out every user and client with junk requests or wrong passwords. Use it only on a private network where every visitor is trusted. |
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
| `DOORWARD_LIMITS_BODY_READ_SECONDS` | `15` | Seconds a client has to send a request body. A slower body is answered with `408` and the connection is closed. At most `300`; a larger value refuses the start. |
| `DOORWARD_LIMITS_WRITE_STALL_SECONDS` | `30` | Seconds a connection may make no progress on a write, such as a client that does not read its answer, before the gateway closes it. An answer the client has not read holds its memory until the client takes it or the connection is closed. At most `300`; a larger value refuses the start. |
| `DOORWARD_LIMITS_TOOLS_LIST_BYTES` | `4194304` | Largest answer in bytes that a server may send in one piece: a tool list, any other JSON answer such as a tool result, or one event of a stream. A larger JSON answer from one server is refused with `502`, and a larger stream event ends that stream. On the combined endpoint, a server whose answer is too large, or whose tools would take the merged list over this size, is left out of the list instead, and the gateway logs which one. |
| `DOORWARD_LIMITS_ANSWER_MEMORY_BYTES` | `33554432` | Bytes of server answers the gateway holds in memory at once, across all users. One user's requests together hold at most a quarter of it, or `DOORWARD_LIMITS_TOOLS_LIST_BYTES` when that is more. When either is used up, further answers get `503` with `Retry-After` until memory is released. Must be at least `DOORWARD_LIMITS_TOOLS_LIST_BYTES`. An answer that a client has not read keeps its place until the client takes it or the connection is closed for making no progress (see `DOORWARD_LIMITS_WRITE_STALL_SECONDS`). |
| `DOORWARD_LIMITS_UPSTREAM_TIMEOUT_SECONDS` | `300` | Seconds an upstream server may stay silent before the call ends. At most `86400` (one day); a larger value refuses the start. |
| `DOORWARD_LIMITS_ACCOUNT_FAILURES` | `5` | Wrong passwords for one account from one client address, inside `DOORWARD_LIMITS_BLOCK_MINUTES`, after which a sign-in to that account from that address answers `429`, right password included. Other addresses are not affected. |
| `DOORWARD_LIMITS_ACCOUNT_CEILING` | `50` | Wrong passwords for one account from all client addresses together, inside `DOORWARD_LIMITS_BLOCK_MINUTES`, that block the account for every address. Must be at least `DOORWARD_LIMITS_ACCOUNT_FAILURES`. |
| `DOORWARD_LIMITS_ADDRESS_FAILURES` | `30` | More than this many wrong passwords from one client address, for any accounts, inside `block_minutes` make that address answer `429`. |
| `DOORWARD_LIMITS_BLOCK_MINUTES` | `15` | Minutes a wrong password stays counted. Each one stops counting this long after it was made. |
| `DOORWARD_LIMITS_DCR_PER_HOUR` | `60` | Client registrations per client address per hour. |
| `DOORWARD_LIMITS_UNUSED_REGISTRATIONS` | `10000` | Most registered clients that have never completed a sign-in. At the bound the oldest such client is dropped to make room; a client that has completed a sign-in is never dropped for this. Must be at least 1. A flood of registrations from many addresses can push out a client that registered but has not finished its first sign-in; it registers again on its next try. |
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

The mail provider, its addresses and its secrets, the setup code, the first owner and
upstream secrets are not environment settings. Mail and upstream secrets are set in the admin
panel. The one mail setting that does come from the environment is the SMTP CA file,
`DOORWARD_MAIL_SMTP_CA_FILE`.

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

`compose.yaml` sets these keys on its one service, `doorward`. It has no `proxy` or `edge`
network and no `ipv4_address`, so `internal`, `enable_ipv6` and `ipv4_address` are absent there.
`compose.caddy.yaml` sets the service keys on both `caddy` and `doorward`, except `user` and
`tmpfs`, which only `doorward` sets, and the gateway's `ports`, which that file does not set.

Caddy keeps the image's default user. All its capabilities are still dropped.

A stop signal, such as `docker compose stop`, starts the gateway's own stop: it stops accepting
connections and waits up to 10 seconds for open requests, such as a stream that is still
running. Then it exits 0, writing `doorward: stopped with requests still open` if any remain.
Docker's `stop_grace_period` of 15 seconds is therefore longer than the gateway's own wait.
A streamed call that is cut at the 10 seconds leaves no row in the activity log.

## Data: database, key file and backups

The database and its key file are one unit. The key file sits next to the database in the
volume, `/data/doorward.db.key`, and holds the key that encrypts mail and upstream secrets.
A database without its exact key will not start. There is no recovery command for a lost key.

The volume is `doorward-data`. Caddy keeps its certificates in `caddy-data`.

### Backup

A backup holds the key, so treat the archive as a secret: with the key in it, the archive
opens the mail and upstream secrets. Credentials that people stored for servers stay sealed
even then, because they also need that person's password or a live sign-in of theirs. To
keep the key apart, copy the key file somewhere else and leave it out of the archive; a
restore needs both. Stop the stack first, so the
database is not written during the copy. The archive is private and owned by you:

```
docker compose -f compose.caddy.yaml stop
mkdir -p backup
docker run --rm -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v doorward-data:/data:ro -v "$PWD/backup:/backup" busybox:1.37 sh -c \
  'umask 077 && tar -C /data -czf /backup/doorward-data.tar.gz . && chown "$HOST_UID:$HOST_GID" /backup/doorward-data.tar.gz'
docker compose -f compose.caddy.yaml start
```

For `compose.yaml`, use the same commands with that file name.

### Restore

A restore replaces everything in the volume. Stop the stack first:

```
docker compose -f compose.caddy.yaml stop
docker run --rm -v doorward-data:/data -v "$PWD/backup:/backup:ro" busybox:1.37 \
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

The registration limit counts an address's attempts; registration attempts are kept for one hour, so it counts only the last hour. The table holds at most the registrations per address limit (`DOORWARD_LIMITS_DCR_PER_HOUR`) rows for each address that registered in that hour.

## Client addresses

The gateway counts requests by client address. It takes the address from the socket peer,
unless the peer is in `DOORWARD_TRUSTED_PROXIES`. Then it takes the last `X-Forwarded-For`
entry that is not itself a trusted proxy.

- `DOORWARD_TRUSTED_PROXIES` takes addresses or CIDR ranges, comma separated. Keep it to the
  proxies you run. A `/0` entry would trust every peer, so the gateway refuses to start with one.
- The gateway refuses to start when `DOORWARD_PUBLIC_URL` is `https` and no trusted proxy is
  set. The message says how to fix it. `DOORWARD_SHARED_CLIENT_ADDRESS=true` accepts the
  refusal instead: the gateway then starts, logs one warning, and every visitor shares one
  address for sign-in throttling and rate limits. Then everyone shares one set of address rate
  limits and one sign-in block, so anyone on the internet can lock out every user and client by
  sending junk requests or wrong passwords. Use it only on a private network where every visitor
  is trusted. For an install reachable from the internet, list the proxy in
  `DOORWARD_TRUSTED_PROXIES` and have it send `X-Forwarded-For`, as the entries above describe.
- Rootless Docker and Docker Desktop may not pass the real client address. The gateway logs a
  warning once when it sees a private client address. On a public install, run a proxy on the
  host that sends `X-Forwarded-For`, and list it in `DOORWARD_TRUSTED_PROXIES`. Use
  `DOORWARD_SHARED_CLIENT_ADDRESS=true` only on a private network where every visitor is trusted.
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
`doorward: health check failed: <error>` names the cause. The check comes from the loopback
address, so it never uses up a rate limit budget. A request counts as
the host's own only when its client address is loopback and it carries no
`X-Forwarded-For` header. Behind a proxy on the same host that sends no `X-Forwarded-For`,
the gateway cannot tell visitors from the host, and `/healthz` is not limited for anyone.

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
- `doorward: client metadata for <host> failed: <reason>`, when a fetched document does not fit: the
  reason is `the document names another client`, `the document asks for a client secret` or
  `the document does not list the redirect address`.
- `doorward: access check failed: <error>`, when the database cannot answer a re-check of an admitted
  call or an open stream. The call ends `unavailable` with the detail `the access check could not be done`.
- `doorward: server <slug> failed: the stored secret cannot be opened`, when a server's stored secret
  cannot be read. The call ends `unavailable`.
- `doorward: password check failed: the stored hash cannot be read`, when a stored password hash cannot
  be read. The sign-in is refused as a wrong password.
- `doorward: mail settings failed: <error>`, when the mail settings cannot be read, and
  `doorward: mail failure record failed: <error>`, when a failed mail cannot be recorded.
- `doorward: health check failed: <error>`, when `/healthz` cannot read the database.
- `doorward: stopping, waiting up to 10 seconds for open requests`, on the first stop signal.
  Not a failure.
- `doorward: stopped with requests still open`, when the wait ends with requests still open.
  Not a failure; the gateway then exits 0.
- At start-up, a file that cannot be used exits 2 with the file's path and the cause:
  `doorward: cannot read the config file <path>: <error>`,
  `doorward: cannot open the database <path>: <error>`,
  `doorward: cannot read the key file <path>: <error>` or
  `doorward: cannot create the key file <path>: <error>`.

No failure line holds a password, an email address, a token, a code, a cookie, a request
body or a full URL. The setup code printed at first start is the one secret line, and it is
unchanged.
