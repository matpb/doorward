# Doorward design (v1)

Status: draft under review. Statement numbers (S1 to S31) refer to `CLAUDE.md`.

## Shape

One Rust crate, library plus binary. The library exposes `build(config, deps) -> Router` so
tests start the real gateway in-process on a free local port and talk to it over real HTTP.
`deps` carries the only seams: clock, Client ID Metadata Document fetcher, DNS resolver.

Modules. The four marked (auth) are the reviewed security core and import nothing from the
others except `db`, `crypto`, `config`.

| Module | Job |
|---|---|
| `config` | TOML file: `public_url`, listen address, database path, key file, trusted proxies, lifetimes, limits |
| `db` | SQLite (WAL), embedded migrations run at start |
| `crypto` | token generation, SHA-256 token hashing, secret encryption (XChaCha20-Poly1305), Argon2id |
| `accounts` (auth) | users, roles, setup code, invitations, password reset, browser sessions, CSRF, login throttling |
| `oauth` (auth) | metadata, authorize, consent, token endpoint, client registration (CIMD and DCR) |
| `guard` (auth) | bearer check for MCP paths: token, resource, user status, assignment |
| `policy` (auth) | tool rule evaluation |
| `proxy` | per-server pass-through |
| `combined` | the combined endpoint: MCP server to the client, MCP client to upstreams |
| `mcp` | strict JSON-RPC parsing, both protocol generations, SSE reading |
| `mail` | `Mailer` trait with SMTP, Resend and Mailgun providers |
| `audit` | activity log |
| `admin` | panel and account pages, server-rendered HTML, no script required |

## HTTP surface

`public_url` is the issuer and the base of every link, including emailed ones. Request
headers such as `Host` or `X-Forwarded-Host` never influence it.

Reserved first path segments: `.well-known`, `oauth`, `login`, `logout`, `setup`, `invite`,
`forgot`, `reset`, `account`, `admin`, `assets`, `healthz`, `mcp`, `favicon.ico`,
`robots.txt`. A server path (slug) matches `[a-z0-9][a-z0-9-]{0,62}`, never contains `__`
and is never a reserved word.

| Path | What |
|---|---|
| `/{slug}` | one upstream, pass-through (POST, GET, DELETE) |
| `/mcp` | combined endpoint |
| `/.well-known/oauth-protected-resource/{slug}` and `/mcp` | RFC 9728 metadata; resource is `{public_url}/{slug}` |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/oauth/register` | authorization server |
| `/setup`, `/login`, `/logout`, `/invite/{token}`, `/forgot`, `/reset/{token}`, `/account` | accounts |
| `/admin/...` | panel: servers, users, invitations, rules, mail, activity |
| `/healthz` | liveness |

Unauthenticated requests to any syntactically valid `/{slug}` get the same 401 with
`WWW-Authenticate: Bearer resource_metadata=...`, whether or not the server exists. An
authenticated user gets 404 for a server that does not exist and for one not assigned to
them, so servers cannot be enumerated.

## Authorization server

Minimal profile: authorization code with PKCE S256, public clients only
(`token_endpoint_auth_methods_supported: ["none"]`), refresh tokens, `resource` required
(RFC 8707), `iss` returned on the authorization response (RFC 9207).

Authorize flow:

1. Validate `client_id` and `redirect_uri` first. If either is bad, show an error page and
   never redirect.
2. Store the request server-side (`auth_requests`, random id, 10 minutes). Nothing but that
   id travels through login and consent.
3. No browser session: go to `/login`, then come back.
4. Consent page names the client (name, host of its `client_id`), the redirect address and
   the server. Approve and Deny are CSRF-protected POSTs. The page cannot be framed.
5. The user must be assigned to the requested server, or no code is issued.
6. Code: random, stored hashed, single use, 60 seconds, bound to client, redirect address,
   resource, user and code challenge. A second use revokes the tokens it produced.

Open question for review: whether a remembered consent may ever skip step 4. A request
started by an attacker with a legitimate client's `client_id` and a victim who is signed in
would complete silently. Proposal: always require the Approve click; "remembered" only
changes the wording.

Client registration:

- CIMD: `client_id` is an HTTPS URL with a path. Fetch over HTTPS only, resolve DNS first and
  refuse loopback, private, link-local and unspecified addresses, connect to the resolved
  address, no redirects, 5 second timeout, 64 KiB cap. The document's `client_id` must equal
  the URL. Cached per its cache headers, 5 minutes to 24 hours.
- DCR: `/oauth/register`, public clients only, rate limited per address, unused
  registrations expire.
- Redirect addresses: HTTPS, or HTTP on a loopback host. Exact match; for loopback only the
  port may differ (RFC 8252). No fragments, no wildcards. An admin-editable allowlist of
  HTTPS redirect hosts ships with the known client hosts.

Tokens: `dw_at_`, `dw_rt_`, `dw_ac_` prefixes plus 32 random bytes, base64url. Only SHA-256
is stored. Access 1 hour, refresh 30 days. Every refresh replaces the refresh token; a used
refresh token presented again revokes the whole family. Each token is bound to one resource
and is refused on any other path. Password change, reset, disable and delete revoke every
family and browser session of the user.

Browser sessions: `__Host-` cookie, `Secure`, `HttpOnly`, `SameSite=Lax`, id stored hashed,
rotated at login. Every POST checks a per-session CSRF token and the `Origin` header. Login
compares against a dummy hash for unknown addresses. Throttling per account and per client
address; the client address comes from the socket unless `trusted_proxies` is set.

## Pass-through (`/{slug}`)

1. `guard`: bearer token, resource equals this path, user active and assigned.
2. POST body: size cap, strict JSON (duplicate keys refused, arrays refused, trailing data
   refused). Read `method`, and for `tools/call` the string `params.name`.
3. If `Mcp-Method` or `Mcp-Name` is present and disagrees with the body: HTTP 400, JSON-RPC
   error -32020. Decisions are always made from the body.
4. `tools/call` on a denied tool: answer as an unknown tool (-32602); the upstream is not
   contacted. The call is logged as denied.
5. Forward the original bytes, not a re-serialization. Request headers go through an
   allowlist (content type, accept, MCP protocol and session headers); `Authorization`,
   `Cookie` and forwarding headers are dropped; the server's secret header is added.
6. Response headers go through an allowlist; `Set-Cookie` and `WWW-Authenticate` never pass.
   Upstream 401 or 403 becomes 502. Redirects are not followed.
7. `tools/list` responses are buffered (capped) and filtered. Everything else streams
   through as it arrives; the stream is observed to log the outcome and duration.
8. An upstream session id is bound to the user that received it. Presenting another user's
   session id gets 404.

Rules cover tools. Resources and prompts pass through for assigned users.

## Combined endpoint (`/mcp`)

The gateway is the MCP server here, tools only. It answers both generations: the handshake
and session-less operation for revisions up to 2025-11-25, and `server/discover` with
stateless requests for 2026-07-28. As a client it speaks to each upstream in the newest
generation that upstream supports, probing once and caching the answer.

`tools/list` merges the permitted tools of every assigned server as `{slug}__{tool}`, in a
stable order. `tools/call` splits at the first `__`, checks policy, forwards, and relays
progress as it arrives. A failing upstream is left out of the list and reported in the log;
the others still answer. Requests initiated by an upstream (sampling, elicitation, roots)
are not relayed in v1.

## Policy

A rule is (subject: everyone or one user) x (effect: allow or deny) x (scope: all tools, one
server, one exact tool). For a call by user U to tool T on server S, among matching rules:
highest scope specificity wins (tool, then server, then all); then a rule for U beats a rule
for everyone; then deny beats allow. No matching rule: allowed, because S is assigned to U.
Names are compared as exact decoded strings. The panel shows each user's effective tool
list with the deciding rule.

## Storage

Tables: `users`, `invitations`, `password_resets`, `sessions`, `servers`, `user_servers`,
`rules`, `oauth_clients`, `auth_requests`, `auth_codes`, `token_families`, `access_tokens`,
`refresh_tokens`, `upstream_sessions`, `settings`, `activity`. Secrets (mail credentials,
upstream secret headers) are encrypted with a key from the environment or a key file with
owner-only permissions, created at first start when none is configured.

## Tests

`tests/common` provides `TestGateway` (real gateway, temp database, controllable clock),
`FakeUpstream` (both generations; records every request and header; modes: progress over
time, hang, garbage, accept anyone), `MailCatcher` (SMTP with and without TLS, fake Resend
and Mailgun endpoints) and `TestClient` (HTTP with its own cookie jar; helpers for owner
setup, invitation, login, the OAuth flow by either registration method, and MCP calls in
either generation). Flow tests use an in-memory CIMD fetcher; the real fetcher has its own
tests against local sockets.

Abuse cases, each a test written before the code it covers:

- Authorize: attacker client plus signed-in victim gets no code without the click; framed
  consent page; forged consent POST; unknown client; redirect address off by one character,
  extra path, other scheme, userinfo trick; missing or `plain` PKCE; missing `resource`.
- Codes and tokens: code replay; code with wrong verifier, client or redirect address;
  refresh reuse; token on another path; token of a disabled, deleted or reset user; raw
  tokens absent from the database file; token in the query string refused.
- Accounts: sign-up after setup; setup without the code; invitation reuse, expiry, revoke;
  reset reuse and expiry; reset enumeration by response and timing class; forged `Host` in
  emailed links; password guessing; session fixation; admin pages as a user or anonymous.
- Registration: CIMD fetch of loopback, private, redirecting, oversized, non-HTTPS and
  mismatched documents; DCR flood; DCR with a non-loopback HTTP redirect.
- Proxy: header and body disagree; duplicate keys; batch hiding a denied call; oversized
  body; denied tool by escape sequences; unassigned server; another user's session id;
  client token or cookie reaching the upstream; upstream setting a cookie or redirecting;
  the upstream secret appearing in any response or log line.
- Combined: denied tool by prefixed name; ambiguous `a__b__c`; a server named to collide
  with another's tool prefix; one upstream down.
