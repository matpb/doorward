# Doorward design (v1)

Status: revised after the first adversarial review. Statement numbers refer to `CLAUDE.md`;
S32 to S36 replace S15, S19, S21 and S22 and add the resources and prompts switch.

## Shape

One Rust crate, library plus binary. The library exposes `build(config, deps) -> Router` so
tests start the real gateway in-process on a free local port and talk to it over real HTTP.
`deps` carries the only seams: clock, Client ID Metadata Document fetcher, DNS resolver.

Modules. Those marked (core) are the reviewed security core. Nothing outside the core
holds an upstream secret, parses a request body for a decision, or issues a credential.

| Module | Job |
|---|---|
| `config` | TOML file: `public_url` (origin only), listen address, database path, key file, trusted proxies, lifetimes, limits |
| `db` | SQLite (WAL, `foreign_keys=ON`, writes in `BEGIN IMMEDIATE`), embedded migrations run at start |
| `crypto` (core) | token generation, SHA-256 token hashing, secret encryption (XChaCha20-Poly1305 with key id and associated data), Argon2id behind a semaphore, off the async executor |
| `accounts` (core) | users, roles, setup code, invitations, password reset, browser sessions, CSRF, login throttling |
| `oauth` (core) | metadata, authorize, consent, token endpoint, client registration (CIMD and DCR), redirect policy |
| `guard` (core) | bearer check for MCP paths |
| `policy` (core) | tool rule evaluation |
| `mcp` (core) | strict JSON-RPC parsing, message shapes, method allowlists per generation, SSE reading |
| `upstream` (core) | the only holder of upstream secrets; request and response header allowlists; the HTTP client |
| `catalog` (core) | each server's cached tool list |
| `proxy` | per-server pass-through, built on `guard`, `mcp`, `policy`, `catalog`, `upstream` |
| `combined` | the combined endpoint, same building blocks |
| `mail` | `Mailer` trait with SMTP, Resend and Mailgun providers |
| `audit` | activity log |
| `admin` | panel and account pages, server-rendered HTML, no script |

## HTTP surface

`public_url` is the issuer and the base of every link, including emailed ones. Request
headers such as `Host` or `X-Forwarded-Host` never influence it.

A server path (slug) matches `[a-z0-9][a-z0-9-]{0,23}`: no underscore, at most 24
characters, never a reserved word. Reserved first segments: `-`, `.well-known`, `oauth`,
`login`, `logout`, `setup`, `invite`, `forgot`, `reset`, `account`, `admin`, `assets`,
`healthz`, `mcp`, `signup`, `register`, `favicon.ico`, `robots.txt`. Any gateway path added after v1 goes under
`/-/`.

| Path | What |
|---|---|
| `/{slug}` | one upstream, pass-through. Deeper paths are 404 and never forwarded; the query string is dropped |
| `/mcp` | combined endpoint |
| `/.well-known/oauth-protected-resource/{slug}` and `/mcp` | RFC 9728 metadata, answered for every syntactically valid slug |
| `/.well-known/oauth-authorization-server` | RFC 8414 metadata |
| `/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/oauth/register` | authorization server |
| `/setup`, `/login`, `/logout`, `/invite/{token}`, `/forgot`, `/reset/{token}`, `/account` | accounts |
| `/admin/...` | panel |
| `/healthz` | liveness |

One refusal shape on MCP paths: any request that is not fully valid for the path (no token,
bad token, token for another server, disabled user, server missing, server not assigned)
gets the identical 401 with `WWW-Authenticate: Bearer resource_metadata=...`, decided
before any server lookup can be observed. MCP paths never accept the browser cookie.

## Authorization server

Profile: authorization code with PKCE S256, public clients only, refresh tokens, `resource`
(RFC 8707), `iss` on the authorization response (RFC 9207). Duplicate OAuth parameters and
`request_uri` are refused. `prompt=none` never yields a code.

Authorize flow:

1. Validate `client_id` shape and `redirect_uri` against the redirect policy first. On
   failure show an error page naming the host; never redirect.
2. Store the request server-side (`auth_requests`, random id, 10 minutes, single use). A
   request started by a signed-in browser belongs to that browser from the start; one
   started signed out belongs to the first signed-in browser that opens it. Only a request
   whose consent page was rendered can be approved or denied. Only the id travels through
   login.
3. No browser session: `/login`, then back.
4. For a CIMD client the metadata document is fetched only now, after login.
5. Consent page (S33): shown every time. Headline is the
   redirect target; then the client name (a dynamically registered client is shown as a claim
   that Doorward cannot check; a document client with its real host), the server, and "signed in as <email>". No client-supplied
   links or images. Approve and Deny are CSRF-protected POSTs answering 303 straight to
   the client.
6. The user must be assigned to the requested server, or no code is issued.
7. Code: random, stored hashed, single use, 60 seconds, bound to client, redirect address,
   server, user, code challenge and the user's sign-in generation at approval, so a code
   approved before a password reset dies with the reset. Concurrent redemption yields one
   success. A second use by a caller who holds the code verifier revokes the family it
   produced; a caller without the verifier changes nothing.
8. A new connection sends the user an email with a disconnect link.

Client registration:

- CIMD: `client_id` is an HTTPS URL with a path. Fetch over HTTPS only; resolve first and
  refuse loopback, private, link-local, carrier-grade NAT, unspecified, IPv4-mapped and
  NAT64 addresses, and any answer mixing public and non-public records; connect to the
  resolved address; no redirects; 5 second timeout; 64 KiB cap. The document's `client_id`
  must equal the URL and its auth method must be `none`.
- DCR: `/oauth/register`, public clients only, rate limited per address, unused
  registrations expire. Issued ids are never URL-shaped. A registration may carry several
  redirect addresses of mixed kinds; each is judged when used.
- Redirect policy (S34): exact match against the client's registered addresses, and the
  address must be allowed. Loopback hosts `localhost`, `127.0.0.1` and `[::1]` (compared as
  strings, never resolved) are always allowed on any port. Anything else must match an
  allowlist entry (scheme, host, optional path prefix). Defaults for the known clients ship
  in code; admin additions and disables live in the database. A blocked attempt of a
  registered client appears in the activity log with a one-click allow; the rows are capped
  per hour, and an unverified client address never writes one, so a stranger cannot fill the
  log or the admin's list.

Tokens: `dw_at_`, `dw_rt_`, `dw_ac_` prefixes plus 32 random bytes, base64url; only SHA-256
is stored. A family is bound to the server's id (or to the combined endpoint), the client
and the user, and has an absolute lifetime. Access 1 hour, refresh 30 days. Server delete,
slug rename, unassignment, password change, reset, disable and delete revoke families; a
per-user `auth_epoch` counter, copied into each session and token family and compared on
use, gives mass revocation. Refresh rechecks user and assignment.

Refresh replay (S35): each refresh replaces the refresh token. On rotation the used row
keeps, for 30 seconds (configurable, 0 = strict), the successor pair encrypted with a key
derived from the presented token. A replay inside the window returns the identical pair;
any other reuse revokes the family.

Browser pages:

- Session cookie `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`, id stored hashed,
  rotated at login. Every POST checks a CSRF token (pre-session token on login, setup,
  invite and reset forms) and the `Origin` header.
- Headers on every page: `Content-Security-Policy: default-src 'none'; style-src 'self';
  img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
  `Referrer-Policy: same-origin`. The consent page alone adds the redirect origin of the
  current request to `form-action`.
- Invitation and reset links render on GET and are consumed on POST, so mail scanners
  cannot use them up.
- Login compares against a dummy hash for unknown addresses. Throttling per account and per
  client address; the address comes from the socket unless `trusted_proxies` is set. A
  failure is reserved before the password is checked, so parallel guesses cannot outrun the
  limit. Password hashing holds its permit until the hashing thread ends, and at most 64
  checks wait at once. A local command unlocks the owner.
- Mail settings belong to the owner alone, and a stored mail secret is dropped when the
  server it would be sent to changes.

## Pass-through (`/{slug}`)

Enforcement is by positive match: a request is forwarded only when the gateway recognises
it and allows it.

1. Origin (statement 48), then `guard`: a foreign `Origin` is refused `403` before the address
   limiter, the database, the token or the upstream, for every method. No `Origin` passes.
2. Body: size cap; UTF-8 only, no byte order mark, no `Content-Encoding`; strict JSON
   (duplicate keys refused at every depth on decoded keys, lone surrogates refused, trailing
   data refused). Arrays (batches) get HTTP 400, -32600.
3. Shape: request, notification or response. Methods outside the allowlist of the request's
   generation get -32601 without upstream contact. `tools/call` without an `id` is refused.
   `tasks/*` and `params.task` are refused in v1. A client-sent response is forwarded only
   on a session bound to the caller, never for 2026-07-28 requests.
4. Headers for 2026-07-28: `Mcp-Method` and, where the method requires it, `Mcp-Name` must
   be present, single, and equal to the body after decoding the base64 form; otherwise HTTP
   400, -32020. Decisions are always made from the body.
5. `tools/call` is forwarded only if `params.name` is byte-equal to a name in this server's
   cached tool list (refreshed once on a miss) and policy allows it. Otherwise -32602
   `Unknown tool: {name}`, no upstream contact, logged as denied. Denied and nonexistent look alike.
6. Resources and prompts (S36): forwarded only when the server's `pass_resources` or
   `pass_prompts` switch is on; otherwise the gateway answers with empty lists.
7. Forward the original bytes. `upstream` applies the request header allowlist, drops
   `Authorization`, `Cookie`, `Last-Event-ID` and forwarding headers, and adds the server's
   secret header. Redirects are not followed.
8. Responses: content type must be `application/json` or `text/event-stream`; headers go
   through an allowlist; `Set-Cookie` and `WWW-Authenticate` never pass; `nosniff` and
   `Content-Security-Policy: sandbox` are added. Upstream 401 or 403 becomes 502.
9. `tools/list` responses are buffered (capped), filtered by policy, and refresh the
   catalog. Other responses stream through as they arrive; the stream is observed for the
   activity log.
10. Sessions: an `Mcp-Session-Id` is accepted only if the gateway recorded it from an
    `initialize` response it relayed to the same server, user and token family (stored
    hashed). Anything else gets 404 without upstream contact, on POST, GET and DELETE. A
    client-supplied id on `initialize` is stripped. An id the upstream issues twice is not
    rebound. A GET without a session gets 405.
11. Open streams end when the user is disabled, reset or unassigned from the server, the
    family is revoked, or the token expires. The check runs every second.

Changing a server's upstream address clears its stored secret. The server page and the
README state what the gateway cannot fix: every user reaches the upstream under one
identity, so upstream-side caches and per-caller state are shared.

## Combined endpoint (`/mcp`)

The gateway is the MCP server here, tools only, and declares no client capabilities. It
answers both generations. As a client it speaks to each upstream in the newest generation
that upstream supports, probing once and caching the answer, with one upstream session per
(token family, server).

`tools/list` merges the permitted tools of every assigned server as `{slug}__{tool}` in a
stable order. Slugs contain no underscore, so the first `__` is the boundary; calls are
still resolved by exact lookup in the merged map. Names over the client-safe length are
omitted and logged. A failing upstream is left out and logged; the others still answer.
Requests initiated by an upstream are not relayed, and an `input_required` result becomes
a tool error. A call is retried only after an explicit session 404.

## Policy (S32)

A rule is (subject: everyone or one user) x (effect) x (scope: all tools, one server, one
exact tool), keyed by server id, unique per subject and target. For a call by user U to
tool T on server S: with no matching deny, allowed. A matching deny stands unless some
matching allow is at least as specific as it on both scope and subject, and strictly more
specific on one. An allow on an unassigned server grants nothing. The panel shows each
user's effective tool list with the deciding rule, flags rules whose target no longer
exists, and logs tools that newly appear on a server. Rules are read on every request, so a
change applies to tokens already issued. A rule that cannot be read refuses the request.

## Storage

Tables: `users`, `invitations`, `password_resets`, `sessions`, `servers`, `user_servers`,
`rules`, `redirect_allow`, `oauth_clients`, `auth_requests`, `auth_codes`,
`token_families`, `access_tokens`, `refresh_tokens`, `upstream_sessions`, `tool_catalog`,
`settings`, `activity`. Activity rows snapshot email, slug, tool and client and do not
cascade. Ciphertexts carry a key id and are bound to their table, column and row. The
database and key files are created with owner-only permissions.

## Tests

`tests/common` provides `TestGateway`, `FakeUpstream`, `MailCatcher` and `TestClient`.
`FakeUpstream` speaks both generations, records every request and header, and has modes:
progress over time, hang, garbage, accept anyone, lenient names (case-insensitive,
trimming, normalising), lenient methods, reused session ids, pending server request.
Header behaviour that only a browser enforces (the consent hand-back under `form-action`)
is proven with a headless browser.

Abuse cases, each a test written before the code it covers:

- Authorize: prior approval on file, yet GET authorize returns the consent page with the
  redirect host, the server and the email, no `Location`, and no code row; approve without
  the CSRF token, with another session's token, with a cross-site, `null` or missing
  `Origin`, on replay, or from another session yields no code; one valid approve yields
  exactly one code; a dynamically registered client named like a known one renders as
  unverified; framed consent; unknown client; duplicate parameters; `request_uri`;
  `prompt=none`; missing or `plain` PKCE.
- Redirects: off by one character, extra path, other scheme, userinfo,
  `localhost.evil.example`, `127.1`, backslash, trailing dot, punycode look-alike; a
  non-allowlisted HTTPS host; an allowlisted host with the wrong path.
- Codes and tokens: code replay and concurrent redemption; wrong verifier, client or
  redirect; parallel refreshes return identical bodies and leave one successor; replay after
  the window revokes; the stored replay blob cannot be opened from the database alone;
  token on another path; token for a deleted and recreated slug; token of a disabled,
  deleted or reset user; raw tokens absent from the database file; token in the query
  string; session cookie on an MCP path.
- Accounts: sign-up after setup; setup without the code; two concurrent setups produce one
  owner; invitation reuse, expiry, revoke, and a scanner's GET leaves the link usable;
  reset reuse and expiry; reset enumeration; forged `Host` in emailed links; password
  guessing; spoofed `X-Forwarded-For`; parallel logins do not exhaust the hasher; session
  fixation; admin pages as a user or anonymous; HTML in tool or client names is escaped;
  database and key file permissions.
- Registration: CIMD fetch of loopback, private, carrier-grade NAT, mapped, NAT64, mixed
  records, redirecting, oversized, non-HTTPS, mismatched, and non-public-client documents;
  DCR flood.
- Proxy: header and body disagree; required header missing or duplicated; base64 header
  form; duplicate keys at depth; batch; oversized or compressed body; look-alike tool names
  against a lenient upstream; unknown and wrong-case methods; id-less `tools/call`; tasks;
  a forged JSON-RPC response; another user's or an invented session id; client token or
  cookie reaching the upstream; upstream cookie, redirect, or unexpected content type; the
  upstream secret in any response or log line; an admin changing the upstream address
  does not send the old secret to the new one; resources with the switch off; a stream
  ending when its user is disabled; a canary in tool arguments appears nowhere in the
  database or logs.
- Policy: the rule table, including a user deny against an everyone allow; an allow on an
  unassigned server.
- Combined: denied tool by prefixed name; `a__b__c`; over-length names; one upstream down.
