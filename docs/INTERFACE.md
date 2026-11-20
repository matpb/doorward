# Doorward interface reference (v1)

The exact surface that tests are written against. `docs/DESIGN.md` says why; this file says
what. `PUB` is the configured `public_url`.

## Conventions

- HTML pages are `text/html; charset=utf-8` and carry the headers listed in the design.
  The outermost `<main>` has a `data-page` attribute naming the page (`login`, `consent`,
  `error`, ...). Error text sits in an element with `class="error"`, notices in
  `class="notice"`.
- Every form has `<input type="hidden" name="csrf" value="...">`. Forms are
  `application/x-www-form-urlencoded`. A successful POST answers `303` with `Location`.
- A form POST with a missing, repeated or wrong `csrf`, or whose `Origin` header is absent,
  repeated or not equal to `PUB` (`Origin: null` included), or whose body is over 64 KiB or
  cannot be parsed, answers `403` with `data-page="forbidden"` and changes nothing. The token endpoint and the registration endpoint are not form pages and
  take neither.
- Cookies: session `__Host-doorward_session`; pre-session CSRF `__Host-doorward_csrf`. Both
  `Secure; HttpOnly; SameSite=Lax; Path=/`, whatever the scheme of the request. A cookie that
  is cleared repeats those attributes with `Max-Age=0`. The CSRF token is bound to the
  session, or to the pre-session cookie for a browser that is not signed in.
- Times use the injected clock everywhere, including throttling and expiry.
- User-supplied and upstream-supplied text is HTML-escaped wherever it is shown.

## Library seam

```rust
pub struct Gateway {
    pub router: axum::Router,
    /// Present only while the instance has no owner. A new code is made at every start.
    pub setup_code: Option<String>,
}
pub async fn build(config: Config, deps: Deps) -> Result<Gateway, StartError>;

pub struct Deps {
    pub clock: Arc<dyn Clock>,
    pub cimd: Arc<dyn CimdFetcher>,
}
pub struct ClientMetadata {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
}
pub enum CimdError { NotAllowed(String), Fetch(String), Invalid(String) }
pub trait CimdFetcher: Send + Sync + 'static {
    fn fetch<'a>(&'a self, client_id: &'a str)
        -> Pin<Box<dyn Future<Output = Result<ClientMetadata, CimdError>> + Send + 'a>>;
}

// doorward::cimd, the fetcher the binary uses
pub trait Resolver: Send + Sync + 'static {
    fn resolve<'a>(&'a self, host: &'a str)
        -> Pin<Box<dyn Future<Output = std::io::Result<Vec<IpAddr>>> + Send + 'a>>;
}
/// False for loopback, private, link-local, carrier-grade NAT, unspecified, multicast,
/// broadcast, documentation and benchmarking ranges, unique-local and link-local IPv6,
/// IPv4-mapped and NAT64 forms of any of those, and every IPv6 address outside `2000::/3`.
pub fn address_allowed(ip: IpAddr) -> bool;
pub struct FetcherParts {
    pub resolver: Arc<dyn Resolver>,
    pub address_allowed: fn(IpAddr) -> bool,
    pub extra_roots_pem: Option<Vec<u8>>,
    pub port: u16,              // the port fetches connect to; 443 in `system()`
    pub timeout: Duration,      // 5 seconds in `system()`
    pub max_bytes: usize,       // 65536 in `system()`
}
impl HttpCimdFetcher {
    pub fn system() -> HttpCimdFetcher;                    // system resolver, `address_allowed`
    pub fn from_parts(parts: FetcherParts) -> HttpCimdFetcher;
}
```

`HttpCimdFetcher::fetch` accepts only `https://host/path` with a host name (no address
literal), no userinfo, no query, no fragment, and no port in the address; any other shape is
`NotAllowed`, decided before any name lookup. It resolves the host once, refuses
when any answer fails `address_allowed` (`NotAllowed`), connects to the resolved address
itself, sends one GET with `Accept: application/json`, follows no redirect, and refuses a
status other than 200, a body over `max_bytes`, a body that is not a JSON object, a
`client_id` different from the URL, missing or empty `redirect_uris`, or an auth method
other than `none` (`Invalid`). Anything else that goes wrong is `Fetch`.

The binary prints the setup code to standard error as `doorward setup code: <code>`.

Encryption key: 32 random bytes written as 64 hexadecimal characters. It is taken from the
environment variable `DOORWARD_KEY`, else from the file named by `key_file`, else from
`<database>.key`. A key file that does not exist is created at start with mode 0600. A key
file that group or others can read, or that is malformed, refuses the start. The database
file is created with mode 0600 as well. The database remembers the id of its key: once it
does, a start without a key never makes a new one, and a start with a different key is
refused, both with a message that asks for the original key.
`doorward unlock --config <path> <email>` clears login blocks for one account.

## Config additions

```toml
trusted_proxies = []          # addresses whose X-Forwarded-For is believed

[lifetimes]
invitation_days = 7
reset_minutes = 60
session_hours = 12
auth_request_minutes = 10
auth_code_seconds = 60
access_token_minutes = 60
refresh_token_days = 30
family_days = 90
refresh_replay_seconds = 30

[limits]
body_bytes = 1048576
tools_list_bytes = 4194304
upstream_timeout_seconds = 300
account_failures = 5          # wrong passwords for one account from one address inside the window
account_ceiling = 50          # wrong passwords for one account from all addresses inside the window
address_failures = 30         # wrong passwords per address, for any accounts, inside the window
block_minutes = 15            # the window
activity_days = 90            # days an activity row is kept
dcr_per_hour = 60             # registrations per address
dcr_total_per_hour = 600      # registrations of all addresses together
general_burst = 240           # per client address: everything not listed below
general_per_minute = 600
oauth_burst = 60              # per client address: token, register, authorize
oauth_per_minute = 120
credentials_burst = 20        # per client address: the forms that take a password or a link token
credentials_per_minute = 20
mcp_burst = 240               # per user: requests that passed the bearer check
mcp_per_minute = 600
mcp_open = 64                 # per user: MCP requests and streams open at once
rate_table_keys = 100000      # addresses and users the limiter counts at once
auth_requests_max = 10000     # pending authorization requests kept

[mail]
# smtp_ca_file = "roots.pem"  # optional: extra trusted roots for SMTP over TLS, PEM
```

## Accounts

Passwords: 12 to 256 characters. A shorter or longer one re-renders the form with `400`
and leaves the link or code usable. A wrong `current_password` answers `400` as well.

| Route | Fields | Outcome |
|---|---|---|
| `GET /setup` | | `200` `data-page="setup"` while no owner exists, else `404` |
| `POST /setup` | `setup_code`, `email`, `password` | owner created, session set, `303 /admin`. Wrong code: `403`, nothing created. Owner exists: `404`. Two concurrent valid posts create one owner |
| `GET /login` | | `200` `data-page="login"`; optional `?req=<auth request id>` is carried in a hidden `req` field |
| `POST /login` | `email`, `password`, `req` | `303 /account`, or `303 /oauth/consent?req=...`. Wrong credentials or unknown address: `401`, same page, error "Wrong email or password." Blocked: `429`. More than 64 password checks in flight: `503` |
| `POST /logout` | | session ended, `303 /login` |
| `GET /invite/{token}` | | `200` `data-page="invite"` if usable, else `404` `data-page="link-invalid"`. A GET never consumes the link |
| `POST /invite/{token}` | `password` | account created, session set, `303 /account`. Unusable link: `404` |
| `GET /forgot` | | `200` `data-page="forgot"` |
| `POST /forgot` | `email` | always `200` `data-page="forgot-sent"` with identical body, whether or not the address exists. The mail is sent after the response, so the answer takes the same time either way; a failed send is recorded as `mail_failed`. A new request replaces an earlier unused link, but at most one reset mail goes to an account per 5 minutes: a request inside that time is ignored silently |
| `GET /reset/{token}` | | `200` `data-page="reset"` or `404` `data-page="link-invalid"` |
| `POST /reset/{token}` | `password` | password set, all sessions and token families of the user revoked, every counted wrong password of the account removed, `303 /login` |
| `GET /account` | | `200` `data-page="account"`; connected clients as rows with `data-family`, `data-client-name`, `data-server`; anonymous: `303 /login` |
| `POST /account/password` | `current_password`, `new_password` | as reset, but the current session is replaced by a new one; `303 /account`. A wrong current password counts as a failed sign-in for the account: `400`, and `429` once the account is blocked |
| `POST /account/clients/{family}/disconnect` | | family revoked, `303 /account` |
| `GET /account/disconnect/{token}` | | link from the new-connection email: `200` `data-page="disconnect"` |
| `POST /account/disconnect/{token}` | | family revoked, `200` `data-page="disconnected"` |

Throttling: a wrong password is counted for its account and its client address together,
and a count lasts `block_minutes`. A sign-in answers `429`, right password included, while
any of three counts is at its limit:

| Count | Limit | Who is blocked |
|---|---|---|
| Wrong passwords for one account from one address | `account_failures` (5) | that account from that address |
| Wrong passwords for one account from all addresses | `account_ceiling` (50) | that account from every address |
| Wrong passwords from one address, for any accounts | more than `address_failures` (30) | that address |

The window rolls: each wrong password stops counting `block_minutes` after it was made,
not after the last one. A right password removes the counts of its own account and address
and no others. A password reset and `doorward unlock` remove every count of the account.
An attempt is counted before its password is checked and uncounted when the password is
right, so attempts made at the same moment cannot exceed a limit. A blocked attempt is
neither checked nor counted.

Someone who knows an email address can therefore keep that account blocked for everyone
only by sending `account_ceiling` wrong passwords from many addresses in every window;
from one address they block only themselves. The ways out are a password reset by mail
and `doorward unlock`.

The address is the socket peer. When the peer is in `trusted_proxies`, it is the last
`X-Forwarded-For` entry that is not itself a trusted proxy; an entry that is not an address
means the peer is used. IPv4-mapped addresses count as IPv4, and an IPv6 address counts as
its /64 network.

Emails (plain text and HTML parts, links built from `PUB`):

| Mail | Subject | Link |
|---|---|---|
| Invitation | `You are invited to Doorward` | `PUB/invite/{token}` |
| Reset | `Reset your Doorward password` | `PUB/reset/{token}` |
| New connection (first connection of that client for that user) | `A new app was connected to your Doorward account` | `PUB/account/disconnect/{token}` |
| Test | `Doorward test email` | none |

## Admin panel

Anonymous: `303 /login`. Signed in without the owner or admin role: `403`
`data-page="forbidden"`. Roles: `owner`, `admin`, `user`. The mail routes (`/admin/mail`,
`/admin/mail/test`) are for the owner alone and answer an admin `403` as well: whoever
controls outgoing mail can read every password reset link.

| Route | Fields | Outcome |
|---|---|---|
| `GET /admin` | | `data-page="admin"` |
| `GET /admin/servers` | | `data-page="servers"`; each row `data-server-id`, `data-slug` |
| `POST /admin/servers` | `name`, `slug`, `upstream_url`, `secret_header_name`, `secret_header_value`, `pass_resources`, `pass_prompts` (checkboxes, `on`) | `303 /admin/servers/{id}`. Bad or reserved or taken slug, or a non-HTTP(S) URL: `400` |
| `GET /admin/servers/{id}` | | `data-page="server"`: settings (secret value never rendered); one `input[name="user_id"]` checkbox per user, `checked` when assigned; the cached tool list, one element per tool with `data-catalog-tool`; lock-down result in `data-lockdown="ok|open|unknown"` on `<main>` |
| `POST /admin/servers/{id}/users` | `user_id` (repeated) | replaces the server's assignments; a removed user's token families for this server are revoked, combined endpoint families stay valid and lose the server's tools; `303` |
| `POST /admin/servers/{id}` | same as create | `303`. A changed `upstream_url` clears the stored secret unless a new `secret_header_value` is sent in the same post |
| `POST /admin/servers/{id}/delete` | | server, its assignments, rules, and token families gone; `303 /admin/servers` |
| `POST /admin/servers/{id}/refresh-tools` | | fetches the upstream tool list; always `303` to the server page. A failed fetch keeps the previous list, and the server page shows the failure as its error until the next successful refresh |
| `POST /admin/servers/{id}/check-lockdown` | | asks the upstream for its tool list without the secret (the stateless form, then the session form's `initialize` when the first was neither refused nor answered); `ok` when refused with 401 or 403, `open` when answered, else `unknown`; `303` |
| `GET /admin/users` | | `data-page="users"`; rows `data-user-id`, `data-email` |
| `GET /admin/users/{id}` | | `data-page="user"`: role, status; one `input[name="server_id"]` checkbox per server, `checked` when assigned; effective tools, one element per tool of each assigned server with `data-server` (slug), `data-tool`, `data-verdict="allow|deny"` and `data-rule` (the id of the rule that decided, empty when no deny matched) |
| `POST /admin/users/{id}/servers` | `server_id` (repeated) | replaces the user's assignments; the user's token families for each removed server are revoked, combined endpoint families stay valid and lose those servers' tools; `303` |
| `POST /admin/users/{id}/role` | `role` (`admin` or `user`) | owner only; `303` |
| `POST /admin/users/{id}/disable`, `/enable`, `/delete` | | disable and delete revoke sessions and families at once; `303`. The owner cannot be disabled or deleted: `400`. An admin may act on accounts with the role `user` only (`403` otherwise); the owner on anyone else |
| `GET /admin/invitations` | | `data-page="invitations"`; open invitations as rows with `data-invitation-id`, `data-email` |
| `POST /admin/invitations` | `email`, `role` | invitation stored and mailed; `303`. An address that already has an account: `400`. Only the owner may invite with the role `admin` (`403` for an admin who asks). A new invitation for an address replaces an open one. If mailing fails: `200` `data-page="invitation-created"` with the error and the link once in `data-invite-link` |
| `POST /admin/invitations/{id}/revoke` | | `303` |
| `GET /admin/rules` | | `data-page="rules"`; rows `data-rule-id`, `data-subject` (`everyone` or the user's email), `data-effect`, `data-scope` (`all`, `server`, `tool`), `data-server` (slug or empty), `data-tool` (name or empty), `data-stale="yes|no"` (`yes` when the rule names a tool that is no longer in its server's cached list) |
| `POST /admin/rules` | `subject` (`everyone` or a user id), `effect` (`allow` or `deny`), `scope` (`all`, `server`, `tool`), `server_id`, `tool` | `303`. `400` for an unknown effect or scope, a subject that is neither `everyone` nor an existing user id, a duplicate subject and target (whatever the effect), a `server` or `tool` scope without an existing `server_id`, a `tool` scope without `tool`, or a tool that is not in the server's cached list. Fields the scope does not use are ignored |
| `POST /admin/rules/{id}/delete` | | `303`, also for an unknown id |
| `GET /admin/redirects` | | `data-page="redirects"`: entries as rows with `data-redirect-id`, `data-scheme`, `data-host`, `data-path-prefix`, `data-source="shipped|added"`, `data-enabled="yes|no"`; blocked attempts |
| `POST /admin/redirects` | `scheme`, `host`, `path_prefix` | `303` |
| `POST /admin/redirects/{id}/disable`, `/enable` | | `303` |
| `GET /admin/mail` | | `data-page="mail"`; stored secrets never rendered |
| `POST /admin/mail` | `provider` (`smtp`, `resend`, `mailgun`), `from`; smtp: `smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `smtp_tls` (`off`, `starttls` or `implicit`); resend: `resend_api_key`, `resend_base_url`; mailgun: `mailgun_api_key`, `mailgun_domain`, `mailgun_base_url` | `303`. An empty secret field keeps the stored one, unless the server it is sent to changed in the same post (SMTP host, port, username or TLS mode; Resend base URL; Mailgun domain or base URL): then the stored secret is deleted. An empty base URL means the provider's own address. A field with a control character: `400`. Requests to Resend carry `User-Agent: doorward/<version>` |
| `POST /admin/mail/test` | `to` | `200` `data-page="mail"` with `class="notice"` "Test email sent." or `class="error"` holding the provider's error |
| `GET /admin/activity` | query `user`, `server` | `data-page="activity"`; rows `data-kind`, `data-user`, `data-server`, `data-tool`, `data-decision`, `data-outcome` |

Activity rows: `data-user` is the user's email (empty when there is none), `data-server`
the server's slug, `data-tool` the tool's name on its server. For `tool_call` rows,
`data-decision` is `allow` or `deny` and `data-outcome` is `ok`, `error` (the upstream
answered an error, or the client left before the answer of a call that went upstream:
that call is still recorded, and the upstream request is closed), `unavailable`
(the upstream could not be reached, answered garbage, or stopped before the answer) or
`refused` (denied, stopped by the gateway before the upstream, or a streamed call cut
off because the caller lost access). Each row
also carries `data-time` (RFC 3339) and, for tool calls, `data-duration-ms`. The `user`
and `server` filters take ids. Newest rows come first.

Activity kinds: `tool_call`, `login`, `login_failed`, `invitation`, `reset`, `admin_change`,
`client_connected`, `client_disconnected`, `redirect_blocked`, `mail_failed`,
`tool_appeared`.

Retention: the housekeeping run, at start and every ten minutes, deletes every activity
row older than `activity_days` days, whatever its kind.

## Authorization server

`GET /.well-known/oauth-protected-resource/{slug}` and `/mcp`, for any syntactically valid
slug:

```json
{"resource": "PUB/{slug}", "authorization_servers": ["PUB"],
 "bearer_methods_supported": ["header"], "scopes_supported": ["mcp"]}
```

`GET /.well-known/oauth-authorization-server`:

```json
{"issuer": "PUB",
 "authorization_endpoint": "PUB/oauth/authorize",
 "token_endpoint": "PUB/oauth/token",
 "registration_endpoint": "PUB/oauth/register",
 "response_types_supported": ["code"],
 "grant_types_supported": ["authorization_code", "refresh_token"],
 "code_challenge_methods_supported": ["S256"],
 "token_endpoint_auth_methods_supported": ["none"],
 "client_id_metadata_document_supported": true,
 "authorization_response_iss_parameter_supported": true,
 "scopes_supported": ["mcp"]}
```

`POST /oauth/register` (JSON): `redirect_uris` (required, 1 to 10), `client_name`. Other
fields are ignored. `201`:

```json
{"client_id": "dcr_<random>", "client_id_issued_at": 1893456000,
 "redirect_uris": ["..."], "client_name": "...",
 "token_endpoint_auth_method": "none",
 "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]}
```

Errors: `400 {"error": "invalid_redirect_uri"}` for a URI with a fragment, a wildcard, or
plain HTTP on a non-loopback host; `400 {"error": "invalid_client_metadata"}` otherwise;
`429` past `dcr_per_hour`. Allowlist membership is not checked here but at authorize time.

`GET /oauth/authorize`: `response_type=code`, `client_id`, `redirect_uri`,
`code_challenge`, `code_challenge_method=S256`, `resource`, optional `state`, `scope`.

| Case | Answer |
|---|---|
| Unknown `client_id`, URL-shaped id that is not HTTPS with a path, `redirect_uri` not registered for the client, or not allowed by the redirect policy | `400` `data-page="error"`, no `Location`. A blocked redirect of a registered client also writes a `redirect_blocked` activity row: one per address per hour, and at most 50 per hour for the instance. A URL-shaped client id writes none before its document was fetched |
| Any parameter repeated, or `request` or `request_uri` present | `400` `data-page="error"`, no `Location` |
| Missing or non-`code` `response_type`, missing `code_challenge`, method not `S256`, missing `resource`, `resource` not `PUB/{valid slug}` or `PUB/mcp`, `prompt=none` | `303` to `redirect_uri` with `error=invalid_request` (or `invalid_target` for `resource`, `interaction_required` for `prompt=none`), plus `state` and `iss` |
| Valid, no session | `303 /login?req={id}` |
| Valid, session | `303 /oauth/consent?req={id}` |

For a URL-shaped `client_id` the metadata document is fetched when the consent page is
rendered, never before login. A fetch failure renders `400` `data-page="error"`.

`GET /oauth/consent?req={id}`: `200` `data-page="consent"` with `data-redirect-host`
(host and port of the redirect address, or the scheme for a private-scheme address),
`data-client-name`, `data-client-verified="yes|no"` (`no` for dynamically registered
clients), `data-client-host` (the host of a URL-shaped `client_id`, absent otherwise),
`data-server` (slug, or `all servers` for the combined endpoint) and `data-user`
(email). Unknown, expired, used, or another session's request: `400` `data-page="error"`.
A user who is not assigned to the server, or a server that does not exist, gives `403`
`data-page="no-access"`; the owner and admins need an assignment like anyone else. The
combined endpoint needs no assignment. Anonymous: `303 /login?req={id}`. For a URL-shaped
client the fetched document must name this `client_id`, declare the auth method `none` or
none at all, and list the redirect address (loopback port aside), else `400`
`data-page="error"`.

Every consent page holds exactly one element with `data-consent-notice`, saying "Approve
only if you started this sign-in yourself." A page for a loopback redirect address also
says "This app runs on your computer."

`POST /oauth/consent`: `req`, `decision` (`approve` or `deny`). `303` to the redirect
address with `code`, `state`, `iss`; or with `error=access_denied`, `state`, `iss`. The
request id is consumed either way.

`POST /oauth/token` (form), always `Cache-Control: no-store`:

- `grant_type=authorization_code`, `code`, `client_id`, `code_verifier`, `redirect_uri`
  (optional; if present it must equal the one used at authorize), `resource` (optional
  here; if present it must equal the code's).
- `grant_type=refresh_token`, `refresh_token`, `client_id`, `resource` (optional, same
  rule).

Success, `200`:

```json
{"access_token": "dw_at_...", "token_type": "Bearer", "expires_in": 3600,
 "refresh_token": "dw_rt_...", "scope": "mcp"}
```

Errors, `400`: `invalid_grant` (unknown, expired, used or mismatched code; wrong verifier;
unknown, expired or revoked refresh token; user disabled; server no longer assigned),
`invalid_request` (missing field, repeated field), `invalid_client` (unknown `client_id`),
`invalid_target` (`resource` differs), `unsupported_grant_type`.

Bearer use on `/{slug}` and `/mcp`: header only. Anything not fully valid answers

```
401
WWW-Authenticate: Bearer resource_metadata="PUB/.well-known/oauth-protected-resource/{slug}", scope="mcp"
```

with an empty body, and `error="invalid_token"` added when a token was presented. A token
in the query string is never read.

## MCP paths

A request is handled by the stateless rules (revision 2026-07-28 and later) when its
`MCP-Protocol-Version` header is `2026-07-28` or a later date, or when its body carries
`params._meta["io.modelcontextprotocol/protocolVersion"]`. Otherwise the session rules
(revisions up to 2025-11-25) apply.

Forwarded methods on `/{slug}`; everything else is refused:

| Group | Session rules | Stateless rules |
|---|---|---|
| Always | `initialize`, `ping`, `tools/list`, `tools/call`, `logging/setLevel`, notifications `notifications/initialized`, `notifications/cancelled`, `notifications/progress`, `notifications/roots/list_changed` | `server/discover`, `tools/list`, `tools/call`, `subscriptions/listen`, notification `notifications/cancelled` |
| `pass_resources` on | `resources/list`, `resources/templates/list`, `resources/read`, `resources/subscribe`, `resources/unsubscribe` | `resources/list`, `resources/templates/list`, `resources/read` |
| `pass_prompts` on | `prompts/list`, `prompts/get` | `prompts/list`, `prompts/get` |
| Either switch on | `completion/complete` | `completion/complete` |

With a switch off, the gateway answers the group's list methods itself with empty lists
(`resources`, `resourceTemplates`, `prompts`), answers the other methods of the group with
`-32601` (HTTP `404` under the stateless rules), and removes `resources` or `prompts` from the capabilities in the relayed
`initialize` and `server/discover` results. Under the stateless rules its own answers carry
`"resultType": "complete"`, and list answers `"ttlMs": 60000, "cacheScope": "private"`.

Stateless header rules: `MCP-Protocol-Version` must be present once and equal the body's
`_meta` version; `Mcp-Method` must be present once and equal the body's `method`;
`Mcp-Name` must be present once for `tools/call` and `prompts/get` (equal to
`params.name`) and for `resources/read` (equal to `params.uri`). A value of the form
`=?base64?...?=` is decoded before comparing. Any failure: `400`, `-32020`, message
starting `Header mismatch:`. A stateless body with no `params._meta` object, or with no string
`io.modelcontextprotocol/protocolVersion` in it, is refused before these rules: `400`, `-32602`,
message `Invalid params: missing _meta or protocol version`. GET and DELETE under the stateless rules: `405`.

Relayed `tools/list` results keep the upstream's fields, minus denied tools and entries
without a text name, on every page, and under the
stateless rules always carry `"cacheScope": "private"`, because the list is per user.

Session rules: an `Mcp-Session-Id` from a relayed `initialize` response is recorded for
(user, token family, server). GET with a recorded session is relayed when the upstream
answers `200` with an event stream; an upstream `405` is relayed as `405` with no body;
any other answer is the `502` below. GET without a recorded session: `405`. DELETE with
a recorded session is relayed and forgets it.

Upstream answers: status 200, 202, 400, 404 or 405 is accepted, any other status is `502`. A `202`,
and any accepted status that declares `Content-Length: 0`, is an empty answer whatever its content
type, and its body is never read or relayed. A notification with an empty answer gets the upstream's
status with no body and no `Content-Type`. A request with an id and an empty answer gets `502`
(`-32000`, null id) for 200 and 202, and the upstream's status with no body for 400, 404 and 405.
Any other non-empty answer must be JSON or an event stream.

Event streams are relayed byte for byte as they arrive, and the gateway ends one when:
the upstream ends it; the upstream sends nothing for `upstream_timeout_seconds`; one
event grows past `tools_list_bytes`; the client leaves; or the caller's token stops
passing the bearer check for this server (user disabled or unassigned, connection
disconnected, password changed, access token expired), which is checked every second.
The upstream connection is closed with the stream. A streamed `tools/call` writes its
activity row when the stream ends, with the outcome of the answer when one was seen.

The combined endpoint `/mcp` is its own MCP server:

- Session rules: `initialize` (answers the requested revision when it is one of
  `2025-11-25`, `2025-06-18`, `2025-03-26`, else `2025-11-25`; capabilities
  `{"tools": {"listChanged": false}}`; `serverInfo.name` `doorward`; no session id),
  `ping`, `tools/list`, `tools/call`, notifications accepted with `202`. GET and DELETE:
  `405`.
- Stateless rules: `server/discover` (`supportedVersions` `["2026-07-28", "2025-11-25",
  "2025-06-18", "2025-03-26"]`, capabilities `{"tools": {}}`, `cacheScope` `private`),
  `tools/list` (`ttlMs` 60000, `cacheScope` `private`), `tools/call`. An unsupported
  version: `400`, `-32022`, with `data.supported` and `data.requested`.
- Tool names are `{slug}__{tool}`. A tool whose name is not `^[A-Za-z0-9_.-]+$`, or whose
  merged name is longer than 128 characters, is left out and logged with the server's slug
  and a count, never the name. A tool with an `x-mcp-header` key at any depth is left out
  of a stateless upstream's list. Tools are ordered by slug, then by the upstream's order.
- At least one assigned server and every one of them failed or timed out: `502`, `-32000`,
  `Upstream mcp is unavailable`. No assigned server: an empty list.
- A request carrying `Mcp-Session-Id`: `404`, upstream not contacted.
- `tools/call` takes `{slug}__{tool}`, split at the first `__`. A name without `__`, with an
  empty or invalid slug or tool, or longer than 128 bytes is refused; so is a name whose
  server does not exist, whose server the caller is not assigned to now, whose tool is not
  in the catalog after one refresh of that server, that the caller's rules deny, or whose
  tool has an `x-mcp-header` key on a stateless link. A refusal is `200` with `-32602` and
  `Unknown tool: {name as sent}` for every one of them; no upstream sees it. Its activity
  row is `deny` / `refused`: under the real server and the bare tool name when the server
  exists, else with no server, the slug `mcp` and the name as sent.
- An allowed call is sent with the client's `params.arguments` as raw bytes (absent when
  absent or `null`), its `_meta.progressToken` when that is a string or an integer, and
  nothing else of the request: no other `_meta` key, no client header, not the client's id.
- An upstream answer that is JSON is read whole. It is returned under the client's id with its
  `result` or `error`. A result whose `resultType` is present and not `complete` becomes a tool
  error with the text `This tool asked for input that this endpoint does not relay.` and
  `isError` true. A stateless client's result has `resultType` `complete`; a session client's
  has none.
- An upstream answer that is an event stream is relayed as a filtered stream: `200`,
  `Content-Type: text/event-stream`, the inert-content headers, no `Mcp-Session-Id`. Each event
  is parsed, and only two kinds reach the client, each as `event: message` and `data:` with its
  compact JSON: a `notifications/progress` with no `id` member, as sent; then the first object
  whose `id` is the id the link sent upstream and that has exactly one of `result` and `error`,
  under the client's id and with the `resultType` rule above. That answer ends the stream, and
  the upstream connection is closed with it. Everything else is dropped without a trace in the
  client's bytes: upstream requests, other notifications, answers under another id, arrays,
  non-objects, invalid JSON, and the SSE `id:`, `retry:`, `event:` and comment lines.
- A relayed stream ends without an answer when the upstream ends it, breaks, sends an event over
  `tools_list_bytes`, or sends no bytes for `upstream_timeout_seconds` (comment lines count as
  bytes). Its last event is then the `-32000` error `Upstream {slug} is unavailable` under the
  client's id. When the client leaves, the upstream connection is closed and no event is sent.
- While a relayed stream is open, the caller's token and its assignment to the server are
  checked every second. A failed check ends the stream with no further event. A check that
  fails before the answer is sent makes the answer the `-32602` refusal above.
- A streamed call writes one row when its stream ends: `allow` with the outcome of the answer
  when one was sent (`ok`, or `error` for a JSON-RPC error or a replaced input request),
  `refused` after a failed check, `unavailable` after a stream that ended without an answer, or
  `error` with the detail `the client closed the stream` when the client left.
- Before the answer is returned the caller's token and its assignment to the server are
  checked again; when either fails the answer is the refusal above and the row is
  `allow` / `refused`. A call that reached an upstream writes one row: `allow` with outcome
  `ok` (any result, also one the tool itself marks as an error), `error` (a JSON-RPC error,
  or a result replaced because it asked for input), or `unavailable`, or, when the
  client leaves before the answer, `error` with the detail `the client left before the answer`.
- An upstream that is unreachable, answers another id, or faults: `502`, `-32000`,
  `Upstream {slug} is unavailable`, row `unavailable`.
- Every other method: `-32601`, HTTP `404` under the stateless rules.

Answers that both endpoints share:

| Case | Answer |
|---|---|
| Body over `body_bytes` | `413` |
| `Content-Encoding` present, charset other than UTF-8, byte order mark | `400`, JSON-RPC `-32600` |
| Not valid JSON, duplicate key at any depth (compared after unescaping), lone surrogate, trailing data, nesting deeper than 64 | `400`, JSON-RPC `-32700` |
| JSON array, `tools/call` without an `id`, a client-sent response under the stateless rules or without a session of the caller | `400`, JSON-RPC `-32600` |
| Method outside the allowlist, `tasks/*`, `params.task` present | `404` under the stateless rules, else `200`; JSON-RPC `-32601`, upstream not contacted |
| `tools/call` for a tool that is not in the server's list or is denied | `200`, JSON-RPC `-32602` with message `Unknown tool: {name}`, upstream not contacted |
| Stateless body with no `params._meta` or no string protocol version in it | `400`, JSON-RPC `-32602`, message `Invalid params: missing _meta or protocol version` |
| Header and body disagree (2026-07-28), or a required header is missing or repeated | `400`, JSON-RPC `-32020` |
| Session id not issued to this user, family and server | `404`, upstream not contacted |
| Upstream unreachable, timed out, answered 401 or 403, redirected, or sent an unexpected content type | `502`, JSON-RPC `-32000` with message `Upstream {slug} is unavailable` |
| Deeper path `/{slug}/...` | `404` |

Headers sent upstream: `Content-Type`, `Accept`, `MCP-Protocol-Version`, `Mcp-Session-Id`
(a recorded one only), `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`, the gateway's own
`User-Agent`, and the server's secret header. Nothing else from the client is forwarded.
Responses to the client carry `X-Content-Type-Options: nosniff` and
`Content-Security-Policy: sandbox`; of the upstream's headers only `Content-Type` and
`Mcp-Session-Id` pass.

## Rate limits

Every request but `GET /healthz` is counted before its route runs. Classes and keys:

| Class | Key | Requests |
|---|---|---|
| oauth | client address | `POST /oauth/token`, `POST /oauth/register`, `GET /oauth/authorize` |
| credentials | client address | `POST` on `/login`, `/setup`, `/forgot`, `/invite/{token}`, `/reset/{token}`, `/account/password`, `/account/disconnect/{token}` |
| general | client address | everything else, and every request on `/mcp` and `/{slug}` until its bearer check passes |
| mcp | user | every request on `/mcp` and `/{slug}` whose bearer check passed |

A class allows `*_burst` requests at once and refills at `*_per_minute`. An IPv6 client is
counted by its /64. On the MCP paths the address is counted first, before the database is
read; a request that is admitted gives that count back and is counted for its user instead,
so a wrong token or a user over their budget keeps using up the address. One user may have
`mcp_open` requests and streams open at once; a stream holds its place until it ends.

A limited request answers `429` with an integer `Retry-After` of at least 1,
`Cache-Control: no-store` and no `WWW-Authenticate`; it changes no state and reaches no
upstream. The body is the error page on pages,
`{"error":"too_many_requests","error_description":"Too many requests. Try again later."}`
on the JSON routes, and the JSON-RPC error `-32029` with a null id on the MCP paths. Over
`mcp_open` the wait is 1. The older refusals carry the same headers: a blocked sign-in or
password change waits `block_minutes * 60`, a registration past `dcr_per_hour` or
`dcr_total_per_hour` waits 3600.

The limiter keeps at most `rate_table_keys` keys, IPv6 at most half of them; past that,
new keys of a class share one bucket and no live key is dropped. Counts live in memory and
start empty after a restart. `auth_requests` keeps at most `auth_requests_max` rows: a new
request past that removes the oldest.

## Test harness (`tests/common`)

```rust
impl TestGateway {
    pub async fn start() -> TestGateway;
    pub async fn start_with(edit: impl FnOnce(&mut Config)) -> TestGateway;
    pub fn setup_code(&self) -> Option<String>;
    pub fn cimd(&self) -> &FakeCimd;          // register documents by client_id URL
    pub fn client(&self) -> TestClient;       // fresh cookie jar
}
```

`FakeUpstream`, `MailCatcher`, `McpClient` and `TestClient` live in `tests/common`; tests
reach every feature through real HTTP on the gateway.

The anti-forgery value is the same on every page of one browser session, so a test may
read it from any form page before posting. `TestClient` sends `Origin: PUB` on every POST,
as a browser would.
