# Doorward

An authentication layer and gateway for MCP servers hosted anywhere. Written in Rust.
This file is the contract every session builds against. Read it before changing anything.

## Definition of done (v1)

Goal: authenticate people's AI agents in front of MCP servers hosted anywhere, with an admin
panel to manage servers, users and who may use what.

Stakes: used by others. Every statement has an automated test, abuse tests are written before
the gateway code they cover, outside input is checked wherever it enters, and the README is
enough for a stranger.

Statement numbers are permanent. A replaced statement stays in place, marked
`replaced by <number>`. Never delete or renumber.

### Done when

A. Install and first owner

1. A fresh machine gets a running gateway from one binary, one config file and one SQLite
   file, and the health address answers.
2. On a fresh instance, the first person to sign up with the one-time setup code printed at
   first start becomes the owner. After that, sign-up is closed and an invitation is the only
   way in.

B. Users, invitations, passwords

3. An admin invites an email address. The person receives a link that works once and expires
   (7 days by default) and sets their own password. A used, expired or revoked link is refused.
4. A user resets their own password by email with a link that works once and expires in an
   hour. The answer to a reset request is the same whether or not the address exists. After a
   reset or a password change, every token and browser session of that user is dead.
5. When an admin disables or deletes a user, that user's tokens are refused on the very next
   request.
6. Passwords exist only as Argon2id hashes, have a 12 character minimum, and repeated wrong
   guesses are slowed and then blocked, per account and per address.

C. Mail

7. The mail settings page offers raw SMTP (server, port, username, password, TLS on or off),
   Resend and Mailgun. A "send test email" button reports delivered, or the provider's own
   error. Provider secrets are encrypted in the database and never shown again.
8. When sending fails, the admin sees the error, the failure is in the activity log, and the
   invitation link can be copied by hand.

D. Servers and routing

9. An admin adds a server: a name, a path, an upstream address, and an optional secret header
   the gateway sends upstream. A client pointed at `https://host/<path>` talks to that
   upstream. Paths the gateway needs for itself cannot be taken.
10. A combined endpoint shows every tool the user may use across their servers, named
    `<path>__<tool>`, and routes each call to the right upstream.
11. Both protocol generations work: a session-style client (handshake, session header;
    revisions up to 2025-11-25) and a stateless client (revision 2026-07-28) can each list and
    call tools on a server path and on the combined endpoint. On the combined endpoint this
    holds whichever generation each upstream speaks.
12. Streamed answers are not held back: when an upstream sends progress as it works, the
    client sees the first message before the last one is sent.
13. When an upstream is down, slow or answers garbage, the client gets a clear error naming
    the server, the gateway stays up, and the other servers on the combined endpoint keep
    working.

E. Who may use what

14. Servers are assigned to users from the user page and from the server page, and both show
    the same thing. A user without a server is refused on its path and does not see it on the
    combined endpoint.
15. (replaced by 32) Tool rules say allow or deny, for all tools, one server, or one exact tool, for everyone
    or for one user. The most specific rule wins, a user's rule beats an everyone rule, deny
    wins a tie, and with no rule a tool on an assigned server is allowed. A denied tool is
    absent from the tool list, and a call to it is refused without the upstream seeing it.
16. The admin chooses tools from the server's real tool list, fetched by the gateway.
17. Every tool call is recorded with time, user, server, tool, allowed or denied, outcome and
    duration. Arguments and results are not stored. Sign-ins, invitations, resets and admin
    changes are recorded too. An activity page filters by user and by server.

F. Security core

18. A client with no token, or a bad one, gets 401 with a pointer to the gateway's
    authorization metadata, on every server path and the combined endpoint. The gateway's
    public address comes from its config file, never from the request, including in the
    links it emails.
19. (replaced by 33) Signing in happens on the gateway's own page with email and password, followed by a
    consent page that names the client, its redirect address and the server it wants. An
    authorization code is issued only after the user approves. Consent is remembered for that
    user, client and redirect address together, and asked again when any of them changes.
    Pages refuse to load in a frame and every form carries an anti-forgery token.
20. Both client registration methods work: Client ID Metadata Documents and Dynamic Client
    Registration. Fetching a metadata document cannot be turned against private addresses,
    and dynamic registration is rate limited.
21. (replaced by 34) The redirect address must match exactly what the client registered; only the port of a
    loopback address may vary. PKCE with S256 is mandatory. An authorization code works once
    and for 60 seconds. A token works only on the path it was issued for.
22. (replaced by 35) Tokens are random 256-bit opaque strings. The database holds only their SHA-256. Access
    tokens last an hour. Refresh tokens are replaced on every use, and presenting an already
    used one revokes that whole chain.
23. The client's token never reaches an upstream; the gateway sends its own secret for that
    server instead. Cookies and authorization headers from the client are stripped, and an
    upstream cannot set cookies on the gateway's address. The server page warns when an
    upstream answers a request that lacks the gateway's secret.
24. Trick requests get the same verdict the upstream would act on, or are refused: a header
    that names one tool while the body names another (HTTP 400, JSON-RPC error -32020),
    duplicate keys in the JSON, several calls bundled in one request, oversized bodies, and
    look-alike or ambiguous names on the combined endpoint.
25. The abuse tests exist, and fail, before the gateway code that makes them pass.

G. Admin panel

26. The panel has pages for servers, users, invitations, assignments, tool rules, mail and
    activity, in English, usable at 390 px wide. Only the owner and admins get in. Each user
    has an account page to change their password and see or disconnect their connected
    clients.

H. Real clients

27. Each of these signs in through the gateway, lists tools, calls an allowed tool, is
    refused a denied one, and the call shows in the activity log under the right user: Claude
    Code, Codex, Cursor, Grok Build, Claude Desktop, ChatGPT desktop, ChatGPT.com and
    claude.ai. Copilot is tried and reported, and does not gate v1.

I. Keeps working

28. One local command, `./check.sh`, runs formatting, lints with warnings as failures, every
    test including the abuse suite, and a known-vulnerability check of the dependencies. It
    passes before every commit. No hosted CI.
29. Stopping and starting the gateway keeps users, rules and live tokens working, and a newer
    version migrates the database by itself at start.
30. The repository is ready for strangers and safe to publish: a README (install, HTTPS in
    front, locking down upstreams, connecting each client), a license, a security policy, and
    no host names, addresses, local paths, personal names, emails or secrets in any tracked
    file or commit message. Nothing is pushed without the owner's word.
31. The project owner has read the auth code. It lives in its own modules and arrives as
    diffs with the abuse tests mapped to each rule; every finding from the adversarial
    reviews is fixed or listed. v1 is not called done before that sign-off.

J. Added after the first security review

32. Tool rules say allow or deny, for all tools, one server, or one exact tool, for everyone
    or for one user. With no matching deny, a tool on an assigned server is allowed. A
    matching deny stands unless a matching allow is at least as specific as it in both scope
    and subject, and more specific in one of them. A denied tool is absent from the tool
    list, and a call to it is refused without the upstream seeing it.
33. Signing in happens on the gateway's own page with email and password, followed every
    time by a consent page that names the redirect address, the client, the server and the
    signed-in user. An authorization code is issued only after the user approves; an earlier
    approval never skips the page. Pages refuse to load in a frame and every form carries an
    anti-forgery token. The user is emailed when a new client connects, with a link to
    disconnect it.
34. The redirect address must match exactly what the client registered, and must be
    allowed: loopback addresses always are, on any port; any other address must be on an
    allowlist that ships with the known clients' addresses, private-scheme ones included,
    and that an admin can extend. A blocked attempt shows in the activity log. PKCE with
    S256 is mandatory. An authorization code works once and for 60 seconds. A token works
    only on the server it was issued for.
35. Tokens are random 256-bit opaque strings. The database holds only their SHA-256 and,
    during the replay window, the successor pair encrypted under a key derived from the
    token it replaces. Access tokens last an hour. Refresh tokens are replaced on every use.
    A used refresh token presented again inside the replay window (30 seconds by default,
    0 disables it) receives the identical successor pair; presented later, it revokes the
    whole chain.
36. Each server has two switches, pass resources and pass prompts, both off by default.
    While a switch is off the gateway answers those requests itself with empty lists and
    the upstream does not see them.

K. Added for container installs

37. Every setting of the config file can also be given as an environment variable
    (`DOORWARD_` and the setting's name in capitals, sections joined by `_`). A variable
    wins over the file, and the file is optional when the variables give the required
    settings. An unknown `DOORWARD_` variable or a value that does not parse refuses the
    start with a message that names the variable and never prints a secret.
38. One command builds a container image from the repository. The image holds the binary
    and nothing to log into, runs as a non-root user on a read-only root file system, keeps
    all its data in one volume, and reports its own health.
39. Two Compose files ship. One puts Caddy in front with automatic HTTPS and does not
    publish the gateway on the host. The other runs the gateway alone, published on the
    host's loopback address only, for a proxy or tunnel the operator already has. With
    either, a fresh machine with one filled-in `.env` file gets a healthy gateway whose
    setup code is in the logs, and stopping and starting the stack keeps its data. Every
    container runs with all capabilities dropped, no privilege escalation, and memory and
    process limits.
40. (replaced by 43) The gateway limits request rates itself, so the protection is the same with or without
    Caddy: per client address on every endpoint, tighter on the sign-in, password reset,
    registration, authorization and token endpoints, and per user on tool calls. A request
    over a limit gets `429` with `Retry-After` and reaches no upstream. Every limit is a
    setting. Behind the shipped Caddy the address is the caller's real one: a forged
    forwarding header does not move a caller into another bucket.
41. The README and `docs/DOCKER.md` cover both Compose files, the first start, every
    environment variable with its default, backup and restore, upgrading, and what each
    hardening setting is for. A test fails when a setting has no documented variable.
42. A gateway whose public address is https refuses to start when no trusted proxy is set,
    with a message that says how to fix it, unless the setting `shared_client_address` is
    true; then it starts with a warning. Plain http on a loopback address is exempt.
43. The gateway limits request rates itself, so the protection is the same with or without
    Caddy. Anonymous and refused requests are counted per client address (IPv6 by /64) on
    every endpoint, tighter on the sign-in, reset, invitation, registration, authorization
    and token endpoints. Requests that pass the bearer check are counted per user, and a
    user's open streams are capped. A request over a limit gets `429` with `Retry-After`,
    changes no state, reaches no upstream, and on MCP paths carries no `WWW-Authenticate`.
    Counters live in a table of bounded size: a flood of new addresses neither grows it
    nor resets an existing counter. Every limit is a setting. Behind the shipped Caddy two
    different callers land in different buckets, and a forged forwarding header does not
    move a caller.

L. Added after the owner's auth review

44. Wrong passwords are counted per account and client address together: five in a row
    from one address block that account for that address only, so the same account still
    signs in from another address with the right password. A higher ceiling per account,
    whatever the address, blocks the account for everyone (default 50 inside the window).
    Both numbers are settings. This narrows the "per account" half of statement 6.
45. Activity rows older than a set number of days are deleted by the housekeeping run
    (default 90, a setting). Newer rows are never touched.
46. Every consent page, for local and for web clients alike, says "Approve only if you
    started this sign-in yourself."
47. A grant for the combined endpoint means everything the user may use at the moment of
    each request: a server assigned later is listed and callable without a new consent,
    and a server unassigned is gone from the list at once and a call to it is refused
    without the upstream seeing it.
48. A request to a server path or to the combined endpoint that carries an `Origin`
    header other than the gateway's own address, or one listed in the `allowed_origins`
    setting, is refused with a 403 before its token is looked at; it reaches no upstream,
    costs the user nothing and is not logged as activity. A request with no `Origin`
    header is unaffected, and the sign-in endpoints that programs call are not covered.

### Proof

Each statement is proven by an automated test that `./check.sh` runs, named after its number
(`s03_...`, `s22_...`), over real HTTP against a gateway started on a free local port with a
temporary database, fake upstream MCP servers of both generations, and a mail catcher built
into the test harness. In addition:

- 7: one real email per provider (raw SMTP, Resend, Mailgun), by `scripts/prove-mail.sh`.
- 11: the official MCP conformance suite in its server role, by `scripts/prove-conformance.sh`.
- 14, 16, 26, 33: a walk-through in a real browser at 390 px and desktop width, screenshots
  kept under `proof/` (not tracked).
- 25: `scripts/prove-tests-first.sh` prints, per abuse test, its first commit and the first
  commit of the code it covers, with the saved failing run.
- 27: one transcript and one screenshot per client under `proof/`, by hand-driven runs.
- 30: `scripts/hygiene.sh` scans tracked files and commit messages.
- 31: by the project owner.
- 38, 39, 43: `scripts/prove-docker.sh` builds the image, starts each Compose file on the
  local machine, and checks health, the setup code in the logs, the user, the read-only
  root, the dropped capabilities, that the gateway's port is closed on the host in the
  Caddy stack, a sign-up and a streamed tool call through Caddy's HTTPS (its internal
  certificate authority for `localhost`), a forged forwarding header against the rate
  limit, two callers in separate buckets, data kept across a restart, and a backup and
  restore that still decrypts a stored upstream secret. `./check.sh` does not run it, so
  that Check passes on a machine without Docker.
- 48: `tests/s48_origin.rs`.

### Assumptions

- Rust, one binary with the panel's pages compiled in, SQLite as the only storage.
- The gateway listens on plain HTTP on a local port and expects a reverse proxy or tunnel in
  front of it for HTTPS. Built-in certificates are not in v1.
- Per-server paths forward the original request bytes of what they allow; only the combined
  endpoint rewrites tool names.
- Roles: one owner, admins, users. No groups.
- Defaults, all in the config file: invitation 7 days, reset link 1 hour, access token
  1 hour, refresh token 30 days, authorization code 60 seconds.
- The key that encrypts mail and upstream secrets comes from the environment or a key file,
  never from the database.
- License: MIT OR Apache-2.0.
- Container installs build the image from the repository. Publishing an image to a registry
  is the owner's call.
- The Caddy in the Compose stack is the stock official image; nothing in the stack needs a
  custom build.
- Mail settings stay in the admin panel, stored encrypted; they are not environment
  variables.
- Rate limit counters live in the memory of the one gateway process.

### Not in v1

Sign-in through an external identity provider, a second factor, tokens for callers with no
browser, stored per-user upstream credentials, hosting or launching MCP servers, upstreams
that are local commands, more than one gateway instance on a database, databases other than
SQLite, languages other than English.

## How to check your work

Run: `cargo run -- --config doorward.toml`
Check: `./check.sh`

Before changing anything, run Check once and note what already fails.
Before calling any change done, run Check, confirm every "Done when" statement still holds,
and add a statement and a test for whatever the change adds.
When Check passes, commit locally. Push nowhere without asking.

## Rules for every change

- Public repository hygiene: no host names, IP addresses, local paths, personal names, emails
  or secrets in code, docs, examples, tests or commit messages. Use `example.com` and
  `127.0.0.1`.
- Abuse tests come first: write the test, watch it fail, then write the code.
- Auth code stays inside its own modules so it can be reviewed as a unit.
- Code comments are one or two factual lines, never narration.
- No hosted CI workflows.
