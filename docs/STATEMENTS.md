# Doorward statements

What Doorward guarantees. Each numbered statement is a behaviour the gateway keeps, with its
proof: a test that `./check.sh` runs, or a proof script under `scripts/`.

Statement numbers are permanent. Test files (`tests/sNN_*.rs`), the docs and code comments cite
them. A replaced statement stays in place, marked `replaced by <number>`. Never delete or
renumber. New behaviour takes the next free number.

## Statements

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
    Replaced by 49.

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
31. (replaced by 50) The project owner has read the auth code. It lives in its own modules and arrives as
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
49. Claude Code and Codex each sign in through the gateway, list tools, call an allowed
    tool, are refused a denied one, and the calls show in the activity log under the right
    user. No other client gates v1 (the owner's decision of 2026-11-20); a run made with
    another client is reported.
50. The auth code and the rest of v1 have been reviewed by an independent advisor standing
    in for the owner as tech lead, on security, code quality, maintainability, observability
    and performance; every finding is fixed or listed with its reason. The owner is not asked
    to read code (the owner's decision of 2026-11-20). v1 is not called done before that
    review signs off.
51. A request that fails inside the gateway (a 500 page, a failed session lookup, a failed
    fetch of client metadata, a database error in the bearer check, a refused token exchange
    for a code or token that exists) writes one line to standard error that says what failed
    and why, with no token, code, cookie, password, email or full address in it. A database
    error in the bearer check answers 503, not 401.
52. (replaced by 62) Every page, error pages included, carries a header with the Doorward name. Panel pages
    show the navigation as one row of tabs that wraps on a narrow screen and marks the
    current section. Pages for signing in, setting a password, consent and errors show their
    content in one centered card; panel pages use the wide layout.
53. Every button says what kind it is: a form has at most one primary button, an action that
    deletes, revokes, removes or disconnects is marked destructive, and every other button
    is secondary. Deleting a server or an account takes two steps: the delete button sits
    inside a closed disclosure that says it cannot be undone, and the delete itself still
    needs the form token.
54. A status is a word with a marker, never a color alone: allow and deny on rules and on a
    user's tools, active and disabled on users, enabled and disabled on redirects, and the
    lock-down state of a server.
55. An activity row reads as a label in plain words (for example "Tool call refused",
    "Client connected") and a time written like `20 Nov 2026 19:25:09 UTC`, and keeps its
    machine-readable kind and time. Every kind the gateway records has a label.
56. The mail page shows one provider form at a time: each provider is a disclosure, the one
    in use is open and marked as in use, and the others are closed. With no provider in use
    the page says so and all three are closed. A provider whose form was just refused is
    open, with the reason.
57. (replaced by 70) The consent page has Approve as its one primary button and Deny as a secondary button,
    and the sentence about a client whose description cannot be confirmed is shown as a
    warning. Its wording is unchanged.
58. (replaced by 63) Text in the stylesheet's two themes has a contrast of at least 4.5 to 1 against the
    background it sits on, buttons, fields and tabs are at least 44 px tall, the pages make
    no request outside the gateway and carry no script and no inline style, and at 390 px
    wide no page scrolls sideways.
59. The admin overview shows how many servers, users, open invitations and rules exist, each
    count linking to its page, and the five latest activity rows with a link to the whole
    activity page.
60. The servers list shows, per server, its path, how many tools it has, how many users are
    assigned to it and its lock-down state. The users list shows, per user, the role, how
    many servers are assigned and whether the account is active or disabled.
61. The activity page shows 50 rows per page, newest first, says which rows of how many it
    shows, and links to older and newer pages that keep the chosen filters. A page number
    that is not a positive number shows the first page, and a page past the end shows no
    rows and still links back to newer ones.
62. Every page, error pages and "page not found" included, carries a header with the
    Doorward name. On panel pages the header holds the navigation: beside the content at
    1100 px wide and more, and under that behind a Menu button that opens it without any
    script. The current section is marked, with exactly one mark on the page. Pages for
    signing in, setting a password, consent and errors have no navigation and show their
    content in one column beside the header.
63. Text in both themes has a contrast of at least 4.5 to 1 against the background it sits
    on, computed from the stylesheet's colour values. Buttons, fields and navigation links
    are at least 44 px tall on a narrow or touch screen and at least 36 px otherwise. The
    pages make no request outside the gateway and carry no script and no inline style, and
    from 360 px wide up no page scrolls sideways.
64. The interface has its own typeface: the font files are compiled into the gateway and
    served by it, the page policy allows fonts from the gateway only, and the fonts'
    licence files are in the repository.
65. Fields that share a row line up: their inputs have the same top and the same bottom,
    whichever of them has a hint or a label that wraps. A hint is a sentence under its
    field, tied to it for screen readers, never text in brackets inside the label.
66. Servers, users, invitations, rules, redirects, connected clients and activity are
    tables with column heads at desktop width, and each row becomes a stacked record on a
    phone. A number stays on one line with its unit, and a name or address breaks only at
    a separator, never in the middle of a word.
67. Moving between pages, opening a disclosure and a notice appearing are animated by the
    stylesheet alone, and nothing moves for a person who asked for reduced motion.
68. A server that answers without the gateway is called out: an alert at the top of its own
    page, and on the overview an alert that names the servers concerned.
69. Colour appears only where the gateway allowed, denied or removed something, or cannot
    verify something. Everything else is ink and paper, the primary button included, and
    every colour in the stylesheet comes from its table of named values.
70. The consent page has Approve as its one primary button and Deny as a secondary button.
    The line about a client whose name or description cannot be confirmed is shown as a
    warning. For a self-registered client it reads: An app that calls itself “NAME” is
    asking to sign in as you. Doorward cannot check this name.
71. A form that is refused for a reason about its values comes back holding what the person
    typed, so only the field at fault has to be corrected. Passwords, secret values, API
    keys and the setup code are never sent back. A value longer than its field's limit comes
    back empty, and a sign-in refused for too many attempts comes back with an empty form.
72. Each count on the overview says what needs attention behind it: how many servers answer
    without the gateway, or are not checked, or that all are locked down; how many users
    are disabled; when the next open invitation expires; how many rules deny and how many
    allow. A count of one takes the singular noun.
73. The account page of an owner or admin keeps the panel navigation, with Your account as
    the marked section; a plain user's account page holds the one link Your account and
    never a panel link. The "Request refused" page links to the start page. An invitation
    whose email was not sent shows its link in a field labelled Invitation link.
    For someone signed in, the start page is their account page.
74. A message that a server could read differently than the gateway judged it is refused with
    `400` and JSON-RPC `-32600`, and never reaches the upstream: one with a top-level member
    other than `jsonrpc`, `id`, `method`, `params`, `result` and `error`; or one where
    `params`, `params._meta` or `params.ref` holds a member name with a non-ASCII character
    or a control character (U+0000 to U+001F, U+007F), or a name that differs only in letter
    case from one the gateway reads there, such as `Name` for `name`. Member names inside
    `params.arguments` belong to the tool and are not checked.
75. The bytes of server answers that the gateway holds in memory at one time are bounded by
    `limits.answer_memory_bytes` (32 MiB by default) over all requests, and one user's
    requests together hold at most a quarter of it, or one largest answer
    (`limits.tools_list_bytes`) when that is more. Each held byte counts once. An answer
    that does not fit is not read further. A plain answer gets `503` and JSON-RPC `-32000`:
    with `Retry-After: 1` and message `The gateway is busy`, or, for a `tools/call` that was
    already sent to the server, with no `Retry-After` and message `The gateway could not
    hold the server's answer. The call was sent to the server.` An open stream ends, and
    the combined tool list leaves that server out, or answers the busy `503` when every
    server was left out for this reason. Nothing is stored as a server error. An answer
    counts until the client has taken it from the gateway: it is handed over in pieces of
    at most 64 KiB, and a connection whose writes make no progress for
    `limits.write_stall_seconds` (30 by default) is closed, which frees what it held.
    Outside the count stay the bytes already handed to a connection for sending, about
    0.5 MiB per open connection, and the 8 queued pieces of an open stream. A user at
    their share does not stop another user's answers.
76. A request body that is not sent in full within `limits.body_read_seconds` (15 by default)
    is answered with `408` and the connection is closed, for browser forms, the token and
    registration endpoints and MCP posts alike. Nothing is processed or forwarded, and no
    activity row is written. A `HEAD` on `/oauth/authorize` is rate limited as a `GET` is.
77. What a caller without an account can make the gateway write or send is bounded. Failed
    sign-ins for addresses that match no account write at most 20 activity rows in any hour
    over the whole instance, and the twentieth says that later ones are not recorded; a
    failed sign-in for an existing account always writes its row. An account receives at
    most five reset mails in each window of 24 hours. A window opens with the first mail
    after the last window ended, so two windows can meet and nine mails can arrive within an
    hour. A request beyond the five answers as every other one does and sends nothing;
    completing a reset, changing the password or an admin disabling the account starts the
    count again. Every answer of the
    token, registration, discovery, health and MCP routes carries
    `X-Content-Type-Options: nosniff`. An upstream secret is never printed by a debug format.
78. What a signed-in user or a server can make the gateway store is bounded. A tool name in
    an activity row is cut to 128 characters, and each control, invisible or
    direction-changing character in it is stored as U+FFFD. One user's refused tool calls
    write at most 100 rows in any hour, over all servers and both endpoints; the hundredth
    row says that later ones are not recorded, and the answers to the client do not change.
    A server's tool list keeps at most 1000 tools and no tool whose name holds such a
    character; the refresh still succeeds and logs how many tools were left out. When the
    table of sign-ins in progress is full, or one address holds 200 of them, a request whose
    consent page has never been shown is dropped before one that has.
79. The three mails share one layout and say who sent them. Each closes with `Sent by the
    Doorward gateway at <host>.` and one sentence about what Doorward does, where the host is
    the gateway's public address. The reset mail says `If this was not you, ignore this mail.
    Your password stays the same.` The new-connection mail names what the app can use (the
    server's name, or `every server assigned to you` for the combined endpoint), where the
    sign-in was sent, named as the consent page named it, and the time in UTC; the name the
    app gave itself is not in the mail. A destination longer than 80 characters keeps its
    last 80.
    The HTML part equals the designed mail byte for byte, a host in it breaks only before a
    dot, and the address shown as text equals the link with no character added. The mark,
    the rule under the header and the neutral button outline are borders with no colour of
    their own, so they take the text colour a mail client gives the mail. Outside a link,
    no text node of a mail holds two labels joined by a dot: the host in the closing line,
    the destination and the server name open a plain `span` at every dot, so a mail client
    finds no address to turn into a link, and the text reads the same. On the consent
    page the sentence about a local app sits inside the one warning box.

M. Added for custom headers and per-user credentials

80. An admin declares up to 8 custom headers per server, each with a name and whether it is
    required, and sets two switches per server: pass the declared headers through from the
    client, and let each user store their own values. A name must be a valid header name of
    at most 64 characters and unique on the server whatever its case. Refused names: the
    ones refused for the secret header, `Cookie`, `User-Agent`, `Origin`, `Referer`,
    `Last-Event-ID`, `Forwarded`, `Via`, `X-Real-IP`, every `X-Forwarded-` name, every
    `Mcp-` and `Proxy-` name, and the server's own secret header name; the secret header
    cannot take a declared name either. `Authorization` may be declared: it is never passed
    through from a client and can only be stored.
81. With pass-through on, a declared header that the client sends reaches that server with
    the client's value, on the server's path and on the combined endpoint (there it goes to
    every server that declares the name and passes it through). With pass-through off, or
    for a name that is not declared, the header does not reach the upstream. A declared
    header sent more than once, or with a value that is empty, longer than 4096 bytes or not
    visible ASCII, is refused with HTTP 400 before any upstream is contacted.
82. With stored values on, a user assigned to the server stores one value per declared
    header on the account page. The page never shows a stored value again: it shows the date
    it was set, the account's email and the host the value is sent to, and it warns when
    that upstream is plain `http` on an address that is not loopback. A value is visible
    ASCII of 1 to 4096 bytes. The gateway attaches the caller's stored values to that
    caller's requests to that server and to no other request. When the client sends the
    header and pass-through is on, the client's value is used for that request. Admins see
    only whether a user has a value.
83. When a required header has no value for a caller, stored or passed through, nothing is
    sent to that server for that caller. The server's path answers HTTP 403 with a JSON-RPC
    error whose message names the server and what is missing: the account page's address
    when values can be stored there, else the header's name; the combined endpoint leaves
    that server out for that caller and keeps serving the others. The
    account page marks each server that still needs values, and the consent page names
    them. A connection made before the user had a key gets the same refusal with the words
    `Reconnect this app`.
    Replaced by 90.
84. Stored values are encrypted so that the database and the key file together do not open
    them. Each user has one random 256-bit data key, made the first time a password is in
    hand (setup, invitation, sign-in), before any value exists. A value is sealed under the
    data key with a context of user, server, lower-cased header name, key generation and
    the server's upstream address. The data key exists only as wraps: one under a key from
    Argon2id over the password with its own salt, and one on each live browser session,
    authorization code, access token and refresh token, under a key derived from that
    secret, of which the database holds only a hash; every wrap is sealed again with the
    server key. A wrap's context names the user, the key generation, the table and the
    row. The password wrap key is derived only after the password was accepted; a failed
    sign-in runs no second derivation, and no password derivation runs on an MCP request.
85. The data key follows the user's secrets and dies with them. Sign-in wraps it for the
    session, consent for the code, the code exchange for the token pair, and a refresh for
    the new pair, each in the same transaction as the row change. A redeemed code, a
    rotated refresh token, an expired row at the sweep, a sign-out and a disconnected app
    lose their wrap. A password change, a reset and a disable remove every wrap on the
    user's codes and tokens. A password change makes a new data key and seals the values
    again; a reset deletes the user's stored values and says so on the reset page and in
    the reset mail. A missing or damaged wrap never changes whether a sign-in, a consent, a
    code exchange or a refresh succeeds: it only makes servers with stored values
    unavailable to that connection.
86. Stored values are deleted when their destination changes: every user's values for a
    server when the server is deleted, its upstream address changes, or a declared header
    is removed (a rename is a removal); one user's values for a server when that user is
    unassigned from it. A value copied to another user, server, header or upstream address
    in the database does not open.
87. A user's values never appear in the database in clear, in an activity row, in a log
    line, in any page or in an error the gateway writes. Storing, replacing and removing a
    value write an activity row with the header's name. Values are sent only inside a
    request that carries the caller's token, or the pressing admin's session for Refresh
    tools; the lock-down check, the gateway's own session closes and a redirect answer from
    the upstream carry none. They are marked sensitive on the outgoing request and are not
    kept in memory between requests. An open stream or upstream session of a user on a
    server ends when that user's values for it change.
88. A server without a stored secret header is never reported as locked down. While it
    declares custom headers its page says that anyone who reaches the upstream directly
    bypasses the gateway's rules and its activity log.
89. The README says how to set up custom headers, pass-through and stored values, and with
    `SECURITY.md` states what the encryption does not cover: an attacker running code in
    the live gateway, a password guessed offline from a stolen database, a stolen live
    token together with the database, an admin who points the server at another address
    before users store values again, and a server that echoes a credential back. It tells
    the reader to rotate the upstream credential after a suspected theft and to keep the
    key file out of backups of the data directory.
90. When a required header has no value for a caller, stored or passed through, when the
    caller's connection cannot open the user's key, or when a stored value cannot be
    opened, nothing is sent to that server for that caller and the gateway answers for the
    server itself, on the server's path and on the combined endpoint: the client connects,
    the tool list is the gateway's stored list for that server under the caller's rules
    (empty until the server's tools were refreshed once), and a call to a tool on that list
    returns a tool error that names the server and what to do: the account page's address
    when values can be stored there, else the header's name; `Reconnect this app` for a
    connection that holds no copy of the user's key; store the credentials again for a
    value that cannot be opened. No request of that caller gets an HTTP 401 or 403 for this
    reason, so a client does not mistake it for a failed sign-in. Each refused call is in
    the activity log with the reason. On the server's path such a caller is steered to a
    session: the probe of the stateless protocol is answered Method not found, and the
    session the client then opens is kept by the gateway. Once the values are there, that
    session keeps working without a new sign-in or a restart of the client: the gateway
    relays its tool lists and tool calls to the server itself, under the caller's rules,
    and serves nothing else on it. A connection that cannot open the user's key has to be
    reconnected. The account page marks each server that still needs values, and the
    consent page says so. Proven with Claude Code and Codex connecting before the value is
    stored.
91. An admin can set the servers and the personal rules of a pending invitation. They are
    stored apart from live assignments and rules, so nothing applies before the account
    exists; accepting the invitation creates the account, its server assignments and its
    rules in one transaction; revoking the invitation or deleting a server removes the plan at
    once; an expired invitation's plan can no longer be applied or carried and is removed with
    the invitation. Proof: the invitation plan tests in `src/admin/tests.rs`, listed in
    `docs/TESTS.md`.
92. An admin cannot revoke, replace or plan an invitation whose role is admin; only the owner
    can. Re-inviting an address carries its pending rules only when the role is unchanged.
    Proof: `admin_cannot_revoke_or_replace_an_admin_invitation`,
    `reinviting_with_another_role_carries_no_rules` and `admin_cannot_plan_an_admin_invitation`
    in `src/admin/tests.rs`.
93. The rule form suggests only the tools of the server chosen in it, on the Rules page and on a
    pending invitation's page; the server is chosen with a form that reloads the page, since pages
    carry no script. Proof: `the_rule_form_lists_only_the_tools_of_the_chosen_server`,
    `the_invitation_rule_form_lists_only_the_tools_of_the_chosen_server`,
    `the_server_picker_is_a_get_form_without_the_csrf_token` and
    `a_rule_posted_from_the_form_uses_the_chosen_server` in `src/admin/tests.rs`.
94. The activity page filters its rows by `period` (`24h`, `7d`, `30d`, `90d`, `all`, or `custom`
    with `from` and `to` as UTC days, both included), `event`, `user`, `email`, `server`, `slug`,
    `tool`, `client` and `q`, all combined with AND, and its paging and its Remove links keep the
    other filters. `email` and `slug` match the recorded user email and server slug exactly: a
    ranked dashboard link names them, so its rows stay the same when the user or server is deleted.
    A value that names nothing matches no row: an unknown period or event, a custom period whose day
    is missing or not a date (the form then shows a field error), a `from` after `to`, a user or
    server that is not an id. `event=tool_any` matches every `tool_call` row, let through, refused or
    failed; `event=tool_let_through` matches the `tool_call` rows that were not refused, whatever
    their outcome, which are the calls the people and duration figures count. The client filter is a
    select of `Any client` and the distinct client names of the tool calls of the last 30 days, by
    name, at most 50; a client that is not in that list still filters and shows as the selected
    option. A repeated key takes its first value and is never refused. `q` is a substring of the
    user, server, tool, client and detail, with ASCII letters matched in either case, and `%`, `_`
    and `\` in it are literal; a search longer than 200 characters is cut to its first 200, and the
    form shows the cut value. Proof: `tests/s94_activity_filters.rs`, `tests/s98_panel_reads.rs` (the
    client list, the cut search and the recorded chips) and the unit tests in
    `src/admin/activity/filters.rs`.
95. `POST /admin/activity.csv` returns every row the filters of statement 94 match, oldest first,
    as CSV with the columns `time_utc,event,user,server,tool,client,decision,outcome,detail,
    duration_ms` and CRLF line ends. The button that posts it is on the Activity page with the
    filters as hidden fields and the csrf token, and the post is checked for its Origin and csrf
    like every form. A cell is quoted as RFC 4180 says. A cell whose first character after leading
    spaces or tabs is `=`, `+`, `-` or `@`, or is the full-width ＝ ＋ － ＠, gets a leading `'`, as
    does a cell that starts with a tab or a CR. The rows are read in chunks, and before the body
    streams the export writes one `admin_change` row, `export started (N rows; ...)`, that names
    the period, event, user, server, tool, client and search in force; that row is not part of the
    export. The button is shown only when the filters match at least one row. `GET
    /admin/activity.csv` answers 405 and writes nothing. An anonymous visitor is redirected to
    sign-in and a plain user gets 403. Proof: `tests/s95_activity_export.rs`,
    `tests/s98_panel_reads.rs` and the unit tests in `src/admin/activity/export.rs`.
96. Dashboards are stored in the database and shared. Every admin and the owner creates, renames,
    reorders and deletes dashboards and their charts, and each change writes one `admin_change`
    row. A chart whose server or user is deleted is removed with it, and the gateway writes one
    `admin_change` row per chart removed, naming the admin, `deleted chart {title} from dashboard {name}: its server
    was deleted` or `... its user was deleted`. A plain user gets 403 on every dashboard route,
    POSTs included, and an anonymous visitor is redirected to sign-in. A form post without the csrf
    token is refused and stores nothing. A dashboard name is trimmed and is 1 to 80 characters,
    unique among the dashboards; there are at most 20 dashboards and 24 charts on one. A chart's
    metric, grouping, shape, period, width, server, user, tool and top count are closed lists or
    bounded values, and a combination the builder cannot draw is refused with 400, stores nothing
    and shows the form again with its refusal. The edit page of a dashboard lists its charts as one
    table under its header, then the chart builder, Name and Delete; the table's Counts cell is the
    chart's caption, and an edited row reads `Editing` in place of its actions. A new database starts
    with one dashboard, `Usage`, of ten charts. Proof: `tests/s96_dashboards.rs` and
    `tests/s98_panel_reads.rs` (the removed charts).
97. The Overview shows the dashboard named by the query key `dashboard`, or the first dashboard
    when the key names none. The key `period` (`24h`, `7d`, `30d` or `90d`) draws every chart of
    that dashboard over that period in place of the chart's own. Each chart counts the rows its
    Activity-page event and filters select, so a figure and the Activity page agree; a chart's Data
    table holds the numbers its figure draws. A ranked label links to the Activity page with the
    rows behind it. For a count metric the link carries the metric's event (`tool_any` for all tool
    calls), the chart's own filters, and the recorded user email (`email`), server slug (`slug`) or,
    for a tool, the tool and its server slug, so the linked page has exactly the bar's count, also
    after the user or server is deleted or re-created with the same email. Active users and the
    duration metrics link to the `tool_let_through` rows they are computed from, failed and
    tool-error calls included. A ranked row with no key (the empty client) is plain text, not a
    link. A chart's caption names each filter in force: ` on` its server slug, ` by` its user email,
    ` of` its tool. Durations are written with ` ms`. A time chart has 24 hourly buckets, one bucket
    per UTC day ending today for 7 and 30 days, or 13 or 14 UTC weeks from Monday for 90 days, the first
    starting on the period's first day. The bucket the clock is still in is drawn as partial: a line
    stops before it, its bar is fainter, and it reads `so far`. A duration bucket with no tool call is a gap labelled `No value`,
    not zero. A ranked list is cut to its top count, with ties ordered by label. The server draws
    each chart as SVG with no script and no inline style, and every label is escaped. A repeated
    query key takes its first value. A figure is drawn from the activity as of the minute shown in
    statement 98: the link is read when followed, so the page it opens may hold rows added since.
    A 90-day Overview over 200,000 rows answers in under three seconds in the debug build. Proof:
    `tests/s97_dashboard_charts.rs` and the unit tests in `src/admin/dashboards/`.
98. Reading the activity log for the panel never delays the gateway. The panel's reads use their own
    read-only connection to the database, which the proxy, the bearer check and sign-in never take.
    Each chart is computed from one scan of its activity rows, folded in memory, with no sort,
    window or temporary table in SQLite, so a chart needs no scratch space. A chart whose numbers
    fail shows `This chart could not be drawn.` in its place, is reported on standard error, and the
    counts and latest activity of the Overview still answer. A chart's figure is kept for the minute
    it was drawn in, so a reload within that minute reads nothing again, and a changed chart is
    drawn at once. Proof: `tests/s98_panel_reads.rs`, whose latency test asks for `/admin?period=90d`
    over 300,000 rows and checks that a panel request answers in under 150 ms while that Overview is
    still computing; `every_chart_statement_searches_an_index_without_a_sort_or_temporary_table` in
    `src/admin/dashboards/query.rs`; `every_page_of_the_export_and_the_activity_page_reads_in_index_order`
    in `src/admin/activity/export.rs`; `the_reader_sets_query_only_and_its_read_only_flag_refuses_writes_once_query_only_is_off`
    in `src/db.rs`, which also refuses a journal that is not WAL and caps the writer's journal at 64 MB;
    `the_listing_answers_while_the_writer_is_held` in `src/admin/activity.rs` and
    `the_overview_series_reads_while_the_writer_is_held` in `src/admin/dashboards/pages.rs`, which hold the
    writer's connection and fail if a panel read waits for it.

N. Added for per-user tool switches

99. The account page has a `Your tools` section. For each server the user is assigned to, it lists
    every tool of that server's stored list that the rules allow the user, with a switch and the
    size of the tool's definition. A tool a rule denies the user is not shown. A server whose list
    was never read says so instead of showing an empty list. Proof: `tests/s99_tool_switches.rs`.
100. A tool the user switched off is absent from that user's tool list on the server's own path and
    on the combined endpoint, in both protocol generations. A call to it is refused without the
    upstream seeing it, the answer says the tool is switched off in the user's account, and the
    activity row reads `switched off` as its detail. A switched-off tool takes no room in the
    combined endpoint's size budget. Proof: `tests/s100_switched_lists.rs`.
101. A switch only subtracts. It never makes a tool that a rule denies, or a server the user is not
    assigned to, reachable, and it changes nothing for any other user. Only the signed-in user sets
    their own switches, through a form that carries their session's token and the gateway's own
    origin; an admin sees them and has no way to set them or to force a tool on. Only names from
    the server's stored list are ever stored, so a form cannot grow the table. Proof:
    `tests/s101_switch_abuse.rs`.
102. A tool that appears in a server's list later is on. A switched-off tool that leaves the list
    and returns is still off. Proof: `tests/s99_tool_switches.rs`.
103. Each server in `Your tools` has `All on` and `All off`. The section shows the size of the tools
    the user leaves on against the size of all the tools they may use, in kilobytes and as a share,
    and says that a client picks up a change when it reconnects or refreshes its tools. Proof:
    `tests/s99_tool_switches.rs`.
104. The admin's page of a user shows each tool that user switched off as `switched off by the
    user`. A user's switches for a server are deleted when the assignment, the user or the server
    is removed, so a server assigned again starts with every tool on. Proof:
    `tests/s99_tool_switches.rs`.
105. A user who switched nothing off receives the lists and answers they received before switches
    existed: the per-server path still forwards the upstream's bytes when no rule and no switch
    removes a tool. Proof: `tests/s100_switched_lists.rs`, and every test of statement 32 unchanged.

## Proof

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
- 27: replaced by 49.
- 30: `scripts/hygiene.sh` scans tracked files and commit messages.
- 31: replaced by 50.
- 38, 39, 43: `scripts/prove-docker.sh` builds the image, starts each Compose file on the
  local machine, and checks health, the setup code in the logs, the user, the read-only
  root, the dropped capabilities, that the gateway's port is closed on the host in the
  Caddy stack, a sign-up and a streamed tool call through Caddy's HTTPS (its internal
  certificate authority for `localhost`), a forged forwarding header against the rate
  limit, two callers in separate buckets, data kept across a restart, and a backup and
  restore that still decrypts a stored upstream secret. `./check.sh` does not run it, so
  that Check passes on a machine without Docker.
- 48: `tests/s48_origin.rs`.
- 49: one transcript and one screenshot per client under `proof/clients/`, by hand-driven
  runs against the stack of `scripts/prove-clients.sh`.
- 50: the advisor's reports, kept under `proof/review/` (not tracked), and the commits that
  fix its findings.
- 51: `tests/s51_failure_log.rs`, which drives the built binary and reads its standard error.
- 59 to 61: `tests/s59_counts_paging.rs`.
- 62 to 64, 67 and 69: `tests/s62_shell.rs`, which reads the served pages, the font files
  and the stylesheet; 65 and 66: `tests/s65_forms_tables.rs`; 68: `tests/s68_exposed.rs`.
  For 63, 65, 66 and 67 also a walk-through of every page in a real browser at 390 px and
  desktop width in both themes, which measures the tops and bottoms of fields on a row,
  control heights, contrast and sideways scroll, and captures a page change mid-way;
  screenshots kept under `proof/` (not tracked).
- 70: the consent tests in `tests/s52_interface.rs` (buttons, warning) and
  `tests/s33_consent.rs`, which pins the sentence for a self-registered client.
- 71: `tests/s71_refused_forms.rs`.
- 72: `tests/s72_overview_state.rs`.
- 73: `tests/s73_account_nav.rs`.
- 74: `tests/s74_key_case.rs`, on the per-server and the combined route under both protocol
  generations, and the classify rows in `src/mcp/tests.rs`.
- 75: `tests/s75_answer_memory.rs`, with a fake upstream that holds its answers open and
  with clients on raw sockets that read the status line and then stop reading; the unit
  tests in `src/proxy/budget.rs`, `src/web/limit.rs`, `src/web/stall.rs` and
  `src/proxy/tests_combined.rs`; and `tests/s75_process_memory.rs`, which runs the real
  binary, holds 64 answers of 4 MB open at once, then leaves 200 answers unread, and reads
  the peak resident memory of the gateway process from `/proc`.
- 76: `tests/s76_body_deadline.rs`, with a raw socket that stalls mid-body on each of the four
  routes, and `a_head_on_authorize_is_limited_at_the_same_count_as_a_get` in
  `tests/s43_rate_limits.rs`.
- 77: `tests/s77_account_abuse.rs`, which moves the test clock and restarts the gateway to
  run the housekeeping sweep; the sweep's unit tests in `src/accounts/housekeeping.rs`; and
  the debug format tests in `src/servers.rs`.
- 78: `tests/s78_bounded_writes.rs` on both endpoints and with a fake upstream that lists
  1200 tools, the unit tests in `src/audit.rs` and `src/proxy/catalog.rs`, and the two
  eviction tests in `src/oauth/tests_consent.rs`.
- 79: `tests/s79_mails.rs`, which reads the mails a first connection, a reset and an
  invitation send; the byte for byte, host rule, address rule, border and unlinked text tests in
  `src/mail/templates.rs` against `src/mail/fixtures/`; the destination and time tests in
  `src/oauth/token.rs`; and the notice test in `src/oauth/consent.rs`.
- 80, 81, 88 and the pass-through half of 83: `tests/s80_custom_headers.rs`, with a fake
  upstream that records the headers of every request, on the server's path and the combined
  endpoint under both protocol generations; the new sections are in the page lists of
  `tests/s52_interface.rs`, `tests/s62_shell.rs`, `tests/s65_forms_tables.rs` and
  `tests/s71_refused_forms.rs`.
- 82, 84 to 87 and the stored half of 83: `tests/s84_stored_values.rs`, which copies the
  database, its write-ahead log and
  the key file while the gateway runs and tries every stored string as a key, replays used
  and revoked secrets against that copy, moves rows between users, servers and headers,
  and reads the activity log, the pages and the gateway's standard error for a canary
  value; the unit tests in `src/crypto.rs`, `src/vault/`, `src/accounts/tests_vault.rs` and `src/oauth/tests_token.rs`. Also one run per real
  client of statement 49 against a server that demands a per-user header, once passed
  through and once stored.
- 89: `tests/s41_docs.rs`.
- 90: `tests/s90_withheld.rs`, the updated tests of 83 in `tests/s80_custom_headers.rs` and
  `tests/s84_stored_values.rs`, and one run each with Claude Code and Codex.
- 96: `tests/s96_dashboards.rs`. 97: `tests/s97_dashboard_charts.rs` and the unit tests in
  `src/admin/dashboards/`. 98: `tests/s98_panel_reads.rs` and the unit tests named in statement 98.
- 52 to 58: `tests/s52_interface.rs`, which reads the served pages and the stylesheet, and
  a walk-through of every page in a real browser at 390 px and desktop width in both
  themes, which also measures control heights and sideways scroll; screenshots kept under
  `proof/` (not tracked).

## Assumptions

- Rust, one binary with the panel's pages compiled in, SQLite as the only storage.
- The gateway listens on plain HTTP on a local port and expects a reverse proxy or tunnel in
  front of it for HTTPS. Built-in certificates are out of scope.
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

## Out of scope

Sign-in through an external identity provider, a second factor, tokens for callers with no
browser, a stored tool list per user (the stored list of a server is shared by its users, and statements 99 to 105 filter it per user), telling a connected client that its tool list changed, a search tool that stands in for the full tool list, hosting
or launching MCP servers, upstreams that are local commands, more than one gateway instance on a database, databases other than
SQLite, languages other than English.
