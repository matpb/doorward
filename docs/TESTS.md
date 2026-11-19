# Doorward test catalogue (v1)

One section per test file. A file is named after the statement of `CLAUDE.md` it proves.
Every test here is written before the gateway code it covers, and fails until that code
exists. `docs/INTERFACE.md` gives the routes, fields, statuses and attributes used below.

## Conventions

- A file starts with `mod common;` and every test is
  `#[tokio::test(flavor = "multi_thread")]`.
- `W` is `common::world::World::start().await`: a gateway with its owner signed in
  (`W.owner`), mail settings pointing at the mail catcher (`W.mail`), and the client
  metadata document `APP_ID` registered. `W.user("bob@example.com")` is an invited,
  signed-in user. `W.upstream("demo", options)` adds a server behind the secret gate and
  returns `(upstream, server_id)`; its tools are `echo`, `search`, `delete_db` unless said
  otherwise. `W.grant(email, &[id])` assigns servers. `W.token(&browser, "demo")` runs the
  whole sign-in and returns tokens; `W.session_mcp` and `W.stateless_mcp` give MCP clients.
- "bob on demo" means: `W.user`, `W.upstream`, `W.grant`, `W.token`, in that order.
- Time moves only through `W.gw.clock.advance(..)`. No sleeps, except waiting for mail with
  `wait_to` and measuring stream timing.
- "upstream untouched" means the fake upstream recorded no request since `clear()`, or none
  with the named method. "No code" means the answer has no `Location` carrying `code`.
- "403 forbidden" is status 403 with `kind() == "forbidden"`. "error page" is status 400
  with `kind() == "error"` and no `Location` header.
- A form post "without csrf" uses `client.post` (which adds none). "Foreign origin" uses
  `post_with(.., &[("Origin", "https://evil.example.com")])`; "no origin" passes
  `("Origin", "")`. A valid csrf value for such posts is read from a form page first.
- Addresses outside `127.0.0.1` and the documentation ranges are built from numbers in the
  test source (`Ipv4Addr::new(10, 0, 0, 1)`), never written as dotted text.
- Assertions carry a message that says what was expected.

## s02_first_owner.rs (statement 2)

Uses `TestGateway::start()` and `gw.client()` unless `W` is named.

1. `setup_page_shows_while_no_owner`: `gw.setup_code()` is `Some` and at least 20
   characters; `GET /setup` is 200 `setup`.
2. `wrong_code_creates_nothing`: `setup_owner("wrong-code", ..)` is 403; `GET /setup` is
   still 200; the right code then answers 303.
3. `owner_is_signed_in_and_reaches_the_panel`: `setup_owner` answers 303 with `Location`
   `/admin`; `GET /admin` is 200 `admin`.
4. `setup_closes_after_the_owner_exists`: on `W`, `GET /setup` is 404 and a post to
   `/setup` with a valid csrf value is 404; after `W.gw.restart()`, `setup_code()` is
   `None`.
5. `there_is_no_open_sign_up`: on `W`, `GET /signup` and `GET /register` are 404 and
   `GET /invite/not-a-real-token` is 404 `link-invalid`.
6. `two_concurrent_setups_make_one_owner`: two browsers each read the setup form, then post
   at the same moment with the right code and different emails. Exactly one answers 303.
   Afterwards exactly one of the two addresses can sign in.
7. `setup_code_changes_at_restart`: code A, restart, code B differs from A; A answers 403;
   B answers 303.
8. `short_password_is_refused_at_setup`: 11 characters answers 400 `setup`; `GET /setup`
   is still 200; 12 characters answers 303.
9. `setup_needs_csrf_and_origin`: without csrf, with a foreign origin, with
   `Origin: null`, and with no origin, each is 403 forbidden and `GET /setup` is still 200.

## s03_invitations.rs (statement 3)

1. `invited_user_sets_a_password_and_signs_in`: `admin::invite` answers 303; the mail to
   bob has subject `You are invited to Doorward` and a link starting `{base}/invite/`;
   `GET` of the link is 200 `invite`; `accept_invite` answers 303 `/account`;
   `GET /account` is 200; after `logout`, `login` answers 303.
2. `invitation_works_once`: after acceptance, `GET` of the link is 404 `link-invalid` and
   a second browser's `accept_invite` attempt (csrf read from `/login`) is 404.
3. `invitation_expires_after_seven_days`: after 7 days and 1 second the link is 404 on
   GET and on POST. A second invitation, 7 days minus 1 minute old, still works.
4. `revoked_invitation_is_refused`: `admin::revoke_invitation` answers 303; the link is
   404; the invitations page no longer lists the address.
5. `a_scanner_get_does_not_use_up_the_link`: three GETs of the link from a browser with no
   cookies, then `accept_invite` still answers 303.
6. `invitation_link_ignores_the_host_header`: the owner posts the invitation with
   `Host: evil.example.com` and `X-Forwarded-Host: evil.example.com`; the link in the mail
   still starts with `{base}/invite/`.
7. `invitation_token_is_not_stored`: the token part of the link is absent from
   `W.stored_bytes()`.
8. `only_admins_invite`: a plain user's post to `/admin/invitations` is 403 forbidden; an
   anonymous one is 303 `/login`; no mail is sent in either case.
9. `invited_admin_reaches_the_panel_and_user_does_not`: `W.admin(..)` gets 200 on
   `/admin`; `W.user(..)` gets 403 forbidden.
10. `existing_address_cannot_be_invited`: inviting `OWNER_EMAIL` is 400 with an `error()`
    and sends no mail.
11. `short_password_keeps_the_link_usable`: 11 characters is 400 `invite`; the same link
    then accepts a 12 character password with 303.
12. `mail_has_text_and_html_parts`: both `text` and `html` of the invitation contain the
    link.

## s04_reset.rs (statement 4)

1. `reset_by_email_sets_a_new_password`: an anonymous browser submits `/forgot` with bob's
   address: 200 `forgot-sent`; mail subject `Reset your Doorward password`, link starting
   `{base}/reset/`; `reset_password` answers 303 `/login`; the new password signs in (303),
   the old one does not (401).
2. `answer_is_identical_for_an_unknown_address`: status and body of the answer for bob's
   address and for `nobody@example.com` are equal byte for byte; no mail goes to the
   unknown address.
3. `reset_link_works_once`: second use is 404 on GET and POST.
4. `reset_link_expires_after_an_hour`: after 61 minutes the link is 404; a fresh one at
   59 minutes works.
5. `reset_kills_sessions_and_tokens`: bob on demo, with a signed-in browser. After the
   reset: that browser's `GET /account` is 303 `/login`; `list_tools` with the old access
   token is 401; `token_refresh` is 400 `invalid_grant`.
6. `password_change_keeps_this_session_and_kills_the_rest`: bob signed in on browsers A
   and B, with a token. A's `change_password` answers 303 `/account`; A's `GET /account` is
   200 and A's session cookie value changed; B's `GET /account` is 303 `/login`; the token
   is 401.
7. `password_change_needs_the_current_password`: a wrong current password is 400 and the
   old password still signs in.
8. `reset_link_ignores_the_host_header`: `/forgot` posted with a forged `Host`; the link
   still starts with `{base}/reset/`.
9. `disabled_user_gets_no_reset_mail`: same `forgot-sent` page, no mail.
10. `reset_token_is_not_stored`: the token part of the link is absent from
    `W.stored_bytes()`.
11. `a_scanner_get_does_not_use_up_the_reset_link`: three GETs, then the reset works.

## s05_disable.rs (statement 5)

1. `disabled_user_is_refused_on_the_next_request`: bob on demo, `list_tools` is 200.
   `admin::user_action(.., "disable")` answers 303. The very next `list_tools` is 401;
   `token_refresh` is 400 `invalid_grant`; bob's browser gets 303 `/login` on `/account`;
   `login` is 401 with the same `error()` text as a wrong password.
2. `deleted_user_is_refused_on_the_next_request`: same with `delete`; the users page no
   longer lists bob.
3. `re_enabled_user_must_connect_again`: after `enable`, the old access token is still 401
   and the old refresh token still `invalid_grant`; `login` works; a new `W.token` works.
4. `owner_cannot_be_disabled_or_deleted`: an admin's attempts are 400; the owner still
   reaches `/admin`.
5. `open_stream_ends_when_the_user_is_disabled`: upstream in
   `Progress { steps: 50, interval_ms: 100 }`. bob's `call_tool` runs in a task; 400 ms
   later the owner disables bob; the call returns within 3 seconds with fewer than 50
   progress events.
6. `admin_cannot_disable_an_admin_of_higher_rank`: a plain user's post to
   `/admin/users/{id}/disable` is 403 forbidden and changes nothing.

## s06_passwords.rs (statement 6)

1. `password_is_stored_as_argon2id_only`: `W.stored_bytes()` contains `$argon2id$` and
   does not contain `PASSWORD`.
2. `twelve_character_minimum_on_every_form`: invitation, reset and password change each
   answer 400 for 11 characters and succeed for 12.
3. `longer_than_256_characters_is_refused`: 257 characters on the invitation form is 400.
4. `account_blocks_after_five_wrong_guesses`: five wrong passwords for bob are each 401;
   the sixth attempt with the right password is 429; after 15 minutes and 1 second the
   right password answers 303.
5. `a_successful_login_resets_the_count`: four wrong, one right (303), four wrong, one
   right (303).
6. `address_blocks_across_accounts`: `start_with` sets `limits.address_failures = 6`.
   Seven wrong guesses on seven unknown addresses, then the owner's right password from the
   same address is 429; after 15 minutes and 1 second it answers 303.
7. `forwarded_for_is_ignored_without_a_trusted_proxy`: as 6, but every request carries a
   different `X-Forwarded-For` from the documentation range; the result is still 429.
8. `forwarded_for_counts_behind_a_trusted_proxy`: `trusted_proxies` holds `127.0.0.1` and
   `address_failures = 6`. Seven wrong guesses with `X-Forwarded-For: 203.0.113.5`, then a
   right password with that header is 429 while one with `203.0.113.6` answers 303. With
   the header `203.0.113.6, 203.0.113.5` (last entry counts) it is 429.
9. `unknown_address_looks_like_a_wrong_password`: status and `error()` are equal for an
   unknown address and for a wrong password; `error()` is `Wrong email or password.`
10. `parallel_logins_do_not_starve_the_gateway`: `address_failures = 1000`. Sixteen wrong
    logins for unknown addresses run at once; while they run, `GET /healthz` answers within
    1 second; all sixteen answer 401.
11. `login_issues_a_new_session_id`: a browser plants
    `__Host-doorward_session=attacker-chosen`, signs in, and its cookie value is different
    afterwards; another browser holding `attacker-chosen` gets 303 `/login` on `/account`.
12. `session_cookie_is_host_only_and_protected`: `cookie_attributes` contains `secure`,
    `httponly`, `samesite=lax` and `path=/`, and no `domain`.
13. `session_ends_after_twelve_hours`: after 12 hours and 1 second, `/account` is 303
    `/login`.
14. `login_needs_csrf_and_origin`: without csrf, foreign origin, no origin: each 403
    forbidden and no session cookie is set.
15. `logout_ends_the_session`: after `logout`, the old cookie value replayed by another
    browser gets 303 `/login`.
16. `database_and_key_files_are_private`: the database file and `{database}.key` exist
    with mode `0600` after start.
17. `a_readable_key_file_refuses_the_start`: `doorward::build` with `key_file` pointing at
    a file of mode `0644` returns `Err`.
18. `session_id_is_not_stored`: the session cookie value is absent from
    `W.stored_bytes()`.

## s07_mail.rs (statement 7)

A second `MailCatcher` `M` is started by the test where TLS is needed, and its CA is given
to the gateway with `World::start_with(|c| c.mail.smtp_ca_file = Some(M.ca_pem_path()))`.

1. `smtp_test_email_arrives`: `admin::mail_test(.., "probe@example.com")` is 200 with
   `notice()` `Test email sent.`; the capture is `Via::Smtp`, `tls == false`, subject
   `Doorward test email`, `from` containing `FROM`, `auth_user` `mailer`, `auth_secret`
   `mail-password`.
2. `smtp_starttls_with_the_configured_roots`: `mail_smtp(.., "localhost",
   M.smtp_starttls_port(), .., "starttls")`; the test mail arrives on `M` with
   `tls == true`.
3. `smtp_implicit_tls`: same with `M.smtp_tls_port()` and `"implicit"`.
4. `untrusted_certificate_shows_an_error`: no roots configured, `"starttls"` against the
   catcher: `mail_test` is 200 with a non-empty `error()`, nothing is captured, and the
   activity has a `mail_failed` row.
5. `smtp_rejection_shows_the_provider_error`: `fail_next(Fail::SmtpReject)`; `error()`
   contains `Relaying denied`.
6. `starttls_is_never_downgraded`: `"starttls"` against `smtp_plain_port()` (no TLS
   offered) fails with an `error()` and captures nothing.
7. `resend_test_email`: `mail_resend(.., "re_test_key", &W.mail.resend_base())`; the
   capture is `Via::Resend`, `auth_secret` `re_test_key`, `path` `/emails`, `to`
   `["probe@example.com"]`, a `user_agent` starting `doorward/`, non-empty `text` and
   `html`.
8. `resend_error_is_shown`: `fail_next(Fail::ResendForbidden)`; `error()` contains
   `domain is not verified`.
9. `mailgun_test_email`: `mail_mailgun(.., "key-test", "mg.example.com",
   &W.mail.mailgun_base())`; the capture is `Via::Mailgun`, `auth_user` `api`,
   `auth_secret` `key-test`, `path` `/v3/mg.example.com/messages`.
10. `mailgun_error_is_shown`: `fail_next(Fail::MailgunUnauthorized)`; `error()` contains
    `Invalid private key`.
11. `secrets_are_encrypted_and_never_shown_again`: save an SMTP password, a Resend key and
    a Mailgun key, each a distinct canary string. `GET /admin/mail` contains none of them;
    `W.stored_bytes()` contains none of them.
12. `an_empty_secret_keeps_the_stored_one`: saving the SMTP form again with an empty
    password, then a test mail, still authenticates with `mail-password`.
13. `invitation_goes_through_the_selected_provider`: with Resend selected, the invitation
    for bob is captured `Via::Resend` and holds the invitation link.
14. `only_admins_change_mail_settings`: a plain user's post is 403 forbidden; anonymous is
    303 `/login`.
15. `mail_settings_survive_a_restart`: after `W.gw.restart()`, a test mail still arrives.

## s08_mail_failure.rs (statement 8)

1. `failed_invitation_shows_the_error_and_the_link`: `fail_next(Fail::SmtpReject)`;
   `admin::invite` is 200 `invitation-created` with a non-empty `error()` and a
   `data-invite-link` attribute starting `{base}/invite/`; that link accepts a password.
2. `mail_failure_is_in_the_activity_log`: after 1, `admin::activity` has a row of kind
   `mail_failed`.
3. `unreachable_mail_server_does_not_hang_the_panel`: SMTP pointed at a closed local port;
   the invitation answers within 10 seconds with the failure page and `/healthz` is 200.
4. `failed_reset_mail_reveals_nothing`: with `fail_next(Fail::SmtpReject)`, `/forgot` for
   bob answers the same body as for an unknown address; within 5 seconds the activity has
   `mail_failed` (the reset mail is sent after the response).
5. `the_link_is_shown_only_once`: after the failure page, `GET /admin/invitations` does
   not contain the token part of the link.

## s09_routing.rs (statement 9)

1. `client_reaches_the_upstream_through_its_path`: bob on demo, session client:
   `initialize` is 200, `list_tools` names equal the upstream's, `call_tool("echo")` text
   is `called: echo`.
2. `two_servers_route_independently`: `a` with tools `["alpha"]`, `b` with `["beta"]`;
   each path lists only its own tool and each call reaches only its own upstream.
3. `reserved_paths_cannot_be_taken`: `admin::add_server_page` with each of `-`,
   `.well-known`, `oauth`, `login`, `logout`, `setup`, `invite`, `forgot`, `reset`,
   `account`, `admin`, `assets`, `healthz`, `mcp`, `signup`, `register`, `favicon.ico`,
   `robots.txt` is 400.
4. `path_syntax_is_enforced`: `Bad`, `a_b`, a 25 character slug, the empty string, `-a`,
   `a/b`, `a.b` are 400; `a`, `a-b-1` and a 24 character slug are 303.
5. `a_taken_path_is_refused`: the second server with slug `demo` is 400.
6. `upstream_address_must_be_http_or_https`: `file:///etc/passwd`, `ftp://example.com/`,
   `javascript:alert(1)` and `not a url` are 400.
7. `deeper_paths_are_not_forwarded`: `POST {base}/demo/extra` with a valid token is 404;
   upstream untouched.
8. `query_string_is_dropped`: a request to `{base}/demo?x=1` works and the upstream's
   recorded `path` is `/mcp`.
9. `only_listed_headers_reach_the_upstream`: a raw request with `X-Custom: 1`,
   `X-Forwarded-For: 203.0.113.9`, `Forwarded: for=203.0.113.9`, `Last-Event-ID: 7`,
   `Cookie: a=b`. The recorded request has none of `x-custom`, `x-forwarded-for`,
   `forwarded`, `last-event-id`, `cookie`, `authorization`, and has `content-type`,
   `accept` and the secret header.
10. `deleting_a_server_stops_routing`: after `admin::delete_server`, the old token is 401
    on the path and the upstream is untouched.
11. `server_survives_a_restart`: after `W.gw.restart()`, the same token still lists tools.

## s10_combined.rs (statement 10)

Servers `a` (tools `echo`, `search`, `delete_db`) and `b` (tool `alpha`); bob assigned to
both; token for the slug `mcp`.

1. `lists_every_permitted_tool_with_its_prefix`: tool names are exactly
   `["a__echo", "a__search", "a__delete_db", "b__alpha"]`.
2. `routes_each_call_to_its_upstream`: `a__echo` gives `called: echo` and only `a` records
   a `tools/call`, with the name `echo`; `b__alpha` likewise for `b`.
3. `descriptions_and_schemas_are_kept`: the merged entry for `a__echo` has description
   `fake tool` and an `inputSchema`.
4. `denied_tools_are_absent_and_refused`: rule "everyone deny tool a/delete_db":
   `a__delete_db` is not listed; calling it is `-32602` with message
   `Unknown tool: a__delete_db`; `a` records no `tools/call`.
5. `unassigned_servers_are_absent_and_refused`: carol assigned to `a` only: no `b__`
   names; `b__alpha` is `-32602`; `b` untouched.
6. `assignment_changes_show_on_the_next_request`: carol is granted `b`: her next
   `list_tools` on the same token includes `b__alpha`.
7. `upstreams_get_the_secret_and_never_the_token`: every request recorded by `a` and `b`
   has the right secret header and no `authorization`; no recorded body contains the
   access token.
8. `one_upstream_session_per_token_family`: `a` started with `Generation::Session`; three
   calls through `/mcp` leave `rpc_count("initialize") == 1`.
9. `a_user_with_no_servers_gets_an_empty_list`: dave has no assignment; his combined
   token lists `[]`.
10. `combined_token_does_not_open_server_paths`: bob's `mcp` token on `{base}/a` is 401,
    and his `a` token on `{base}/mcp` is 401.
11. `ambiguous_and_malformed_names_are_refused`: with a tool named `b__c` on server `a`:
    `a__b__c` reaches `a` as `b__c`. `a__nope`, `echo`, `__echo`, `A__echo`, `a__` and
    `a___echo` are each `-32602` with no upstream call.
12. `over_length_names_are_left_out`: server `a` with one tool of 125 characters and one of
    126; the 128 character merged name is listed, the 129 character one is not and calling
    it is `-32602`.
13. `only_tool_methods_exist_here`: `resources/list`, `prompts/list` and `ping` under the
    stateless rules are `-32601`; under the session rules `ping` answers `{}`.

## s11_generations.rs (statement 11)

1. `session_client_on_a_server_path`: upstream `Generation::Both`. `initialize` result
   has `protocolVersion` `2025-11-25` and the reply has an `mcp-session-id` header;
   `list_tools` and `call_tool` work.
2. `stateless_client_on_a_server_path`: `discover` lists `2026-07-28`; `list_tools` has
   `resultType` `complete` and `cacheScope` `private`; `call_tool` works; the upstream
   recorded `mcp-method` and `mcp-name` headers.
3. `session_client_on_the_combined_endpoint_with_a_stateless_upstream`: upstream
   `Generation::Stateless`. On `/mcp`: `initialize` has `serverInfo.name` `doorward` and no
   `mcp-session-id` header; `demo__echo` is listed and callable.
4. `stateless_client_on_the_combined_endpoint_with_a_session_upstream`: upstream
   `Generation::Session`; list and call work; two calls leave one upstream `initialize`.
5. `combined_endpoint_with_mixed_upstreams`: `a` session-only, `b` stateless-only; a
   session client and a stateless client each list both tool sets and call one tool on
   each.
6. `combined_discover_shape`: `supportedVersions` is
   `["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26"]`, `capabilities` is
   `{"tools": {}}`, `cacheScope` is `private`, `resultType` is `complete`.
7. `combined_initialize_negotiates_the_revision`: a raw `initialize` asking `2025-06-18`
   is answered `2025-06-18`; one asking `1999-01-01` is answered `2025-11-25`.
8. `combined_refuses_an_unknown_stateless_revision`: header and `_meta` version
   `2031-01-01`: 400, `-32022`, `error.data.supported` is an array.
9. `older_session_revision_is_relayed`: a raw `initialize` asking `2025-03-26` on a server
   path answers that revision.
10. `get_stream_needs_a_session`: after `initialize`, `get()` is 200 `text/event-stream`;
    a session client that never initialised gets 405; on `/mcp` GET is 405; a GET carrying
    `MCP-Protocol-Version: 2026-07-28` is 405.
11. `delete_ends_the_session`: `delete()` is 200 and the upstream recorded a `DELETE`; the
    next `list_tools` is 404.
12. `notifications_are_accepted`: `notify("notifications/initialized", ..)` is 202 on a
    server path and on `/mcp`.
13. `ping_follows_the_generation`: a session client's `ping` returns `{}` and reaches the
    upstream; a stateless `request("ping", ..)` is `-32601` and never reaches it.

## s12_streaming.rs (statement 12)

Upstream in `Progress { steps: 3, interval_ms: 300 }`.

1. `progress_arrives_before_the_end_session`: the reply has at least 4 events, the first
   at least 500 ms before the last, and `text()` is `called: echo`.
2. `progress_arrives_before_the_end_stateless`: the same with a stateless client.
3. `progress_arrives_before_the_end_on_the_combined_endpoint`: the same through `/mcp`
   calling `demo__echo`.
4. `stream_headers_are_clean`: content type `text/event-stream`, `x-content-type-options`
   `nosniff`, no `set-cookie`.
5. `a_hung_upstream_ends_with_a_named_error`: `limits.upstream_timeout_seconds = 1`,
   upstream in `Hang`: `call_tool` returns within 4 seconds with 502 and message
   `Upstream demo is unavailable`.
6. `server_request_is_relayed_on_a_session`: upstream in `ServerRequest`; the first event
   has method `elicitation/create`; the result follows. The client's answer, a raw
   `{"jsonrpc":"2.0","id":"srv-1","result":{"action":"accept"}}` with its session headers,
   is 202 and reaches the upstream.
7. `combined_endpoint_does_not_relay_server_requests`: through `/mcp` no event has method
   `elicitation/create`, and the result still arrives.

## s13_upstream_faults.rs (statement 13)

"Named error" is HTTP 502 with JSON-RPC code `-32000` and message
`Upstream demo is unavailable`.

1. `a_stopped_upstream_gives_a_named_error`: after `upstream.shutdown()`; `/healthz`
   stays 200.
2. `garbage_gives_a_named_error`: `Mode::Garbage`.
3. `an_unexpected_content_type_gives_a_named_error`: `Mode::WrongContentType`; the
   client's body does not contain `<script>`.
4. `a_redirect_is_not_followed`: `Mode::Redirect` pointing at a second fake upstream:
   named error, and the second upstream is untouched.
5. `an_upstream_401_is_not_passed_on`: an open server whose upstream demands a secret the
   gateway does not have: the client gets the named error, never 401, and no
   `www-authenticate` header.
6. `a_slow_upstream_times_out`: `upstream_timeout_seconds = 1` and `Mode::Hang`.
7. `combined_endpoint_keeps_the_healthy_servers`: `a` up, `b` stopped: the list has the
   `a__` tools and no `b__` tool; `a__echo` works; `b__alpha` fails with a message
   containing `Upstream b is unavailable`; the activity has a row with outcome
   `unavailable`.
8. `the_gateway_survives_repeated_failures`: twenty failing calls, then `/healthz` is 200
   and a healthy server still answers.
9. `errors_do_not_leak_the_upstream`: the 502 body contains neither the upstream's port
   number nor its secret.
10. `failures_are_recorded`: the activity row for a failed call has decision `allow` and
    outcome `unavailable`.

## s14_assignment.rs (statement 14)

1. `assigning_on_the_user_page_shows_on_the_server_page`: `admin::assign`, then
   `admin::assigned_user_ids(server)` contains bob's id.
2. `assigning_on_the_server_page_shows_on_the_user_page`: `admin::assign_users`, then
   `admin::assigned_server_ids(bob)` contains the server's id.
3. `an_unassigned_user_gets_no_consent`: bob is not assigned: `authorize` leads to the
   consent address, whose GET is 403 `no-access`; approving anyway yields no code.
4. `unassigning_refuses_the_next_request`: bob on demo; `admin::assign(bob, &[])`; the
   next `list_tools` is 401 and `token_refresh` is `invalid_grant`.
5. `unassigned_server_is_absent_from_the_combined_endpoint`: see `s10` test 5; here the
   check runs after an unassignment on a live combined token.
6. `the_owner_needs_an_assignment_too`: the owner's consent page for demo is 403
   `no-access` until `W.grant(OWNER_EMAIL, ..)`.
7. `only_admins_assign`: a plain user's post to `/admin/users/{id}/servers` is 403
   forbidden.

## s16_tool_list.rs (statement 16)

1. `server_page_shows_the_real_tools`: upstream tools `["alpha", "beta"]`;
   `admin::catalog_tools` equals that list.
2. `refresh_picks_up_changes`: `set_tools(&["alpha", "gamma"])`, `admin::refresh_tools`;
   the list is `["alpha", "gamma"]` and the activity has a `tool_appeared` row for
   `gamma`.
3. `rules_can_only_name_real_tools`: `admin::add_rule(.., "tool", Some(id),
   Some("nope"))` is 400; with `alpha` it is 303.
4. `the_fetch_sends_the_secret_and_no_user_credential`: the recorded `tools/list` has the
   secret header and neither `authorization` nor `cookie`.
5. `markup_in_tool_names_is_escaped`: a tool named `<img src=x onerror=alert(1)>`: the
   server page body does not contain `<img src=x` and `admin::catalog_tools` returns the
   name unchanged.
6. `an_oversized_tool_list_is_refused`: `limits.tools_list_bytes = 2000` and an upstream
   with 200 tools: after refresh the page shows an `error()`, the catalog is empty and
   `/healthz` is 200.
7. `a_failed_refresh_keeps_the_old_list`: stop the upstream, refresh: `error()` is shown
   and the previous tools are still listed.
8. `a_new_tool_is_usable_without_a_manual_refresh`: `set_tools` adds `gamma` after the
   first refresh; bob's `call_tool("gamma")` succeeds (the catalog refreshes once on a
   miss) and the upstream records one extra `tools/list`.

## s17_activity.rs (statement 17)

1. `a_tool_call_is_recorded`: bob calls `echo`; `admin::activity` has a row with kind
   `tool_call`, user bob's email, server `demo`, tool `echo`, decision `allow`, outcome
   `ok`; the activity page gives that row a `data-time` and a numeric `data-duration-ms`.
2. `a_denied_call_is_recorded`: with a deny rule, the row has decision `deny` and outcome
   `refused`.
3. `arguments_and_results_are_not_stored`: bob calls `echo` with
   `{"text": "CANARY-7f3a91"}`; neither that string nor `called: echo` is in
   `W.stored_bytes()` or on the activity page.
4. `account_events_are_recorded`: after a sign-in, a failed sign-in, an invitation, a
   reset and a server change, the kinds `login`, `login_failed`, `invitation`, `reset` and
   `admin_change` are all present.
5. `filter_by_user_and_by_server`: two users and two servers; `activity(Some(bob_id),
   None)` has only bob's rows and `activity(None, Some(a_id))` only server `a` rows.
6. `only_admins_read_the_activity`: a plain user is 403 forbidden; anonymous is 303.
7. `a_combined_call_is_recorded_under_the_real_server_and_tool`: `demo__echo` through
   `/mcp` gives a row with server `demo` and tool `echo`.
8. `activity_outlives_the_user`: after bob is deleted his rows still show his email.
9. `user_text_is_escaped`: a failed sign-in for the address
   `"<b>x</b>"@example.com` leaves no `<b>x</b>` in the activity page body.

## s18_unauthorized.rs (statement 18)

`H(slug)` is
`Bearer resource_metadata="{base}/.well-known/oauth-protected-resource/{slug}", scope="mcp"`.

1. `no_token_gets_401_with_the_metadata_pointer`: a client with no token on `/demo`:
   status 401, empty body, `www-authenticate` equal to `H("demo")`. The same on `/mcp`
   with `H("mcp")`.
2. `a_bad_token_adds_invalid_token`: token `dw_at_garbage`: 401 and the header is
   `H("demo")` followed by `, error="invalid_token"`.
3. `missing_and_unassigned_servers_look_the_same`: with a valid token for `demo`, requests
   to `/ghost` (no such server) and `/other` (exists, not assigned) get the same status,
   the same body and the same header apart from the slug.
4. `protected_resource_metadata`: `GET /.well-known/oauth-protected-resource/demo` is the
   JSON of `INTERFACE.md` exactly; the same shape is served for the unknown slug `ghost`;
   `Bad_Slug` and a 25 character slug are 404.
5. `authorization_server_metadata`: every field of `INTERFACE.md`, with exact values.
6. `metadata_ignores_request_headers`: with `Host: evil.example.com`,
   `X-Forwarded-Host: evil.example.com` and `X-Forwarded-Proto: https`, the `issuer` and
   the 401 header still use `{base}`.
7. `get_and_delete_without_a_token_get_401`.
8. `a_token_in_the_query_is_not_read`: `POST {base}/demo?access_token={valid}` with no
   header is 401.
9. `the_session_cookie_does_not_open_mcp_paths`: a raw request carrying bob's session
   cookie and no bearer is 401; upstream untouched.
10. `an_expired_access_token_is_refused_and_refresh_recovers`: after 61 minutes 401;
    `token_refresh` gives a token that works.
11. `only_one_bearer_header_is_accepted`: `Authorization: Basic ...` is 401; two
    `Authorization` headers are 401; the scheme written `bearer` in lower case is accepted.
12. `no_request_reaches_the_upstream_without_a_valid_token`: after tests 1, 2, 7, 8 and 9
    in one scenario the upstream is untouched.

## s20_registration.rs (statement 20, both methods)

`C3` is the list `cursor://anysphere.cursor-mcp/oauth/callback`,
`https://www.cursor.com/agents/mcp/oauth/callback`, `http://localhost:8787/callback`.

1. `dynamic_registration_issues_a_public_client`: `register("Cursor", C3)` is 201;
   `client_id` starts with `dcr_`; `token_endpoint_auth_method` is `none`;
   `redirect_uris` is echoed; there is no `client_secret`.
2. `a_registered_client_completes_the_flow`: bob connects with the registered id and
   `http://localhost:8787/callback`; the consent page had `data-client-verified` `no`.
3. `bad_registrations_are_refused`: a redirect with a fragment, plain HTTP on
   `client.example.com`, a wildcard host: 400 `invalid_redirect_uri`. An empty list, eleven
   addresses, a body that is not JSON: 400 `invalid_client_metadata`.
4. `registration_is_rate_limited_per_address`: `limits.dcr_per_hour = 3`: three 201, then
   429; after one hour and 1 second, 201 again.
5. `a_confidential_registration_becomes_public`: asking for `client_secret_basic` still
   answers `none` and no secret.
6. `a_client_named_like_a_known_one_is_marked_unverified`: `register("Claude",
   &["http://localhost:8787/callback"])`; the consent page has `data-client-verified`
   `no` and `data-redirect-host` `localhost:8787`.
7. `an_unlisted_redirect_is_blocked_at_authorize`: `register("X",
   &["https://attacker.example.com/cb"])` is 201; `authorize` with it is an error page;
   the activity has a `redirect_blocked` row.
8. `metadata_document_client_completes_the_flow`: `W.app()`; the consent page has
   `data-client-name` `Example Client` and `data-client-verified` `yes`.
9. `the_document_is_fetched_only_after_sign_in`: an anonymous `authorize` is 303
   `/login?req=..` and `W.gw.cimd().fetches(APP_ID) == 0`; after `login_for` and the
   consent GET it is at least 1.
10. `a_failed_fetch_shows_an_error`: `cimd().fail(APP_ID, CimdError::Fetch(..))`; the
    consent GET is an error page; no code.
11. `the_redirect_must_be_in_the_document`: `authorize` with
    `http://127.0.0.1:53535/other`; the consent GET is an error page.
12. `a_loopback_port_may_differ`: `http://127.0.0.1:40123/callback` works;
    `http://localhost:53535/callback` (other host name) gives an error page.
13. `the_client_id_must_be_https_with_a_path`: `http://client.example.com/app.json`,
    `https://client.example.com` and `https://client.example.com/` each give an error page
    at `authorize`.
14. `the_document_must_name_itself_and_be_public`: `put_metadata` with another
    `client_id`, then with `token_endpoint_auth_method` `client_secret_basic`: each consent
    GET is an error page.
15. `the_unknown_client_id_is_refused`: `dcr_doesnotexist` gives an error page.

## s20_cimd_fetcher.rs (statement 20, the fetcher itself)

Tests `doorward::cimd` directly. A fake `Resolver` maps host names to addresses. Where a
server is needed, the test runs a small TLS server on `127.0.0.1` with a certificate for
`client.example.com` signed by a test CA, and builds the fetcher with `from_parts` using
that CA, a resolver pointing the name at `127.0.0.1`, and an `address_allowed` that lets
loopback through. `system()` behaviour is tested without any server.

1. `address_table`: `address_allowed` is false for loopback (v4 and v6), the three
   private v4 ranges, link-local v4 (including the metadata address), carrier-grade NAT,
   the unspecified addresses, multicast, broadcast, the documentation ranges, the
   benchmarking range, unique-local and link-local v6, the IPv4-mapped form of a private
   address, and the NAT64 form of a loopback address. It is true for two ordinary public
   v4 addresses and one public v6 address.
2. `a_private_answer_is_refused_before_any_connection`: a resolver answering `127.0.0.1`
   with the real `address_allowed`: `Err(CimdError::NotAllowed(_))`, and a listener on
   that address accepted nothing.
3. `a_mixed_answer_is_refused`: one public and one private address, in either order:
   `Err(NotAllowed)`.
4. `only_https_host_names_on_the_default_port`: `http://client.example.com/a`,
   `https://127.0.0.1/a`, `https://client.example.com:8443/a`,
   `https://user@client.example.com/a`, `https://client.example.com/a#f` and
   `https://client.example.com` are each `Err(NotAllowed)` with no resolver call.
5. `a_good_document_is_returned`: name, redirect list and auth method are read.
6. `a_redirect_is_not_followed`: the server answers 302 to another path: `Err`, and the
   second path is never requested.
7. `an_oversized_document_is_refused`: `max_bytes = 1024` and a 4096 byte body: `Err`.
8. `a_slow_server_times_out`: `timeout = 300 ms` and a server that never answers: `Err`
   within 2 seconds.
9. `a_mismatched_client_id_is_refused`: `Err(CimdError::Invalid(_))`.
10. `a_confidential_document_is_refused`: auth method `client_secret_basic`:
    `Err(Invalid)`.
11. `a_document_without_redirects_is_refused`: `Err(Invalid)`.
12. `a_body_that_is_not_json_is_refused`: plain text, and JSON that is not an object:
    `Err(Invalid)`.
13. `an_untrusted_certificate_is_refused`: `from_parts` without the test CA: `Err(Fetch)`.

## s23_upstream_isolation.rs (statement 23)

1. `the_client_token_never_reaches_the_upstream`: after `initialize`, `list_tools`,
   `call_tool`, `get()` and `delete()`, no recorded request has `authorization` and no
   recorded body contains the access token; every one has the secret header.
2. `client_cookies_are_stripped`: a raw request with `Cookie: a=b` arrives without
   `cookie`.
3. `the_upstream_cannot_set_cookies`: `Mode::SetCookie`: the client's reply has neither
   `set-cookie` nor `www-authenticate`.
4. `responses_are_marked_inert`: replies carry `x-content-type-options: nosniff` and
   `content-security-policy: sandbox`.
5. `an_open_upstream_is_flagged`: `W.open_upstream`, `admin::check_lockdown`:
   `admin::lockdown` is `Some("open")`. For a gated upstream it is `Some("ok")`. For a
   stopped one, `Some("unknown")`. The probe's recorded request has no secret header.
6. `the_secret_is_never_shown_or_stored_in_the_clear`: the server page body and
   `W.stored_bytes()` do not contain `secret_for("demo")`.
7. `changing_the_address_clears_the_secret`: `admin::update_server` with a second
   upstream's address and no secret; requests recorded by the second upstream have no
   secret header and contain `secret-demo` nowhere.
8. `changing_the_address_with_a_new_secret_sends_the_new_one`.
9. `the_secret_never_reaches_the_client`: no reply of a whole session contains it, the
   error replies of `s13` included.
10. `a_planted_session_id_is_stripped_from_initialize`: a raw `initialize` carrying
    `Mcp-Session-Id: planted`; the upstream's recorded `initialize` has no
    `mcp-session-id`.
11. `foreign_and_invented_session_ids_are_refused`: bob initialises; carol, assigned to
    the same server, sends bob's session id: 404 on POST, GET and DELETE, upstream
    untouched; an invented id likewise.
12. `a_reused_upstream_session_id_is_not_rebound`: `Mode::ReuseSessionId`: bob
    initialises, then carol initialises; bob's session keeps working and carol's
    `list_tools` is not 200.
13. `a_session_dies_with_its_token_family`: after bob disconnects the client from
    `/account`, a new token of bob's with the old session id is 404.

## s24_trick_requests.rs (statement 24)

bob on demo with the rule "everyone deny tool demo/delete_db". `S(name)` is a well-formed
stateless `tools/call` body for that tool, sent with `raw` and explicit headers.

1. `header_and_body_name_different_tools`: `Mcp-Name: echo` with `S("delete_db")`: HTTP
   400, `-32020`; upstream records no `tools/call`.
2. `required_headers_must_be_present_once`: `Mcp-Method` missing; `Mcp-Method` twice;
   `Mcp-Name` missing; `Mcp-Name` twice; `MCP-Protocol-Version` different from `_meta`:
   each 400, `-32020`, message starting `Header mismatch:`.
3. `the_base64_header_form_is_decoded`: `Mcp-Name` as the base64 form of `echo` with
   `S("echo")` is 200 `called: echo`; the base64 form of `echo` with `S("delete_db")` is
   400 `-32020`.
4. `the_decision_is_made_from_the_body`: header and body both `delete_db`: `-32602`
   `Unknown tool: delete_db`; upstream records no `tools/call`.
5. `duplicate_keys_are_refused`: `"name":"echo","name":"delete_db"` in `params`; a
   duplicate inside `arguments`; a duplicate written with an escape (`"\u006eame"`): each
   400 `-32700`, upstream untouched, under both generations.
6. `batches_are_refused`: a JSON array of two calls: 400 `-32600`, under the stateless
   rules, the session rules, and a session that negotiated `2025-03-26`.
7. `oversized_bodies_are_refused`: `limits.body_bytes = 2000` and a 3000 byte body: 413,
   upstream untouched.
8. `compressed_bodies_are_refused`: `Content-Encoding: gzip`: 400 `-32600`.
9. `malformed_text_is_refused`: a byte order mark, bytes that are not UTF-8, a lone
   surrogate escape, and a second JSON value after the first: each 400.
10. `deep_nesting_is_refused`: 10000 nested arrays in `arguments`: 400, and `/healthz`
    still answers.
11. `look_alike_tool_names_do_not_reach_a_lenient_upstream`: upstream in
    `Mode::LenientNames`. ` delete_db`, `DELETE_DB`, `delete_db` followed by a zero-width
    space, and `delete_db ` are each `-32602`; the upstream records no `tools/call`.
12. `wrong_case_methods_are_refused`: upstream in `Mode::LenientMethods`. `Tools/Call` and
    `tools/call ` (trailing space) are `-32601` and never forwarded.
13. `methods_outside_the_list_are_refused`: `admin/shutdown`, `tasks/list`, `tasks/get`,
    `sampling/createMessage`, `roots/list`, `elicitation/create`: `-32601`, never
    forwarded, under both generations.
14. `task_requests_are_refused`: a `tools/call` with `params.task`: `-32601`, not
    forwarded.
15. `a_tool_call_without_an_id_is_refused`: 400 `-32600`, not forwarded.
16. `a_forged_response_is_refused`: `{"jsonrpc":"2.0","id":1,"result":{}}` under the
    stateless rules and under the session rules without a session: 400 `-32600`, not
    forwarded.
17. `denied_and_missing_tools_look_alike`: calling `delete_db` and calling `nope` give the
    same code and the same message shape, `Unknown tool: {name}`.

## s26_panel.rs (statement 26)

`PAGES` is `/admin`, `/admin/servers`, `/admin/users`, `/admin/invitations`,
`/admin/rules`, `/admin/redirects`, `/admin/mail`, `/admin/activity`.

1. `every_page_renders_for_the_owner`: each of `PAGES` is 200 with its `data-page`; the
   body has `<html lang="en">` and a viewport meta tag.
2. `anonymous_visitors_are_sent_to_sign_in`: each of `PAGES` is 303 `/login`.
3. `plain_users_are_refused`: each of `PAGES` is 403 forbidden.
4. `only_the_owner_changes_roles`: an admin's `admin::set_role` is 403 forbidden; the
   owner's is 303 and the user then reaches `/admin`.
5. `account_page_lists_and_disconnects_clients`: after `W.token`, `/account` has a row
   with `data-client-name` `Example Client` and a `data-family`; posting
   `/account/clients/{family}/disconnect` answers 303; the token is 401; the row is gone.
6. `a_user_cannot_disconnect_someone_elses_client`: carol posting bob's family id is 404
   or 403 and bob's token still works.
7. `every_page_sends_the_security_headers`: `/login`, `/forgot`, `/account`, and each of
   `PAGES`: `content-security-policy` contains `default-src 'none'` and
   `frame-ancestors 'none'`; `x-frame-options` is `DENY`; `x-content-type-options` is
   `nosniff`; `cache-control` contains `no-store`; `referrer-policy` is `same-origin`.
8. `pages_carry_no_script`: no body among those pages contains `<script`.
9. `every_post_form_carries_the_token`: on each page,
   `count("form[method=post]") == count("form[method=post] input[name=csrf]")`.
10. `panel_posts_need_csrf_and_origin`: `POST /admin/servers` without csrf, with another
    session's csrf, with a foreign origin, with no origin: each 403 forbidden and no
    server is created.
11. `the_stylesheet_is_served_from_the_gateway`: the page's `link[rel=stylesheet]` points
    under `/assets/`, and that address answers 200 with content type `text/css`.
12. `pages_have_no_outside_resources`: no `src` or `href` on those pages starts with
    `http://` or `https://`, except links to `{base}`.

## s29_state_survives.rs (statement 29)

1. `users_rules_and_tokens_survive_a_restart`: bob on demo with a deny rule on
   `delete_db`. After `W.gw.restart()`: bob's browser session still opens `/account`; his
   access token lists tools without `delete_db`; `token_refresh` works; `login` works; the
   server and the rule are still listed.
2. `a_live_mcp_session_survives_a_restart`: bob's session client, initialised before the
   restart, still lists tools after it.

## s32_rules.rs (statement 32)

Server `S` (tools `echo`, `search`, `delete_db`) and server `T` (tool `echo`). bob and
carol are assigned to `S`. `tools(user)` is the name list from `list_tools` on `/S`. A rule
is written `subject effect scope`.

1. `no_rules_allows_everything`: `tools(bob)` has all three.
2. `a_denied_tool_is_absent_and_refused`: `everyone deny tool S/delete_db`: it is missing
   from `tools(bob)`; `call_tool("delete_db")` is `-32602` `Unknown tool: delete_db`;
   `upstream.calls_to("delete_db") == 0`; `echo` still works.
3. `a_narrower_allow_beats_a_wider_deny`: `everyone deny all`, `everyone allow tool
   S/search`: `tools(bob) == ["search"]`.
4. `allow_tool_beats_deny_server`: `everyone deny server S`, `everyone allow tool
   S/search`: `["search"]`.
5. `a_user_deny_is_not_pierced_by_an_everyone_allow`: `bob deny all`, `everyone allow tool
   S/search`: `tools(bob)` is empty; `tools(carol)` has all three.
6. `a_user_allow_beats_an_everyone_deny_of_the_same_scope`: `everyone deny tool
   S/delete_db`, `bob allow tool S/delete_db`: bob has it, carol does not.
7. `a_wider_allow_does_not_beat_a_narrower_deny`: `everyone deny tool S/delete_db`, `bob
   allow server S`: bob still lacks it. The same with `bob allow all`.
8. `user_allow_all_beats_everyone_deny_all`: bob has all three, carol none.
9. `user_allow_server_beats_everyone_deny_server`: bob has all three, carol none.
10. `everyone_allow_does_not_beat_a_user_deny_of_the_same_scope`: `bob deny server S`,
    `everyone allow server S`: bob has none.
11. `user_allow_tool_beats_user_deny_server`: `bob deny server S`, `bob allow tool
    S/echo`: `["echo"]`.
12. `each_deny_needs_its_own_override`: `everyone deny all`, `bob allow server S`,
    `everyone deny tool S/delete_db`: bob has `echo` and `search` only.
13. `duplicate_rules_are_refused`: the same subject and target twice is 400, whatever the
    effect.
14. `an_allow_on_an_unassigned_server_grants_nothing`: `everyone allow server T`: bob's
    consent for `T` is 403 `no-access` and his combined list has no `T__` name.
15. `rules_do_not_cross_servers`: bob assigned to `T` as well; `everyone deny tool
    S/echo`: `echo` is missing on `/S` and present on `/T`.
16. `rules_apply_to_live_tokens_at_once`: a deny added after the token was issued hides
    the tool on the next `list_tools`; deleting the rule brings it back.
17. `both_generations_and_the_combined_endpoint_are_filtered`: with rule 2, the stateless
    list on `/S`, the session list on `/S` and both lists on `/mcp` all lack the tool, and
    calls are refused on each.
18. `the_user_page_shows_the_effective_tools`: with the rules of 6,
    `admin::effective_tools(bob)` has `("S", "delete_db", "allow")` and for carol
    `("S", "delete_db", "deny")`.
19. `rule_shapes_are_checked`: scope `tool` without a tool, scope `server` without a
    server, an unknown effect, an unknown subject id: each 400.
20. `deleting_a_server_removes_its_rules`: `admin::rule_ids` shrinks.
21. `only_admins_write_rules`: a plain user's post is 403 forbidden.

## s33_consent.rs (statement 33)

bob is assigned to demo and signed in. `A` is `W.app()`.

1. `the_consent_page_names_everything`: `authorize` answers 303 to
   `/oauth/consent?req=..`; its GET is 200 `consent` with `data-redirect-host`
   `127.0.0.1:53535`, `data-client-name` `Example Client`, `data-client-verified` `yes`,
   `data-server` `demo`, `data-user` bob's email, and no `Location`.
2. `consent_is_asked_every_time`: after a complete `W.token`, a second `authorize` again
   answers 303 to `/oauth/consent` and never to the client's address.
3. `one_approval_issues_one_code`: `consent(req, "approve")` answers 303 to an address
   starting `APP_REDIRECT` with a `code` starting `dw_ac_`, the `state` sent, and `iss`
   equal to `{base}`. Posting the same approval again is an error page.
4. `denying_returns_access_denied`: `error=access_denied` with `state` and `iss`, no
   `code`; the request cannot be approved afterwards.
5. `approval_needs_the_csrf_token`: a post without csrf is 403 forbidden and yields no
   code; a proper approval of the same request then still works.
6. `another_sessions_token_is_refused`: carol's csrf value in bob's post: 403 forbidden.
7. `approval_needs_the_gateway_origin`: a foreign origin, `Origin: null`, and no origin,
   each with a valid csrf value: 403 forbidden, no code.
8. `a_request_belongs_to_one_browser`: carol's browser opening bob's `req` gets an error
   page, on GET and on POST; an anonymous GET is 303 `/login?req=..`.
9. `a_request_expires_after_ten_minutes`: after 10 minutes and 1 second, GET and POST are
   error pages.
10. `an_unassigned_user_gets_no_code`: dave, not assigned: GET is 403 `no-access`; an
    approval post yields no code.
11. `a_missing_server_looks_like_no_access`: `resource` `{base}/ghost`: an anonymous
    `authorize` is 303 `/login?req=..`; after sign-in the consent GET is 403 `no-access`.
12. `the_consent_page_cannot_be_framed`: `x-frame-options` is `DENY`; the policy has
    `frame-ancestors 'none'`; `form-action` lists `'self'` and `http://127.0.0.1:53535`.
13. `client_text_is_escaped`: a document named `<script>alert(1)</script>`: the body does
    not contain `<script>alert` and `data-client-name` reads back as the raw name.
14. `a_new_connection_is_announced_by_mail`: after the first `W.token`, bob has a mail
    with subject `A new app was connected to your Doorward account` and a link starting
    `{base}/account/disconnect/`. A second `W.token` with the same client sends no second
    mail.
15. `the_mailed_link_disconnects_the_client`: GET of the link is 200 `disconnect` and
    changes nothing; its POST is 200 `disconnected`; the token is then 401.
16. `the_combined_endpoint_is_named_on_the_page`: `resource` `{base}/mcp` gives
    `data-server` `all servers`.
17. `prompt_none_never_yields_a_code`: with a completed approval on file,
    `authorize_raw` with `prompt=none` answers 303 to the client with
    `error=interaction_required`, `state` and `iss`, and no `code`.
18. `sign_in_then_consent_round_trip`: an anonymous `authorize` is 303 `/login?req=X`;
    `login_for(X, ..)` is 303 `/oauth/consent?req=X`; approval and `token_code` succeed.
19. `errors_that_must_not_redirect`: an unknown `client_id`, a repeated `state`
    parameter, a `request_uri` parameter, a `request` parameter: each an error page.
20. `errors_that_go_back_to_the_client`: `response_type=token`, no `code_challenge`,
    `code_challenge_method=plain`: 303 to the client with `error=invalid_request`. No
    `resource`, a `resource` on another origin, a `resource` with the path `/Bad_Slug`:
    303 with `error=invalid_target`. Each carries `state` and `iss`.
21. `a_plain_challenge_never_reaches_consent`: after test 20's `plain` attempt there is no
    consent address in any answer.

## s34_redirects_codes.rs (statement 34)

`R` is `https://www.cursor.com/agents/mcp/oauth/callback`. `L` is
`http://127.0.0.1:53535/callback`. `D` is a client registered dynamically with `[R, L]`.

1. `the_redirect_must_match_exactly`: `authorize` for `D` with each of: `R` plus `x`, `R`
   plus `/extra`, `R` plus `?a=1`, `R` with `http`, `R` with `user@` before the host, `R`
   with a trailing dot on the host, `R` on port 444, `R` with the host in upper case, `R`
   with `\@evil.example.com` after the host, and a punycode look-alike host. Each is an
   error page.
2. `loopback_look_alikes_are_refused`: for `D`, each of: host `127.1`, host
   `localhost.evil.example.com`, host `127.0.0.1.evil.example.com`, the all-zero address,
   host `[::ffff:127.0.0.1]`, host `2130706433`, `L` with `https`, `L` with the path
   `/callback2`. Each is an error page.
3. `any_loopback_port_is_allowed`: `L` on port 40001 answers 303; a client registered
   with `http://localhost:8787/callback` may use port 9999; one registered with
   `http://[::1]:9/callback` may use port 1234.
4. `known_clients_ship_on_the_list`: `GET /admin/redirects` has enabled rows from source
   `shipped` for the hosts `claude.ai`, `chatgpt.com` and `www.cursor.com`, and one with
   scheme `cursor`. Clients registered with `https://claude.ai/api/mcp/auth_callback`,
   `https://chatgpt.com/connector_platform_oauth_redirect`,
   `https://chatgpt.com/connector/oauth/abc123`, `R`, and
   `cursor://anysphere.cursor-mcp/oauth/callback` each get 303 from `authorize`.
5. `a_listed_host_with_another_path_is_blocked`: `https://claude.ai/evil`: error page and
   a `redirect_blocked` activity row.
6. `an_admin_can_allow_and_disable_an_address`: `https://app.example.com/oauth/cb` is an
   error page; after `admin::add_redirect("https", "app.example.com", "/oauth/")` it
   answers 303; after `admin::redirect_action(id, "disable")` it is an error page again.
7. `a_shipped_entry_can_be_disabled`: after disabling the `claude.ai` row, its address is
   an error page.
8. `private_schemes_must_be_listed`: `evilapp://callback`: error page.
9. `a_code_works_once`: the second `token_code` is 400 `invalid_grant`, and the access
   token from the first exchange is then 401.
10. `a_code_expires_after_sixty_seconds`: after 61 seconds, `invalid_grant`; at 59
    seconds it works.
11. `concurrent_redemption_yields_one_success`: eight `token_code` calls at once: exactly
    one 200.
12. `the_verifier_must_match`: a wrong verifier is `invalid_grant`; no verifier is
    `invalid_request`.
13. `client_and_redirect_must_match`: another registered client's id is `invalid_grant`;
    another redirect address is `invalid_grant`; an unknown `client_id` is
    `invalid_client`.
14. `the_resource_must_match_when_given`: another resource is `invalid_target`; no
    resource is 200.
15. `a_token_works_only_on_its_server`: bob assigned to `a` and `b`: the `a` token is 401
    on `/b` and on `/mcp`, both upstreams untouched.
16. `a_deleted_server_does_not_revive_tokens`: delete `demo`, create `demo` again with the
    same upstream and assign bob to it: a new token works, the old access token is 401 and
    the old refresh token `invalid_grant`.
17. `renaming_a_path_revokes_its_tokens`: `admin::update_server` with slug `demo2`: 401 on
    both paths.
18. `token_response_shape`: `cache-control` contains `no-store`; `token_type` is `Bearer`;
    `expires_in` is 3600; `scope` is `mcp`; the tokens start `dw_at_` and `dw_rt_`.
19. `token_endpoint_refuses_odd_requests`: an unknown grant type is
    `unsupported_grant_type`; a repeated `code` field is `invalid_request`; `GET` is 405.
20. `the_code_is_not_stored`: the code is absent from `W.stored_bytes()`.

## s35_tokens.rs (statement 35)

bob on demo; `T1` is the first token pair, `R1` its refresh token.

1. `tokens_are_opaque_and_not_stored`: each token is its prefix plus 43 characters of
   `[A-Za-z0-9_-]`; neither token is in `W.stored_bytes()`.
2. `refresh_replaces_both_tokens`: `token_refresh(R1)` gives a pair that differs from
   `T1`; the new access token works.
3. `a_replay_inside_the_window_gets_the_same_pair`: `R1` again 10 seconds later returns a
   body equal to the first refresh answer.
4. `parallel_refreshes_get_identical_answers`: eight refreshes of `R1` at once are all 200
   with one and the same pair; that pair's refresh token then works.
5. `a_replay_after_the_window_revokes_the_chain`: `R1` used, 31 seconds pass, `R1` again
   is `invalid_grant`; the successor refresh token is `invalid_grant`; both access tokens
   are 401.
6. `a_zero_window_is_strict`: `lifetimes.refresh_replay_seconds = 0`: the second use of
   `R1` is `invalid_grant` at once and the chain is revoked.
7. `the_replay_copy_cannot_be_read_from_the_database`: right after a refresh, the
   successor tokens are absent from `W.stored_bytes()`.
8. `a_refresh_token_lasts_thirty_days`: unused for 30 days and 1 second: `invalid_grant`.
9. `a_chain_ends_after_ninety_days`: refreshing every 20 days works four times; the fifth,
   at day 100, is `invalid_grant`.
10. `refresh_rechecks_the_user_and_the_assignment`: after unassignment, and separately
    after disabling, `token_refresh` is `invalid_grant`.
11. `refresh_needs_the_same_client`: another client's id is `invalid_grant`; the right
    client refreshes a second pair with 200.
12. `refresh_needs_the_same_resource_when_given`: another resource is `invalid_target`.
13. `an_access_token_lasts_an_hour`: at 59 minutes it works; at 61 minutes it is 401.
14. `the_old_access_token_stays_valid_until_it_expires`: after a refresh, the access token
    of `T1` still works until its hour is over.

## s36_switches.rs (statement 36)

bob on demo; the fake upstream offers one resource and one prompt.

1. `resources_and_prompts_are_empty_by_default`: a session client's `resources/list`
   answers `{"resources": []}`, `resources/templates/list` answers
   `{"resourceTemplates": []}`, `prompts/list` answers `{"prompts": []}`; the upstream
   records none of them.
2. `reads_are_refused_while_off`: `resources/read` and `prompts/get` are `-32601`, not
   forwarded.
3. `capabilities_are_removed_while_off`: the `initialize` result and the `server/discover`
   result have neither `resources` nor `prompts` under `capabilities`.
4. `the_resources_switch_opens_resources_only`: `admin::update_server` with
   `pass_resources: true`: `resources/list` has one entry and `resources/read` returns
   `TOP-SECRET`; `prompts/list` is still empty.
5. `the_prompts_switch_opens_prompts_only`.
6. `the_gateways_own_stateless_answers_are_well_formed`: while off, the stateless
   `resources/list` answer has `resultType` `complete`, `ttlMs` 60000 and `cacheScope`
   `private`.
7. `completion_needs_a_switch`: while both are off `completion/complete` is `-32601` and
   not forwarded; with one on, the upstream records it.
8. `subscriptions_follow_the_resources_switch`: `resources/subscribe` under the session
   rules is `-32601` while off.
9. `switches_default_to_off_on_a_new_server`: the server page shows both checkboxes
   unchecked.
