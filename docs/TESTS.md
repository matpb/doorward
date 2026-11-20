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

## cli_unlock.rs (review findings O1 and O7)

Real binary, with a config file in a temp dir and the database beside it. Two tests predate
the findings and now create an account first, as the refusal of O1 requires.

1. `unlock_removes_the_block_and_prints_the_line`: an account for `bob@example.com` with five
   failures: exit 0, `unlocked bob@example.com` on standard output, no failures left. (It
   changed in phase B: the account is created first.)
2. `unlock_succeeds_when_no_block_exists`: an account and no block: exit 0 and the
   unlocked line. (It changed in phase B: the account is created first.)
3. `unlock_does_not_create_a_missing_database`: no database file: exit 1, standard error
   `doorward: no database at {path}`, the file is not created, and the directory holds
   only the config file.
4. `unlock_refuses_an_email_no_account_has`: exit 1, standard error
   `doorward: no account has that email address`, nothing on standard output, the failures
   stay, and no activity row is written.
5. `unlock_writes_an_activity_row`: an account with a block: exit 0; one `unlock` row
   holds the account's id and email and the detail `from the command line`.

## config.rs (review findings O2 and O5)

The other tests of this file check other settings and are not listed here.

1. `a_proxy_range_of_every_address_is_refused`: `0.0.0.0/0` and `::/0` in the file, and
   `0.0.0.0/0` in `DOORWARD_TRUSTED_PROXIES`, are refused with
   `trusted_proxies: {entry} would trust every address`; a range with prefix 8 in the 10
   network and `127.0.0.1` are kept.
2. `a_day_is_the_longest_upstream_timeout`: `upstream_timeout_seconds` 86400 is accepted;
   86401 is refused with `limits.upstream_timeout_seconds must be at most 86400`.

## In-crate tests (review finding O9)

1. `crypto::tests::the_dummy_password_never_signs_in_an_unknown_account`: `verify` with the
   dummy password and no hash is false. With `&& known` removed from `verify` this test
   fails (checked on a scratch copy).
2. `accounts::tests_races::an_unknown_account_reaches_the_equal_cost_check`: an attempt for
   an unknown address is counted with no user, hash or epoch, so sign-in continues to the
   equal-cost check. It does not count hashes; that needs a counter the code does not have.

## s01_install.rs (statement 1)

1. `the_root_address_leads_to_setup_then_to_sign_in`: on a fresh gateway `GET /` is 303
   `/setup`; after the owner is created, `GET /` is 303 `/login`; `GET /nothing-here` is
   still 401, the answer of a server path.
2. `health_says_unavailable_when_the_database_fails`: a spawned gateway answers `200` with
   `{"status":"ok"}` on `/healthz`; with the table `settings` renamed away it answers `503`
   with `{"status":"unavailable"}` and one line starts `doorward: health check failed: `;
   with the name restored it answers `200` again.

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
13. `an_admin_cannot_invite_an_admin`: alice is an admin. Her invitation for carol with the
    role `admin` is 403 forbidden and sends no mail; with the role `user` it is 303 and the
    mail arrives. The owner's invitation for dave with the role `admin` is 303.

14. `a_removed_admin_takes_their_pending_invitations_along`: carol, an admin, invites alice
    and dave; alice accepts. The owner then disables carol, changes her role to user, or
    deletes her, one run each. Dave's unused link is 404 `link-invalid` on GET and 404 on
    POST, his invitation is gone from the invitations page, and alice still signs in (303).
    The owner invites erin before each change; her link still opens (200) afterwards, so a
    delete of every invitation would fail here. This control passes before the change.
15. `the_invitations_page_says_who_invited`: bob's row holds `[data-invited-by]` reading
    `invited by owner@example.com` and dave's reads `invited by carol@example.com`; with the
    inviter of bob's invitation cleared in the database, his row reads
    `invited by a removed account`.

## s04_reset.rs (statement 4)

1. `reset_by_email_sets_a_new_password`: an anonymous browser submits `/forgot` with bob's
   address: 200 `forgot-sent`; mail subject `Reset your Doorward password`, link starting
   `{base}/reset/`; `reset_password` answers 303 `/login`; the new password signs in (303),
   the old one does not (401).
2. `answer_is_identical_for_an_unknown_address`: status and body of the answer for bob's
   address and for `nobody@example.com` are equal byte for byte; no mail goes to the
   unknown address.
3. `reset_link_works_once`: second use is 404 on GET and POST.
4. `reset_link_expires_after_an_hour`: one link opens at 59 minutes and is 404 on GET and
   POST at 61 minutes; a link requested after that works.
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
12. `a_second_request_within_five_minutes_sends_nothing`: bob asks for a reset and the mail
    arrives; `W.mail.clear()`. He asks again at once: 200 `forgot-sent`, and one second
    later there is no mail to bob; the first link still renders (200 `reset`). After 5
    minutes and 1 second a third request sends a mail whose link differs from the first,
    and the first link is 404.
13. `a_reset_lifts_the_login_block`: five wrong passwords block bob (his right password
    answers 429). After a reset by mail, the new password answers 303 without waiting.

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
7. `an_admin_cannot_disable_or_delete_another_admin`: alice and carol are admins. alice's
   `disable` and `delete` on carol are 403 forbidden and carol's `/admin` is still 200.
   alice's `disable` on the plain user bob is 303.
8. `a_server_path_answer_is_not_returned_after_access_was_lost`: upstream in
   `Delayed { millis: 1500 }`. bob's `call_tool("echo")` runs in a task; 400 ms later the
   owner disables bob. The call answers `200` with `-32602` and `Unknown tool: echo`, as
   `/mcp` answers, its body does not hold the upstream's `called: echo`, and its one
   `tool_call` row is `refused` with the detail `access was lost`.
9. `a_combined_answer_is_not_returned_after_access_was_lost`: the same on `/mcp` with
   `demo__echo`; `-32602` with `Unknown tool: demo__echo`, because the caller may still use
   other servers there. It passes before the change.
10. `a_lost_access_on_another_method_gets_the_challenge`: upstream in
    `SlowListing { millis: 1500 }`. bob's `list_tools` runs in a task; 400 ms later the owner
    disables bob. The listing answers 401 with `www-authenticate`. It passes before the
    change, since only tools/call changes.
11. `a_token_that_expires_during_a_call_still_gets_its_answer`: upstream in
    `Delayed { millis: 1500 }`. The test clock moves two hours ahead 400 ms into the call, so
    the access token expires while the call runs. `/demo` answers 200 with `called: echo`,
    the upstream sees one `tools/call`, and one `tool_call` row for echo on demo is `ok`.
12. `a_token_that_expires_during_a_combined_call_still_gets_its_answer`: the same on `/mcp`
    with `demo__echo`.
13. `a_token_that_expires_during_a_streamed_call_still_gets_its_answer`: upstream in
    `Progress { steps: 5, interval_ms: 300 }`; the clock moves two hours ahead 400 ms in.
    All five progress events and the answer `called: echo` arrive; one `tool_call` row is
    `ok`.

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
19. `parallel_guesses_cannot_outrun_the_block`: `address_failures = 1000`. Twenty browsers
    post a wrong password for the owner at once: exactly five answer 401 and fifteen answer
    429. The owner's right password then answers 429.
20. `a_wrong_or_foreign_csrf_token_is_refused`: browsers A and B each load `/login`. B
    posts the owner's right password with A's csrf value: 403 forbidden and no session
    cookie. B posts it with a made-up value of the same length: 403 forbidden. B posts it
    with its own value: 303 (control). The value B read before signing in is then refused
    on `/logout` (403 forbidden), and B's `/account` still answers 200.
21. `wrong_current_passwords_count_toward_the_block`: bob is signed in. Five
    `change_password` attempts with a wrong current password are each 400. The sixth, with
    the right current password, is 429, and a fresh browser's login with bob's right
    password is 429.

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
16. `an_admin_cannot_touch_mail_settings`: alice is an admin. Her `GET /admin/mail` is 403
    forbidden; her settings post and her test-mail post (csrf read from `/account`) are 403
    forbidden; the owner's test mail then still arrives with `auth_secret` `mail-password`.
17. `a_new_server_address_drops_the_stored_password`: a test mail arrives with
    `auth_secret` `mail-password` (control), then `W.mail.clear()`. Saving the SMTP form
    with the host `localhost` instead of `127.0.0.1` and an empty password answers 303.
    `mail_test` then answers 200, and no captured message has `auth_secret`
    `mail-password`.

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
19. `the_tasks_capability_is_not_relayed`: upstream in `DeclaresTasks`, both switches on.
    `initialize` on `/demo` has capabilities `{tools: {listChanged: false}, resources: {},
    prompts: {}}`; `server/discover` on `/demo` has `{tools: {}, resources: {}, prompts: {}}`;
    `/mcp` initialize has no `tasks` and its discover is `{tools: {}}`.

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
   `{"tools": {}}`, `cacheScope` is `private`, `resultType` is `complete`, and `_meta` names
   the server as `io.modelcontextprotocol/serverInfo` with `name` `doorward` and the crate version.
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
    upstream; a stateless `request("ping", ..)` is 404 with `-32601` and never reaches it.
14. `a_typescript_style_upstream_works_in_session_mode`: upstream `Generation::Session` in
    `Mode::TypeScriptNotices` (notices answered 202, `text/plain; charset=UTF-8`, no body).
    The notice is accepted as 202 with an empty body and no content type; the session
    client lists and calls a tool.
15. `stateless_refusals_have_the_specified_shapes`: stateless `ping` and `/mcp`
    `resources/list` are 404 with `-32601` and the request's id; session `/mcp`
    `resources/list` and session `tasks/get` are 200 with `-32601`; a stateless body without
    `_meta` (on a server path) or with `_meta` lacking the version (on `/mcp`) is 400 with
    `-32602` and `Invalid params: missing _meta, protocol version or client capabilities`
    (a request without `clientCapabilities` on either endpoint); a `_meta` version
    `2025-11-25` under header `2026-07-28` is 400 with `-32020`.
16. `stateless_subscriptions_are_refused_and_not_advertised`: a stateless `subscriptions/listen`
    on `/demo` and on `/mcp` is 404 with `-32601` and the request's id, and the upstream
    records no such request. Upstream `Mode::DeclaresFlags`: a stateless discover on `/demo`
    has capabilities `{"tools": {"extra": 1}}` (no `listChanged` or `subscribe`, switches off);
    a session initialize keeps `tools.listChanged`.
17. `a_stateless_notification_needs_no_metadata`: `notifications/cancelled` with no `params`,
    with `params` lacking `_meta`, and with `_meta: {}` is 202; a `_meta` version `2025-11-25`
    under header `2026-07-28` is 400 `-32020`; a numeric version is 400 `-32602`; a missing
    `Mcp-Method` header is 400 `-32020`.
18. `an_upstream_error_reaches_the_combined_client_with_its_own_id`: a stateless `tools/call` on
    `/mcp` to an upstream that answers 400 with -32021 and `data` is 400 with the same error under
    the client's id 401; a session call (no version) gets 200 with the same error under id 402.

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
11. `a_fault_row_says_why`: `upstream_timeout_seconds` 1 and `tools_list_bytes` 1024. One
    server per cause, each given one stateless `echo` call: the client gets the 502 named
    error, and the row's detail is `no connection` (closed port), `the upstream answered 307`
    (redirect), `an answer of the wrong content type`, `an answer over the size limit`
    (4096 bytes), `an answer that is not valid JSON`, `no answer in time` (hang).

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
9. `the_rule_form_offers_the_real_tools`: after a refresh of upstream tools
   `["alpha", "beta"]`, `/admin/rules` has `input#rule-tool[list="rule-tools"]` and a
   `datalist#rule-tools` whose option values are `["alpha", "beta"]`, each labelled with
   the server's path; after `set_tools(&["alpha", "gamma"])` and a refresh the values are
   `["alpha", "gamma"]`.
10. `the_rule_form_lists_every_servers_tools_by_slug_then_name`: servers `demo` (`alpha`,
    `beta`) and `aaa` (`zeta`): the option values are `zeta`, `alpha`, `beta`, labelled
    `aaa`, `demo`, `demo`.
11. `a_refresh_that_cannot_read_the_secret_is_recorded_as_failed`: the stored secret of
    `demo` is replaced by text that cannot be opened; the refresh answers 303, one
    `admin_change` row has the detail `tool refresh failed`, and no `tools refreshed` row
    is added.

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
10. `the_activity_page_offers_a_user_and_a_server_filter`: the page holds one GET form
    `form[data-form="activity-filter"]` to `/admin/activity` with a `user` select (labelled
    User, options `Any user`, then every user by email) and a `server` select (labelled
    Server, options `Any server`, then every server by slug, `{name} ({slug})`) and one
    Filter button. `user={bob id}` shows only bob's rows and selects bob's option;
    `user=&server=` shows the rows of the unfiltered page.
11. `the_user_and_server_pages_link_to_their_activity`: bob's page has one
    `a[data-link="activity"]` reading Activity with href `/admin/activity?user={id}`; the
    server page has one with href `/admin/activity?server={id}`.
12. `a_refused_call_says_why`: a deny rule on `delete_db` for everyone. The call to it
    has detail `rule {id}` of that rule; a call to `nope` has `not in the tool list`.
13. `a_tool_error_is_marked`: the upstream answers `isError` true. The client gets that
    answer as sent; the row is `allow` / `ok` with detail `the tool reported an error`.
14. `owner_creation_and_password_change_have_their_kinds`: setup writes one `owner_created`
    row naming the owner; bob's signed-in password change writes one `password_change` row;
    a reset by link then writes a `reset` row with the detail `completed` and no second
    `password_change`. (The reset writes two `reset` rows, `requested` and `completed`; the
    first version of this test counted exactly one, which was wrong.)
15. `a_failed_mail_says_which_mail`: the invitation mail fails; the `mail_failed` row's
    detail starts with `invitation: ` and holds the error text after it.
16. `a_failed_reset_mail_says_reset`: bob exists and the reset mail fails; the `mail_failed`
    row, polled for 5 seconds because the mail is sent in the background, starts with
    `reset: `.

17. `a_header_refusal_says_so`: a stateless upstream whose tools carry an `x-mcp-header`
    key, on `/mcp`: `demo__echo` is `-32602`, and its `tool_call` row for echo on demo has
    the detail `the request headers do not match the call`.

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
8. `metadata_document_client_completes_the_flow`: `W.app()`, a document on the loopback redirect
   `127.0.0.1:53535`; the consent page has `data-client-name` `Example Client` and
   `data-client-verified` `no`, since a document is verified only on an https redirect.
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
16. `addresses_at_their_limit_do_not_stop_a_fresh_address`: `limits.dcr_per_hour` is 55 and
    loopback is a trusted proxy, so `X-Forwarded-For` names the caller. Eleven addresses in
    `203.0.113.0/24` each take 55 registrations and then get 429; a twelfth address gets 201.
17. `the_oldest_unused_registration_gives_way_at_the_bound`: `limits.unused_registrations` is
    3, set through a round-trip of the config. After four registrations the first client id
    is unknown at `/oauth/authorize` and the other three are known. A client whose
    authorization completed stays known after four more registrations.

18. `the_attempts_table_has_an_index_on_time`: `EXPLAIN QUERY PLAN DELETE FROM dcr_attempts
    WHERE at < 1` on the test database names the index `dcr_attempts_at`, so the clean-up
    of old attempts does not scan the table.

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
18. `unknown_tool_names_do_not_make_the_gateway_refetch_the_list`: ten stateless calls with
    ten unknown names send at most one `tools/list` to the upstream; 31 seconds later one
    more unknown name sends exactly one more.
19. `a_call_denied_for_all_tools_needs_no_upstream`: a deny rule with scope `server`. A call
    to `nope` is `Unknown tool: nope` and the upstream records no request at all.

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

18. `ten_misses_at_once_cost_one_list`: upstreams in `SlowListing { millis: 1000 }`, one
    server on `/demo` and one on `/mcp`. Ten stateless calls with unknown names run at once
    on each endpoint: each is `-32602`, and each upstream records one `tools/list`. It
    passes before the change; it guards the miss gate under concurrency.
19. `a_hung_refresh_does_not_queue_more_refreshes`: upstream in `HangListing`. Three misses
    in a row on `/demo`: the first answers `-32602` in under 13 seconds (the 10 second list
    limit and a margin), and the upstream records one `tools/list` for the three.
20. `a_clock_stepped_back_does_not_hold_a_refresh_off`: a miss refreshes the list; the clock
    moves back one second, which the rate limiter tolerates; the next miss refreshes it again (two `tools/list` in all).
21. `a_refresh_goes_on_when_the_client_leaves`: upstream in `SlowListing { millis: 1000 }`
    with `fresh` added to its tools. The client gives up after 300 ms; two seconds later
    `fresh` is callable, so the refresh the client left still stored the list.

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
13. `every_panel_page_carries_the_navigation`: as the owner, each of `/admin`,
    `/admin/users`, one user page, `/admin/invitations`, `/admin/servers`, one server
    page, `/admin/rules`, `/admin/redirects`, `/admin/activity`, `/admin/mail` has one
    `nav[data-nav="panel"]` first in `main`, its nine links in order, and one link with
    `aria-current="page"`: the Users link on a user page, the Servers link on a server
    page, the link of the section otherwise.
14. `an_admin_sees_no_mail_link`: a non-owner admin's `/admin/users` has the eight links
    without Mail.
15. `a_plain_user_and_public_pages_get_no_navigation`: a plain user's 403 under
    `/admin/users`, the plain user's `/account`, and `/login`, `/forgot` and an invitation
    page carry no `data-nav`.
16. `the_account_page_links_to_the_panel_for_admins_only`: the owner and an admin see
    `a[data-nav="to-panel"]` reading `Admin panel` with href `/admin`; a plain user does
    not.
17. `a_refused_form_keeps_the_navigation`: the owner's `/admin/servers` form with the slug
    `Not A Slug!` answers 400 with an error and still carries the navigation, with the
    Servers link current.
18. `the_stylesheet_wraps_the_nav_row_and_long_text`: the served stylesheet has a rule for
    `nav[data-nav="panel"] ul` with `display: flex`, `flex-wrap: wrap`, a `gap` and
    `list-style: none`, and rules for `li`, `p`, `td` and `th` with
    `overflow-wrap: anywhere`.

## s29_state_survives.rs (statement 29)

1. `users_rules_and_tokens_survive_a_restart`: bob on demo with a deny rule on
   `delete_db`. After `W.gw.restart()`: bob's browser session still opens `/account`; his
   access token lists tools without `delete_db`; `token_refresh` works; `login` works; the
   server and the rule are still listed.
2. `a_live_mcp_session_survives_a_restart`: bob's session client, initialised before the
   restart, still lists tools after it.

## s29_restart.rs (statement 29)

1. `s29_restart_keeps_data`: a settings row written before `gateway.restart()` is still there
   after it, and `/healthz` answers 200.
2. `s29_migrations_apply_once`: the migration rows are versions 1 upward at the first start
   and are identical after a restart.
3. `a_start_up_failure_names_the_file_and_the_cause`: the real binary, four starts, each
   exit 2 with one line on standard error. A config file that does not exist:
   `doorward: cannot read the config file {path}: No such file or directory (os error 2)`.
   A database in a directory that does not exist: `doorward: cannot open the database
   {path}: ...` with the OS error, and the directory is not created. A key file in a
   directory that does not exist: `doorward: cannot create the key file {path}: No such
   file or directory (os error 2)`, and no key file is made. A key file that is a directory:
   `doorward: cannot read the key file {path}: Is a directory (os error 21)`.
4. `a_stop_signal_ends_the_gateway_while_a_stream_is_open`: the real binary, with server
   `demo` whose upstream sends one progress event a second; the owner's tool call is still
   open when `SIGTERM` is sent. The process runs on 5 seconds later, exits 0 within 14
   seconds, and standard error holds the stopping line and then the still-open line.
5. `a_second_signal_ends_the_wait`: the same stream; the process runs on 2 seconds after the
   first `SIGTERM`; a second `SIGTERM` ends it within 3 seconds with exit 0 and the same two
   lines.
6. `a_stop_with_nothing_open_is_immediate`: no request open; exit 0 within 3 seconds; the
   stopping line and no still-open line.

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
   `127.0.0.1:53535`, `data-client-name` `Example Client`, `data-client-verified` `no` (a
   document on a loopback redirect is unverified), `data-server` `demo`, `data-user` bob's
   email, and no `Location`.
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
17. `prompt_none_never_yields_a_code`: for a registered client with a completed approval on
    file, `authorize_raw` with `prompt=none` answers 303 to the client with
    `error=interaction_required`, `state` and `iss`, and no `code`.
    `prompt_none_never_yields_a_code_for_a_document_client_is_an_error_page`: the same request
    for the document client, with an approval on file, is an error page with no `Location`
    and no `code`.
18. `sign_in_then_consent_round_trip`: an anonymous `authorize` is 303 `/login?req=X`;
    `login_for(X, ..)` is 303 `/oauth/consent?req=X`; approval and `token_code` succeed.
19. `errors_that_must_not_redirect`: an unknown `client_id`, a repeated `state`
    parameter, a `request_uri` parameter, a `request` parameter: each an error page.
20. `errors_that_go_back_to_the_client`: for a registered client, `response_type=token`, no
    `code_challenge`, `code_challenge_method=plain`: 303 to the client with
    `error=invalid_request`. No `resource`, a `resource` on another origin, a `resource` with
    the path `/Bad_Slug`: 303 with `error=invalid_target`. Each carries `state` and `iss`, and
    no `code`. `errors_that_go_back_to_the_client_for_a_document_client_is_an_error_page`: the
    same six requests for the document client are error pages with no `Location` and no `code`.
21. `a_plain_challenge_never_reaches_consent`: for a registered client, a signed-in and an
    anonymous `plain` attempt are each refused with `error=invalid_request` and show no consent
    address. `a_plain_challenge_never_reaches_consent_for_a_document_client_is_an_error_page`:
    the same two attempts for the document client are error pages with no consent address.
22. `a_registered_client_is_shown_as_a_claim`: a client registered as `Claude Code published
    by claude.ai` with `APP_REDIRECT` has one `p[data-client="registered"]` reading `An app
    that calls itself Claude Code published by claude.ai. Doorward cannot check this name.`;
    its `q.client-name` is the name; the page has no `(unverified)`.
23. `a_document_client_with_a_web_redirect_names_its_publisher`: `APP_ID` with the redirect
    `https://claude.ai/api/mcp/auth_callback` has one `p[data-client="document"]` reading
    `Example Client, published by client.example.com.`, the name in `q.client-name` and the
    host in `span.client-host`; there is no `document-loopback` line.
24. `a_document_client_with_a_loopback_redirect_is_shown_as_a_claim`: `W.app()` has one
    `p[data-client="document-loopback"]` reading `Says it is Example Client from
    client.example.com. Any program on this computer can use that description.`; `p.local-app`
    reads `The sign-in will be handed to whatever program is listening on this computer.`;
    the page does not contain `This app runs on your computer.`; `data-client-verified` is `no`.
25. `a_document_client_on_a_private_scheme_is_shown_as_a_claim`: the document lists
    `cursor://anysphere.cursor-mcp/oauth/callback`. One `p[data-client="document-loopback"]`
    reads the claim text of item 24 with `client.example.com`, there is no `document` line,
    `p.local-app` reads `The sign-in will be handed to whatever program on this computer
    opens addresses of this kind.`, and `data-client-verified` is `no`.
26. `a_registered_client_on_a_private_scheme_gets_the_local_sentence`: a registered client
    with the cursor redirect gets the same `p.local-app` sentence and `data-client-verified`
    `no`.
27. `a_document_that_does_not_list_the_redirect_shows_the_error_page`: the document lists
    another address; the consent page is 400 with kind `error` and no `Location`. The reason
    `the document does not list the redirect address` is asserted in-crate at `document_fits`
    (`oauth::tests_consent`, `a_document_not_listing_the_redirect_gives_that_reason`), since an
    in-process test cannot read standard error; no test reads the line on standard error.

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
21. `a_document_client_gets_no_error_redirect_to_a_loopback_address`: a valid request from the
    document to `L` is accepted; the same request with no `response_type` is an error page
    with no `Location`.
22. `a_document_client_gets_no_error_redirect_to_a_listed_callback`: the document lists
    `https://claude.ai/api/mcp/auth_callback`; a valid request is accepted; the same request
    with no `response_type` is an error page with no `Location`.

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
10. `a_completion_follows_the_switch_of_its_kind`: resources on and prompts off: a
    `ref/resource` completion reaches the upstream, a `ref/prompt` one is `-32601` and does
    not. The mirror case holds too. With both on, a completion with no `ref` or with
    `ref.type` `ref/tool` is `-32601` and is not forwarded.

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

10. `completions_are_not_advertised_with_both_switches_off`: upstream in
    `DeclaresCompletions`. With both switches off, `initialize` and `server/discover` have no
    `completions` under `capabilities`; with resources on, `initialize` has it again.

## s37_environment.rs (statement 37)

These tests start the real binary (`env!("CARGO_BIN_EXE_doorward")`) with
`std::process::Command`, a cleared environment, a temporary directory and a free local
port, and stop it afterwards. "Starts" means `GET /healthz` answers `200` within 5
seconds; "refuses" means the process exits non-zero within 5 seconds.

1. `starts_from_variables_alone`: no config file; `DOORWARD_PUBLIC_URL`,
   `DOORWARD_LISTEN` and `DOORWARD_DATABASE` set: starts, and the setup code is printed.
2. `a_variable_beats_the_file`: the file says one `listen` port, `DOORWARD_LISTEN` another:
   the gateway answers on the variable's port and not on the file's.
3. `an_empty_variable_is_unset`: `DOORWARD_LISTEN=""` with a file that sets `listen`:
   starts, and answers on the file's port.
4. `an_unknown_variable_is_refused_and_named`: `DOORWARD_LIMIT_BODY_BYTES=1` (misspelt):
   refuses, and the output names that variable.
5. `a_bad_value_is_refused_without_echoing_it`: `DOORWARD_LIMITS_BODY_BYTES=hunter2-not-a-number`:
   refuses; the output names the variable and says a whole number is expected; the output
   does not contain `hunter2`.
6. `every_setting_has_a_variable`: in process, for each row of `config::SETTINGS`: the
   loader given that one variable with a valid non-default value returns a `Config` that
   differs from the default in exactly that setting, and given a wrong-typed value returns
   an error that names the variable. Every field of `Config` is reached by one row.
7. `lists_and_booleans_parse`: `DOORWARD_TRUSTED_PROXIES` with two comma separated entries,
   one of them a CIDR range, and `DOORWARD_SHARED_CLIENT_ADDRESS=true` are in effect;
   `DOORWARD_SHARED_CLIENT_ADDRESS=yes` refuses.
8. `orchestrator_variables_are_ignored`: `DOORWARD_PORT`, `DOORWARD_PORT_8717_TCP` and
   `DOORWARD_SERVICE_HOST` set to arbitrary text: starts.
9. `the_key_never_reaches_the_output`: `DOORWARD_KEY` set to a valid random key and an
   unknown variable beside it: refuses, and neither stdout nor stderr contains the key.
10. `subcommands_use_the_same_settings`: with variables only, `doorward health` exits 0
    while the gateway runs and 1 after it stopped. `doorward unlock` for an email no account
    has, with five failures for it in the database given by variable and no `--config`,
    exits 1 with standard error `doorward: no account has that email address` and empty
    standard output; the five failures stay. (It changed in phase B: the refusal shows that
    the database given by variable was opened.)
11. `health_opens_nothing`: `doorward health` against a closed port, with
    `DOORWARD_DATABASE` pointing into an empty directory: exit 1 and the directory is still
    empty.

12. `pages_tell_browsers_to_stay_on_https`: with `public_url`
    `https://doorward.example.com` and a trusted proxy, `GET /login` carries
    `Strict-Transport-Security: max-age=31536000`; with a loopback `http` `public_url` no
    answer carries that header.

## s41_docs.rs (statement 41)

1. `every_setting_is_documented_with_its_default`: for each row of `config::SETTINGS`,
   `docs/DOCKER.md` has a table row with the variable name and the default that
   `Config::default()` holds.
2. `no_documented_variable_is_unknown`: every `DOORWARD_` name in `docs/DOCKER.md`,
   `README.md`, the Compose files and `.env.example` is a `SETTINGS` variable, `DOORWARD_KEY`
   or `DOORWARD_CONFIG`.
3. `the_example_env_file_starts_a_gateway`: `.env.example` with its placeholders filled is
   accepted by the loader (`Config::from_sources` with no file, over those pairs).
4. `the_example_config_passes_the_start_check`: `doorward.example.toml`, loaded by
   `Config::load`, has `start_check()` equal to `Ok(None)`.
5. `the_readme_config_passes_the_start_check`: the first `toml` fenced block of
   `README.md`, written to a temp dir and loaded by `Config::load`, has `start_check()`
   equal to `Ok(None)`.

6. `the_unused_registrations_row_says_what_a_flood_does`: the `DOORWARD_LIMITS_UNUSED_REGISTRATIONS`
   row of `docs/DOCKER.md` ends with the flood sentence.
7. `the_rate_limits_say_how_long_registration_attempts_are_kept`: the Rate limits section
   says registration attempts are kept for one hour.
8. `design_says_json_answers_are_buffered_and_rechecked`: `docs/DESIGN.md` no longer says
   that other responses stream through as they arrive, and says that JSON answers are
   buffered and re-checked.
9. `the_interface_names_the_new_phrases_and_lines`: `docs/INTERFACE.md` names `admission
   time`, the stored secret phrase, the header refusal detail, the password check line, the
   three document reasons and the private-scheme sentence.

## s42_proxy_start.rs (statement 42)

Real binary, as in s37.

1. `https_without_a_trusted_proxy_refuses`: `public_url` `https://doorward.example.com`,
   no `trusted_proxies`: refuses; the output names `trusted_proxies` and
   `shared_client_address` and shows the loopback entry for a proxy on the same host.
2. `the_opt_out_starts_with_a_warning`: the same with `shared_client_address = true`:
   starts, and the log has one warning that every visitor shares one address.
3. `a_trusted_proxy_starts_quietly`: with `trusted_proxies = ["127.0.0.1"]`: starts, no
   such warning.
4. `http_on_loopback_is_exempt`: `public_url` `http://127.0.0.1:{port}` and
   `http://localhost:{port}`, no proxies: starts without the warning.
5. `http_on_a_public_name_follows_the_https_rule`: `public_url`
   `http://doorward.example.com`, no proxies: refuses.

6. `a_trusted_proxy_that_sends_no_address_is_logged_once`: `trusted_proxies =
   ["127.0.0.1"]`; three requests without `X-Forwarded-For`: the log has exactly one line
   saying that a trusted proxy sent no client address.
7. `a_private_client_address_on_a_public_install_is_logged_once`: `public_url`
   `https://doorward.example.com`, `trusted_proxies = ["127.0.0.1"]`; three requests with
   an `X-Forwarded-For` address from the private 10/8 range: exactly one line says that
   the client address is private and names the usual causes; requests with
   `X-Forwarded-For: 203.0.113.9` add none.

## s43_rate_limits.rs (statement 43)

`W` is prepared under the default limits (owner, users, servers, tokens), then restarted
on the same database with `trusted_proxies = ["127.0.0.1"]` and every burst set to 2
unless a test says otherwise; a restart empties the limiter. A caller "from A" sends `X-Forwarded-For: A`; addresses come from the
documentation ranges. "Limited" is status `429` with an integer `Retry-After` of at least
1, `Cache-Control: no-store` and no `WWW-Authenticate`. Waiting is `W.gw.clock.advance`.

1. `each_class_limits_after_its_burst`: from one address, the third request of each class
   is limited: `GET /nothing-here` (general), `POST /oauth/token` (oauth), `POST /login`
   (credentials); the `login_failures` table has two rows, not three, after three wrong
   passwords.
2. `a_forged_header_from_an_untrusted_peer_changes_nothing`: with `trusted_proxies` empty
   and `shared_client_address = true`, three requests each naming another
   `X-Forwarded-For`: the third is limited.
3. `prepended_addresses_are_ignored`: behind the trusted peer, requests whose
   `X-Forwarded-For` is `{rotating}, A`: the third is limited.
4. `two_callers_have_two_buckets`: two requests from A, then one from B: B is answered.
5. `ipv6_callers_are_counted_by_their_64`: two addresses of one /64 share a bucket; an
   address of another /64 is answered.
6. `a_limited_refresh_keeps_the_token`: the limited `POST /oauth/token` answers JSON
   `{"error": "too_many_requests"}`; after the wait the same refresh token is accepted and
   the family is not revoked.
7. `a_limited_exchange_keeps_the_code`: a code exchange that is limited, then repeated
   after the wait: tokens are issued.
8. `a_bad_bearer_flood_is_limited_without_a_challenge`: from A, the third request with an
   invalid bearer on `/demo` is limited, with JSON-RPC error `-32029` and `id` `null`;
   bob's valid token from B is answered `200`.
9. `a_user_is_limited_whatever_the_address`: bob's third `tools/list` in the window is
   limited although each came from another address; the upstream records two; carol's
   first is answered.
10. `open_requests_are_capped_per_user`: `mcp_open = 2`: with two streams of bob open a
    third request is limited; after one stream is dropped the next request is answered.
11. `the_limit_is_checked_before_the_body`: a 10 MiB POST to an exhausted bucket is `429`,
    not `413`.
12. `the_table_is_bounded`: `rate_table_keys = 4`; A exhausts its bucket; 100 other
    addresses each send one request; A is still limited, and after the flood two new
    addresses in a row are limited by the shared overflow bucket.
13. `rotating_addresses_cannot_fill_the_request_tables`: 200 `GET /oauth/authorize`
    requests from 200 addresses with a valid client leave at most the documented cap of
    pending rows; the same for `POST /oauth/register`.
14. `existing_refusals_carry_retry_after`: the `429` of a blocked sign-in, of the
    password change throttle and of the registration limit each carry `Retry-After`.
15. `every_limit_is_a_setting`: each class's burst and rate, `mcp_open` and
    `rate_table_keys` appear in `config::SETTINGS`, and a start with `burst = 1` limits the
    second request.
16. `health_is_counted_for_a_caller_that_is_not_local`: from A (not loopback), the first two
    `GET /healthz` are `200`; the third is limited with the JSON `too_many_requests` answer.
    With the settings table renamed, a further request from A is still limited, so the
    limited answer reads no database. B's first request is `200`.
17. `health_from_the_host_itself_is_never_limited`: six `GET /healthz` with no forwarded
    address (the loopback peer) are all `200`, with a burst of 2.

## s44_lockout.rs (statement 44)

`W` is started with `trusted_proxies = ["127.0.0.1"]`; a browser "at A" sends
`X-Forwarded-For: A` with every request, addresses from the documentation ranges. The
tests of `s06_passwords.rs` keep their meaning: there every request comes from one address.

1. `a_strangers_failures_do_not_lock_the_owner_out`: five wrong passwords for the owner at
   A are each 401; the owner's right password at A is then 429, and at B it answers 303.
2. `the_block_of_a_pair_ends_with_the_window`: four wrong passwords at A, a fifth ten
   minutes later; fourteen minutes after the first the right password at A is 429, and 15
   minutes and 1 second after the first it answers 303 (the window rolls: it is not
   counted from the last failure).
3. `a_success_clears_only_its_own_pair`: four wrong at A and four wrong at B; the right
   password at A answers 303; one more wrong at B is 401 and the right password at B is
   then 429; at A four more wrong passwords are each 401, not 429.
4. `a_blocked_attempt_is_neither_checked_nor_counted`: while A is blocked, ten more
   attempts at A are 429 and the `login_failures` table does not grow.
5. `the_account_ceiling_blocks_every_address`: `start_with` sets `account_ceiling = 8`.
   Two wrong passwords at each of four addresses; the right password at a fifth address
   is 429; after 15 minutes and 1 second it answers 303.
6. `the_ceiling_defaults_to_fifty_and_both_numbers_are_settings`: `Limits::default()` has
   `account_failures` 5 and `account_ceiling` 50; a config with `account_ceiling` below
   `account_failures` is refused at start.
7. `parallel_guesses_from_many_addresses_stop_at_the_ceiling`: `account_ceiling = 10`,
   `address_failures = 1000`. Thirty browsers, each at its own address, post a wrong
   password at once: exactly ten are 401 and the rest 429; the right password is then 429.
8. `an_unknown_account_is_throttled_like_a_real_one`: the same sequence as test 1 for an
   email with no account gives the same statuses and the same bodies.
9. `a_reset_lifts_every_block_of_the_account`: `account_ceiling = 8`; five wrong at A and
   three at B, so A is blocked and the ceiling is reached;
   after a reset by mail the new password answers 303 at A without waiting.
10. `unlock_lifts_every_block_of_the_account`: the same, lifted by `doorward unlock`.
11. `wrong_current_passwords_count_for_the_pair`: bob is signed in at A. Five wrong
    current passwords on `/account/password` are each 400; the sixth, with the right
    current password, is 429; a fresh browser at B signs bob in with 303.
12. `the_address_rule_still_spans_accounts`: `address_failures = 6`; seven wrong passwords
    at A, each for another email: the next attempt at A for any account is 429 and the
    same account at B is not.
13. `a_right_current_password_clears_its_own_pair`: bob is signed in at A. Two wrong
    current passwords are each 400 and leave two rows in `login_failures`; the right
    current password answers 303 and leaves none.

## s45_retention.rs (statement 45)

Rows are written straight into the `activity` table with chosen times; a housekeeping run
is forced with `W.gw.restart()`.

1. `rows_older_than_the_period_are_deleted`: rows aged 91 days and 89 days; after the run
   the first is gone and the second is on `/admin/activity`.
2. `the_boundary_is_exact`: a row aged 90 days minus 1 second stays, one aged 90 days plus
   1 second goes.
3. `the_period_is_a_setting`: `start_with` sets `activity_days = 7`: a row aged 8 days is
   deleted. `Limits::default()` has 90; 0 is refused at start.
4. `every_kind_of_row_is_pruned_alike`: old `tool_call`, `login_failed` and `admin_change`
   rows all go; no other table loses a row.

5. `the_reset_gap_is_one_public_constant`: reads `src/accounts`: `reset.rs` exports
   `REQUEST_GAP_SECONDS` as `pub const`, and `housekeeping.rs` keeps no copy of it. A source
   check, since the constant is private until phase B.

## s46_consent_notice.rs (statement 46)

1. `a_local_app_sees_the_notice`: the consent page of a client with a loopback redirect
   has an element `[data-consent-notice]` whose text contains "Approve only if you started
   this sign-in yourself."
2. `a_web_client_sees_the_notice`: the same for a client whose redirect is an allowlisted
   https address.
3. `the_combined_endpoint_sees_the_notice`: the same on the consent page for `/mcp`.
4. `only_a_local_app_is_told_it_runs_on_this_computer`: "The sign-in will be handed to whatever
   program is listening on this computer."
   is on the page of test 1 and on neither of the other two.

## s47_combined_grants.rs (statement 47)

bob has a token for the combined endpoint; servers `a` (tool `alpha`) and `b` (tool
`beta`) exist; bob is assigned to `a` only when he connects.

1. `a_server_assigned_later_is_listed_without_a_new_consent`: `tools/list` shows
   `a__alpha` only; after `W.grant` adds `b`, the same token lists `a__alpha` and
   `b__beta` and calls `b__beta` successfully.
2. `an_unassigned_server_is_gone_at_once`: after bob is unassigned from `a`, the same
   token's list has no `a__` tool, and a call to `a__alpha` is `-32602`
   `Unknown tool: a__alpha` with upstream `a` untouched and a `deny` / `refused` row.
3. `a_token_with_no_server_left_still_answers`: unassigned from everything, `tools/list`
   is `200` with an empty list, and the refresh token still rotates.
4. `the_check_is_made_on_every_call`: bob lists while assigned, is unassigned, then calls
   `a__alpha` from the list he already holds: refused as in test 2.
5. `both_generations_follow_the_same_rule`: tests 1 and 2 with a stateless client.

## s48_origin.rs (statement 48)

bob on demo (`W.user`, `W.upstream`, `W.grant`); his tokens are for `/demo` and for the
combined `/mcp`. "Refused" is status `403`, `Content-Type: application/json`, the exact
refusal body, and no `WWW-Authenticate`. Foreign origin is `https://evil.example.com`.

1. `a_foreign_origin_is_refused_before_anything_else`: `initialize` and stateless
   `tools/list` on `/demo` and `/mcp` with the foreign origin are refused; the upstream
   saw no request and bob has no new activity row. With `general_burst` at 3, six refused
   requests leave the address bucket intact: a normal `tools/list` on `/demo` is `200`.
2. `refused_origin_forms`: the refused forms (another origin, an uppercase scheme of the
   own origin, `null`, empty, trailing slash, uppercase host, explicit default port, other
   scheme, other port, look-alike, non-visible ASCII, own origin beside a foreign one, two
   own origins) are each refused on `/demo` and `/mcp`; the upstream saw no request.
3. `the_gateways_own_origin_and_no_origin_pass`: no `Origin`, and the public address as
   `Origin`, are both `200` on `/demo` and `/mcp`.
4. `a_foreign_origin_is_refused_without_a_token_too`: without a token, no `Origin` gives
   `401` with a challenge; a foreign origin gives the refusal with no challenge.
5. `get_and_delete_are_covered`: `GET`, `DELETE`, `PUT` and `OPTIONS` on `/demo` and on
   `/mcp` with the foreign origin are refused; the upstream saw no request. `PUT` and
   `OPTIONS` with no `Origin` and with the own origin are `405` with an empty body on both
   paths, as they were at commit 964606d.
6. `an_allowed_origin_passes`: with `allowed_origins` holding
   `chrome-extension://abcdefghijklmnop`, that origin is `200` on both paths and
   `chrome-extension://other` is refused.
7. `bad_allowed_origins_stop_the_start`: each bad entry (`*`, `null`, empty, path, query,
   fragment or trailing slash, outside visible ASCII, over 256 bytes, 33 entries) stops
   the start with exit 2 and a line naming the entry, from the config file and from
   `DOORWARD_ALLOWED_ORIGINS`.
8. `a_refused_origin_costs_the_user_nothing`: with `mcp_burst` at 2, three refused lists
   then two normal ones: both normal ones are `200`, and only two lists reach the upstream.
9. `the_non_rules_hold`: a foreign `Host` alone is `200`; `/oauth/token` and
   `/oauth/register` answer a foreign origin with the same status and body as without it;
   no response on these paths, nor an `OPTIONS` preflight to `/mcp`, carries an
   `Access-Control-*` header. `/login`, `/.well-known/oauth-authorization-server` and
   `/.well-known/oauth-protected-resource/demo` answer a foreign origin with the same status
   as without it, and carry no `Access-Control-*` header.
10. `unknown_paths_follow_the_same_rule`: `GET /zzz` and `POST /zzz` (bob's demo token, a
   slug that does not exist) with no `Origin` are `401`; with the foreign origin they are
   refused. The upstream saw no request.
6. `an_unreachable_upstream_writes_one_line`: the owner is assigned to demo, whose upstream
    (run in the test process) fills the tool list and then stops. The owner's stateless
    `echo` call, with a token from registration and consent, is `502`; exactly one new line
    reads `doorward: upstream demo failed: no connection`.

## s51_failure_log.rs (statement 51)

Real binary, as in s42, started with a temp config and waited on until `/healthz` answers.
The owner is made with the setup code the binary prints. The database fails in one of two
ways: `WriteLock` holds `BEGIN EXCLUSIVE`, so writers wait out the 5 second busy timeout and
fail; `hide_table` renames a table away, so a read of it fails with "no such table". A lock
does not stop readers in WAL mode. "One line" means exactly one line added to standard error
by the request.

1. `a_failed_sign_in_writes_one_line`: a fresh browser gets the sign-in form, the write lock
   is taken, and the form is posted with the owner's email and password: `500`; one line
   starts `doorward: sign-in failed: ` and contains neither the password nor the email.
2. `a_failed_session_lookup_writes_one_line`: the owner is signed in, `sessions` is renamed
   away, `GET /account` is `303` to `/login` (the request is anonymous); one line starts
   `doorward: session lookup failed: ` and holds no session token.
3. `a_database_error_in_the_bearer_check_answers_503`: `access_tokens` is renamed away;
   `POST /demo` with `Authorization: Bearer` and a token of valid shape is `503` with
   `Retry-After: 1`, no `WWW-Authenticate` and an empty body; one line starts
   `doorward: bearer check failed: ` and holds no token. Restored, the same request is `401`
   with `WWW-Authenticate`.
4. `a_failed_metadata_fetch_writes_one_line`: `GET /oauth/authorize` with the client ID
   `https://client.example.invalid/dw-probe/metadata.json` and a loopback redirect is `303`
   to consent; consent is `400` with kind `error`; one line starts
   `doorward: client metadata for client.example.invalid failed: ` and has no `dw-probe`
   path and no query.
5. `a_refused_code_writes_one_line_and_an_unknown_code_writes_none`: the owner registers a
   client (`201`), authorizes and approves. A code exchanged with a wrong verifier is `400`
   `invalid_grant`, and one line starts `doorward: token refused: ` with a reason and holds
   neither the code nor a verifier. A code of valid shape that matches no row is `400`
   `invalid_grant` and adds no line.
6. `an_unreadable_secret_writes_one_line_and_blames_no_upstream`: a server whose stored
   secret is replaced by `not a sealed value`. A stateless call on `/demo` is `502`; one
   line is `doorward: server demo failed: the stored secret cannot be opened`; one
   `tool_call` row is `unavailable` with that phrase as detail. A call on `/mcp` is `502`
   with that same one line, and the stored refresh error does not say the upstream did not
   answer. It is red before the change.
7. `a_broken_stored_hash_writes_one_line`: the owner's stored hash is replaced by `not a
   hash`; a sign-in is `401` with `Wrong email or password.`; one line is `doorward:
   password check failed: the stored hash cannot be read`, with no email in it.
8. `a_mail_settings_read_failure_writes_one_line`: the `settings` table is renamed away while
   an invitation is mailed (the invitation is stored first); one line starts
   `doorward: mail settings failed: `.
9. `a_mail_failure_record_that_cannot_be_written_writes_one_line`: the SMTP port refuses, and
   the `activity` table is renamed away while the failure is recorded; one line starts
   `doorward: mail failure record failed: `.
10. `a_database_error_on_the_combined_endpoint_writes_one_line`: a session-style upstream on
    `/mcp`; after the session starts, `upstream_sessions` is renamed away and one tool call
    is made: exactly one line starts `doorward: upstream sessions failed: ` and none says
    `no connection`. It is red before the change, since a second line says `no connection`.
11. `a_database_error_during_the_access_check_writes_one_line_and_ends_unavailable`: a stateless
    `/demo` call whose upstream is delayed; 500 ms in, `access_tokens` is renamed away, so the bearer
    check has passed but the re-check after the answer cannot read the table. The answer is 502, exactly
    one line reads `doorward: access check failed: database error: no such table: access_tokens`, and
    the one `tool_call` row is `allow` / `unavailable` with the detail `the access check could not be done`.
    It is red before the change, since the old check wrote `access was lost` and no line.
