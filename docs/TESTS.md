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
3. `admin::tests::a_newer_link_past_the_end_goes_to_the_last_page_with_rows`: with 120
   activity rows, pages 4, 6 and 40 answer 200 with no rows, and each newer link goes to
   `page=3`, the last page with rows. It is red before the change.
4. `oauth::consent::tests::a_confirmed_publisher_is_a_plain_line`: the document line of a
   client published by an https host is `p[data-client="document"]`, and no element with
   `data-notice` holds it. It is red before the change.
5. `web::headers::tests`, statements 62 to 64: the page policy is the exact string with
   `font-src 'self'`; `stylesheet_href()` is `/assets/doorward.css?v=` and the first 8 bytes
   of the stylesheet's SHA-256 in hex; the stylesheet asked for by that version is cached
   for a year, and any other query revalidates; each of the four fonts is `font/woff2`
   cached for a year, with `nosniff` and a body starting `wOF2`, for each of the four names
   (review fix 2, which looped it over all four); any other font name is a bare 404.
   `web::page::tests::the_head_preloads_both_fonts_before_the_stylesheet` (statement 64): the
   head holds the two font preloads, then the stylesheet link.
   `web::page::tests::every_preloaded_font_is_answered_by_the_font_handler` (review fix 5): each
   `link[rel="preload"]` href of a rendered page is a font the font handler answers 200.
6. `web::ui::tests::breakable_*`, statement 62 (identifiers): `breakable` breaks after
   `_`, `/`, `?`, `&`, `=`, before `@` and before a `.` that a letter or digit follows; it
   never breaks after the last character. Maud escapes every piece of the text: the escaping
   tests are unchanged (review fix 4 rewrote the function without `PreEscaped`), and
   `breakable_escapes_quotes_and_markup_in_every_piece` is new for it.
7. Rewritten for the new shell (statement 62): `admin::tests::html_pages_carry_the_browser_headers`
   (the exact policy string now carries `font-src 'self'`);
   `admin::tests::panel_and_mail_refuse_anonymous_and_plain_users` and
   `admin::tests::unknown_server_and_user_ids_answer_404` (an unknown address answers 404
   with the `not-found` page, not a bare 404); `oauth::tests_consent::the_policy_text_is_fixed_and_takes_one_form_target`
   (the policy string with `font-src 'self'`); `oauth::tests_guard::another_users_client_is_a_plain_404_and_is_not_revoked`
   (a browser-facing 404: the body is the `not-found` page, the status is still 404);
   `paths_that_are_not_slugs_are_404s_without_a_challenge` answers 404 with no
   `www-authenticate` on every path: one-segment paths answer an empty 404, deeper paths
   answer the `not-found` page;
   `accounts::account::tests::the_panel_link_is_in_the_header_not_the_body` (replaces
   `the_admin_link_is_left_out_for_a_plain_user`, which asserted the link in the body).
8. `web::ui::tests`, statements 65 and 66 (the shared markup): `email` is a `span.email` that
   holds a local-part span, a `<wbr>`, and an `@domain` span, split at the last `@` (the four
   `email` tests were rewritten to this markup, with markup characters and a second `@` covered);
   `a_refusal_with_a_field_links_to_it_after_its_lead_in` and
   `a_refusal_without_a_lead_or_a_field_is_its_message_alone` are new for `refused`;
   `time_cell` keeps its
   `datetime` and splits the date and the clock into `nowrap` spans, with the `UTC` unit only
   when asked; `count_with_unit` keeps the number beside a `span.unit`; `field`, `check` and
   the notes put the label, the control and the hint or error in the order the tests read.
9. `servers::tests::the_open_servers_are_the_open_ones_by_name`: the query behind the
   overview's alert returns the servers whose lock-down is `open`, by name, and none when none is open.
10. `admin::tests::the_overview_names_every_open_server_in_name_order_and_cuts_none`: three open
    servers are named in one notice, `alpha, beta and gamma`, each a link to its lock-down part.
11. `admin::tests::an_activity_row_without_a_user_has_an_empty_user_cell`: a row with no user
    on the overview has `<td class="user"></td>` with nothing inside.
12. `admin::tests::a_refused_server_form_says_so_and_marks_its_path_field` and
    `admin::tests::a_refused_server_page_says_the_server_was_not_saved`: the refusal is an
    alert with the lead-in, its link to the field, and the field marked `aria-invalid`.
13. Added for statement 65 (the pages of users, invitations, rules and redirects):
    `admin::tests::a_refused_invitation_says_so_and_marks_its_email_field`,
    `admin::tests::a_refused_rule_says_so_and_marks_the_field_it_is_about`,
    `admin::tests::a_refused_role_on_the_user_page_marks_the_role_field` (each: the notice
    with its lead-in and its link, the field `aria-invalid` with its `-error` paragraph),
    `admin::tests::a_refused_address_says_so_and_names_no_field` (a refusal about no one
    field has no link), and `admin::tests::a_blocked_attempt_that_cannot_be_allowed_gives_its_reason`
    (plain http reads "Plain http cannot be allowed.", any other case without a one-click
    allow reads "Add it by hand below.", newest first).
14. Changed for statement 65 (markup only: a list row is a `tr` where it was an `li`, the
    counts and pills keep their words, the `Answer::error()` helper reads
    `[data-notice="error"]` as well as `.error`): `admin::tests::a_blocked_client_name_is_shown_as_a_claim_and_escaped`
    (the claim is the second cell of the row, its prefix now in the prototype's lower case
    "asked by a client that calls itself"; the name is still escaped),
    `admin::tests::a_rule_row_holds_one_pill_and_names_its_target_in_words` (the subject is
    the lead cell, the target the "Applies to" cell, where it was a paragraph under the subject),
    `admin::tests::every_refused_rule_answers_400_with_its_message_and_stores_nothing` (the
    message is inside the refusal notice, which starts "The rule was not added. "; the
    refused rule is still not stored), `admin::tests::a_refused_address_answers_400_and_stores_nothing`
    (the refusal is the notice), and the row selectors of
    `a_blocked_attempt_offers_one_click_allow_only_when_it_may`,
    `the_shipped_addresses_are_listed_enabled`, `an_admin_address_is_added_disabled_enabled_again_and_recorded`,
    `an_allowed_address_shows_enabled_or_disabled_and_its_toggle_is_secondary`,
    `a_rule_is_listed_with_its_subject_effect_scope_and_target`,
    `a_tool_rule_for_a_tool_that_left_the_list_is_flagged_stale`,
    `a_rule_is_deleted_and_recorded_and_an_unknown_id_changes_nothing`,
    `a_rule_ignores_the_fields_its_scope_does_not_use`,
    `the_user_page_names_the_deciding_rule_for_each_tool`,
    `a_tool_row_of_the_user_page_holds_one_allow_or_deny_pill_by_its_verdict`,
    `the_user_page_lists_no_tool_of_a_server_the_user_is_not_assigned_to` and
    `the_user_list_counts_assigned_servers_and_shows_active_or_disabled` (rows `tr`).
15. Changed for statements 65 and 66 (markup and wording only: each test asserts the same
    status, redirect, stored value, logged row, shown fact and warning as before):
    `accounts::login::tests::the_sign_in_form_has_one_primary_button_and_keeps_its_fields`
    (the labels sit in `div.field`, no `p.error`), `accounts::login::tests::a_refused_sign_in_shows_its_message_as_an_error_paragraph`
    (renamed `a_refused_sign_in_shows_its_message_in_an_error_notice`: the message is in
    `div.notice[data-notice="error"]`), `accounts::setup::tests::the_setup_page_has_a_lede_under_its_heading_and_one_primary_button`
    (no `p.error`; the password hint is under its field), `accounts::reset::tests::the_forgot_page_has_a_lede_and_one_primary_button`
    and `accounts::reset::tests::the_choose_password_page_has_one_primary_button_and_its_field`
    (labels in `div.field`, the hint out of the bracketed label), `accounts::invite::tests::the_invitation_page_has_the_address_as_a_lede_and_one_primary_button`
    (renamed `..._as_a_fact_and_one_primary_button`: section 10 sets the address in `dl.facts`),
    `accounts::account::tests::the_page_is_a_stack_of_a_head_a_lede_and_two_cards` (renamed
    `the_page_is_a_head_with_the_address_then_two_parts`), `accounts::account::tests::a_connected_client_is_a_row_with_its_details_and_a_danger_disconnect`
    and `accounts::account::tests::the_password_fields_sit_in_a_fields_grid_inside_a_card`
    (rows are `table.clients` rows, the Sign out button is on the title row),
    `web::limit::tests::a_limited_page_tells_a_browser_when_to_try_again_and_no_one_else`
    (the sentence is a `p.lede`), `admin::tests::a_post_naming_no_provider_is_refused_at_the_top_of_the_mail_page`
    (the refusal is a `div.notice[data-notice="error"]`), `admin::tests::a_detail_with_markup_is_escaped_on_the_page`
    (compares the detail text; the escaping and the absent raw `<b>` are still checked),
    `admin::tests::each_row_reads_in_plain_words_beside_its_time_element` and
    `admin::tests::the_activity_pages_hold_fifty_rows_and_link_with_the_filters` (rows `tr`),
    `oauth::tests_consent::a_url_shaped_client_writes_no_blocked_row`,
    `oauth::tests_consent::an_address_that_does_not_parse_is_not_recorded`,
    `oauth::tests_consent::the_consent_page_shows_its_parts_in_order_with_two_decisions`
    (the page is compared by its text, since the host and the approve sentence are split by
    `<wbr>` and `<span>`; the host of an attacker-chosen address is checked in text, which is
    stricter than the raw markup, in `an_attacker_chosen_host_text_is_never_printed`).
    Added: `accounts::login::tests::the_forgot_link_is_the_password_fields_last_child`,
    `accounts::reset::tests::a_refused_password_names_the_refusal_and_marks_its_field`,
    `accounts::account::tests::sign_out_sits_on_the_title_row`,
    `accounts::account::tests::a_refused_change_names_the_refusal_in_a_notice_above_the_fields`,
    `oauth::connected::tests::keep_connected_is_a_link_to_the_account_beside_the_disconnect_button`,
    `oauth::connected::tests::a_server_path_is_code_and_all_servers_is_plain_words` and
    `web::page::tests::each_message_page_is_a_heading_and_one_lede`. The consent test
    `the_consent_page_shows_its_parts_in_order_with_two_decisions` also asserts that the server
    value is a `dl.facts > dd.grant` reading `all servers`, and that the `dd` after `Signed in as`
    reads the signed-in address.
    Integration: `s17_activity.rs` and `s59_counts_paging.rs` read rows as `tr[data-kind]`;
    `s52_interface.rs`: `an_activity_row_reads_in_plain_words` (rows `tr`),
    `the_mail_page_with_no_provider_shows_all_three_closed` (section 10 replaces "No provider
    is in use." with "Current provider: none."), `a_refused_provider_form_is_open_with_its_reason`
    and `a_test_email_sent_is_an_ok_notice` (the notice markup), and `assert_consent` (the
    approve sentence is read as text, since "sign-in" sits in a `span.nowrap`). The shared
    reader `tests/common/admin.rs` takes `.detail` for a row's detail, which is now a span.
15. Refusal marks, form rows and activity details (the look changes of round 7): the refusal page's heading is
    `h1[data-tone="bad"]`, the other message pages' headings carry no tone:
    `web::page::tests::the_refusal_page_marks_its_heading_as_refused`,
    `web::page::tests::the_messages_that_are_not_verdicts_have_no_tone_on_their_heading` and
    `web::page::tests::each_message_page_is_a_heading_and_one_lede` (its refusal case is the
    marked heading), with `the_refusal_page_is_a_403_with_its_title_heading_and_lede` rewritten
    to the marked heading; `oauth::authorize::tests::the_sign_in_cannot_continue_page_marks_its_heading_as_refused`
    and `oauth::consent::tests::the_no_access_page_marks_its_heading_as_refused` do the same for
    the sign-in and no-access pages. `admin::tests::a_limited_page_does_not_mark_its_heading_as_refused`
    reads a real 429 page (a burst of one) and finds `Too many requests` with no tone.
    `admin::tests::the_invitation_email_has_a_row_of_its_own_and_the_role_a_narrower_one`,
    `admin::tests::the_redirect_scheme_has_a_wide_row_and_the_host_a_row_of_its_own` and
    `admin::tests::the_raw_smtp_form_puts_server_alone_then_port_and_tls_then_the_credentials`
    check the `div.fields` rows of each form (`data-cols` and the fields in each) and, for SMTP,
    the document order of the controls. `admin::activity::tests`: a number joins the word after
    it in `span.nowrap` (`assignments of github set to 6 users`, a number last, `1 2 servers`,
    a number before an address, an identifier after a number), each with its text checked, and a
    word that is not only digits, or an empty word, does not join.
16. `web::limit::tests::a_held_body_hands_out_copies_of_its_pieces`: each piece of a held answer is
    a copy, so no piece points into the answer's own allocation, and the pieces join to the answer.

## s01_install.rs (statement 1)

1. `the_root_address_leads_to_setup_then_to_sign_in`: on a fresh gateway `GET /` is 303
   `/setup`; after the owner is created, `GET /` is 303 `/login`; `GET /nothing-here` is
   still 401, the answer of a server path.
2. `health_says_unavailable_when_the_database_fails`: a spawned gateway answers `200` with
   `{"status":"ok"}` on `/healthz`; with the table `settings` renamed away it answers `503`
   with `{"status":"unavailable"}` and one line starts `doorward: health check failed: `;
   with the name restored it answers `200` again.
3. `s01_unknown_path_is_404`: `GET /no/such/page` is 404 and its body is the `not-found`
   page (`main[data-page="not-found"]`), statement 62. It was a bare 404 before the change.

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
    (now the `[data-notice="error"]` notice; `Page::error` reads it too, changed for statement 65)
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
14. `a_call_that_outlives_its_token_survives_the_housekeeping_run`: the setup of 11, with the
    clock 80 minutes ahead (20 minutes past the token's expiry) 400 ms into the call. The
    token part of a housekeeping run is then called at that clock with `families::sweep` on
    the gateway's database, since a restart would wait for the call to end. The call answers
    `200` with `called: echo`, the upstream sees one `tools/call`, and one `tool_call` row for
    echo on demo is `ok`.
15. `a_combined_call_that_outlives_its_token_survives_the_housekeeping_run`: the same on `/mcp`
    with `demo__echo`.

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
   `admin::invite` is 200 `invitation-created` with a non-empty `[data-notice="warning"]` (changed for
   statement 65: the failure is the warning notice, not the old `p.error`) and a
   `data-invite-link` attribute starting `{base}/invite/`; that link accepts a password.
2. `mail_failure_is_in_the_activity_log`: after 1, `admin::activity` has a row of kind
   `mail_failed`.
3. `unreachable_mail_server_does_not_hang_the_panel`: SMTP pointed at a closed local port;
   the invitation answers within 10 seconds with the failure page, whose non-empty
   `[data-notice="warning"]` text is the failure (changed for statement 65 from `error()`),
   and `/healthz` is 200.
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
   with 200 tools: after refresh the page shows a `[data-notice="error"]` notice, the catalog
   is empty and `/healthz` is 200. (Changed with the rebuilt server page: the error is a notice,
   no longer the `.error` class.)
7. `a_failed_refresh_keeps_the_old_list`: stop the upstream, refresh: a `[data-notice="error"]` notice is shown
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
18. `the_activity_helper_reads_every_page`: 55 `echo` calls by bob; the helper
    `activity_with_details` returns the 55 `tool_call` rows, and its row count equals the
    total the activity page shows in `[data-range]`, so rows past the first page are read. It
    is red before the change.

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
    `nav[data-nav="panel"]` in the header and not in `main`, its nine links in order, the
    first reading Overview, and one link with `aria-current="page"`: the Users link on a user
    page, the Servers link on a server page, the link of the section otherwise.
14. `an_admin_sees_no_mail_link`: a non-owner admin's `/admin/users` has the eight links
    without Mail.
15. `a_plain_users_account_page_holds_one_link_and_public_pages_hold_none`: a plain user's 403 under
    `/admin/users` carries no `data-nav`; `/login`, `/forgot` and an invitation page carry no
    `data-nav`. The plain user's `/account` holds one `header nav[data-nav="account"]` with one
    link (round 5, statement 62: the account's own link is its one navigation). It was named
    `a_plain_user_and_public_pages_get_no_navigation`.
16. `the_account_page_links_to_the_panel_for_admins_only`: the owner and an admin see
    `a[data-nav="to-panel"]` reading `Admin panel` with href `/admin`; a plain user does
    not.
17. `a_refused_form_keeps_the_navigation`: the owner's `/admin/servers` form with the slug
    `Not A Slug!` answers 400 with a `[data-notice="error"]` notice and still carries the navigation, with the
    Servers link current.
18. `the_stylesheet_wraps_the_nav_row_and_long_text`: removed: replaced by s62_shell,
    statement 62 (the navigation is a rail or a Menu sheet, not a wrapping row).

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
    that calls itself Claude Code published by claude.ai is asking to sign in as you. Doorward
    cannot check this name.` (round 5 added "is asking to sign in as you"); its
    `q.client-name` is the name; the page has no `(unverified)`.
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
23. `the_address_cells_hold_their_addresses_whole_and_unchanged` (the redirects page, round 10): an allowed
    address `https://app.example.com/oauth/` and a blocked attempt `https://claude.ai/evil` each read
    as their address in the `code` of their first cell, and each holds its path piece in one
    `span.whole`. The unit tests of `web::ui` (`web_address`) and `admin::redirects` pin the markup,
    and the text of every input (the samples, markup characters, non-ASCII, a 2000 character piece).

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
18. `health_with_a_forwarded_header_from_the_host_is_counted`: with no trusted proxy, the
    loopback peer sends `GET /healthz` with `X-Forwarded-For: 192.0.2.60`. The first two are
    `200`; the third is limited with the JSON `too_many_requests` answer. A header from a
    loopback peer is not a reason to skip the count.

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
   email with no account gives the same statuses and the same bodies, once the csrf value
   and each side's own typed address (sent back since statement 71) are masked. The owner
   and the unknown address are typed in another spelling than stored (` Owner@example.com `,
   ` Nobody@example.com `, with spaces and capitals in the local part). Each 401 body holds its typed address
   exactly once, each 429 body none, and the rest of the body does not hold the stored spelling.
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
6. `an_expired_access_token_is_removed_after_its_grace`: bob on demo, so a token row exists.
   The clock moves 90 minutes ahead, 30 minutes past the token's expiry, and a housekeeping run
   is forced with `W.gw.restart()`; a row aged 91 days is written before it, and the run has
   finished when that row is gone. The token's row survives and `initialize` with the token
   answers 401. The clock moves 40 minutes more and a second run deletes the row.
7. `an_expired_family_is_removed_after_its_grace`: the family lasts 90 days. The clock moves
   90 days and 30 minutes ahead; a run keeps the one family row. The clock moves 40 minutes
   more; a second run deletes it.

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

## s52_interface.rs (statements 52 to 58)

`covered(..)` is the list of pages the tests read, each with the layout it must carry: the
sign-in, forgot and account pages, the owner's panel pages, one server page, one user page
(bob) and one disabled user's page, the two consent pages (a local client and a web client,
the web one from the client metadata document `APP_ID` put at `CLAUDE_CALLBACK`), the
invitation acceptance page, the reset page reached from a mailed link, the 403 page a plain
user gets on `/admin`, and the "link is not valid" 404 page. `seeded()` gives the world:
one server `demo` with the tools `echo`, `search`, `delete_db` and bob granted, a second
server `refuser` whose upstream refuses every call, an everyone-allow and an everyone-deny
rule, an open invitation for dave, carol disabled, one redirect entry disabled, and a
activity of allowed, denied and failed tool calls.

1. `every_page_has_the_header_and_its_layout`: each covered page holds one
   `body > header[data-brand]` naming Doorward with an `svg[aria-hidden="true"]`, before
   `main`; `body[data-layout]` is `panel` on the panel pages, `page` on `/account`, `card`
   on the others. It is red before the change.
2. `a_rate_limited_page_has_the_header_and_the_card_layout`: with a general burst of 2, a
   browser request (`Accept: text/html`) to `/login` that is limited answers 429 HTML with
   the header, `h1` "Too many requests" and `data-layout="card"`. It is red before the change.
3. `every_button_says_its_kind`: every button on every covered page has `data-kind` primary,
   secondary or danger; no form holds two primary buttons; `Delete`, `Revoke`, `Remove` and
   `Disconnect` are danger; `Disable`, `Enable`, `Deny`, `Filter`, `Refresh tools`,
   `Check lock-down`, `Send test email` and `Sign out` are secondary. It is red before the change.
4. `deleting_a_server_or_an_account_takes_two_steps`: the server and user pages each hold
   one closed `details[data-confirm]` whose `summary` itself says "cannot be undone" (round 5
   moved the words into the summary as `span.confirm-note`; the body keeps its own sentence) and holds the
   `/delete` form with csrf, and no other `/delete` form. Posting that form without csrf is
   403 forbidden and deletes nothing; with csrf it is 303 and the row is gone. It is red
   before the change.
5. `a_status_is_a_word_with_a_marker` (its rows are `tr`, changed for statement 65 from `li`):
   every `[data-pill]` on the covered pages has a tone
   of ok, bad, warn or muted and text; each rule row holds `Allow` (ok) or `Deny` (bad) by
   its effect; each user row holds `Active` (ok) or `Disabled` (muted); each tool row of
   bob's page holds `Allow` or `Deny` by its verdict; each redirect row holds `Enabled` (ok)
   or `Disabled` (muted). It is red before the change.
6. `the_lock_down_state_is_a_word_with_a_marker`: three servers, one checked as ok (the
   upstream refuses without the secret), one open (answers without it), one unchecked. The
   Lock-down part of each server page holds one pill with tone ok, bad and warn. It is red
   before the change.
7. `an_activity_row_reads_in_plain_words`: every `tbody tr[data-kind]` row on the activity page has
   `data-time`, one `[data-label]` that is not the raw kind, and one `time` whose `datetime`
   is `data-time` and whose text reads `20 Nov 2026 19:25:09 UTC`. The labels are `Tool call`,
   `Tool call refused`, `Tool call failed`, `Sign-in`, `Client connected`, `Admin change`,
   `Invitation`, `Mail not sent` and `Owner created`. Seeded: a sign-in, a failed sign-in, a
   failed invitation mail. It is red before the change.
8. `the_mail_page_shows_one_provider_at_a_time`: the mail page has one `details[data-provider]`
   for each of `smtp`, `resend`, `mailgun`, each holding its form; with smtp in use, only smtp
   is open and marked `[data-in-use]`. It is red before the change.
9. `the_mail_page_with_no_provider_shows_all_three_closed`: on a gateway with no mail
   settings, all three disclosures are closed and the lead line says `Current provider: none.`
   It is red before the change.
10. `a_refused_provider_form_is_open_with_its_reason`: with smtp in use, a resend form and then a
    mailgun form, each with a control character in its from address, are refused with 400; on
    each page the only open `details` is the refused provider's, and that disclosure holds
    a paragraph of a `div.notice[data-notice="error"]` reading "The Resend settings were not
    saved. Go to the from address field", with one link to the field, and the reason "The from
    address contains a control character." under the field (`p.field-error`).
    It is red before the change, since smtp stayed open beside the refused resend form.
    `a_refused_base_address_is_the_one_marked_field_of_its_form`: a resend post with a control
    character in the base address marks only `#resend-base` with `aria-invalid`; its
    `-error` element reads "The base address contains a control character."; the notice reads
    "The Resend settings were not saved. Go to the base address field" with one link to
    `#resend-base`; the reason appears once in the resend form, under the field.
11. `consent_has_one_primary_button` (statement 57, replaced by 70: the buttons and the warning;
    the sentence for a self-registered client is pinned by `tests/s33_consent.rs`
    `a_registered_client_is_shown_as_a_claim`): on the local-client and the web-client consent pages,
    one primary button reads Approve, Deny is secondary, the sentence "Approve only if you
    started this sign-in yourself." is present; on the local-client page `p.local-app` sits
    in `[data-notice="warning"]`. It is red before the change.
12. `the_stylesheet_meets_contrast_and_size`: removed: replaced by s62_shell, statement 63
    (contrast of the new named colours, and the 36 and 44 px controls).
13. `pages_carry_no_inline_style`: no covered page holds ` style=` or `<style`. It passes
    before the change, since no page carries one today; it guards the restyle.
14. `the_current_tab_is_marked_by_the_stylesheet`: removed: replaced by s62_shell,
    statement 62 (the current section is marked with one `span.nav-mark`).
15. `a_registered_client_line_is_a_warning`: a registered client redirecting to
    `https://app.example.com/oauth/cb`, an address the allow list holds, has its
    `p[data-client="registered"]` directly inside `[data-notice="warning"]`. It is red before
    the change.
16. `a_loopback_document_line_is_a_warning`: the document client on its loopback redirect has
    its `p[data-client="document-loopback"]` directly inside `[data-notice="warning"]`. It is
    red before the change.
17. `the_mail_providers_sit_in_one_wrapper`: the mail page holds the three
    `details[data-provider]` directly in one `div.providers`. It is red before the change.
18. `a_test_email_sent_is_an_ok_notice`: after a test email, the mail page holds
    a paragraph of `div.notice[data-notice="ok"]` reading "Test email sent.". It is red before the change.
19. `the_panel_navigation_is_labelled_admin`: each panel page of the covered set holds one
    `nav[data-nav="panel"][aria-label="Admin"]`. It is red before the change.
20. `no_covered_page_holds_a_script`: no covered page holds `<script`, in any case. It passes
    before the change, since no page carries one; it guards statement 58.
21. `every_src_and_href_is_a_same_site_path`: every `src` and `href` on every covered page
    starts with `/` and not `//` or `/\`, or is a fragment `#...` naming a place on the same
    page, so no page names an address outside the gateway. The rule is `is_same_site_path`,
    which `a_same_site_path_is_a_fragment_or_a_slash_path_that_names_no_host` checks directly. It passes
    before the change, since no page does; it guards statement 58.
22. `the_stylesheet_loads_no_url_and_no_import`: removed: replaced by s62_shell,
    statement 64 (the stylesheet names its four fonts by `url()`, and the gateway serves them).
23. `every_tone_has_a_marker_rule_with_content`: the stylesheet holds one rule whose selector
    list contains `.state::before` and declares `content: ""` (the mark of every
    `.state[data-tone]`), and for each of ok, bad, warn and muted a rule whose selector list
    contains `.state[data-tone="<tone>"]::before` and declares `inline-size` (its shape). The
    marker of statement 54. Review fix 3: it used to check the selector only, not the content.
24. `every_post_form_carries_the_csrf_field`: on every covered page, each
    `form[method="post"]` holds an `input[name="csrf"]`. It passes before the change, since
    every form carries one today; it guards the anti-forgery rule of statement 33.

## s59_counts_paging.rs (statements 59 to 61)

Each test builds its own world. The overview test has three users (owner, bob, and carol as an admin),
two servers (`demo` with three tools and bob granted, and `other` with one tool), four rules,
one open invitation (dave) next to one revoked (eve) and one accepted (bob), and the
activity rows the harness writes. Activity rows beyond those are inserted straight into the
gateway's database file (`activity` table), one second apart, which is the cheapest route to
more than 100 rows; the expected order and counts come from the same table.

1. `the_overview_counts_and_shows_the_latest_activity`: `a[data-count]` links for `servers`
   (2), `users` (3), `invitations` (1) and `rules` (4), each to its page and holding
   `[data-count-value]` with that number, for the owner and for an admin; the
   `[data-latest-activity]` section holds the five newest rows (`tr[data-kind]`), newest first,
   and links to `/admin/activity`. It is red before the change.
2. `the_lists_show_counts_and_states`: each `tr[data-server-id]` holds `[data-tool-count]`
   (3 tools for demo, 1 for other), `[data-user-count]` (1 user for demo, 0 for other), its
   path and one lock-down pill; each `tr[data-user-id]` (changed for statement 65 from `li`)
   holds `[data-server-count]` (0, 1
   or 0), its role and one pill, `Active` (ok) or `Disabled` (muted) for carol. It is red
   before the change.
3. `activity_is_paged`: `Rows 1 to 50 of N` with N the stored row count, 50 rows per page
   newest first, older and newer links that carry `page=`, no newer link on page 1 and no
   older link on the last page; the filtered view counts and keeps the user and server
   filters in its links; `page=0`, `page=abc` and `page=-1` show page 1; a page past the end
   is 200 with no rows, `No activity matches.` and a newer link. It is red before the change.
4. `filters_reset_to_the_first_page`: the filter form holds no `page` field, and a submit
   built from its user and server fields shows page 1 of the filtered rows. It is red before
   the change.

## s62_shell.rs (statements 62 to 64, 67 and 69)

The shell and the stylesheet, read from the served pages and the served stylesheet. Most tests
read one world, `seeded()`: an owner, bob as a plain user granted `demo`, an admin, `demo` with
the tools `echo`, `search` and `delete_db`, and an open invitation for dave. The covered pages
are the sign-in and forgot pages, the account page for the owner, an admin and bob, the panel
pages (overview, servers, one server, users, one user, invitations, rules, redirects, mail,
activity), the local and the web consent pages, the invitation page, the reset page, the 403
page for bob on `/admin`, and the "link is not valid" 404 page. The unknown address is
`/no/such/page`: a single segment such as `/no-such-page` is a server path, which answers 401
for a client with no token (statement 18), so it cannot be the 404 of statement 62.

The stylesheet checks read the rules of `assets/doorward.css` as served; the colour checks
convert each token from oklch to sRGB with the OKLab matrices, then compute the WCAG contrast.
The conversion is guarded by `the_oklch_conversion_matches_known_colours`.

1. `every_page_holds_the_site_header_and_its_layout`: each covered page and the unknown
   address hold one `body > header.site[data-brand]` naming Doorward, before `main`, with
   `body[data-layout]` of `panel`, `page` or `card` as the page kind requires. It is red
   before the change, since the unknown address answers without a header.
2. `the_not_found_page_is_a_full_card_page`: the unknown address answers 404 with the header,
   `body[data-layout="card"]`, `main[data-page="not-found"]` and the h1 `Page not found`. It is
   red before the change.
3. `a_panel_page_holds_the_navigation_in_its_header`: each panel page holds one
   `nav#panel-nav[data-nav="panel"][aria-label="Admin"][popover]` inside the header, no nav in
   `main`, and `a.brand` to `/admin`; the links read Overview, Users, Invitations, Servers,
   Rules, Redirects, Activity, Mail and Your account in that order, with `nav-break` on Users,
   Servers and Activity and `nav-end` on Your account, and the admin's list has no Mail. It is
   red before the change.
4. `the_current_section_is_marked_once`: each covered page holds exactly one `span.nav-mark`
   (aria-hidden), inside the link to its section, which is the only link with `aria-current`.
   A page whose header holds no `nav` holds no `span.nav-mark`. A plain user's account page
   holds its one navigation and its one mark (round 5), so it is covered like the others.
5. `the_account_page_holds_its_own_navigation`: the owner's and an admin's account pages hold
   `nav#account-nav[data-nav="account"][aria-label="Account"]` in the header, with `Your account`
   as the current link and `li.nav-end > a[href="/admin"][data-nav="to-panel"]`. Bob's account
   page (round 5, statement 62) holds one `header > nav[data-nav="account"][aria-label="Account"]`
   with no `popover` and no `id`, exactly one link to `/account` with `aria-current="page"`
   reading `Your account`, the one `span.nav-mark`, and no `button.menu-button`. It was red
   before the round 5 change, which put the link in the header.
6. `a_card_page_holds_the_note_and_no_navigation`: each card page and the unknown address hold
   one non-empty `p.site-note` in the header, and no nav and no Menu button. It is red before
   the change.
7. `a_rate_limited_page_holds_the_site_note`: with a general burst of 2, the third browser
   request to `/login` answers 429 with one `p.site-note` in the header and no nav. It is red
   before the change.
8. `the_menu_button_opens_the_panel_without_script`: each panel page holds one
   `button.menu-button[type="button"][popovertarget="panel-nav"]` in the site bar, with the
   spans `Menu` (when closed) and `Close` (when open), and the panel is a `popover`. It is red
   before the change.
9. `every_page_links_the_gateways_stylesheet`: each covered page and the unknown address link
   exactly one stylesheet whose href starts with `/assets/doorward.css`. It is red before the
   change, since the unknown address page links none.
10. `no_page_holds_a_script_or_an_inline_style`: no covered page or the unknown address holds
    `<script`, ` style=` or `<style`. It passes before the change; it guards statement 63.
11. `the_oklch_conversion_matches_known_colours`: `oklch(1 0 0)` gives 255 in each channel,
    `oklch(0 0 0)` gives 0, `oklch(0.5 0 0)` gives 99 within 1, and `oklch(0.628 0.2577 29.23)`
    gives (255, 0, 0) within 2. It passes before the change; it guards the converter.
12. `text_reaches_4_5_to_1_on_its_background_in_both_themes`: the 19 text pairs of statement
    63 (`--ink`, `--ink-2`, `--ink-3` on `--paper`, `--surface`, `--sunken`; `--ink` and
    `--ink-2` on the three washes; `--on-door` and `--on-door-2` on `--door`; `--on-deny` on
    `--deny`; `--paper` on `--ink`) reach 4.5 to 1 in the light and in the dark theme; a missing
    token fails the test by name. It is red before the change, since the tokens do not exist.
13. `colour_and_rules_reach_3_to_1_on_their_background_in_both_themes`: `--allow`, `--deny` and
    `--warn` on `--paper` and `--surface`, and `--line-strong` on both, reach 3 to 1 in both
    themes. It is red before the change, since the tokens do not exist.
14. `the_controls_are_36_px_and_44_px_on_a_touch_or_narrow_screen`: `:root` declares
    `--control: 36px`; the block `@media (pointer: coarse), (max-width: 639.98px)` redeclares
    it as `44px`; a rule whose selector mentions `button`, one mentioning `input` and one
    mentioning `select` sizes its height with `var(--control)`. It is red before the change.
15. `the_stylesheet_names_only_the_gateways_font_files`: no `@import`; at least one
    `@font-face` with a `src`; every `url(` has the form `url("fonts/<name>.woff2")`. It is red
    before the change.
16. `the_font_files_are_served_as_woff2`: each font the stylesheet names answers 200 from
    `/assets/fonts/<name>.woff2` with `content-type` `font/woff2`, `nosniff`, and a body that
    starts with `wOF2`. It is red before the change.
17. `an_unknown_font_answers_404`: `/assets/fonts/nope.woff2` answers 404. It passes before the
    change.
18. `the_page_policy_allows_fonts_from_the_gateway_only`: the content-security-policy of the
    sign-in page and of the consent page has the directive `font-src 'self'` and keeps
    `default-src 'none'`. It is red before the change.
19. `the_font_licences_are_in_the_repository`: `assets/fonts/OFL-Atkinson-Hyperlegible-Next.txt`
    and `...-Mono.txt` exist and say SIL OPEN FONT LICENSE. It is red before the change, since
    the font files are not in the repository yet.
20. `the_stylesheet_moves_pages_only_when_motion_is_allowed`: `@view-transition` with
    `navigation: auto` inside `@media (prefers-reduced-motion: no-preference)`; the names
    `door`, `brand`, `nav-mark` and `room` for `view-transition-name`; and inside
    `@media (prefers-reduced-motion: reduce)` a universal rule (`*`) that sets
    `transition-duration` and `animation-duration`. It is red before the change.
21. `colour_is_only_named_values_outside_custom_properties`: no declaration whose property does
    not start with `--` holds `oklch(`, `rgb(`, `rgba(`, `hsl(`, `hsla(` or a `#` followed by
    3, 4, 6 or 8 hex digits. It passes before the change, since the current stylesheet keeps
    its colours in custom properties.

## s65_forms_tables.rs (statements 65 and 66)

Forms are read from the server add form, one server, the rules, redirects, invitations and
mail pages, one user, the account page of bob, the sign-in and forgot pages, and the setup
page of an instance with no owner. The tables are read from `seeded()`: `demo` with bob
granted, two rules (allow everyone on the server, deny `delete_db` for everyone), a redirect,
an open invitation for dave, and bob's allowed `echo` call and refused `delete_db` call over a
connected client. Each test builds that world, except the setup page, which has its own gateway.

1. `every_field_sits_in_a_row_under_its_label`: every input (not hidden, checkbox or radio),
   select and textarea on each form page sits directly in a `div.field`, that in a
   `div.fields` (or a fieldset), after a `label[for]` that is its direct child. Each page
   holds at least one such control. It is red before the change, since the server form has
   no field rows.
2. `labels_are_tied_to_their_control_and_hold_no_brackets`: each label has a `for`, holds no
   input, and holds a bracket only inside `span.optional` whose text is `(optional)`. It is red
   before the change, since the server form's Path label holds its hint in brackets.
3. `hints_are_tied_to_their_control`: each `p.hint` has an id that a control in its
   `div.field` or `div.check` names in `aria-describedby`. It is red before the change.
4. `checkboxes_sit_in_a_check_beside_their_label`: each checkbox sits directly in a `div.check`
   with a sibling `label[for]` equal to its id; the server page holds at least one checkbox.
   It is red before the change.
5. `the_server_form_says_what_the_path_and_the_upstream_take`: the label `Path` has the hint
   `Letters, digits and hyphens, at most 24 characters.` and `Upstream address` has the hint
   `An http or https address.`. It is red before the change.
6. `the_lists_are_tables_with_column_heads_and_rows`: servers, users, invitations, rules,
   redirects, activity and the connected clients on `/account` each hold one `table.list` with
   `thead th[scope="col"]` heads and `tbody tr` rows; the overview's latest activity holds one
   such table; no list page holds `ul.rows` or `ol.rows`. It is red before the change.
7. `the_rows_carry_their_data_on_the_row_element`: `tr[data-server-id][data-slug]` (one row),
   `tr[data-user-id][data-email]`, `tr[data-invitation-id][data-email]` (one row),
   `tr[data-rule-id]` (two rows), `tr[data-redirect-id]`, `tr[data-kind]` and
   `tr[data-family]` are present, and no `li` carries those attributes. It is red before the
   change.
8. `the_servers_counts_carry_their_unit_in_the_cell`: the row of demo holds `td[data-tool-count]`
   starting with 3 and `td[data-user-count]` starting with 1, each with one `span.unit`. It is
   red before the change.
9. `the_rule_row_starts_with_the_rule_id`: the first cell of each rule row reads its
   `data-rule-id`, after an optional `Rule ` prefix. It is red before the change.
10. `a_tool_name_breaks_only_after_its_underscores`: the raw server page holds `delete_<wbr>db`,
    and an element whose text is `delete_db` holds that markup, so the text is unchanged. It is
    red before the change.
11. `an_email_address_breaks_before_the_at_sign_first`: the raw users page holds
    `bob</span><wbr><span>@example`, and a `span.email` whose text is `bob@example.com` holds
    `bob<wbr>@example` once its `<span>` and `</span>` tags are removed. It is red before the
    change.
12. `a_tool_call_row_shows_its_duration_in_ms`: the activity page holds at least two
    `tr[data-kind="tool_call"]` rows (the allowed and the refused call), each with one
    `td.duration` whose text is digits then ` ms`. It is red before the change.
13. `the_duration_cell_keeps_its_text_on_one_line`: the stylesheet holds a rule whose selector
    mentions `.duration` and declares `white-space: nowrap`. It is red before the change.
14. `ids_are_unique_and_every_description_exists`: on every page above and on each list page, no
    id is on two elements, every `label[for]` names an id on the page, and every id in an
    `aria-describedby` exists. It passed on the pages as they stood, so no page was changed.

## s68_exposed.rs (statement 68)

Each test builds its own world. An exposed server is one whose upstream asks for no secret;
its lock-down check leaves it in the state `open`. A healthy server is one whose upstream
refuses without the gateway's secret, so its state is `ok`.

1. `an_open_server_has_an_alert_on_its_own_page`: the server page carries `data-lockdown="open"`
   and holds one `main div.notice[data-notice="error"][data-lockdown-alert]` that says `This server answers without the gateway.` and links to `#lockdown-title`, and the page
   holds the element `#lockdown-title`.
2. `the_overview_names_one_exposed_server`: with one open server and one healthy one, the
   overview holds `div.notice[data-notice="error"][data-open-servers="1"]` reading `Open Demo answers without the gateway.` with a link to `/admin/servers/<id>#lockdown-title`, and the
   healthy server is not named.
3. `the_overview_counts_two_exposed_servers`: with two open servers, the overview holds
   `[data-open-servers="2"]` reading `2 servers answer without the gateway.` with one link per
   server, each to `/admin/servers/<id>#lockdown-title`, whose text is the server's name.
4. `no_alert_without_an_exposed_server`: with only a healthy server (`ok`), the overview holds
   no `[data-open-servers]` and the server page holds no `[data-lockdown-alert]`. It passes
   before the change, since the negative case has no alert today either.

## s71_refused_forms.rs (statement 71)

Each test posts a refused form with distinctive typed values and reads the controls back.
Each test builds its own world: `W` for the admin and sign-in pages, a plain gateway for setup.

- `a_refused_header_form_sends_back_its_name_and_its_required_box`: a refused name `Cookie` comes back
  in `input#header-name`, with the notice, the field error and the Required box as it was sent.
The owner's rule and redirect forms use `W.upstream("demo", ..)` and `W.user(bob)`.

1. `a_refused_setup_sends_back_the_email`: a short password with the right setup code answers
   `400`, and `input#email` holds the typed address. Red before the change.
2. `a_refused_sign_in_sends_back_the_email`: a wrong password answers `401`, and
   `input#email` holds the typed address. Red before the change.
3. `a_refused_invitation_sends_back_the_email_and_the_role`: an address that has an account,
   with role `admin`, answers `400`; `input#invite-email` holds the address and the option
   `admin` of `select#invite-role` is selected. Red before the change.
4. `a_refused_rule_sends_back_every_choice`: a tool the server does not list, for bob, answers
   `400`; the subject, effect, scope and server selects each keep the posted option selected,
   and `input#rule-tool` holds the tool name. Red before the change.
5. `a_refused_redirect_sends_back_every_part`: plain `http` answers `400`; `input#redirect-scheme`,
   `input#redirect-host` and `input#redirect-path` hold the posted scheme, host and path prefix.
   Red before the change.
6. `a_refused_mail_provider_sends_back_its_posted_settings`: a port that is not a number
   answers `400`; the raw SMTP form shows the posted address, server, port and username, and
   selects the posted TLS setting, while the Resend and Mailgun forms keep showing the stored
   address. Red before the change.
7. `a_refused_test_email_sends_back_the_address`: a test address without an `@` answers `400`,
   and `input#test-to` holds it. Red before the change.
8. `no_refusal_sends_back_a_secret`: a refusal of setup (password, setup code), sign in
   (password), server add (secret header value), SMTP (password), Resend and Mailgun (API key),
   the password change, the reset and the invitation acceptance. Each password-type input
   renders with no `value` attribute, and the posted secret appears nowhere in the body. It
   passes before the change, since no secret was ever sent back.
9. `a_refused_sign_in_reads_the_same_for_a_known_and_an_unknown_address`: the owner, an unknown
   address and a disabled account (dave), typed with spaces and capitals, each refused with a
   wrong password, and dave also with the right one: four `401` bodies that are equal once the
   csrf value and each typed address are replaced by placeholders, each `input#email` holding
   its own typed address. The equality holds before the change; the echo is red.
10. `a_typed_value_with_markup_comes_back_escaped`: a host of `"><b>x` answers `400`, the input
    holds those characters, the page has no `b` element, and the attribute is escaped as
    `&quot;&gt;&lt;b&gt;x`. Red before the change.
11. `a_control_character_is_removed_from_the_value_sent_back`: a host with a bell character and
    a tab answers `400` and comes back as `typed.example.org`, and the bell appears nowhere in
    the page. Red before the change.
12. `an_overlong_value_is_not_sent_back`: a host of 501 characters renders empty while the short
    scheme beside it comes back; an email of 262 characters renders empty. Red before the change.
13. `a_limited_sign_in_sends_no_address_back`: the sixth wrong password from one address answers
    `429` with `input#email` holding no value. It passes before the change, which pins the limit
    page as it was.
14. `a_refused_server_form_sends_back_cleaned_values`: a name with a bell character and a
    501-character upstream address, on add and on edit, answer `400`; the page has no bell,
    `input#server-name` holds `Typed`, and `input#server-url` is empty. Red before the change.
15. `a_refused_mail_secret_is_asked_for_again`: for SMTP, Resend and Mailgun, a refused post that
    carried the secret shows `Enter it again: a secret is never sent back.` as the hint under
    the secret field, and the secret appears nowhere; a refused SMTP post without a secret shows
    the usual hint. Red before the change.
16. `a_refused_server_form_asks_for_the_secret_again`: on add and on edit, a refused post that
    carried a secret header value shows the same sentence under the value; without one, the
    usual hint (`Kept encrypted and never shown again.` on add, the stored-secret hint on edit).
    Red before the change.

The helper `sent_back` in `src/web/ui.rs` has in-crate tests for its limit, its counting of
characters and its control characters: `a_sent_back_value_*`. The sign-in form's hidden `req`
has an in-crate test in `src/accounts/login.rs`, `a_req_that_is_a_request_id_is_sent_back_and_any_other_is_not`.

## s72_overview_state.rs (statement 72)

Each test builds its own world and reads the overview's count links whole, markup and text.
A gated server is `W.upstream`; `check-lockdown` makes it `ok`, or `open` for `W.open_upstream`
when it answers; an unchecked server is `unknown`. Dates are the harness clock (2030-01-01 at
the start) plus the 7-day invitation lifetime.

1. `one_open_server_reads_answers_without_the_gateway_in_the_singular`: one open server gives
   `Server` and `1 answers without the gateway`, tone `bad`. Red before the change.
2. `two_open_servers_read_answer_without_the_gateway_in_the_plural`: `2 answer without the gateway`, `bad`.
3. `unchecked_servers_with_none_open_read_not_checked`: `2 not checked`, tone `warn`.
4. `an_unchecked_server_beside_a_locked_down_one_reads_not_checked`: `1 not checked`, not locked.
5. `an_open_server_hides_the_unchecked_count`: open beats not checked; one line only.
6. `one_locked_down_server_reads_locked_down`: `Locked down`, tone `ok`, label `Server`.
7. `every_server_locked_down_reads_all_locked_down`: `All locked down`, tone `ok`, label `Servers`.
8. `one_disabled_user_reads_disabled_in_muted`: `1 disabled`, tone `muted`.
9. `two_disabled_users_read_two_disabled`: `2 disabled`, tone `muted`.
10. `one_open_invitation_reads_expires_with_its_date`: `Expires` and `<time datetime="2030-01-08T00:00:00Z">8 Jan 2030</time>`, label `Open invitation`.
11. `two_open_invitations_read_the_next_expiry_of_the_earliest`: `Next expires` with the earlier of two.
12. `a_revoked_or_expired_invitation_is_not_open`: a revoked and an expired invitation are not counted; the one open one reads `Expires 16 Jan 2030`.
13. `deny_and_allow_rules_read_deny_then_allow`: `2 deny` (`bad`), one space, `1 allow` (`ok`).
14. `only_deny_rules_read_deny_alone`: `1 deny` only, label `Rule`.
15. `only_allow_rules_read_allow_alone`: `2 allow` only.
16. `a_quiet_overview_has_no_count_state_and_plural_labels_at_zero`: owner only; no `span.count-state` in any of the four cells; `Servers`, `User` at one, `Open invitations`, `Rules`.
17. `the_nouns_take_the_singular_at_one_and_the_plural_otherwise`: one of each reads the singular labels; two of each the plural ones, with their lines.
18. `an_admin_who_is_not_the_owner_sees_the_same_lines`: an admin's four count links equal the owner's, with their lines.
19. `a_plain_user_cannot_open_the_overview_and_sees_no_count`: a plain user gets `403` and no `data-count`.

Rewritten tests (the old markup they pinned, before the round 8 `span.whole` wrapper):

- `oauth::consent::tests::the_other_client_lines_keep_their_sentences`: the host of both lines now
  sits in `span.whole` with its full stop, and the host passes through `ui::breakable`
  (`example<wbr>.com`). The sentences, the warning notice and `data-client` are unchanged.
- `oauth::connected::tests::a_server_path_is_code_and_all_servers_is_plain_words`: the server path
  is `p.lede > span.whole > code`.
- `admin::activity::tests` (`a_url_with_an_at_in_its_path_is_not_an_email`,
  `markup_characters_are_escaped_and_the_text_is_unchanged`, `a_detail_with_no_space_is_one_word`,
  `the_word_after_a_number_still_breaks_as_an_identifier`): a non-address word with a break point is
  in `span.whole`; the text is unchanged.

New unit tests for the `span.whole` places: `oauth::authorize::tests::the_cannot_continue_host_sits_in_one_whole_span`,
`oauth::connected::tests::the_server_path_sits_in_a_whole_span_as_code`,
`accounts::account::tests::the_server_of_a_connected_app_sits_in_a_whole_span_as_code`,
`admin::users::tests::the_server_of_a_tool_sits_in_a_whole_span_as_code`,
`admin::rules::tests::the_applies_to_names_sit_in_whole_spans_as_code`.

## s73_account_nav.rs (statement 73)

Each test builds its own world. The account page of an owner or admin is checked against the
links the panel pages show, so the two cannot drift apart.

1. `the_owners_account_page_is_a_panel_page_marked_on_your_account`: `body[data-layout="panel"]`, one
   `nav#panel-nav` with the nine owner links in order (Mail included) and the same links as GET /admin,
   the brand to `/admin`, Your account the only `aria-current="page"` and the last item, no
   `#account-nav`, no link reading Admin panel. Red before the change.
2. `an_admins_account_page_is_a_panel_page_marked_on_your_account`: the same for an admin, with the
   eight links and no Mail. Red before the change.
3. `a_plain_users_account_page_holds_one_link_and_no_panel_link`: `body[data-layout="page"]`, no
   `nav#panel-nav`, no `a[href^="/admin"]`, one navigation link reading Your account, no Menu button.
   Passes before and after the change.
4. `a_plain_user_refused_a_panel_page_links_to_the_start_page`: GET /admin for a plain user answers 403
   with `data-page="forbidden"`, and one `p.back a[href="/"]` reading `Go to the start page`. Red before.
5. `a_refused_form_post_links_to_the_start_page`: a post without the anti-forgery token answers 403 with
   the same page and link. Red before.
6. `the_too_many_requests_page_holds_no_link_in_its_main`: the 429 page holds no `a` inside `main`.
   Passes before and after the change.
7. `an_invitation_not_sent_shows_its_link_in_a_labelled_field`: the page holds `span.label#invite-link-label`
   reading Invitation link, one `div.field[role="group"][aria-labelledby="invite-link-label"]` inside
   `div.fields.narrow`, and `code.copy[data-invite-link]` whose raw text equals the stored link. The code
   holds two spans (origin, then path), one `wbr` as its own child between them, and no text node of its
   own. The way back sits in `div.form-actions`. Red before.
8. `the_start_page_leads_a_signed_in_person_to_their_account`: a plain user, an admin and the owner each
   get `303` to `/account` from `GET /`. Red before the change of `root`.
9. `the_start_page_still_leads_an_anonymous_visitor_to_sign_in`: an anonymous `GET /` is `303` to
   `/login`. Passes before and after. `tests/s01_install.rs` keeps the `/setup` and `/login` answers.
10. `a_plain_user_refused_a_panel_page_reaches_their_account_by_the_start_link`: the refusal page's
    `p.back a` link, followed through its redirects (at most three), ends on a `200` page whose `h1`
    reads Your account. Red before.
11. `a_demoted_admin_keeps_the_session_and_sees_a_plain_users_account`: an admin on `/account` holds the
    panel navigation; the owner changes that account's role to `user` through the real form (`303`); the
    same session's next `GET /account` is `200` with `body[data-layout="page"]`, one `nav[data-nav="account"]`,
    no `nav#panel-nav` and no `a[href^="/admin"]`; its `GET /admin` is `403`. Observed: a role change does
    not end the session, because the role is read from the users row on every request. Passes on the code
    as it was; it records the behaviour for the security review and changes nothing.

Rewritten tests (old expectation, then new; roles and counts kept):

- `s62_shell::the_account_page_holds_its_own_navigation`, owner and admin part: was `nav#account-nav` in
  the header, brand to `/account`, the Your account link current, and a `li.nav-end` link to `/admin`
  reading Admin panel. Now `nav#panel-nav` in the header, brand to `/admin`, Your account current and
  marked at the foot, and no `#account-nav`. The plain user part is unchanged.
- `s62_shell::every_page_holds_the_site_header_and_its_layout`, the covered list: `/account (owner)` and
  `/account (admin)` expected layout `page`, now `panel`. `/account (bob)` stays `page`.
- `s62_shell::a_panel_page_holds_the_navigation_in_its_header`: the call site gave the owner's nine links
  for every panel shot. The admin's account page has eight, so it is checked with `owner = false`.
- `s52_interface::every_page_has_the_header_and_its_layout`: `/account (owner)` expected layout `page`,
  now `panel`. `/account (bob)` stays `page`.
- `s26_panel::the_account_page_links_to_the_panel_for_admins_only`: was a `a[data-nav="to-panel"]` link
  to `/admin` reading Admin panel for the owner and an admin. Now the brand `header[data-brand] a.brand`
  links to `/admin`, no link reads Admin panel and no to-panel link exists. For a plain user, no
  `a[href^="/admin"]` at all.
- `web::page::tests::a_plain_users_account_nav_is_one_link_with_no_popover_and_no_menu`: only the
  constructor changed (`Nav::Account { admin: false }` is now `Nav::Account`). The expected header string
  is unchanged.

New unit tests: `web::page::tests` `the_refusal_page_links_to_the_start_page_after_its_lede`,
`an_account_page_takes_its_layout_from_its_navigation` (a plain user's account page stays `page`) and
`a_panel_navigation_does_not_change_the_layout_of_another_kind`; `admin::invitations::tests`
`a_link_is_cut_before_the_first_slash_after_its_host`, `a_link_that_is_not_scheme_host_shaped_is_not_cut`,
`the_link_code_holds_origin_and_path_in_two_spans_with_one_wbr`,
`a_link_without_a_path_has_one_span_and_no_wbr_between` and
`a_link_that_is_not_shaped_is_one_span_with_no_path_span`.

## s74_key_case.rs (statement 74)

Each test builds its own world: bob on the `demo` server, whose tool `search` is denied for
everyone. The test checks that the deny rule is stored, sends the trick bodies to one route, and
checks each refusal. An ordinary call and a call with odd argument names follow.

1. `per_server_session_refuses_each_trick_body`: on `/demo` under the session rules. Body A has
   `params.name` as `echo` and `params.Name` as `search`. Body B has a top-level `Method` member
   and `params.Name`. Body C is a response with a top-level `Method` and `Params`. Each answers
   `400` with JSON-RPC `-32600` and message `Invalid request`, reaches no upstream, and adds no
   allowed row for `echo` or `search` to the activity log. Then `echo` answers `200` with the
   text `called: echo`, and the upstream gets one `tools/call`. Last, a call whose
   `params.arguments` holds `Name`, `näme`, `ProgressToken` and `Arguments` reaches the upstream
   with the same bytes.
2. `per_server_stateless_refuses_each_trick_body`: the same on `/demo` under the stateless rules,
   with `params._meta` in each body. Bodies A and B are sent. Body C is a response, and it is
   sent on a session only. The odd-argument call is forwarded with the same bytes.
3. `combined_session_refuses_each_trick_body`: the same on `/mcp` under the session rules, with
   the tool names `demo__echo` and `demo__search`. The odd-argument call is not compared byte for
   byte. The test compares the parsed `arguments` value with the one it sent.
4. `combined_stateless_refuses_each_trick_body`: the same on `/mcp` under the stateless rules,
   with the names `demo__echo` and `demo__search`. Bodies A and B are sent. The odd-argument
   call is compared as in item 3.
5. `a_control_character_in_a_name_is_refused_on_both_session_routes`: on `/demo` and on `/mcp`
   under the session rules, a body whose `params` holds `name` as the allowed tool and `name` with
   a U+0000 after it as the denied one. Each answers `400` with JSON-RPC `-32600` and message
   `Invalid request`, reaches no upstream and adds no activity row. Then the allowed call answers
   `200` on each route.
6. `a_non_ascii_name_under_meta_is_refused_on_the_per_server_route`: on `/demo` under the session
   rules, a `params._meta` that holds a name with a non-ASCII character. The same refusal, no
   upstream call and no activity row.
7. `a_case_variant_decision_key_under_ref_is_refused_on_the_per_server_route`: on `/demo`, a
   `completion/complete` whose `params.ref` holds `Type` for `type`. The same refusal, no upstream
   call and no activity row.

## s75_answer_memory.rs (statement 75)

Each test sets `limits.tools_list_bytes` to 262144 and `limits.answer_memory_bytes` to a budget of
its own. The fake upstream holds its answers open, so the test sees the budget while the answers
are held and again after they are released. A held answer is 200000 bytes of text.

1. `a_burst_past_the_budget_is_refused_while_held_and_the_budget_comes_back`: the budget is
   524288 bytes. Six `echo` calls on the session route start at once, and the upstream holds all
   six. While they are held, at least one call is refused. The refusals that arrive then are `503`
   with `Cache-Control: no-store`, no `Retry-After`, JSON-RPC `-32000`, message
   `The gateway could not hold the server's answer. The call was sent to the server.` and a null
   id. Every call answers `200` or `503`, at most two answer `200`, and each `200` holds the whole
   text. After the release, a new call answers `200` with the whole text within 10 seconds.
2. `the_same_burst_on_the_stateless_generation`: the same burst on the stateless route, in its own
   world with a budget of 524288 bytes. The call after the burst uses a new stateless client and
   must answer `200` with the whole text within 10 seconds.
3. `a_stream_event_past_the_remaining_budget_ends_the_stream`: five plain `echo` calls start first
   and use most of the budget. Then one `echo` call on a second server gets a stream whose one
   event is about 200000 bytes, of which the first 4096 bytes are sent at once. The test
   releases the stream. The call's reply has no `result`, so the stream ended before its event
   was whole. The activity log holds one `tool_call` row for that server, with outcome
   `unavailable` and the detail `the answer memory budget is exhausted`. The five held answers
   are released last.
4. `a_user_at_its_share_is_refused_and_another_user_still_answers`: the budget is 1048576 bytes,
   so one user's share is 262144 bytes. Alice starts four stateless `echo` calls on a held server,
   and the test waits until all four begin. At least two of her calls are refused while the
   others are held, each in the form of item 1 for a call that was sent. Bob calls a second server whose answer is
   200000 bytes, sent at once. His call must answer `200` with a result within 20 seconds. After
   the release, at most one of Alice's held answers answers `200` with the whole text, and any
   other is refused in the form of item 1. All four of her calls are answered.
5. `a_refresh_the_budget_refuses_says_the_gateway_is_busy`: the budget is 262144 bytes. Alice and
   Bob each call one held server whose answers are 262000 bytes, and both answers are held. An
   admin's refresh of that server's tool list answers `503`. The server page shows
   `The gateway is busy. Try again in a moment.` in its error notice. After the release, each of
   the two calls answers `200` or `503`.

6. `a_client_that_does_not_read_keeps_its_share_until_the_connection_is_closed`: the budget is
   33554432 bytes, so one user's share is 8388608 bytes, and the write stall is 2 seconds. The
   upstream answers 4000000 bytes to every call. Two raw sockets with a 4 KiB receive buffer send
   a stateless `echo` call each, read only the status line, and do not read on. Both answer `200`.
   One second later Alice's third call answers `503` in the form of item 1. Bob's call answers
   `200` with the whole text. After the stall time, Alice's call answers `200` with the whole
   text within 10 seconds, and the busy answers in between are in the form of item 1.
7. `a_tools_list_of_two_thirds_of_the_limit_answers_200_on_mcp`: both limits are 262144 bytes. A
   server lists 750 tools, whose list is checked to be between 60 and 70 percent of the limit.
   The combined endpoint lists the same 750 tools as `200`, not `502`.
8. `a_250000_byte_stream_answer_completes_on_the_slug_and_on_mcp`: both limits are 262144 bytes.
   A `tools/call` on the server path and on the combined endpoint each answer one stream event of
   250000 bytes. Each answers `200` with the whole text.
9. `a_call_whose_answer_does_not_fit_is_refused_after_it_was_sent_on_the_server_path`: both limits
   are 262144 bytes. Alice's held `echo` call takes the budget, and Bob's `echo` call on a second
   server, whose answer is 200000 bytes, is refused after it was sent. Bob's refusal is in the
   form of item 1. Alice's held call ends as `200` or `503`.
10. `a_call_whose_answer_does_not_fit_is_refused_after_it_was_sent_on_mcp`: the same on the
    combined endpoint, with the names `held-answers__echo` and `plain-answers__echo`.
11. `a_tools_list_that_does_not_fit_keeps_retry_after_and_the_busy_text`: while Alice's held
    call takes the budget, Bob's tools list of a second server, about 216 KB, is refused. The
    refusal is `503`, `Retry-After: 1`, `Cache-Control: no-store`, JSON-RPC `-32000`, message
    `The gateway is busy` and a null id.
12. `a_combined_list_whose_only_server_is_left_out_for_the_budget_answers_busy`: the same with
    Bob's combined list, whose only server is left out for the budget. The answer is the busy
    form of item 11.

13. `a_call_refused_before_it_was_sent_keeps_the_busy_form_on_the_server_path`: the limits of item 11.
    Alice's held `echo` call takes the budget. Bob's `echo` call on the plain server, whose tool
    list is not stored yet, finds the budget refuses the list that would store it. The call is
    refused in the form of item 11 and the upstream receives no call.
14. `a_call_refused_before_it_was_sent_keeps_the_busy_form_on_mcp`: the same on the combined
    endpoint, with the name `plain-answers__echo`, whose definition is not stored. The answer is
    the form of item 11.

Items 6 to 14 set their own limits, as their texts say.

The unit tests of statement 75 are `a_held_body_yields_frames_of_at_most_64_kib_and_keeps_its_guard_until_the_last_frame`
in `src/web/limit.rs`, and `a_write_that_makes_no_progress_errors_with_timed_out_after_the_stall_time`,
`a_write_that_progresses_within_the_stall_time_never_errors` and `an_idle_read_is_not_closed_by_the_stall_time`
in `src/web/stall.rs`. The stall tests run on real time with a stall of 300 ms or 5 seconds, because the
crate builds tokio without `test-util`.

## s75_process_memory.rs (statement 75)

This file runs the real gateway binary with a config file of its own, not the test world. The
owner signs in through the setup code that the binary prints. A fake upstream answers the `echo`
calls. Each burst sends 64 calls at once, and each answer is 4000000 bytes. The upstream sends
half of each answer, waits until all 64 have begun and two seconds have passed, then sends the
rest. The first test's budget is 33554432 bytes (32 MiB) for `limits.answer_memory_bytes`, and
`limits.tools_list_bytes` is set to the same value. The second test's budget is 8589934592 bytes
(8 GiB). The ceiling is 262144 KiB (256 MiB) of growth in the peak, and the upstream has 60
seconds to begin every answer.

The file reads the peak resident memory of the gateway process, `VmHWM` in `/proc/<pid>/status`.
The process is found by its config path on its command line. The file reads `/proc`, so it is
Linux only.

1. `the_gateway_process_stays_under_its_ceiling_in_a_burst_of_large_answers`: with the 32 MiB
   budget, every call answers `200` or `503`, at least one answers `200`, at least one answers
   `503`, and the peak resident memory grows by less than 262144 KiB during the burst. The counts
   are written to standard error.
2. `the_same_burst_passes_the_ceiling_when_no_budget_is_reached`: with the 8 GiB budget, all 64
   calls answer `200`, and the peak grows by more than 262144 KiB. So the first test would catch a
   missing budget.
3. `stalled_readers_do_not_grow_the_process_past_the_ceiling`: the default limits, with a write
   stall of 30 seconds. 200 raw sockets with a 4 KiB receive buffer each send one `echo` call for
   a 4000000 byte answer, read only its status line, and do not read on. Every client gets a
   status line, at least one answers `503`, and after 5 seconds the peak resident memory has
   grown by less than 262144 KiB. The counts are written to standard error.

## s76_body_deadline.rs (statement 76)

Each test builds its own world with `limits.body_read_seconds` set to 1. A raw socket sends the
head of a POST that promises 100 body bytes, sends the first few bytes of the body, and stops.
The gateway must answer within 5 seconds and close the connection. The answer must be `408` with
`Connection: close` and an empty body. Then a complete request on the same route is sent, and it
keeps its usual answer.

1. `a_stalled_token_request_is_answered_408_and_closed`: a form POST to `/oauth/token` stalls
   after `grant`. A complete token request with `client_id=x` and no grant then answers `400`.
2. `a_stalled_registration_is_answered_408_and_closed`: a JSON POST to `/oauth/register` stalls
   after `{"cli`. A complete registration with a client name and one redirect address then
   answers `201`.
3. `a_stalled_logout_is_answered_408_and_closed`: a form POST to `/logout`, with the gateway's
   own origin, stalls after `csrf=`. A complete logout with a wrong anti-forgery value then
   answers `403`.
4. `a_stalled_mcp_post_is_answered_408_forwards_nothing_and_writes_no_activity`: a JSON POST to
   `/demo` with bob's bearer token stalls after `{"jso`. The activity log gains no row, and the
   upstream gets no `echo` call. Then a complete stateless `echo` call answers `200`, the upstream
   gets one `echo` call, and the activity log gains its row.

## s77_account_abuse.rs (statement 77)

Each test builds its own world. The first test raises `limits.credentials_burst` to 100, so the
per-address limit of sign-in does not answer first. Tests that need a later time move the harness
clock. One test restarts the gateway to run the housekeeping sweep.

1. `unknown_address_rows_stop_at_twenty_an_hour`: 25 sign-ins for 25 made-up addresses each
   answer `401`. Then exactly 20 `login_failed` rows exist, and none names an account. The first
   nineteen details are `unknown address`, and the twentieth ends with the sentence `Further failed
   sign-ins for unknown addresses are not recorded for up to an hour.`. A wrong
   password for the owner answers `401` and adds one row, so there are 21 rows, and exactly one
   names the owner. The clock moves 3601 seconds. A new unknown address answers `401`, and the
   count is 22.
2. `a_failed_sign_in_for_an_existing_account_writes_one_row_naming_it`: a wrong password for the
   owner answers `401`, and the activity log holds exactly one `login_failed` row, naming the
   owner.
3. `an_unknown_address_and_a_wrong_password_get_the_same_answer`: a sign-in for an unknown address
   and one for the owner with a wrong password both answer `401`. The two bodies are equal once
   the anti-forgery value and each typed address are replaced by placeholders.
4. `six_reset_requests_in_a_day_send_five_mails_and_a_day_later_one_more`: five anonymous
   `POST /forgot` requests for bob, 301 seconds apart, each send one reset mail. The sixth request,
   301 seconds later, answers the same status and body as the fifth. After one second no sixth mail
   has arrived, and the stored reset link is unchanged. The clock is then set to one day after the
   first mail. A request answers `200`, and a sixth mail reaches bob.
5. `the_daily_cap_survives_a_sweep_while_its_day_is_current`: a wrong password for the owner adds a
   `login_failures` row. Five reset requests for bob are sent as in item 4. The clock moves two
   hours, and the gateway restarts. The test waits until the `login_failures` table is empty, which
   shows the sweep ran. The `password_resets` table still holds one row. The link from the newest
   reset mail shows the `link-invalid` page. A sixth request answers `200`, and after one second
   there are still five reset mails.
6. `every_discovery_health_token_and_register_answer_carries_nosniff_once`: six anonymous requests
   with one server, `demo`, in place: `GET` of the authorization server metadata, `GET` of the
   protected resource metadata for `demo`, `POST /oauth/token` with an empty form,
   `POST /oauth/register` with `{}`, `GET /healthz`, and `POST /mcp` without a token. Each answer
   has exactly one `X-Content-Type-Options` header, with the value `nosniff`.
7. `the_reset_window_opens_at_the_first_mail`: the clock is set from the first mail. The second to
   fifth requests, at 23 hours 40 minutes, 23 hours 45 minutes 1 second, 23 hours 50 minutes 2
   seconds and 23 hours 55 minutes 3 seconds, each send a mail, so five mails exist. A sixth request
   at 23 hours 59 minutes 59 seconds sends nothing, since it comes within 5 minutes of the fifth. The
   requests at 24 hours 0 minutes 4 seconds and every 301 seconds after send mails six to ten, so ten
   mails arrive, nine of them in the last 40 minutes. The test passes on the window as it is coded.
8. `completing_a_reset_starts_the_count_again`: five reset requests 301 seconds apart send five
   mails, and a sixth sends nothing. The newest link completes the reset and answers `303`. A
   request 301 seconds later sends a sixth mail. The test passes on the window as it is coded.

## s78_bounded_writes.rs (statement 78)

Each test builds its own world.

1. `a_long_tool_name_is_stored_cut_and_clean`: a call to a tool name of 5000 characters that
   begins with a right-to-left override and a bell character answers `-32602`, Unknown tool. The
   stored `tool` of its refused row holds at most 128 characters, and neither the override nor the
   bell.
2. `refused_rows_stop_at_one_hundred_an_hour`: bob calls 105 missing tools on `/demo`, each
   answering `-32602`. Exactly 100 refused rows exist for bob, and the 100th row's detail is `not in
   the tool list` followed by the notice that later refusals are not recorded. Carol's refused call
   still writes its row, and an allowed `echo` call writes one `allow` row. The clock moves 3601
   seconds; bob's next refused call writes row 101 with the detail `not in the tool list` and no
   notice.
3. `refused_rows_stop_at_one_hundred_an_hour_on_the_combined_route`: the same 105 calls on `/mcp`
   write exactly 100 refused rows, and the 100th carries the notice.
4. `a_catalog_keeps_at_most_one_thousand_tools`: an upstream lists 1200 tools. The server page
   shows 1000, from `tool_0` to `tool_999`. Bob calls `tool_999` and gets `called: tool_999`;
   `tool_1000` answers `Unknown tool: tool_1000`.

## s79_mails.rs (statement 79)

Each test builds its own world. The mail catcher holds what the gateway sends.

1. `a_first_connection_to_one_server_is_announced_with_its_facts`: a server named `Internal
   documentation search` (slug `docs`) is granted to bob, and the client's metadata document names
   the client `Sneaky Name 4711`. Bob's first connection to `/docs` sends the new connection mail.
   Its text holds `It can use Internal documentation search.`, `The sign-in was sent to
   127.0.0.1:53535.`, a line that begins `Connected on` and ends ` UTC.`, and the closing sentence
   with the gateway's host. Its HTML holds the host in its last span, before ` Doorward decides`,
   and the server name. Neither part holds `Sneaky Name 4711`.
2. `a_first_connection_through_the_combined_endpoint_says_so`: the first connection to `/mcp` says
   `It can use every server assigned to you.` in the text part and `every server assigned to you`
   in the HTML part, and the server's name is in neither.
3. `the_reset_mail_says_what_to_do_when_it_was_not_asked_for`: a reset request for bob answers 200.
   The reset mail's text holds `If this was not you, ignore this mail. Your password stays the
   same.`, its HTML holds the same sentence with a non-breaking space before `same.`, and its text
   closes with the gateway's host.
4. `the_invitation_mail_closes_with_the_gateway_sentence`: the invitation to carol has the subject
   `You are invited to Doorward`; its text closes with the gateway's host, and its HTML holds the
   closing sentence with a non-breaking space before `call.`.

## s80_custom_headers.rs (statements 80, 81, 83 and 88)

Each test builds its own world. Declared headers are added through the admin panel, the pass-through
switch is saved the same way, and bob (assigned to the server) makes the calls.

1. `an_admin_declares_a_header_and_the_page_lists_it_with_its_flag` (statement 80): a required and an
   optional header are listed with `data-required` `yes` and `no`.
2. `a_ninth_header_is_refused_with_400` and `each_refused_name_is_refused_with_400` (statement 80):
   the ninth header and each refused name answer 400 with one error notice and create no row.
3. `the_same_name_in_another_case_is_refused_as_a_duplicate`, `a_name_of_64_characters_is_accepted`
   and `authorization_can_be_declared` (statement 80): case-insensitive uniqueness, the length limit,
   and `Authorization` as a valid name.
4. `a_declared_name_and_the_secret_header_name_cannot_be_the_same` (statement 80): a name equal to the
   secret header's name is refused on declaration, and a secret named like a declared header is refused
   on the settings form with 400.
5. `removing_a_header_removes_its_row`, `the_two_switches_are_saved_and_shown_checked` and
   `only_admins_declare_remove_and_switch_headers` (statement 80): removal, the switches, and the
   refusal of a plain user with 403.
6. `pass_through_reaches_the_upstream_for_session_and_stateless_clients`,
   `on_the_combined_endpoint_the_header_reaches_only_the_server_that_declares_it` and
   `a_value_of_4096_bytes_with_inner_space_and_tab_reaches_the_upstream_unchanged` (statement 81): a
   declared header reaches its server with the client's value, only on the server that declares it.
7. `with_pass_through_off_the_declared_header_does_not_reach_the_upstream`,
   `an_undeclared_header_does_not_reach_the_upstream_even_with_pass_through_on` and
   `a_declared_authorization_header_is_never_passed_through` (statement 81).
8. `a_declared_header_sent_twice_is_refused_before_the_upstream` and
   `bad_header_values_are_refused_before_the_upstream` (statement 81): an empty value, a value of 4097
   bytes, a non-ASCII value and a value holding byte 0x80 answer 400 and reach no upstream.
9. `a_missing_required_header_answers_403_on_the_server_path`,
   `a_missing_required_header_leaves_its_server_out_of_the_combined_list` and
   `a_header_that_is_not_required_and_is_missing_changes_nothing` (statement 83).
10. `a_server_without_a_secret_that_refuses_the_probe_is_not_reported_ok` (statement 88): a probe that
    the upstream refuses leaves the server `nosecret`, never `ok`.
11. `a_server_without_a_secret_that_declares_a_header_warns_on_its_page` (statement 88): the direct
    warning appears on the server without a secret that declares a header, and not on one with a secret.
12. `the_remove_link_opens_a_confirm_page_that_names_the_header_the_server_and_the_count`,
    `the_confirm_page_says_nobody_stored_a_credential_when_none_is_stored`,
    `the_confirm_page_counts_every_person_who_stored_a_credential` and
    `the_confirm_page_is_not_found_for_another_servers_header_or_an_unknown_one` (statement 80, the
    removal page): the title and the header name in its span, the sentence for none, one and two
    people, the danger "Remove header" and the secondary "Keep header", and 404 for a header that is
    not the server's.
13. `a_plain_user_cannot_open_the_confirm_page` and
    `the_remove_link_is_a_link_and_the_removal_answers_with_the_notice`: 403 for a plain user; the row's
    Remove is a link to the confirm page, and the removal redirects to the headers part with
    `done=header-removed` and shows `X-Trace-Id removed.`.
14. `adding_a_header_redirects_to_the_part_with_its_name_in_the_notice` and
    `saving_a_header_made_required_says_how_many_have_not_stored_it`: the notices name the header and
    count the assigned users without a stored credential.
15. `save_headers_changes_required_only_for_the_rows_it_lists` and
    `a_switch_post_without_listed_fields_changes_no_required_flag` (statement 80): a listed row takes
    its box, an unlisted row keeps its flag, and a post without `listed_` fields changes no flag.
16. `the_switches_form_is_absent_until_a_header_exists` and
    `at_eight_headers_the_add_form_gives_way_to_one_sentence`: with no header the switches form is not
    rendered; at eight headers the add form is replaced by the sentence.
17. `the_direct_warning_links_to_the_secret_header_field`: the warning's link goes to `#secret-name`.

## Round 5: tests added and rewritten for the design changes

Each entry names the change of the round 5 list it proves, and why an existing test changed.

New tests:

1. `admin::activity::tests` (unit, change 1): `an_address_in_a_detail_is_an_email_span`,
   `a_url_with_an_at_in_its_path_is_not_an_email`, `two_addresses_are_two_email_spans_with_a_space_between`,
   `markup_characters_are_escaped_and_the_text_is_unchanged`, `a_detail_with_no_space_is_one_word`
   `markup_inside_an_address_shaped_word_is_escaped` and `a_word_is_an_address_only_with_text_on_both_sides_of_one_at`. Each asserts the exact
   HTML and that the text read back equals the stored detail.
2. `admin::tests::an_address_in_an_activity_detail_is_an_email_span` (change 1): an address
   inside a detail on `/admin/activity` is a `span.email` inside `span.detail`.
3. `web::page::tests::a_plain_users_account_nav_is_one_link_with_no_popover_and_no_menu`
   (change 2): the exact header of a plain user's account page.
4. `admin::tests::an_invitation_role_cell_holds_the_role_after_a_unit_span` (change 4): the
   role cell is `as user` and `as admin`, with `span.unit` holding `as `.
5. `admin::tests::a_stored_invitation_without_mail_links_the_owner_to_the_mail_page` and
   `admin::tests::a_stored_invitation_without_mail_gives_an_admin_no_mail_link` (change 5):
   the owner sees `a[data-link="mail"]`; a non-owner admin sees the sentence alone.
6. `accounts::reset::tests::the_forgot_page_links_back_to_sign_in_after_its_form` (change 6):
   `p.back` with the link to `/login` follows the form.
7. `oauth::consent::tests::a_registered_client_line_is_its_sentence_in_a_warning` and
   `oauth::consent::tests::the_other_client_lines_keep_their_sentences` (change 7): the exact
   registered sentence, and the document and loopback sentences unchanged.
8. `web::page::tests::the_refusal_page_is_a_403_with_its_title_heading_and_lede` (change 8):
   status 403, title, heading, lede and `main[data-page="forbidden"]`.
9. `admin::tests::assignment_logs_say_one_or_many_in_the_same_words` (change 9): the log reads
   `set to 0 users`, `set to 1 user`, `set to 3 users`, and for a user `set to 0 servers`,
   `set to 1 server`, `set to 2 servers`.

Further new tests:

- `admin::tests::each_refused_mail_field_is_the_one_marked_and_named`: for each provider and
  each field a refusal can name (the control character of each, the port, the TLS setting),
  the one marked input is that field, its `-error` element holds the sentence, the notice names
  the outcome of its provider with one link to the marked field, and the sentence appears once
  in the form, under the field. `admin::tests::a_refusal_about_another_providers_field_marks_nothing`:
  a control character in another provider's field keeps the general sentence and marks nothing.
- `web::page::tests::the_not_found_page_links_to_the_start_page_after_its_lede` and
  `the_bare_not_found_has_an_empty_body`; `accounts::reset::tests::the_check_email_page_links_back_to_sign_in_after_its_sentence`;
  `oauth::connected::tests::the_disconnected_page_links_to_the_account_after_its_sentence`;
  `oauth::consent::tests::the_no_access_page_links_to_the_account_after_its_sentence`: one
  `main p.back a` with its exact text and href on each message page.
- `admin::invitations::tests` (`mail_warning`): a warning other than "not set up" has no mail
  link; the owner gets the link only for "not set up".
- `tests/s62_shell.rs` `the_account_page_holds_its_own_navigation`: bob's account page holds
  exactly one `nav` element in total.

Rewritten tests (the old markup or sentence they pinned):

- `tests/s26_panel.rs` `a_plain_users_account_page_holds_one_link_and_public_pages_hold_none`
  (renamed from `a_plain_user_and_public_pages_get_no_navigation`): the plain user's
  account page now holds its one header navigation (change 2); the other pages keep "no
  navigation".
- `tests/s62_shell.rs` `the_account_page_holds_its_own_navigation`: bob's account page holds
  one `header > nav[data-nav="account"]` with no popover and no id, one link, one mark, and no
  Menu button (change 2). The admin case is unchanged. `the_current_section_is_marked_once`
  already passes for bob's page (it is one of the covered pages) and is unchanged.
- `tests/s52_interface.rs` `deleting_a_server_or_an_account_takes_two_steps` (its helper
  `assert_two_step_delete`): the `summary` itself must say "cannot be undone" (change 3). The
  test read the whole disclosure before, where the body's own sentence also matched.
- `tests/s33_consent.rs` `a_registered_client_is_shown_as_a_claim`: the registered sentence now
  reads "is asking to sign in as you" (change 7).
- `web::page::tests::each_message_page_is_a_heading_and_one_lede`: the refusal row carries the
  round 5 title and lede (change 8).

## Key layer of stored values (statements 84 and 85)

Unit tests, then the route and the proxy tests below.

1. `vault::tests` (statement 84): a wrap round trips with a token and with a password; a wrong
   token, password, salt, table, row, user, generation, server key or one flipped byte opens
   nothing; a string that is not a sealing token never wraps or opens; two wraps of one key
   differ; a value round trips and opens nothing for another user, server, header, generation,
   upstream address, key or flipped byte.
2. `crypto::tests::a_failed_sign_in_runs_one_argon2_and_a_successful_one_two` (statements 84 and
   85): a wrong password adds one Argon2 run, an unknown account one, a right password two, and
   `crypto::tests::the_vault_holder_key_differs_from_the_token_seal_key`.
3. `vault::tests_keys` (statement 85): first unlock makes the key, later unlocks open it; another
   salt or a damaged wrap gets no key and changes nothing; rekey moves values to the next
   generation or deletes them with one `values_dropped` row; `forget`; `clear_user_tokens`.
4. `accounts::tests_vault` (statement 85): sign-in, setup and invitation wrap the same key onto
   the new session; a damaged password wrap never fails the sign-in; a password change reseals
   the values, drops them with a `values_dropped` row when the old key does not open, and clears
   every old wrap; a reset deletes values and wraps and bumps the generation; `revoke_all`
   nulls token wraps; a sign-out takes the session wrap with its row.
5. `oauth::tests_token` (statement 85): `the_data_key_follows_consent_exchange_and_refresh_with_no_password_work`
   (code, pair and rotated pair open to the user's key, consumed wraps are NULL, a replay wraps
   nothing, no Argon2 run), `garbage_in_every_wrap_column_changes_no_outcome_and_leaves_no_wrap_on_new_rows`,
   `a_code_that_fails_pkce_keeps_its_wrap_and_a_wrong_verifier_issues_nothing`,
   `the_sweep_nulls_the_wrap_of_every_expired_or_used_row_and_keeps_live_ones` and
   `a_disconnect_and_a_revoke_all_leave_no_wrap_behind`.

## s84_stored_values.rs and s87_value_leaks.rs (statements 82 to 87)

- `saving_credentials_lands_on_the_part_with_the_server_named_in_the_notice`: the save redirects to
  `/account` with `done=credentials-saved` and `server=demo`, the part's fragment, and the account page
  shows `Credentials saved for demo.` without the stored value.

Each test builds its own world: bob is assigned to the demo server, the header `X-Trace-Id` is
declared and the store switch is on. The value is the canary `canary-7f3a9c51e2d44b06`.

1. Statement 82: `a_stored_value_reaches_the_upstream_on_session_stateless_and_combined_calls`,
   `a_value_stored_after_a_token_was_issued_is_used_by_its_next_call`,
   `the_client_header_wins_with_pass_through_on_and_is_ignored_with_it_off`,
   `two_servers_with_one_header_name_each_get_their_own_value`,
   `a_second_users_calls_never_carry_the_first_users_value`,
   `bad_values_are_refused_with_400_and_never_sent_back`,
   `an_unassigned_server_and_a_server_with_the_switch_off_answer_404_on_the_values_route` and
   `the_admin_server_page_shows_how_many_users_stored_a_value_and_never_the_value`; in
   `s87_value_leaks.rs` `a_stored_value_of_4096_bytes_reaches_the_upstream_whole` and
   `a_value_posted_with_its_remove_box_is_refused_and_changes_nothing`.
2. Statement 83: `a_missing_or_partial_set_of_required_values_reaches_no_upstream_and_names_the_account_page`
   (403 naming the account page, the server left out of `/mcp`, the consent page naming the server,
   `data-needs-values` on the account page) and
   `with_every_wrap_damaged_sign_in_consent_exchange_and_refresh_still_work_and_values_say_reconnect`.
3. Statement 84: `a_copy_of_the_database_log_and_key_holds_no_value_and_opens_only_through_the_real_token`,
   `a_wrap_or_value_moved_to_another_row_user_generation_server_header_or_address_does_not_open`,
   `swapping_two_users_sealed_rows_in_the_live_database_gives_neither_the_others_value`,
   `a_password_wrap_copied_before_a_change_does_not_open_values_stored_after_it` and
   `two_sign_ins_of_a_user_without_a_key_at_the_same_moment_leave_one_key_and_two_sessions`.
4. Statement 85: `no_copy_taken_afterwards_opens_a_redeemed_code_a_rotated_token_a_signed_out_session_or_a_disconnected_app`,
   `after_a_password_change_old_tokens_open_nothing_and_new_connections_get_the_values`,
   `after_a_reset_by_mail_the_values_are_gone_and_the_old_password_opens_nothing` (the reset page
   says so too), `after_disable_and_enable_old_tokens_carry_no_wrap_and_values_work_after_sign_in`,
   `parallel_refreshes_return_one_pair_and_a_replay_after_the_window_leaves_no_wrap` and
   `disconnecting_one_app_leaves_another_app_of_the_same_user_working_with_the_values`; the
   conditional reset mail line is `mail::templates::tests::the_reset_mail_names_the_deleted_credentials_only_when_asked`.
5. Statement 86: `changing_the_upstream_address_in_the_panel_deletes_every_users_values`,
   `editing_the_upstream_address_in_the_database_keeps_the_canary_from_the_new_upstream`,
   `removing_a_declared_header_deletes_its_stored_values`,
   `unassigning_a_user_deletes_that_users_values_for_the_server_and_nobody_elses` and
   `deleting_the_server_deletes_every_stored_value`.
6. Statement 87: `an_upstream_that_echoes_the_header_puts_the_canary_in_no_activity_row_or_admin_or_account_page`,
   `storing_replacing_and_removing_a_value_each_write_an_activity_row_without_the_value`,
   `the_lock_down_check_and_refresh_by_an_admin_with_no_value_carry_no_user_header_and_with_a_value_carry_it`,
   `an_upstream_redirect_is_not_followed_and_the_redirect_target_sees_no_request` and
   `after_a_replace_the_next_call_carries_the_new_value_and_an_old_session_is_refused_404`;
   in `s87_value_leaks.rs` `storing_a_value_and_a_failed_call_write_no_line_holding_the_value`
   (the real binary: its standard error holds no line with the value after a store, a refused
   store, a call and a failed call).
7. Units for the ends of streams and links (statement 87): `proxy::tests_stream`
   `a_change_of_the_users_stored_values_ends_an_open_stream` and
   `a_change_of_stored_values_does_not_end_another_users_stream`; `proxy::tests_links`
   `a_link_made_under_other_stored_values_is_not_reused`; `proxy::values::tests` (an opened value is
   marked sensitive, a secret that opens no wrap locks a held value, a value sealed for another
   address is named as unopened, a held optional value that does not open refuses the request unless
   the client supplies that header, no held value and no need means no key work).
8. Review fixes (S2 to S6, N1 to N8): in `s84_stored_values.rs`
   `a_combined_call_to_a_left_out_server_says_why_and_is_not_a_connection_failure` (isError tool result with
   the server path's text, a `credentials missing` or `reconnect needed` row, no `no connection` detail, the
   upstream not contacted), `a_locked_connection_whose_client_passes_the_header_itself_is_served`,
   `a_damaged_password_wrap_heals_at_the_next_sign_in_and_values_can_be_stored_again`,
   `a_password_change_with_a_damaged_password_wrap_but_a_good_session_wrap_keeps_the_values`,
   `the_first_store_ends_the_upstream_sessions_of_that_user_on_that_server`,
   `a_refresh_without_the_admins_openable_key_says_the_stored_credentials_were_not_sent`,
   `with_the_store_switch_off_no_value_is_attached_and_the_user_can_delete_what_was_stored` (the `forget=1`
   field) and `a_client_delete_while_the_values_are_locked_is_answered_and_the_session_is_forgotten`; in
   `s80_custom_headers.rs` `the_lockdown_note_of_a_server_without_a_secret_does_not_describe_a_passed_check`
   and `two_servers_declaring_one_header_with_pass_through_on_both_receive_a_clients_value_on_mcp`; units
   `crypto::tests::the_vault_key_derivation_has_a_known_answer`,
   `crypto::tests::the_hash_job_still_returns_a_hash_when_the_vault_derivation_fails` and
   `db::tests::a_schema_14_database_upgrades_and_keeps_its_users_sessions_and_tokens` (migration 17).

## s90_withheld.rs (statement 90)

Bob is assigned to the demo server with a required header and nothing stored, unless a test says otherwise.

1. `a_caller_with_a_missing_required_value_opens_a_connection_on_the_server_path`: initialize is 200 with a
   `dw-wait-` session id, instructions naming the account page, `no-store`, and the upstream sees nothing.
2. `the_tool_list_of_a_withheld_caller_is_the_stored_catalog_under_that_callers_rules`.
3. `a_tool_call_of_a_withheld_caller_is_a_tool_error_with_one_deny_row`: the row says `credentials missing`;
   a rule-denied tool and an unlisted tool are still unknown tools with their usual rows.
4. `a_locked_connection_gets_reconnect_this_app_the_same_way` (`reconnect needed`).
5. `a_value_that_cannot_be_opened_gets_the_store_again_text_the_same_way`.
6. `after_the_value_is_stored_the_placeholder_session_is_answered_404_and_a_new_one_carries_it`.
7. `with_pass_through_only_the_text_names_the_header`.
8. `the_stateless_generation_gets_the_same_answers`.
9. `get_is_405_and_delete_is_204_for_a_withheld_caller`.
10. `on_the_combined_endpoint_the_withheld_servers_tools_are_listed_and_a_call_returns_the_text`.
11. `no_answer_to_a_withheld_caller_is_a_401_or_a_403`.

Review additions in `s84_stored_values.rs`: `a_refresh_with_a_stored_value_that_does_not_open_says_the_stored_credentials_were_not_sent`,
`the_saved_notice_shows_only_when_the_query_carries_the_saved_marker` and
`forget_with_the_store_switch_on_does_not_redirect_with_the_saved_notice`. Units: `vault::tests_keys`
heal tests (including one wrapped session after a heal) and
`accounts::tests_vault::a_password_change_without_a_vault_part_clears_the_wrap_and_drops_the_values`.
