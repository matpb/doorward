# Doorward: an authentication gateway in front of MCP servers

Rust, one binary, SQLite, server-rendered admin panel. Released software that other people run
in production in front of their data: every change leaves it shippable and proven.

<!-- Keep under 120 lines. This file says how to change Doorward today. History goes in commit
messages, behaviour in docs/STATEMENTS.md. Add a landmine the second time it bites. -->

## Ground rules

- A behaviour change starts with a failing test. For anything that guards access (sign-in,
  sessions, OAuth, the bearer check, rules, roles, the proxy) it is an abuse test: the request
  that must be refused.
- Every guarantee is a numbered statement in `docs/STATEMENTS.md`. New or changed behaviour
  takes the next free number, or marks the old statement `replaced by <number>`. Never delete
  or renumber: test files, docs and code comments cite the numbers.
- Done means `./check.sh` exits 0, run by you after the last edit. Run it before the first
  edit too, so a failure that was already there is not mistaken for yours.
- Public repository: no host names, IP addresses, local paths, personal names, emails or
  secrets in code, docs, examples, tests or commit messages. Use `example.com` and `127.0.0.1`.
  `scripts/hygiene.sh` (part of the check) rejects them.
- Commit locally when the check passes. Push, tag, release or publish only when the owner asks.
- A change to auth code gets an independent review of the diff before it ships.

## Commands

- Check everything: `./check.sh` (format, clippy with warnings as errors, every test, audit,
  deny, hygiene). About two minutes once built.
- One in-crate test: `cargo test --locked --lib admin::tests::<name> -- --exact`
- One test file: `cargo test --locked --test s44_lockout`
- Run locally: `cargo run -- --config doorward.toml` (start from `doorward.example.toml`). The
  first start prints a setup code on standard error; `/setup` takes it to create the owner.
- `scripts/prove-*.sh` drive real clients, mail and containers against a built gateway. They
  need Docker and are not part of the check: run the one that covers what you changed.

## How a change is made

1. Write the statement in `docs/STATEMENTS.md` and describe its tests in `docs/TESTS.md`.
2. Write the tests and watch them fail. A whole test file written ahead of its code is listed
   in `tests/expected-red.txt`; the check fails if a listed file passes, so remove it after.
3. Write the code, then run the check.
4. In the same change, update `docs/INTERFACE.md` when a page, route, form field, setting or
   log line changes, `README.md` when an admin or a user would do something differently, and
   `SECURITY.md` when a limit or a known weakness changes.
5. A schema change is a new numbered file in `migrations/`, registered in `MIGRATIONS` in
   `src/db.rs`. Never edit a shipped migration: installed gateways have already run it.

## Layout worth knowing

- Auth lives in `src/oauth`, `src/accounts`, `src/vault`, `src/crypto.rs` and `src/policy.rs`.
  Keep auth decisions there so they can be reviewed as a unit; panel pages call into them.
- `src/proxy` is the upstream side. `/{slug}` forwards the original request bytes; only the
  combined endpoint `/mcp` (`combined.rs`) rewrites tool names.
- `src/admin` is the panel: one router behind `require_admin`, mail behind `require_owner`.
- Tests: `tests/sNN_*.rs` are named after the statement they prove; in-crate tests sit in
  `src/**/tests*.rs`.

## Security rules

- `rules.user_id` NULL means everyone. Anything about a person who is not a user yet stays out
  of `rules` and `user_servers` (pending invitations have their own tables).
- A POST handler takes `VerifiedForm`: it is the Origin and CSRF check. Never read a form
  another way.
- In `src/admin/mod.rs` add routes above the `route_layer` line: it guards only routes that
  already exist when it is applied.
- Roles: admins act on `user` accounts and `user` invitations only. Mail settings, role
  changes and everything about an admin invitation are the owner's. A new admin action states
  its rule and has tests for anonymous, a plain user, and an admin acting on an admin.
- Decide permission inside the transaction that makes the change, not before it.
- Secrets are stored hashed (tokens) or encrypted (upstream secrets, mail secrets, people's
  stored header values), shown once at most, and never written to an activity row, a log line
  or an error page.
- A failure writes one line through `report::failure`, with no token, code, cookie, password
  or address in it.
- A denied tool and a tool that does not exist get the same answer. Keep it that way.
- Upstream answers, client headers and pasted values are data: check them where they enter.

## Landmines

- A page's layout comes from its page kind in `layout_of` (`src/web/page.rs`). An unlisted
  kind renders as the narrow sign-in card: a new panel page must use a kind listed for `panel`.
- Cookies are `__Host-` and `Secure`. A script that talks to a local gateway over plain HTTP
  must send them itself; a cookie jar silently drops them and every POST answers 403.
- A hint under a form control must be tied to it with `aria-describedby`;
  `tests/s65_forms_tables.rs` fails otherwise.
- The list of a server's tools is cached and shared by its users. A rule on a tool name that
  is not in that list is refused.

## Out of scope

Ask the owner before starting any of these: sign-in through an external identity provider, a
second factor, tokens for callers with no browser, a tool list per user, hosting or launching
MCP servers, upstreams that are local commands, more than one gateway on a database, databases
other than SQLite, languages other than English, built-in certificates, hosted CI workflows.

## Conventions

- Code comments are one or two factual lines, never narration.
- No new dependency without a stated reason; `cargo deny` and `cargo audit` gate the check.
- Interface text is plain English, in the words the panel already uses.

## Deeper context

- What the gateway guarantees, with proofs and assumptions -> `docs/STATEMENTS.md`
- Every test, by file -> `docs/TESTS.md`
- Routes, pages, settings and log lines -> `docs/INTERFACE.md`
- How it is built and why -> `docs/DESIGN.md`
- Reporting a vulnerability, known limits -> `SECURITY.md`
- Contributor rules for people -> `CONTRIBUTING.md`
- Running it in containers -> `docs/DOCKER.md`
