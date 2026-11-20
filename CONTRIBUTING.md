# Contributing

Doorward is an authentication gateway, so a change is judged first on what it lets through.
Small, tested changes are welcome.

## Before you start

- A security problem is not a pull request: follow [SECURITY.md](SECURITY.md).
- For a new feature, open an issue first and say what it is for. The scope of version 1 is
  the list of statements in `CLAUDE.md`.

## Build and check

You need Linux, Rust 1.89 or newer, `cargo-audit` and `cargo-deny`.

```sh
./check.sh
```

`check.sh` runs the formatter, clippy with warnings as errors, every test, the advisory and
licence checks, and a scan of the tracked files for home directory paths, email addresses
outside the example domains and IPv4 addresses outside the loopback and documentation
ranges. The scan does not find everything: host names and secrets are yours to keep out.
It must pass before a change is proposed. There is no hosted CI: the same script is the
gate everywhere.

The scripts under `scripts/prove*` drive real clients and containers against a built
gateway. They need Docker and take longer; run the ones that cover what you changed.

## How a change is made

1. Describe the behaviour in `docs/TESTS.md`, in the section of the test file it belongs to.
2. Write the test and watch it fail. A test file that is expected to fail is listed in
   `tests/expected-red.txt`, so the red state can be committed.
3. Write the code, remove the file from `tests/expected-red.txt`, and run `./check.sh`.
4. Update `docs/INTERFACE.md` when a page, an endpoint, a setting or a log line changes.

For anything that guards access (sign-in, sessions, OAuth, the bearer check, rules, the
proxy), the test in step 2 is an abuse test: it shows the request that must be refused.

## Rules

- No host names, IP addresses, local paths, personal names, email addresses or secrets in
  code, docs, tests or commit messages. Use `example.com` and `127.0.0.1`.
- Authentication code stays in its own modules.
- A failure inside the gateway writes one line through `report::failure`, with no token,
  code, cookie, password or address in it.
- Comments are one or two factual lines.
- No new dependency without a reason in the pull request.

## Licence

Contributions are accepted under the project's licence, MIT OR Apache-2.0.
