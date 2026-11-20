# Security policy

Doorward is an authentication gateway, so a flaw in it can expose the servers behind it.
Reports are welcome.

## Supported versions

Doorward is pre-release. Fixes go into the newest version only.

## Report a vulnerability

Please report it privately, not in a public issue or discussion.

Use GitHub's private vulnerability reporting: open this repository's security tab and
choose "Report a vulnerability". Only the maintainers see the report.

A useful report says:

- the version or commit you ran, and how the gateway was deployed (binary or container,
  which proxy in front);
- the steps to reproduce it, with the requests you sent;
- what an attacker gains, and what they need to start with (no account, a user account, an
  admin account);
- your settings, with every secret removed.

Test against an instance you run yourself. Do not test against someone else's gateway or
the servers behind it.

## What counts

Anything that lets a person do what the gateway is there to prevent, for example:

- reaching a server or calling a tool without a valid sign-in, or one the access rules
  deny;
- obtaining another person's session, token, authorization code, invitation or reset link;
- getting a token issued to a client the person did not approve, or to a redirect address
  that was not registered;
- reading a stored secret (a mail password, an upstream secret header, the encryption key)
  through the gateway;
- acting as an admin or the owner without being one;
- making the gateway send requests to an address no admin configured, such as one on the
  operator's private network.

## What does not

- Flaws in an upstream MCP server itself. Report those to that server's maintainers.
- An upstream server that answers without the gateway because it was never locked down.
  The README explains the lock-down and the check for it.
- A gateway run without HTTPS in front of it, against the README.
- Findings from an automated scanner with no demonstrated impact.
