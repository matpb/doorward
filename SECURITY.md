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
- What the admin role allows by design, such as setting a server's address to one on the
  operator's own network. Admins are trusted with that reach.
- A secret header read on the network between the gateway and a server that an admin
  chose to reach over plain `http`.
- Findings from an automated scanner with no demonstrated impact.

## Known limits

These are the limits known at this release.

- Anyone who knows a person's email address can stop that account from signing in. Wrong
  passwords sent from any addresses count against the account. By default, 50 of them within
  15 minutes block the account for every address, the right password included. Existing
  sessions and connected clients keep working. `doorward unlock` with the email address, or a
  password reset by email, lifts the block.
- Anyone who knows an account's address can ask for five reset mails and so stop further reset
  mails for that account for up to a day. Each reset mail replaces the link sent before it, so
  only the newest link keeps working until it expires.
- The tables that hold sign-ins in progress and unused client registrations are bounded. When
  one fills, its oldest entries are dropped. A flood of requests from many addresses can
  therefore cancel sign-ins in progress and push out clients that have not finished a sign-in.
  A client that has finished one is kept.
- People who reach the gateway through one shared address share its rate limits and its
  sign-in block. A client service that reaches the gateway from addresses it shares between its
  users shares them among those users, so junk requests sent through that service count against
  everyone who uses it. Anyone who sends junk requests or wrong passwords from that address can
  lock them all out.
- Approving a sign-in that someone else started connects your account to their app. The
  consent page says so. The gateway sends the code only to a loopback address or to an
  address on the allowed list.
- The name of an app that registered itself is its own claim. Doorward does not verify it.
  The consent page says so.
- Sign-in uses a password only. There is no second factor.
- The gateway does not limit open connections, and it has no header-read timeout of its own.
  Most of its rate limits count per address, so a flood from many addresses can pass each
  of them. Keep a proxy in front of it to limit connections and flood traffic. Each open
  connection can also hold about 0.5 MiB of an answer already handed to it for sending, outside
  the answer memory budget and outside the limit on open requests.
- A signed-in user who reads answers very slowly keeps them in the memory count for as long as
  each connection makes some progress. One user can fill only their own share; four such users
  can use up the whole budget, and others then get `503` on answers until those connections end.

For limits on what the gateway enforces between users and servers, see the README section
[What the gateway does not do](README.md#what-the-gateway-does-not-do).

## Stored credentials

A person can store values for a server's custom headers. The gateway seals them under keys
that only that person's password, session or token opens. The README section
[What the encryption covers](README.md#what-the-encryption-covers) has the details.

Covered: a copy of the database, its write-ahead log and the key file together open no stored
credential without that person's password, or a live session or token of theirs. An admin
cannot read them.

Not covered:

- Code running inside the live gateway sees credentials as calls pass through it.
- A password guessed offline from a stolen database. Argon2id slows each guess, and a long
  random password stops it.
- A stolen live token or session, together with the database.
- An admin who points a server at another address and waits for people to store their values
  again. Changing the address deletes what was stored, and the next values go to the new
  address.
- An upstream that echoes a credential back in its answer.
- The refresh replay window. Inside it (`lifetimes.refresh_replay_seconds`, 30 seconds by
  default) a rotated refresh token together with a copy of the database still opens that
  person's key.
- Values held in memory. The gateway clears them on a best effort basis, and a value lives in
  memory for the length of a request.

Sharing limits. On the combined endpoint a header a client passes goes to every server that
declares that name and passes headers through. One cached tool list for each server is shared
by its users, so a server whose list depends on the caller's credentials shows the list of
whoever fetched it last. Turning "store credentials" off for a server keeps what people
stored until they delete it on their account page or the server changes.

After a suspected theft, rotate the upstream credential at the upstream server. Keep the key
file out of backups of the data directory.
