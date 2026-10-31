# Security policy

ping-shield is a security tool, so vulnerabilities in it matter twice over. Thank you for reporting
them responsibly.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately instead:

- **Preferred:** open the repository's **Security** tab and click **Report a vulnerability**
  (GitHub private vulnerability reporting).
- **Alternatively,** email **yoszed22@gmail.com** with the subject `ping-shield security`.

Please include:

- the affected version (`ping-shield --version`) and your distribution;
- what an attacker can achieve and under which conditions;
- steps to reproduce, or a proof of concept.

## What to expect

- An acknowledgement within **3 days**.
- An initial assessment within **7 days**.
- A fix released as a patch version, with credit in the changelog unless you'd prefer not to be named.

Please give us a reasonable amount of time to release a fix before you disclose the issue publicly.

## Supported versions

Only the latest release on PyPI gets security fixes. Upgrade with `pipx upgrade ping-shield`.

## In scope

For example:

- a way to make ping-shield miss, suppress or fake an alert;
- a secret leaking to Telegram despite redaction;
- the bot accepting commands from a chat other than the configured one;
- code execution through a feed, Telegram channel page or extension manifest.

Problems that require an attacker who already has full control of your user account are generally
out of scope. At that point they can also stop ping-shield itself. Treat a sudden stop in alerts as a
signal too.
