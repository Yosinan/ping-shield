# Contributing to ping-shield

Thanks for helping. Bug reports, new checks, new intel sources, docs fixes and platform support are
all welcome.

**Found a security vulnerability?** Don't open a public issue. Follow [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a bug:** open an issue using the *Bug report* template. Include the output of
  `ping-shield --status`. Remove your chat id first.
- **Suggest a check or a source:** open an issue using the *Feature request* template. Explain how
  attackers use that location, or why the source is worth following.
- **Send a pull request:** for anything bigger than a small fix, open an issue first, so we can agree on
  the approach before you spend time on it.

## Development setup

```bash
git clone https://github.com/<your-username>/ping-shield.git   # your fork
cd ping-shield
python3 -m venv .venv && source .venv/bin/activate
pip install -e .            # `ping-shield` / `pshield` now run your working copy
ping-shield --version
```

Use a **separate Telegram bot** for development (create one with @BotFather), and give your dev
checkout its **own config and state directory**. That way dev runs can't send alerts to your real
chat, or record your real changes as already alerted:

```bash
export XDG_CONFIG_HOME="$PWD/.dev-config"   # isolates config.json, state.json and the run lock
ping-shield --init                          # paste the dev bot's token
```

Don't run `--setup-service` from a dev checkout. Use `--run`, `--bot` or `--watch` in the
foreground instead.

## Project layout

| Module | Responsibility |
|---|---|
| `ping_shield/main.py` | CLI flags and routing |
| `ping_shield/config.py` | Config, paths, state store, run lock |
| `ping_shield/monitor.py` | What's watched (targets), snapshots, diffs, exactly-once alerting |
| `ping_shield/watch.py` | Real-time inotify watcher |
| `ping_shield/intel.py` | Feed fetching, keyword matching, news deduplication |
| `ping_shield/sources.py` | Source catalog and the Telegram channel parser |
| `ping_shield/notify.py` | Telegram API client and alert rendering |
| `ping_shield/bot.py` | Interactive bot: buttons and chat commands |
| `ping_shield/service.py` | systemd user units |
| `ping_shield/tester.py` | `--test` end-to-end self-test |

## Ground rules

These hold the project together. A PR that breaks one of them will be asked to change.

1. **No runtime dependencies.** Standard library only. A tool that guards your supply chain shouldn't
   widen its own.
2. **No root.** Everything runs as the user.
3. **Exactly-once alerts.** Record something as seen only after Telegram confirms delivery. Never
   send the same finding twice.
4. **Nothing sensitive leaves the machine.** Anything sent to Telegram goes through `redact()`, so
   secrets in diffs are masked.
5. **Python 3.9+.** Don't use syntax or stdlib APIs that are newer than 3.9.
6. **Match the surrounding code.** Same naming, docstring style and comment density.

## Before you open a pull request

```bash
python3 -m pyflakes ping_shield            # pip install pyflakes
ping-shield --run -v                       # a real scan against your dev bot
ping-shield --test                         # end-to-end self-test against your dev bot
```

If you change the alert format or the bot, check the result on a real phone as well.

Then:

1. Add a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md), in the right section
   (Added / Changed / Fixed / Removed).
2. **Don't change the version number.** The maintainer sets it at release time
   (see [RELEASING.md](RELEASING.md)).
3. Open the PR against `main` and fill in the template.

## Review and merging

`main` is protected. Every change lands through a pull request and needs the maintainer's approval
(see `.github/CODEOWNERS`). If you push new commits after an approval, the PR needs a fresh one.
Workflow runs for first-time and outside contributors start only after the maintainer approves them.

Be kind, and assume good intent. That applies to everyone, in issues, pull requests and reviews.
