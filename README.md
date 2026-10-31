# ping-shield

[![PyPI](https://img.shields.io/pypi/v/ping-shield)](https://pypi.org/project/ping-shield/)
[![Python](https://img.shields.io/pypi/pyversions/ping-shield)](https://pypi.org/project/ping-shield/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/Yosinan/ping-shield/blob/main/LICENSE)

**A real-time tripwire for Linux workstations.** ping-shield watches the places attackers use to keep
access to your machine: SSH keys, crontabs, systemd user services, autostart entries, shell start-up
files and VS Code / Cursor extensions. When one of them changes, your phone gets a Telegram alert
within seconds, with the exact diff. It also follows security news and official advisories (RSS feeds
and public Telegram channels) and alerts you only about serious threats to software actually
installed on your machine. Every finding is reported **exactly once**, and you can act on it with
buttons in Telegram.

- **Zero runtime dependencies.** It uses only the Python standard library, so a supply-chain security
  tool doesn't widen its own supply chain.
- **Real-time.** Changes to SSH keys, auto-start entries and extensions are reported about 2 seconds
  after they happen, with a full scan every 15 minutes as a safety net.
- **No root required.** Everything runs as your user, configured under `~/.config/ping-shield/`.
- **Works on any systemd distribution:** Fedora, Ubuntu, Debian, Arch, openSUSE and others. Python 3.9+.

```text
🚨 SSH Trust Change
~/.ssh/authorized_keys

🖥 Host: laptop
🕒 Detected: 31 Oct 2026, 14:05 EAT
📊 Changes: 🟢 1 added

--- a/~/.ssh/authorized_keys
+++ b/~/.ssh/authorized_keys
@@ -1 +1,2 @@
 ssh-ed25519 AAAAC3Nza…Original user@laptop
+ssh-rsa AAAAB3Nza…EVIL attacker@evil

⚠️ Not you? Investigate immediately: this file controls who can log in to your account over SSH.

#ssh #laptop · 🛡 ping-shield
```

```text
🔴 Critical Threat

Official AI Extension on Cursor Marketplace Trojanized with Persistent SSH Backdoor
▌ Researchers found a trojanized build of a popular extension…   (tap to expand)

🎯 Affects you: Cursor · SSH
🏷 Signals: backdoor · CVSS 9.6
🔖 CVE: CVE-2026-40123
🗞 Source: The Hacker News
📅 Published: 31 Oct 2026, 13:42 EAT

#threat_intel #cursor · 🛡 ping-shield
[ 📖 Read full article ]
[ 🔎 CVE-2026-40123 on NVD ]
```

Messages use Telegram HTML: diffs appear in syntax-highlighted code blocks, article summaries appear
in collapsible quotes, and links are inline buttons. Hashtags let you filter alerts by category or host.

---

## Quick start

```bash
pipx install ping-shield          # or: python3 -m pip install --user ping-shield

ping-shield --init                # paste your Telegram bot token + chat id
ping-shield --test                # end-to-end self-test: two alerts arrive on your phone
ping-shield --setup-service       # scan every 15 minutes + start the interactive bot
ping-shield --add-source t.me/thehackernews   # optional: more sources (see below)
```

To create a Telegram bot, message [@BotFather](https://t.me/BotFather), send `/newbot`, and copy the
token. Then open a chat with your new bot and press **Start**. `--init` can find your chat id
automatically if you leave that prompt blank.

## Commands

| Command | What it does |
|---|---|
| `ping-shield` / `--run` | Run one scan now (this is what the timer runs). `--only monitor` or `--only intel` limits the scan to one engine. |
| `--init` | Interactive setup. The token is entered hidden, checked with Telegram, and saved with mode `0600`. |
| `--test [-y]` | Automated simulation of the full alerting pipeline (see [Self-test](#self-test)). |
| `--setup-service` | Generates `~/.config/systemd/user/ping-shield.{service,timer}` and `ping-shield-bot.service`, then enables and starts them. Re-run it after upgrading. |
| `--remove-service` | Stops and deletes the units. |
| `--sources` | Lists your subscribed sources and the catalog of official sources you can add. |
| `--add-source SOURCE…` | Subscribes to an RSS/Atom URL, a public Telegram channel (`t.me/name` or `@name`) or a catalog id. |
| `--remove-source SOURCE…` | Unsubscribes by list number, catalog id, channel or URL. |
| `--bot` | Runs the interactive Telegram bot and real-time watcher in the foreground. The systemd service normally does this for you. |
| `--watch` | Runs only the real-time file watcher in the foreground (for systems without the bot service). |
| `--status` | Shows the config, which targets have a baseline, the detected keywords and the timer state. |
| `--rebaseline` | Accepts the current state of all monitored files as trusted, without sending alerts. |
| `-v` / `-vv` | More detailed logging (written to stderr, which goes to the journal under systemd). |

Logs: `journalctl --user -u ping-shield.service -u ping-shield-bot.service -f`

## What is monitored

| Target id | Location | Why it matters |
|---|---|---|
| `ssh.authorized_keys`, `ssh.authorized_keys2` | `~/.ssh/` | A key added here gives someone a login to your machine. ping-shield also flags group- or world-writable files and files owned by another user. |
| `ssh.rc`, `ssh.environment` | `~/.ssh/` | Code that runs on every SSH login. |
| `cron.user` | `crontab -l` | The classic persistence mechanism. |
| `systemd.user` | `~/.config/systemd/user/` | User services and timers that survive reboots. |
| `autostart` | `~/.config/autostart/` | Programs launched when your desktop session starts. |
| `environment.d` | `~/.config/environment.d/` | A place to inject `LD_PRELOAD` or a malicious `PATH`. |
| `shell.*` | `~/.bashrc`, `~/.bashrc.d/`, `~/.profile`, `~/.zshrc`, `config.fish`, … | Code that runs in every new shell. |
| `ext.vscode`, `ext.cursor`, `ext.vscode-oss`, `ext.windsurf` | `~/.<ide>/extensions/` | Reports installs, removals and updates. It also hashes each extension's `package.json` and entry-point script, so **code modified in place without a version change** is reported as possible tampering. |

**Diffs are redacted before they are sent.** Values that look like credentials are replaced with
`«redacted»` before anything leaves the machine. This covers `export API_KEY=…`, `password: …`,
`https://user:pass@host`, and GitHub, GitLab, OpenAI, Slack, AWS, Google and Telegram tokens.

## Threat intelligence

The default sources are The Hacker News, BleepingComputer and CISA advisories. An item triggers an
alert only if it matches **both**:

1. a **severity** term, such as `actively exploited`, `zero-day`, `backdoor`, `supply chain`,
   `remote code execution`, `malicious package`, or a CVSS score of 9.0 or higher; **and**
2. an **environment** keyword describing *this* machine. These are detected automatically from
   `/etc/os-release` and from the tools on your `PATH`: your distro, OpenSSH, sudo, systemd, Python,
   PyPI, npm, Docker, Podman, VS Code, Cursor, xz/liblzma, and so on. Run `ping-shield --status` to
   see the detected list.

### Adding sources: official feeds and Telegram channels

```bash
ping-shield --sources                              # what you have + the catalog (★ = recommended)
ping-shield --add-source t.me/thehackernews        # any public Telegram channel
ping-shield --add-source fedora-security oss-security   # catalog ids
ping-shield --add-source https://example.org/feed.xml   # any RSS/Atom feed
ping-shield --remove-source 4
```

You can do the same from Telegram with `/catalog` (tap ➕ to subscribe), `/addsource`, `/sources` and
`/removesource`.

| Group | Catalog ids |
|---|---|
| 📰 Security news | `thn`, `bleepingcomputer`, `krebs`, `darkreading` |
| 🏛 Official advisories | `cisa`, `cisa-news`, `oss-security`, `github-security`, `pypi`, `socket` |
| 🐧 Distribution advisories | `ubuntu-usn`, `debian-dsa`, `fedora-security`, `arch-asa` (the one for your distro is ★ recommended) |
| ✈️ Telegram channels | `tg-thehackernews`, `tg-bleepingcomputer`, `tg-cvenotify` |

Every new source is fetched once before it's added, to prove it works. Its existing posts are marked
as already seen, so you are alerted only about posts published after you subscribed.

**How Telegram channels work:** Telegram bots can't read channels they don't administer, so
ping-shield reads a public channel's web preview (`https://t.me/s/<channel>`). This needs no login, API
key or extra dependency. **Private channels can't be read this way.** When a channel post links to an
article that also arrives through RSS, both are recognised as the same story by the article link,
title and CVE id, so you get one alert.

## How detection works

ping-shield detects changes in two ways. Both go through the same baseline and exactly-once alerting:

| | Real-time watcher | Scheduled scan |
|---|---|---|
| **Runs** | Continuously, inside `ping-shield-bot.service` | Every 15 minutes (`ping-shield.timer`), and on `/scan` |
| **Speed** | Alerts about 2 s after a change | Up to 15 min after a change |
| **Covers** | SSH files, shell rc files, systemd user units, autostart, `environment.d`, extensions being installed or removed | Everything, including your crontab and code modified deep inside installed extensions |
| **Cost** | No CPU while idle. Linux (inotify) wakes it only when a watched directory changes. | A few seconds of work per run |

The watcher watches the *directories* that contain monitored files. That way it also catches
editors and attackers that replace a file through a rename. It ignores unrelated files such as
`.bash_history`, waits for a burst of writes to settle, and then scans only the affected targets.
Real-time alerts carry a "⚡ Caught: in real time" line. Your crontab can't be watched in real time,
because it lives in a spool directory only root can read, so the 15-minute scan covers it.

ping-shield is a tripwire for the ways attackers keep access to a machine. It isn't an antivirus: it
doesn't scan every file for malware, and it doesn't watch processes or network traffic.

To turn real-time watching off, set `"realtime": false` in `config.json` and run
`systemctl --user restart ping-shield-bot`.

## Interactive bot

`--setup-service` also starts `ping-shield-bot.service`, which listens to your bot. When it's
running, alerts get action buttons:

| Button | What it does |
|---|---|
| ✅ **It was me** | Marks the change as expected. The button turns into "Confirmed by &lt;name&gt; · 14:20". |
| 🚨 **Not me** | Flags the alert and replies with a step-by-step response checklist for SSH, persistence or extension incidents. |
| 🔕 **Mute "&lt;keyword&gt;"** | Stops news that only matches that keyword (for example, an over-broad `Linux`). Undo with `/unmute`. |
| 📖 / 💬 / 🔎 | Opens the article, the original Telegram post, or the CVE on NVD. |

Chat commands (shown in Telegram's menu): `/status`, `/scan`, `/sources`, `/catalog`, `/addsource`,
`/removesource`, `/mute`, `/unmute`, `/help`.

The bot serves **only the chat id in your config**. Anyone else who finds it is refused, so nobody else
can run scans, change your sources or press your buttons. If the bot service isn't running, alerts are
sent without the action buttons, so you never see buttons that do nothing.

## Anti-spam guarantees

Everything that has already been seen is cached in `~/.config/ping-shield/state.json` (mode `0600`).

- **Monitor:** the first scan records a SHA-256 baseline and sends no alerts. After that, a target
  alerts only when its fingerprint changes. The baseline moves forward **only after Telegram confirms
  delivery**, so if the network is down the alert is retried on the next run. Once an alert is
  delivered, it is never sent again.
- **Intel:** news items are remembered by GUID. When several outlets or channels carry the same
  story, the copies are matched by normalised title, **article link and CVE id**, so one threat
  produces one alert.
  Conditional GETs (ETag and `Last-Modified`) avoid downloading feeds that haven't changed. At most
  8 news alerts are sent per run; any extra alerts are deferred to the next run, not dropped.
- An exclusive lock (`run.lock`) prevents overlapping runs.

## Self-test

`ping-shield --test` runs the real detection and alerting code against your real Telegram chat:

| Test | What happens |
|---|---|
| 0: Telegram | Validates the bot token with `getMe` **before** anything on disk is touched. |
| 1: SSH monitoring | Appends `# test-alert-trigger-svc-telemetry` to your real `~/.ssh/authorized_keys`, runs the monitor, and checks that an alert with a `diff` code block was delivered. It then checks that a second scan stays silent, and **restores the file byte for byte**. |
| 2: Threat intel | Injects a simulated "critical zero-day" item that names software found on this machine (for example `Fedora`). It checks that the item is broadcast, that re-processing it is suppressed, and that a harmless control item is filtered out. |

The SSH test is safe for these reasons:

- `sshd` ignores lines starting with `#`, so the marker grants no access.
- The file is rewritten in place, so its inode, permissions, owner and SELinux label (`ssh_home_t` on
  Fedora) are preserved.
- Cleanup runs in a `finally` block, which also runs on Ctrl-C, SIGTERM and SIGHUP.
- If anything else edits the file during the test, only the marker line is removed.
- If you have no `~/.ssh/authorized_keys`, a temporary one is created and then deleted.
- The test refuses to run if the file is a symlink.
- The simulations use an in-memory state store and hold the run lock. Your real baselines are never
  touched, and a scheduled scan can never see the marker.

When stdin is not a terminal, the test refuses to run unless you pass `--yes`.

## Configuration

`~/.config/ping-shield/config.json` (`$XDG_CONFIG_HOME` is honoured). Every field is optional except
the two Telegram fields:

```json
{
  "telegram_bot_token": "123456789:AA…",
  "telegram_chat_id": "123456789",
  "feeds": [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml"
  ],
  "keywords": [],
  "extra_keywords": ["PostgreSQL", "Tailscale"],
  "severity_keywords": ["critical", "zero-day", "actively exploited", "backdoor", "…"],
  "extension_dirs": ["~/.vscode/extensions", "~/.cursor/extensions"],
  "disabled_checks": ["shell.zshrc", "ext."],
  "muted_keywords": ["Linux"],
  "news_max_age_days": 3,
  "max_news_alerts_per_run": 8,
  "request_timeout": 20,
  "realtime": true
}
```

- `keywords`: leave it empty to auto-detect, or set it to replace detection entirely.
  `extra_keywords` is always added to whichever list is used.
- `disabled_checks`: target ids, or prefixes ending in `.` (for example `ext.` disables all
  extension checks).
- Environment overrides for headless or CI use: `PING_SHIELD_TELEGRAM_BOT_TOKEN` and
  `PING_SHIELD_TELEGRAM_CHAT_ID`.
  Note that the systemd timer does **not** read `~/.bashrc`, so variables exported there only affect
  manual runs. To give the scheduled service the variables, add a drop-in, which survives
  re-running `--setup-service`:

  ```bash
  systemctl --user edit ping-shield.service
  # in the editor that opens:
  [Service]
  Environment=PING_SHIELD_TELEGRAM_BOT_TOKEN=123456789:AA…
  Environment=PING_SHIELD_TELEGRAM_CHAT_ID=123456789
  ```

  Drop-in files are created world-readable, so `--init` (mode `0600`) is the safer place for the token.
- `PING_SHIELD_TELEGRAM_API_BASE` points the client at a self-hosted Bot API server. It must use
  `https://` (`http://` is allowed only for loopback addresses).

When you legitimately change a monitored file (for example you install a new extension or edit
`.bashrc`), you will get one alert. That is the intended behaviour. To reset all baselines silently,
run `ping-shield --rebaseline`.

### Running while logged out

User timers run only while you are logged in. To scan around the clock:

```bash
sudo loginctl enable-linger "$USER"
```

### Uninstall

```bash
ping-shield --remove-service
pipx uninstall ping-shield
rm -rf ~/.config/ping-shield
```

---

## Development, build and publishing

### 1. Clone and set up a development environment

```bash
git clone https://github.com/Yosinan/ping-shield.git
cd ping-shield
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip build twine
python -m pip install -e .          # editable install; the `ping-shield` command is now on PATH
ping-shield --version
```

### 2. Versioning

ping-shield follows [Semantic Versioning](https://semver.org/). The version has a single source:
`__version__` in `ping_shield/__init__.py`.

| Bump | When | Example |
|---|---|---|
| **MAJOR** `2.0.0` | Something existing users rely on breaks: a CLI flag is removed or renamed, a config field changes meaning, or the state file needs a migration | dropping `--rebaseline` |
| **MINOR** `1.2.0` | New backwards-compatible features | a new command, check, source type or bot button |
| **PATCH** `1.1.1` | Backwards-compatible bug fixes only | a parser fix, a wrong exit code |

Every change goes under `## [Unreleased]` in [CHANGELOG.md](https://github.com/Yosinan/ping-shield/blob/main/CHANGELOG.md) when it's made. Each release
gets a git tag `vX.Y.Z` on the commit that sets the version. Never reuse or move a published tag or
version: PyPI rejects re-uploads, and users may already have pinned it.

### 3. Cut a release

```bash
# 1. In CHANGELOG.md, rename [Unreleased] to [1.2.0] - YYYY-MM-DD, add a fresh empty
#    [Unreleased] section, and update the compare links at the bottom.
# 2. Set __version__ = "1.2.0" in ping_shield/__init__.py
git commit -am "Release 1.2.0"
git tag -a v1.2.0 -m "ping-shield 1.2.0"
git push origin main v1.2.0
```

### 4. Build the source distribution and wheel

```bash
rm -rf dist/
python3 -m build
```

This creates:

```text
dist/ping_shield-1.2.0.tar.gz             # source distribution (sdist)
dist/ping_shield-1.2.0-py3-none-any.whl   # universal pure-Python wheel
```

The wheel is tagged `py3-none-any`: it has no compiled code, so the same file installs on every
Linux distribution and CPU architecture. This is the modern equivalent of a "universal" wheel.

Check the artifacts before uploading:

```bash
python3 -m twine check dist/*
python3 -m venv /tmp/ps-smoke && /tmp/ps-smoke/bin/pip install dist/*.whl && /tmp/ps-smoke/bin/ping-shield --help
```

### 5. Publish to PyPI with twine

1. Create an account on [pypi.org](https://pypi.org) and on [test.pypi.org](https://test.pypi.org),
   and enable 2FA on both.
2. Create an **API token** under *Account settings → API tokens*. The first upload needs an
   account-wide token. After that, replace it with a token scoped to the `ping-shield` project.
3. Provide the token to twine. The username is always the literal string `__token__`. Choose one
   of these methods:

   ```bash
   # a) environment variables (good for CI; nothing is written to disk)
   export TWINE_USERNAME=__token__
   export TWINE_PASSWORD=pypi-AgEIcHlwaS5vcmc...   # read it from your password manager

   # b) ~/.pypirc, readable only by you
   cat > ~/.pypirc <<'EOF'
   [pypi]
   username = __token__
   password = pypi-AgEIcHlwaS5vcmc...
   [testpypi]
   repository = https://test.pypi.org/legacy/
   username = __token__
   password = pypi-AgENdGVzdC5weXBp...
   EOF
   chmod 600 ~/.pypirc
   ```

4. Do a dry run on TestPyPI first:

   ```bash
   python3 -m twine upload --repository testpypi dist/*
   pipx install --index-url https://test.pypi.org/simple/ ping-shield
   ```

5. Publish for real:

   ```bash
   python3 -m twine upload dist/*
   ```

PyPI never lets you re-upload a file with the same version number. If something is wrong, bump the
version and build again. Once releases are routine, consider switching to
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) from GitHub Actions. It removes
long-lived API tokens completely.

## Security notes

- The bot token is stored with mode `0600` in a `0700` directory. If the file's permissions are too
  open, they are tightened on load. The token is scrubbed from all error messages and logs.
- Feeds are parsed with the standard library's XML parser. Documents that declare XML entities are
  rejected, downloads are capped at 10 MiB, and only `http` and `https` URLs are fetched.
- ping-shield detects changes. It does not prevent them. An attacker who already runs code as your
  user can tamper with ping-shield itself, so treat a sudden stop in scans (visible with
  `--status` and in the journal) as a signal too.

## License

MIT
