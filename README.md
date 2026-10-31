# ping-shield

**A tripwire for Linux developer workstations.** ping-shield watches the places attackers use to
keep access to your machine (SSH trust files, crontabs, systemd user units, shell start-up files and
VS Code / Cursor extensions). It also reads public security news for high-severity threats that affect
software actually installed on your machine. Every finding is sent to your phone through Telegram
**exactly once**.

- **Zero runtime dependencies.** It uses only the Python standard library, so a supply-chain security
  tool doesn't widen its own supply chain.
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
ping-shield --setup-service       # scan automatically every 15 minutes
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
| `--setup-service` | Generates `~/.config/systemd/user/ping-shield.{service,timer}`, then runs `daemon-reload` and `enable --now`. |
| `--remove-service` | Stops and deletes the units. |
| `--status` | Shows the config, which targets have a baseline, the detected keywords and the timer state. |
| `--rebaseline` | Accepts the current state of all monitored files as trusted, without sending alerts. |
| `-v` / `-vv` | More detailed logging (written to stderr, which goes to the journal under systemd). |

Logs from scheduled runs: `journalctl --user -u ping-shield.service -f`

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

The default feeds are The Hacker News, BleepingComputer and CISA advisories (any RSS 2.0, RSS 1.0 or
Atom feed works). An item triggers an alert only if it matches **both**:

1. a **severity** term, such as `actively exploited`, `zero-day`, `backdoor`, `supply chain`,
   `remote code execution`, `malicious package`, or a CVSS score of 9.0 or higher; **and**
2. an **environment** keyword describing *this* machine. These are detected automatically from
   `/etc/os-release` and from the tools on your `PATH`: your distro, OpenSSH, sudo, systemd, Python,
   PyPI, npm, Docker, Podman, VS Code, Cursor, xz/liblzma, and so on. Run `ping-shield --status` to
   see the detected list.

## Anti-spam guarantees

Everything that has already been seen is cached in `~/.config/ping-shield/state.json` (mode `0600`).

- **Monitor:** the first scan records a SHA-256 baseline and sends no alerts. After that, a target
  alerts only when its fingerprint changes. The baseline moves forward **only after Telegram confirms
  delivery**, so if the network is down the alert is retried on the next run. Once an alert is
  delivered, it is never sent again.
- **Intel:** news items are remembered by GUID. When several outlets syndicate the same story, the
  copies are matched by normalised title **and by CVE id**, so one threat produces one alert.
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
  "news_max_age_days": 3,
  "max_news_alerts_per_run": 8,
  "request_timeout": 20
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

### 2. Start version control (new project)

```bash
git init
git add .
git commit -m "Initial release of ping-shield"
git branch -M main
git remote add origin git@github.com:Yosinan/ping-shield.git
git push -u origin main
```

`.gitignore` already excludes `dist/`, virtual environments, `.pypirc` and any stray
`config.json` or `state.json`. **Never commit a Telegram token or a PyPI token.**

### 3. Cut a release

The version has a single source: `__version__` in `src/ping_shield/__init__.py`.

```bash
# bump the version in src/ping_shield/__init__.py, e.g. 1.0.0 -> 1.0.1
git commit -am "Release 1.0.1"
git tag -a v1.0.1 -m "ping-shield 1.0.1"
git push origin main --tags
```

### 4. Build the source distribution and wheel

```bash
rm -rf dist/
python3 -m build
```

This creates:

```text
dist/ping_shield-1.0.1.tar.gz             # source distribution (sdist)
dist/ping_shield-1.0.1-py3-none-any.whl   # universal pure-Python wheel
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
