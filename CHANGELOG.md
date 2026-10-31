# Changelog

All notable changes to ping-shield are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `pshield`, a short alias for the `ping-shield` command.

### Changed

- The package author contact email is now yoszed22@gmail.com.

## [1.1.0] - 2026-10-31

First public release on PyPI.

### Added

- Real-time detection: an inotify watcher inside the bot service reports changes to SSH files,
  shell rc files, systemd user units, autostart entries, `environment.d` and extension folders
  about 2 seconds after they happen. Adds `--watch` and the `realtime` config option.
- Interactive Telegram bot (`--bot`, `ping-shield-bot.service`):
  - alert buttons: ✅ It was me, 🚨 Not me (sends a response checklist), 🔕 Mute keyword;
  - commands: `/status`, `/scan`, `/sources`, `/catalog`, `/addsource`, `/removesource`,
    `/mute`, `/unmute`, `/help`;
  - live progress messages for slow actions;
  - serves only the configured chat.
- News source management: `--sources`, `--add-source`, `--remove-source`, and a catalog of 17
  sources (security news, official advisories, distro advisories, Telegram channels).
- Public Telegram channels as sources, read from their `t.me/s/` web preview.
- Deduplication of stories across sources by article link.
- `muted_keywords` config option.

### Changed

- Alerts are rendered as Telegram HTML instead of MarkdownV2. They gain severity levels, a
  summary of changes, local timestamps, hashtags, a collapsible article summary and inline
  buttons for the article, the Telegram post and NVD entries.
- The package moved from `src/ping_shield/` to `ping_shield/`.

### Fixed

- The crontab check failed under systemd: `NoNewPrivileges=yes` blocked the setuid `crontab`
  binary.
- `--setup-service` no longer reports its own unit files as a persistence change.

## [1.0.0] - 2026-10-31

Initial version (not published to PyPI).

### Added

- Monitoring of SSH trust files, the user crontab, systemd user units, autostart, `environment.d`,
  shell rc files and VS Code / Cursor / VSCodium / Windsurf extensions, with SHA-256 baselines and
  exactly-once alerting.
- Threat-intel scraping of RSS/Atom feeds, filtered by severity and auto-detected environment
  keywords, with deduplication by GUID, title and CVE id.
- `--init`, `--test`, `--setup-service`, `--remove-service`, `--status` and `--rebaseline`.
- Secret redaction in diffs sent to Telegram.

[Unreleased]: https://github.com/Yosinan/ping-shield/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Yosinan/ping-shield/releases/tag/v1.1.0
[1.0.0]: https://github.com/Yosinan/ping-shield/commit/798093a
