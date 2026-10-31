"""Command-line entry point and execution routing for ping-shield."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
from typing import Optional, Sequence

from . import __version__
from .config import (
    ConfigError,
    StateStore,
    config_path,
    load_config,
    mask_secret,
    run_init,
    run_lock,
    state_path,
)
from .notify import Alert, Field, NotifyError, TelegramNotifier
from .service import ServiceError

log = logging.getLogger("ping_shield")

EXIT_OK = 0
EXIT_ALERT_FAILURE = 1
EXIT_USAGE = 2

EPILOG = """\
typical setup:
  ping-shield --init            store your Telegram bot token and chat id
  ping-shield --test            send two self-test alerts end to end
  ping-shield --setup-service   scan every 15 minutes + start the interactive bot

news sources:
  ping-shield --sources                         list subscribed and catalog sources
  ping-shield --add-source t.me/thehackernews   add a public Telegram channel
  ping-shield --add-source ubuntu-usn           add a catalog source by id
  ping-shield --add-source https://x.org/rss    add any RSS/Atom feed
  ping-shield --remove-source 3                 remove by list number, id or URL

other commands:
  ping-shield                   run one scan now (same as --run)
  ping-shield --status          show configuration, baselines and service state
  ping-shield --rebaseline      trust the current files without alerting
  ping-shield --bot             run the interactive Telegram bot in the foreground
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ping-shield",
        description="Detect SSH backdoors, persistence, malicious IDE extensions and relevant "
        "high-severity threat news; alert to Telegram exactly once.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--init", action="store_true", help="interactively configure Telegram credentials")
    action.add_argument("--setup-service", action="store_true",
                        help="install and start the systemd user service + 15-minute timer")
    action.add_argument("--remove-service", action="store_true", help="stop and remove the systemd user units")
    action.add_argument("--test", action="store_true", help="run the end-to-end alerting self-test")
    action.add_argument("--run", action="store_true", help="run one scan (default when no command is given)")
    action.add_argument("--status", action="store_true", help="show configuration and service status")
    action.add_argument("--rebaseline", action="store_true",
                        help="accept the current state of all monitored files as trusted, without alerting")
    action.add_argument("--sources", action="store_true", help="list subscribed news sources and the catalog")
    action.add_argument("--add-source", nargs="+", metavar="SOURCE",
                        help="subscribe to feed URLs, public Telegram channels (t.me/name) or catalog ids")
    action.add_argument("--remove-source", nargs="+", metavar="SOURCE",
                        help="unsubscribe by list number, catalog id, channel or URL")
    action.add_argument("--bot", action="store_true",
                        help="run the Telegram bot that answers alert buttons and chat commands "
                             "(also runs the real-time watcher)")
    action.add_argument("--watch", action="store_true",
                        help="run only the real-time file watcher in the foreground")
    parser.add_argument("--only", choices=("monitor", "intel"), help="with --run: run a single engine")
    parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation (for --test)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="more logging (-vv for debug)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING - 10 * min(verbosity, 2)
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)


def _notifier(config) -> TelegramNotifier:
    if not config.telegram_configured:
        raise ConfigError(f"Telegram is not configured. Run `ping-shield --init` (config: {config_path()}).")
    return TelegramNotifier(config.telegram_bot_token, config.telegram_chat_id, timeout=config.request_timeout)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_init(args: argparse.Namespace) -> int:
    def discover(token: str):
        try:
            return TelegramNotifier(token, "").discover_chats()
        except NotifyError as exc:
            if "conflict" in str(exc).lower():
                raise NotifyError("the ping-shield bot service is reading updates; type the chat id "
                                  "instead (see it with: ping-shield --status)") from None
            raise

    config = run_init(discover=discover)
    notifier = _notifier(config)
    try:
        me = notifier.get_me()
        print(f"✓ Token verified: bot @{me.get('username', '?')}")
    except NotifyError as exc:
        print(f"⚠ Saved, but the token could not be verified: {exc}")
        return EXIT_ALERT_FAILURE
    answer = input("Send a confirmation message to the chat now? [Y/n] ").strip().lower()
    if answer in ("", "y", "yes"):
        try:
            notifier.send_alert(Alert(
                icon="✅",
                title="ping-shield Connected",
                fields=[
                    Field("🖥", "Host", socket.gethostname(), mono=True),
                    Field("📦", "Version", __version__),
                ],
                note="Security alerts for this machine will be delivered to this chat.",
            ))
            print("✓ Message sent. Check Telegram.")
        except NotifyError as exc:
            print(f"✗ Could not send to chat {config.telegram_chat_id}: {exc}")
            print("  Make sure you have pressed Start in the bot chat (or added the bot to the group).")
            return EXIT_ALERT_FAILURE
    print("\nNext: `ping-shield --test`, then `ping-shield --setup-service`.")
    return EXIT_OK


def cmd_run(args: argparse.Namespace) -> int:
    from .intel import IntelEngine
    from .monitor import Monitor

    from .service import bot_active

    config = load_config()
    notifier = _notifier(config)
    interactive = bot_active()  # only offer callback buttons when something will answer them
    with run_lock() as acquired:
        if not acquired:
            log.warning("another ping-shield instance is running; skipping this run")
            return EXIT_OK
        state = StateStore(state_path())
        if state.reset_reason:
            try:
                notifier.send_alert(Alert(
                    icon="♻️",
                    title="State Reset",
                    fields=[Field("🖥", "Host", socket.gethostname(), mono=True)],
                    bullets=[state.reset_reason],
                    note_title="ℹ️ Note:",
                    note="baselines are re-established on this run; changes made since the last "
                         "good state cannot be diffed.",
                ))
            except NotifyError as exc:
                log.error("could not report state reset: %s", exc)

        failures = 0
        if args.only in (None, "monitor"):
            report = Monitor(config, state, notifier, interactive=interactive).scan()
            print(f"monitor: {len(report.baselined)} baselined, {report.unchanged} unchanged, "
                  f"{len(report.events)} change(s), {len(report.errors)} error(s)")
            for event in report.events:
                status = "alerted" if event.delivered else f"NOT DELIVERED ({event.error})"
                print(f"  ! {event.target.id}: {status}")
            for error in report.errors:
                print(f"  error: {error}")
            failures += len(report.undelivered)

        if args.only in (None, "intel"):
            intel = IntelEngine(config, state, notifier, interactive=interactive).run()
            print(f"intel: {intel.fetched} item(s), {len(intel.sent)} alerted, {intel.duplicates} duplicate, "
                  f"{intel.ignored} not relevant, {intel.stale} too old, {intel.deferred} deferred")
            for item in intel.sent:
                print(f"  ! {item.title}")
            for error in intel.errors:
                print(f"  warning: {error}")
            failures += intel.undelivered

    return EXIT_ALERT_FAILURE if failures else EXIT_OK


def cmd_setup_service(args: argparse.Namespace) -> int:
    from .monitor import Monitor
    from .service import install_service

    config = load_config()
    if not config.telegram_configured:
        print("⚠ Telegram is not configured yet; scheduled scans will fail until you run `ping-shield --init`.")
    # Hold the run lock while writing our own unit files and re-trusting them, so
    # neither a scheduled scan nor the real-time watcher reports them as a change.
    with run_lock(wait_seconds=60) as acquired:
        steps = install_service()
        state = StateStore(state_path())
        if acquired and "systemd.user" in state.section("monitor"):
            Monitor(config, state, None).rebaseline(["systemd.user"])
    for step in steps:
        print(f"✓ {step}" if not step.startswith("note:") else f"\n{step}")
    print("\nFollow the logs with: journalctl --user -u ping-shield.service -f")
    return EXIT_OK


def cmd_remove_service(args: argparse.Namespace) -> int:
    from .monitor import Monitor
    from .service import remove_service

    with run_lock(wait_seconds=60) as acquired:
        steps = remove_service()
        state = StateStore(state_path())
        if acquired and "systemd.user" in state.section("monitor"):
            Monitor(load_config(), state, None).rebaseline(["systemd.user"])
    for step in steps:
        print(f"✓ {step}")
    return EXIT_OK


def cmd_rebaseline(args: argparse.Namespace) -> int:
    from .monitor import Monitor

    config = load_config()
    with run_lock(wait_seconds=60) as acquired:
        if not acquired:
            print("✗ A scan is running; try again shortly.")
            return EXIT_ALERT_FAILURE
        done = Monitor(config, StateStore(state_path()), None).rebaseline()
    print(f"✓ Re-baselined {len(done)} target(s): {', '.join(done)}")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    from .intel import KeywordMatcher
    from .monitor import default_targets
    from .service import service_status

    config = load_config()
    state = StateStore(state_path())
    monitor_state = state.section("monitor")
    intel_state = state.section("intel")
    print(f"ping-shield {__version__}")
    print(f"config:  {config_path()}")
    print(f"state:   {state_path()}")
    print(f"telegram token: {mask_secret(config.telegram_bot_token)}")
    print(f"telegram chat:  {config.telegram_chat_id or '(not set)'}")
    targets = default_targets(config)
    print(f"monitor: {sum(1 for t in targets if t.id in monitor_state)}/{len(targets)} targets baselined")
    for target in targets:
        mark = "✓" if target.id in monitor_state else "·"
        print(f"  {mark} {target.id:<24} {target.label}")
    print(f"intel:   {len(config.feeds)} feed(s), {len(intel_state.get('seen', {}))} item(s) remembered")
    matcher = KeywordMatcher.from_config(config)
    source = "configured" if config.keywords else "auto-detected"
    print(f"  environment keywords ({source}): {', '.join(matcher.environment)}")
    for line in service_status():
        print(f"service: {line}")
    from .service import bot_active

    if not config.realtime:
        realtime = "off (realtime: false in config)"
    else:
        realtime = "on (inside the bot service)" if bot_active() else "off (start the bot service)"
    print(f"real-time watch: {realtime}")
    return EXIT_OK


def cmd_sources(args: argparse.Namespace) -> int:
    from . import sources
    from .intel import detect_distro_ids

    config = load_config()
    print("Subscribed sources:")
    if not config.feeds:
        print("  (none)")
    for i, url in enumerate(config.feeds, 1):
        print(f"  {i:>2}. {sources.display_name(url):<34} {url}")
    recommended = {s.id for s in sources.recommended(detect_distro_ids())}
    available = [s for s in sources.CATALOG if s.url not in config.feeds]
    if available:
        print("\nCatalog (add with: ping-shield --add-source <id>)   ★ = recommended for this machine")
        for group, title in sources.GROUP_TITLES.items():
            entries = [s for s in available if s.group == group]
            if entries:
                print(f"\n  {title}")
                for s in entries:
                    star = "★" if s.id in recommended else " "
                    print(f"   {star} {s.id:<20} {s.description}")
    print("\nAny public Telegram channel or RSS/Atom URL also works: ping-shield --add-source t.me/<channel>")
    return EXIT_OK


def cmd_add_source(args: argparse.Namespace) -> int:
    from .intel import add_sources

    results = add_sources(load_config(apply_env=False), args.add_source, state_path())
    for r in results:
        print(f"{'✓' if r.ok else '✗'} {r.name or r.value}: {r.message}")
    return EXIT_OK if all(r.ok or r.message == "already subscribed" for r in results) else EXIT_ALERT_FAILURE


def cmd_remove_source(args: argparse.Namespace) -> int:
    from .intel import remove_sources

    results = remove_sources(load_config(apply_env=False), args.remove_source)
    for r in results:
        print(f"{'✓' if r.ok else '✗'} {r.name or r.value}: {r.message}")
    return EXIT_OK if all(r.ok for r in results) else EXIT_ALERT_FAILURE


def cmd_bot(args: argparse.Namespace) -> int:
    from .bot import Bot

    if args.verbose == 0:
        logging.getLogger().setLevel(logging.INFO)
    notifier = _notifier(load_config())
    try:
        name = notifier.get_me().get("username", "?")
    except NotifyError as exc:
        print(f"✗ Cannot reach Telegram: {exc}", file=sys.stderr)
        return EXIT_ALERT_FAILURE
    print(f"🤖 @{name} is listening. Send /help to it in Telegram. Press Ctrl+C to stop.", flush=True)
    if load_config().realtime:
        print("👁 Real-time file watching is on.", flush=True)
    if sys.stdout.isatty():
        print("   To keep it running in the background, use: ping-shield --setup-service", flush=True)
    Bot(notifier).run_forever()
    return EXIT_OK


def cmd_watch(args: argparse.Namespace) -> int:
    from .service import bot_active
    from .watch import Watcher

    if args.verbose == 0:
        logging.getLogger().setLevel(logging.INFO)
    config = load_config()
    if bot_active() and config.realtime:
        print("The bot service is already watching in real time; no need to run --watch as well.")
        return EXIT_OK
    print("👁 Watching monitored files. Changes are reported within seconds. Press Ctrl+C to stop.", flush=True)
    Watcher(_notifier(config), interactive=bot_active()).run_forever()
    return EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    from .tester import run_tests

    return run_tests(load_config(), assume_yes=args.yes)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    handlers = [
        (args.init, cmd_init),
        (args.setup_service, cmd_setup_service),
        (args.remove_service, cmd_remove_service),
        (args.test, cmd_test),
        (args.status, cmd_status),
        (args.rebaseline, cmd_rebaseline),
        (args.sources, cmd_sources),
        (args.add_source, cmd_add_source),
        (args.remove_source, cmd_remove_source),
        (args.bot, cmd_bot),
        (args.watch, cmd_watch),
    ]
    if args.only and any(flag for flag, _ in handlers):
        print("error: --only can only be combined with --run", file=sys.stderr)
        return EXIT_USAGE
    handler = next((fn for flag, fn in handlers if flag), cmd_run)
    try:
        return handler(args)
    except (ConfigError, ServiceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception:  # noqa: BLE001 - last-resort guard for a CLI / systemd unit
        log.exception("unexpected error")
        return EXIT_ALERT_FAILURE


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    run()
