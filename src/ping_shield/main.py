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
  ping-shield --setup-service   scan automatically every 15 minutes

other commands:
  ping-shield                   run one scan now (same as --run)
  ping-shield --status          show configuration, baselines and timer state
  ping-shield --rebaseline      trust the current files without alerting
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
        return TelegramNotifier(token, "").discover_chats()

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

    config = load_config()
    notifier = _notifier(config)
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
            report = Monitor(config, state, notifier).scan()
            print(f"monitor: {len(report.baselined)} baselined, {report.unchanged} unchanged, "
                  f"{len(report.events)} change(s), {len(report.errors)} error(s)")
            for event in report.events:
                status = "alerted" if event.delivered else f"NOT DELIVERED ({event.error})"
                print(f"  ! {event.target.id}: {status}")
            for error in report.errors:
                print(f"  error: {error}")
            failures += len(report.undelivered)

        if args.only in (None, "intel"):
            intel = IntelEngine(config, state, notifier).run()
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
    for step in install_service():
        print(f"✓ {step}" if not step.startswith("note:") else f"\n{step}")
    # The new unit files are ours: don't report them as a persistence change.
    with run_lock(wait_seconds=60) as acquired:
        state = StateStore(state_path())
        if acquired and "systemd.user" in state.section("monitor"):
            Monitor(config, state, None).rebaseline(["systemd.user"])
    print("\nFollow the logs with: journalctl --user -u ping-shield.service -f")
    return EXIT_OK


def cmd_remove_service(args: argparse.Namespace) -> int:
    from .monitor import Monitor
    from .service import remove_service

    for step in remove_service():
        print(f"✓ {step}")
    with run_lock(wait_seconds=60) as acquired:
        state = StateStore(state_path())
        if acquired and "systemd.user" in state.section("monitor"):
            Monitor(load_config(), state, None).rebaseline(["systemd.user"])
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
    return EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    from .tester import run_tests

    return run_tests(load_config(), assume_yes=args.yes)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    if args.only and any(
            (args.init, args.setup_service, args.remove_service, args.test, args.status, args.rebaseline)):
        print("error: --only can only be combined with --run", file=sys.stderr)
        return EXIT_USAGE
    handlers = [
        (args.init, cmd_init),
        (args.setup_service, cmd_setup_service),
        (args.remove_service, cmd_remove_service),
        (args.test, cmd_test),
        (args.status, cmd_status),
        (args.rebaseline, cmd_rebaseline),
    ]
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
