"""Automated end-to-end simulation (``ping-shield --test``).

The self-test exercises the real detection and alerting code paths against
the real Telegram chat, while guaranteeing it leaves the machine untouched:

* **Test 0 - Telegram connectivity.** Validates the token with ``getMe``
  before anything on disk is touched.
* **Test 1 - SSH monitoring.** Appends the harmless comment line
  ``# test-alert-trigger-svc-telemetry`` to ``~/.ssh/authorized_keys``
  (sshd ignores ``#`` lines), runs the monitor so a Telegram alert with a
  markdown diff is sent, verifies a second scan stays silent (anti-spam), then
  restores the file byte-for-byte *in place* so its inode, permissions,
  owner and SELinux label are preserved.
* **Test 2 - Threat intel.** Injects a simulated high-severity news item that
  names software detected on this machine, verifies it is broadcast, that
  re-processing it is suppressed, and that a benign item is filtered out.

Simulations use an in-memory state store, so the real baselines and news
cache are never modified, and they hold the run lock, so a scheduled scan
cannot observe the temporary marker.
"""

from __future__ import annotations

import contextlib
import dataclasses
import os
import signal
import stat
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, List, Optional

from .config import Config, ConfigError, StateStore, run_lock
from .intel import IntelEngine, NewsItem, detect_distro_ids
from .monitor import Monitor
from .notify import NotifyError, TelegramNotifier

MARKER = "# test-alert-trigger-svc-telemetry"
TEST_PREFIX = "🧪 ping-shield SELF-TEST"
LOCK_WAIT_SECONDS = 120


@dataclasses.dataclass
class TestResult:
    name: str
    passed: bool = False
    skipped: bool = False
    details: List[str] = dataclasses.field(default_factory=list)

    def ok(self, message: str) -> None:
        self.details.append(f"✓ {message}")

    def fail(self, message: str) -> None:
        self.details.append(f"✗ {message}")


class _CheckFailed(Exception):
    pass


def _check(result: TestResult, condition: bool, success: str, failure: str) -> None:
    if condition:
        result.ok(success)
    else:
        result.fail(failure)
        raise _CheckFailed(failure)


@contextlib.contextmanager
def _signals_raise() -> Iterator[None]:
    """Turn SIGTERM/SIGHUP into SystemExit so ``finally`` cleanup always runs."""

    def handler(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    previous = {}
    for sig in (signal.SIGTERM, signal.SIGHUP):
        with contextlib.suppress(ValueError):  # not in the main thread
            previous[sig] = signal.signal(sig, handler)
    try:
        yield
    finally:
        for sig, old in previous.items():
            signal.signal(sig, old)


def _write_in_place(path: Path, content: bytes) -> None:
    """Rewrite *path* without replacing the inode (keeps mode, owner and SELinux context)."""
    with open(path, "r+b") as fh:
        fh.seek(0)
        fh.write(content)
        fh.truncate()
        fh.flush()
        os.fsync(fh.fileno())


def _strip_marker(content: bytes) -> bytes:
    marker = MARKER.encode()
    return b"".join(line for line in content.splitlines(keepends=True) if line.strip() != marker)


# --------------------------------------------------------------------------- #
# Test 0
# --------------------------------------------------------------------------- #
def test_telegram(notifier: TelegramNotifier) -> TestResult:
    result = TestResult("Telegram connectivity")
    try:
        me = notifier.get_me()
    except NotifyError as exc:
        result.fail(f"getMe failed: {exc}")
        return result
    result.ok(f"bot token is valid (@{me.get('username', '?')})")
    result.passed = True
    return result


# --------------------------------------------------------------------------- #
# Test 1
# --------------------------------------------------------------------------- #
def test_ssh_monitoring(config: Config, notifier: TelegramNotifier) -> TestResult:
    result = TestResult("SSH monitoring (~/.ssh/authorized_keys)")
    ssh_dir = Path.home() / ".ssh"
    path = ssh_dir / "authorized_keys"

    if path.is_symlink():
        result.fail(f"{path} is a symlink; refusing to modify it")
        return result
    if path.exists() and not path.is_file():
        result.fail(f"{path} is not a regular file; refusing to modify it")
        return result

    created_dir = not ssh_dir.exists()
    created_file = not path.exists()
    original: Optional[bytes] = None
    injected = b""

    # disabled_checks applies to real scans only; the test always needs this target.
    test_config = dataclasses.replace(config, disabled_checks=[])
    monitor = Monitor(test_config, StateStore.ephemeral(), notifier, alert_prefix=TEST_PREFIX)
    target = monitor.target("ssh.authorized_keys")

    with _signals_raise():
        try:
            if created_dir:
                ssh_dir.mkdir(mode=0o700)
                result.ok(f"created {ssh_dir} (mode 0700) for the test")
            if created_file:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.close(fd)
                original = b""
                result.ok(f"created empty {path} (mode 0600) for the test")
            else:
                original = path.read_bytes()
                if MARKER.encode() in original:
                    original = _strip_marker(original)
                    _write_in_place(path, original)
                    result.ok("removed a marker left behind by an interrupted earlier test")

            monitor.rebaseline([target.id])
            result.ok("captured baseline (in-memory; real state untouched)")

            separator = b"" if not original or original.endswith(b"\n") else b"\n"
            injected = separator + MARKER.encode() + b"\n"
            with open(path, "ab") as fh:
                fh.write(injected)
                fh.flush()
                os.fsync(fh.fileno())
            result.ok(f"appended '{MARKER}'")

            report = monitor.scan([target])
            _check(result, not report.errors, "monitor scan completed", f"scan errors: {report.errors}")
            _check(result, len(report.events) == 1, "change detected",
                   f"expected 1 change event, got {len(report.events)}")
            event = report.events[0]
            _check(result, f"+{MARKER}" in event.diff, "diff contains the injected line",
                   "injected line missing from diff")
            _check(result, event.delivered,
                   f"Telegram alert delivered with markdown diff (message id {event.message_id})",
                   f"Telegram delivery failed: {event.error}")

            repeat = monitor.scan([target])
            _check(result, not repeat.events, "second scan sent nothing (duplicate suppressed)",
                   f"second scan produced {len(repeat.events)} duplicate alert(s)")
            result.passed = True
        except _CheckFailed:
            pass
        except (OSError, NotifyError) as exc:
            result.fail(f"{type(exc).__name__}: {exc}")
        finally:
            _restore_authorized_keys(result, path, original, injected, created_file, created_dir)
    return result


def _restore_authorized_keys(
    result: TestResult,
    path: Path,
    original: Optional[bytes],
    injected: bytes,
    created_file: bool,
    created_dir: bool,
) -> None:
    if original is None:
        # Failed before the file was read or created: at most an empty ~/.ssh was made.
        if created_dir:
            with contextlib.suppress(OSError):
                path.parent.rmdir()
        return
    try:
        current = path.read_bytes() if path.exists() else b""
        if current == original + injected:
            restored = original
        else:
            # Something else edited the file meanwhile: remove only our line.
            restored = _strip_marker(current)
        if created_file and not restored.strip():
            path.unlink(missing_ok=True)
            result.ok(f"cleanup: removed temporary {path}")
            if created_dir:
                with contextlib.suppress(OSError):
                    path.parent.rmdir()
                    result.ok(f"cleanup: removed temporary {path.parent}")
            return
        if restored != current:
            _write_in_place(path, restored)
        final = path.read_bytes()
        if final == original:
            result.ok(f"cleanup: marker removed, file restored byte-for-byte (mode "
                      f"{stat.S_IMODE(path.stat().st_mode):04o})")
        elif MARKER.encode() not in final:
            result.ok("cleanup: marker removed (file was also changed by another process during the test)")
        else:
            raise OSError("marker still present after cleanup")
    except OSError as exc:
        result.passed = False
        result.fail(f"CLEANUP FAILED: {exc}. Remove the line '{MARKER}' from {path} manually.")


# --------------------------------------------------------------------------- #
# Test 2
# --------------------------------------------------------------------------- #
def _pick_local_keyword(engine: IntelEngine) -> str:
    available = {k.lower(): k for k in engine.matcher.environment}
    preferred = detect_distro_ids() + ["openssh", "python", "linux"]
    for candidate in preferred:
        if candidate in available:
            return available[candidate]
    return engine.matcher.environment[0] if engine.matcher.environment else "Linux"


def test_intel_pipeline(config: Config, notifier: TelegramNotifier) -> TestResult:
    result = TestResult("Threat-intel news alerting")
    engine = IntelEngine(config, StateStore.ephemeral(), notifier, alert_prefix=TEST_PREFIX)
    keyword = _pick_local_keyword(engine)
    if keyword not in engine.matcher.environment:
        engine.matcher = type(engine.matcher)(engine.matcher.severity, engine.matcher.environment + [keyword])
    result.ok(f"local keyword chosen for the simulation: '{keyword}'")

    test_id = uuid.uuid4().hex[:12]
    dummy = NewsItem(
        guid=f"ping-shield-self-test-{test_id}",
        title=f"[SIMULATION] Critical zero-day backdoor actively exploited in {keyword}",
        summary=(
            "This is a simulated high-severity advisory generated by `ping-shield --test` to verify "
            "that threat-intel alerts reach this chat. It is not real news; no action is required."
        ),
        published=datetime.now(timezone.utc),
        source="ping-shield self-test",
    )
    benign = NewsItem(
        guid=f"ping-shield-self-test-benign-{test_id}",
        title="Weekly roundup: productivity tips and new conference talks",
        summary="Nothing security-relevant here.",
        published=datetime.now(timezone.utc),
        source="ping-shield self-test",
    )
    try:
        report = engine.process_items([dummy, benign])
        _check(result, not report.errors, "pipeline ran without errors", f"errors: {report.errors}")
        _check(result, report.ignored == 1, "benign item filtered out",
               "benign item was not filtered out")
        _check(result, len(report.sent) == 1, "high-severity item matched and broadcast to Telegram",
               f"expected 1 alert, sent {len(report.sent)}")
        match = report.matched_keywords[dummy.key]
        result.ok(f"matched severity {match.severity} and environment {match.environment}")

        repeat = engine.process_items([dummy])
        _check(result, not repeat.sent and repeat.duplicates == 1,
               "re-processing the same item sent nothing (duplicate suppressed)",
               "the same news item was alerted twice")
        result.passed = True
    except _CheckFailed:
        pass
    except NotifyError as exc:
        result.fail(f"Telegram error: {exc}")
    return result


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #
def run_tests(
    config: Config,
    assume_yes: bool = False,
    notifier: Optional[TelegramNotifier] = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    if not config.telegram_configured:
        raise ConfigError("Telegram is not configured. Run `ping-shield --init` first.")
    print("ping-shield self-test")
    print("  • Test 1 temporarily appends a comment line to ~/.ssh/authorized_keys and removes it")
    print("    immediately afterwards. Comment lines are ignored by sshd and grant no access.")
    print("  • Two clearly labelled SELF-TEST messages will be sent to your Telegram chat.")
    if not assume_yes:
        if not sys.stdin.isatty():
            raise ConfigError("refusing to modify ~/.ssh/authorized_keys non-interactively without --yes")
        if input_fn("Continue? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    notifier = notifier or TelegramNotifier(
        config.telegram_bot_token, config.telegram_chat_id, timeout=config.request_timeout
    )
    results: List[TestResult] = []
    with run_lock(wait_seconds=LOCK_WAIT_SECONDS) as acquired:
        if not acquired:
            print("✗ A scheduled scan is still running; try again in a minute.")
            return 1
        results.append(test_telegram(notifier))
        if results[0].passed:
            results.append(test_ssh_monitoring(config, notifier))
            results.append(test_intel_pipeline(config, notifier))
        else:
            for name in ("SSH monitoring (~/.ssh/authorized_keys)", "Threat-intel news alerting"):
                results.append(TestResult(name, skipped=True, details=["- skipped: Telegram unreachable"]))

    print()
    for i, res in enumerate(results):
        status = "SKIP" if res.skipped else ("PASS" if res.passed else "FAIL")
        print(f"[{status}] Test {i}: {res.name}")
        for line in res.details:
            print(f"       {line}")
    passed = all(r.passed for r in results)
    print("\nAll tests passed. Check your phone for two SELF-TEST alerts." if passed
          else "\nSome tests failed; see details above.")
    return 0 if passed else 1
