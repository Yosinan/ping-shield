"""Real-time detection with Linux inotify (standard library only, via ctypes).

The 15-minute timer remains the safety net; the watcher only makes detection
fast. It watches the *directories* that contain monitored files (editors and
attackers often replace a file by rename, which a watch on the file itself
would miss), filters events down to the monitored names, waits for the burst
of writes to settle, then runs the normal monitor scan on just the affected
targets. Alerts therefore go through the same baseline and exactly-once logic
as scheduled scans.

Not watched in real time: the user crontab (it lives in a root-only spool
directory) and files deep inside installed extensions; the timer covers both.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import logging
import os
import select
import struct
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from .config import Config, StateStore, load_config, run_lock, state_path
from .monitor import Monitor, Target, default_targets
from .notify import TelegramNotifier

log = logging.getLogger(__name__)

IN_ATTRIB = 0x00000004
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ONLYDIR = 0x01000000
IN_EXCL_UNLINK = 0x04000000
IN_ISDIR = 0x40000000
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000

WATCH_MASK = (IN_ATTRIB | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE
              | IN_DELETE_SELF | IN_MOVE_SELF | IN_ONLYDIR | IN_EXCL_UNLINK)
_EVENT = struct.Struct("iIII")

SETTLE_SECONDS = 2.0  # quiet period before scanning
MAX_DELAY_SECONDS = 10.0  # scan at the latest this long after the first event
MAX_TREE_DIRS = 200

# directory -> {child name (None = any child) -> target ids}
Plan = Dict[Path, Dict[Optional[str], Set[str]]]


class WatchError(RuntimeError):
    pass


def _nearest_existing(path: Path) -> Tuple[Path, str]:
    """Return (closest existing ancestor, name of the next missing component)."""
    child = path
    parent = path.parent
    while not parent.is_dir() and parent != parent.parent:
        child, parent = parent, parent.parent
    return parent, child.name


def build_plan(targets: Iterable[Target]) -> Plan:
    plan: Plan = {}

    def add(directory: Path, name: Optional[str], target_id: str) -> None:
        plan.setdefault(directory, {}).setdefault(name, set()).add(target_id)

    for target in targets:
        if not target.watch or target.path is None:
            continue
        path = target.path
        if target.watch == "file":
            if path.parent.is_dir():
                add(path.parent, path.name, target.id)
            else:
                add(*_nearest_existing(path.parent), target.id)
            continue
        # "tree" and "dir": watch the directory itself plus its entry in the parent,
        # so creating, deleting or replacing the whole directory is noticed too.
        if not path.is_dir():
            add(*_nearest_existing(path), target.id)
            continue
        add(path.parent, path.name, target.id)
        add(path, None, target.id)
        if target.watch == "tree":
            count = 0
            for root, dirs, _files in os.walk(path, followlinks=False):
                for d in dirs:
                    if count >= MAX_TREE_DIRS:
                        break
                    add(Path(root) / d, None, target.id)
                    count += 1
    return plan


class Inotify:
    """Thin ctypes wrapper around inotify_init1 / inotify_add_watch / read."""

    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self.fd = self._libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise WatchError(f"inotify_init1 failed: {os.strerror(ctypes.get_errno())}")
        self.paths: Dict[int, Path] = {}

    def add(self, path: Path) -> None:
        wd = self._libc.inotify_add_watch(self.fd, os.fsencode(str(path)), WATCH_MASK)
        if wd < 0:
            err = ctypes.get_errno()
            if err == errno.ENOSPC:
                raise WatchError("inotify watch limit reached (raise fs.inotify.max_user_watches)")
            log.debug("cannot watch %s: %s", path, os.strerror(err))
            return
        self.paths[wd] = path

    def read(self, timeout: Optional[float]) -> List[Tuple[Path, int, str]]:
        ready, _, _ = select.select([self.fd], [], [], timeout)
        if not ready:
            return []
        try:
            data = os.read(self.fd, 256 * 1024)
        except BlockingIOError:
            return []
        events = []
        offset = 0
        while offset + _EVENT.size <= len(data):
            wd, mask, _cookie, length = _EVENT.unpack_from(data, offset)
            offset += _EVENT.size
            name = data[offset:offset + length].split(b"\0", 1)[0].decode("utf-8", "replace")
            offset += length
            events.append((self.paths.get(wd, Path("?")), mask, name))
        return events

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


class Watcher:
    """Watch monitored locations and run targeted scans moments after they change."""

    def __init__(
        self,
        notifier: TelegramNotifier,
        config_loader: Callable[[], Config] = load_config,
        interactive: bool = True,
    ):
        self.notifier = notifier
        self.config_loader = config_loader
        self.interactive = interactive
        self.plan: Plan = {}
        self.inotify: Optional[Inotify] = None
        self.all_ids: Set[str] = set()

    def _rebuild(self) -> None:
        if self.inotify:
            self.inotify.close()
        targets = default_targets(self.config_loader())
        self.all_ids = {t.id for t in targets if t.watch}
        self.plan = build_plan(targets)
        self.inotify = Inotify()
        for directory in self.plan:
            self.inotify.add(directory)
        log.info("real-time watch active on %d directories", len(self.inotify.paths))

    def _affected(self, directory: Path, mask: int, name: str) -> Set[str]:
        if mask & IN_Q_OVERFLOW:
            return set(self.all_ids)
        rules = self.plan.get(directory, {})
        hit = set(rules.get(None, set()))
        if name:
            hit |= rules.get(name, set())
        return hit

    def scan(self, target_ids: Set[str]) -> bool:
        """Scan *target_ids*; returns False if the run lock could not be taken."""
        config = self.config_loader()
        with run_lock(wait_seconds=120) as acquired:
            if not acquired:
                return False
            monitor = Monitor(config, StateStore(state_path()), self.notifier,
                              interactive=self.interactive, realtime=True)
            report = monitor.scan([t for t in monitor.targets if t.id in target_ids])
        for event in report.events:
            log.warning("real-time: %s changed (%s)", event.target.id,
                        "alerted" if event.delivered else f"NOT DELIVERED: {event.error}")
        return True

    def run_forever(self, stop: Optional[Callable[[], bool]] = None) -> None:
        self._rebuild()
        pending: Set[str] = set()
        rebuild = False
        first = last = 0.0
        while not (stop and stop()):
            assert self.inotify is not None
            timeout: Optional[float] = None
            if pending:
                deadline = min(last + SETTLE_SECONDS, first + MAX_DELAY_SECONDS)
                timeout = max(0.0, deadline - time.monotonic())
            if stop is not None:  # stay responsive to stop requests
                timeout = 1.0 if timeout is None else min(timeout, 1.0)
            for directory, mask, name in self.inotify.read(timeout):
                if mask & (IN_ISDIR | IN_DELETE_SELF | IN_MOVE_SELF | IN_IGNORED) and directory in self.plan:
                    rebuild = True  # a watched directory appeared, vanished or moved
                hit = self._affected(directory, mask, name)
                if hit:
                    now = time.monotonic()
                    if not pending:
                        first = now
                    pending |= hit
                    last = now
                    log.debug("change in %s/%s -> %s", directory, name, sorted(hit))
            if not pending:
                continue
            now = time.monotonic()
            if now - last < SETTLE_SECONDS and now - first < MAX_DELAY_SECONDS:
                continue
            targets, pending = pending, set()
            if rebuild:
                self._rebuild()
                rebuild = False
            try:
                if not self.scan(targets):
                    pending |= targets  # lock busy: try again shortly
                    first = last = time.monotonic()
            except Exception:  # noqa: BLE001 - keep watching even if one scan fails
                log.exception("real-time scan failed")
