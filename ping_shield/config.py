"""Configuration, on-disk layout and persistent state for ping-shield.

Everything ping-shield owns lives in one directory that is resolved at runtime
from :meth:`pathlib.Path.home` (honouring ``$XDG_CONFIG_HOME``), so the same
wheel works for every user on Fedora, Ubuntu, Debian, Arch, openSUSE, ...::

    ~/.config/ping-shield/          mode 0700
    ├── config.json                 mode 0600  Telegram credentials + tuning
    ├── state.json                  mode 0600  baselines + already-alerted news
    └── run.lock                    mode 0600  prevents overlapping runs
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import getpass
import json
import logging
import os
import re
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple

log = logging.getLogger(__name__)

APP_NAME = "ping-shield"

ENV_TOKEN = "PING_SHIELD_TELEGRAM_BOT_TOKEN"
ENV_CHAT_ID = "PING_SHIELD_TELEGRAM_CHAT_ID"

TOKEN_RE = re.compile(r"^\d{5,16}:[A-Za-z0-9_-]{30,64}$")
CHAT_ID_RE = re.compile(r"^(-?\d{1,20}|@[A-Za-z][A-Za-z0-9_]{4,31})$")

DEFAULT_FEEDS: Tuple[str, ...] = (
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
)

DEFAULT_SEVERITY_KEYWORDS: Tuple[str, ...] = (
    "critical",
    "zero-day",
    "zero day",
    "0-day",
    "actively exploited",
    "exploited in the wild",
    "under active exploitation",
    "backdoor",
    "backdoored",
    "supply chain",
    "supply-chain",
    "remote code execution",
    "RCE",
    "privilege escalation",
    "root access",
    "malicious package",
    "malicious packages",
    "malicious extension",
    "malicious extensions",
    "compromised",
    "hijacked",
    "wormable",
    "rootkit",
    "emergency patch",
    "known exploited vulnerabilities",
)

DEFAULT_EXTENSION_DIRS: Tuple[str, ...] = (
    "~/.vscode/extensions",
    "~/.cursor/extensions",
    "~/.vscode-oss/extensions",
    "~/.windsurf/extensions",
)


class ConfigError(RuntimeError):
    """Raised for unreadable or invalid configuration."""


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def config_home() -> Path:
    """Return ``$XDG_CONFIG_HOME`` if it is set to an absolute path, else ``~/.config``."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg)
    return Path.home() / ".config"


def app_dir() -> Path:
    return config_home() / APP_NAME


def config_path() -> Path:
    return app_dir() / "config.json"


def state_path() -> Path:
    return app_dir() / "state.json"


def lock_path() -> Path:
    return app_dir() / "run.lock"


def ensure_app_dir() -> Path:
    """Create the application directory with owner-only permissions."""
    directory = app_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(directory, 0o700)
    return directory


def atomic_write_text(path: Path, data: str, mode: int = 0o600) -> None:
    """Write *data* to *path* atomically (temp file + fsync + rename)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _str_list(value: Any, name: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"config field '{name}' must be a list of strings")
    return [v.strip() for v in value if v.strip()]


def _positive_number(value: Any, name: str, kind: type) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"config field '{name}' must be a positive number")
    return kind(value)


@dataclasses.dataclass
class Config:
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    # Threat-intel feeds (RSS 2.0 or Atom).
    feeds: List[str] = dataclasses.field(default_factory=lambda: list(DEFAULT_FEEDS))
    # Environment keywords. Empty means "auto-detect from this machine".
    keywords: List[str] = dataclasses.field(default_factory=list)
    # Added on top of the detected (or explicit) environment keywords.
    extra_keywords: List[str] = dataclasses.field(default_factory=list)
    severity_keywords: List[str] = dataclasses.field(
        default_factory=lambda: list(DEFAULT_SEVERITY_KEYWORDS)
    )
    extension_dirs: List[str] = dataclasses.field(
        default_factory=lambda: list(DEFAULT_EXTENSION_DIRS)
    )
    # Monitor target ids (or id prefixes such as "shell.") to skip.
    disabled_checks: List[str] = dataclasses.field(default_factory=list)
    # Environment keywords silenced from Telegram ("🔕 Mute" button or /mute).
    muted_keywords: List[str] = dataclasses.field(default_factory=list)
    news_max_age_days: int = 3
    max_news_alerts_per_run: int = 8
    request_timeout: float = 20.0

    @property
    def telegram_configured(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        if not isinstance(data, dict):
            raise ConfigError("config root must be a JSON object")
        cfg = cls()
        known = {f.name for f in dataclasses.fields(cls)}
        for key in sorted(set(data) - known):
            log.warning("ignoring unknown config field %r", key)
        for key in ("telegram_bot_token", "telegram_chat_id"):
            if key in data:
                if not isinstance(data[key], (str, int)) or isinstance(data[key], bool):
                    raise ConfigError(f"config field '{key}' must be a string")
                setattr(cfg, key, str(data[key]).strip())
        for key in (
            "feeds",
            "keywords",
            "extra_keywords",
            "severity_keywords",
            "extension_dirs",
            "disabled_checks",
            "muted_keywords",
        ):
            if key in data:
                setattr(cfg, key, _str_list(data[key], key))
        if "news_max_age_days" in data:
            cfg.news_max_age_days = _positive_number(data["news_max_age_days"], "news_max_age_days", int)
        if "max_news_alerts_per_run" in data:
            cfg.max_news_alerts_per_run = _positive_number(
                data["max_news_alerts_per_run"], "max_news_alerts_per_run", int
            )
        if "request_timeout" in data:
            cfg.request_timeout = _positive_number(data["request_timeout"], "request_timeout", float)
        return cfg


def mask_secret(value: str) -> str:
    if not value:
        return "(not set)"
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]}"


def load_config(path: Optional[Path] = None, apply_env: bool = True) -> Config:
    """Load the config file (defaults if absent) and apply environment overrides."""
    path = path or config_path()
    cfg = Config()
    if path.exists():
        try:
            st = path.stat()
            if stat.S_IMODE(st.st_mode) & 0o077:
                log.warning("%s was readable by other users; tightening to 0600", path)
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
        cfg = Config.from_dict(data)
    if apply_env:
        token = os.environ.get(ENV_TOKEN, "").strip()
        chat_id = os.environ.get(ENV_CHAT_ID, "").strip()
        if token:
            cfg.telegram_bot_token = token
        if chat_id:
            cfg.telegram_chat_id = chat_id
    return cfg


def save_config(cfg: Config, path: Optional[Path] = None) -> Path:
    ensure_app_dir()
    path = path or config_path()
    atomic_write_text(path, json.dumps(cfg.to_dict(), indent=2, sort_keys=False) + "\n", mode=0o600)
    return path


# --------------------------------------------------------------------------- #
# Interactive ``--init``
# --------------------------------------------------------------------------- #
ChatDiscovery = Callable[[str], List[Tuple[str, str]]]


def _ask_token(current: str, getpass_fn: Callable[[str], str]) -> str:
    print("\nStep 1/2 · Telegram bot token")
    print("  Create a bot with @BotFather in Telegram (/newbot) and paste the token it gives you.")
    print("  Input is hidden.")
    while True:
        hint = f" [Enter keeps {mask_secret(current)}]" if current else ""
        value = getpass_fn(f"  TELEGRAM_BOT_TOKEN{hint}: ").strip()
        if not value and current:
            return current
        if TOKEN_RE.match(value):
            return value
        print("  ✗ That does not look like a bot token (expected '123456789:AA…'). Try again.")


def _ask_chat_id(
    current: str,
    token: str,
    input_fn: Callable[[str], str],
    discover: Optional[ChatDiscovery],
) -> str:
    print("\nStep 2/2 · Telegram chat id")
    print("  This is where alerts are delivered: your private chat with the bot, a group, or a channel.")
    if discover:
        print("  Leave it blank to auto-detect: first send any message to your bot (or add it to the")
        print("  group and post there), then press Enter.")
    while True:
        hint = f" [Enter keeps {current}]" if current else ""
        value = input_fn(f"  TELEGRAM_CHAT_ID{hint}: ").strip()
        if not value and current:
            return current
        if not value and discover:
            try:
                chats = discover(token)
            except Exception as exc:  # noqa: BLE001 - surface any discovery failure to the user
                print(f"  ✗ Auto-detection failed: {exc}")
                continue
            if not chats:
                print("  ✗ No messages found yet. Send your bot a message, then press Enter again.")
                continue
            if len(chats) == 1:
                chat_id, title = chats[0]
                print(f"  ✓ Found chat {title} ({chat_id})")
                return chat_id
            for i, (chat_id, title) in enumerate(chats, 1):
                print(f"    {i}) {title} ({chat_id})")
            choice = input_fn("  Pick a chat number: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(chats):
                return chats[int(choice) - 1][0]
            print("  ✗ Invalid choice.")
            continue
        if CHAT_ID_RE.match(value):
            return value
        print("  ✗ Expected a numeric id (e.g. 123456789 or -1001234567890) or @channelname.")


def run_init(
    input_fn: Callable[[str], str] = input,
    getpass_fn: Callable[[str], str] = getpass.getpass,
    discover: Optional[ChatDiscovery] = None,
) -> Config:
    """Interactively collect Telegram credentials and persist them with mode 0600.

    Every other field of an existing config file is preserved.
    """
    if not sys.stdin.isatty() and input_fn is input:
        raise ConfigError(
            "--init needs an interactive terminal. For unattended setups export "
            f"{ENV_TOKEN} and {ENV_CHAT_ID} instead."
        )
    ensure_app_dir()
    cfg = load_config(apply_env=False)
    print(f"ping-shield setup · settings are stored in {config_path()} (owner-only, mode 0600)")
    cfg.telegram_bot_token = _ask_token(cfg.telegram_bot_token, getpass_fn)
    cfg.telegram_chat_id = _ask_chat_id(cfg.telegram_chat_id, cfg.telegram_bot_token, input_fn, discover)
    path = save_config(cfg)
    print(f"\n✓ Saved {path}")
    return cfg


# --------------------------------------------------------------------------- #
# Persistent state (anti-spam cache)
# --------------------------------------------------------------------------- #
class StateStore:
    """JSON-backed state: monitor baselines and already-alerted intel items.

    ``StateStore(None)`` is an in-memory store that is never written to disk;
    the self-test engine uses it so simulated events cannot pollute the real
    baselines.
    """

    VERSION = 1

    def __init__(self, path: Optional[Path]):
        self.path = path
        self.reset_reason: Optional[str] = None
        self.data: Dict[str, Any] = self._load()

    @classmethod
    def ephemeral(cls) -> "StateStore":
        return cls(None)

    @staticmethod
    def _empty() -> Dict[str, Any]:
        return {"version": StateStore.VERSION, "monitor": {}, "intel": {}}

    def _load(self) -> Dict[str, Any]:
        if self.path is None or not self.path.exists():
            return self._empty()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("monitor", {}), dict):
                raise ValueError("unexpected structure")
        except (OSError, ValueError) as exc:
            backup = self.path.with_name(f"{self.path.name}.corrupt-{int(time.time())}")
            with contextlib.suppress(OSError):
                os.replace(self.path, backup)
            self.reset_reason = f"state file was unreadable ({exc}); moved to {backup.name}"
            log.error("%s", self.reset_reason)
            return self._empty()
        data.setdefault("version", self.VERSION)
        data.setdefault("monitor", {})
        data.setdefault("intel", {})
        return data

    def section(self, name: str) -> Dict[str, Any]:
        value = self.data.setdefault(name, {})
        if not isinstance(value, dict):
            value = self.data[name] = {}
        return value

    def save(self) -> None:
        if self.path is None:
            return
        ensure_app_dir()
        atomic_write_text(self.path, json.dumps(self.data, sort_keys=True, separators=(",", ":")))


@contextlib.contextmanager
def run_lock(wait_seconds: float = 0.0) -> Iterator[bool]:
    """Hold an exclusive advisory lock so scans and self-tests never overlap.

    Yields ``True`` when the lock was acquired, ``False`` if another instance
    still held it after *wait_seconds*.
    """
    ensure_app_dir()
    fd = os.open(str(lock_path()), os.O_RDWR | os.O_CREAT, 0o600)
    acquired = False
    try:
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.5)
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def disabled(target_id: str, patterns: Sequence[str]) -> bool:
    """Return True if *target_id* matches a ``disabled_checks`` entry (exact or prefix ending in '.')."""
    for pattern in patterns:
        if target_id == pattern or (pattern.endswith(".") and target_id.startswith(pattern)):
            return True
    return False
