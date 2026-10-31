"""Telegram delivery for ping-shield alerts.

Standard library only: a security monitor should not drag a third-party HTTP
stack into its own supply chain. Messages are formatted as Telegram
MarkdownV2 (with an automatic plain-text fallback), rate limits are honoured,
and the bot token never appears in logs or exception messages.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from . import __version__

log = logging.getLogger(__name__)

API_BASE_ENV = "PING_SHIELD_TELEGRAM_API_BASE"
DEFAULT_API_BASE = "https://api.telegram.org"
USER_AGENT = f"ping-shield/{__version__} (+https://pypi.org/project/ping-shield/)"
MAX_MESSAGE_LEN = 4096
_MAX_ATTEMPTS = 4
_MD_SPECIAL = frozenset("_*[]()~`>#+-=|{}.!\\")


def escape_md(text: str) -> str:
    """Escape *text* for use outside code entities in MarkdownV2."""
    return "".join("\\" + ch if ch in _MD_SPECIAL else ch for ch in text)


def escape_code(text: str) -> str:
    """Escape *text* for use inside a MarkdownV2 ``pre``/``code`` entity."""
    return text.replace("\\", "\\\\").replace("`", "\\`")


def escape_url(url: str) -> str:
    return url.replace("\\", "\\\\").replace(")", "\\)")


class NotifyError(RuntimeError):
    """Raised when a message could not be delivered to Telegram."""


def _fit_lines(lines: List[str], budget: int) -> List[str]:
    """Keep as many whole lines as fit in *budget* characters, noting what was cut."""
    kept: List[str] = []
    used = 0
    for i, line in enumerate(lines):
        cost = len(line) + 1
        if used + cost > budget:
            kept.append(f"… {len(lines) - i} more line(s) truncated")
            break
        kept.append(line)
        used += cost
    return kept


@dataclasses.dataclass
class Alert:
    """A structured alert that renders to MarkdownV2 or plain text within Telegram's limit."""

    title: str
    fields: List[Tuple[str, str]] = dataclasses.field(default_factory=list)
    body: str = ""
    code: str = ""
    code_lang: str = ""
    link: str = ""
    prefix: str = "🛡️ ping-shield"

    def _render(self, markdown: bool, limit: int) -> str:
        esc = escape_md if markdown else (lambda s: s)
        parts = [f"*{esc(self.prefix)}*" if markdown else self.prefix]
        parts.append(f"*{esc(self.title)}*" if markdown else self.title)
        parts.append("")
        for key, value in self.fields:
            parts.append(f"*{esc(key)}:* {esc(value)}" if markdown else f"{key}: {value}")
        if self.body:
            parts += ["", esc(self.body)]
        if self.link:
            parts += ["", f"[Read the full report]({escape_url(self.link)})" if markdown else self.link]
        text = "\n".join(parts)
        if self.code:
            opener = f"\n\n```{self.code_lang}\n" if markdown else "\n\n"
            closer = "\n```" if markdown else ""
            budget = limit - len(text) - len(opener) - len(closer) - 8
            if budget > 80:
                raw = self.code.splitlines()
                lines = _fit_lines([escape_code(l) for l in raw] if markdown else raw, budget)
                text += opener + "\n".join(lines) + closer
        if len(text) > limit:
            text = text[: limit - 1].rstrip("\\") + "…"
        return text

    def to_markdown(self, limit: int = MAX_MESSAGE_LEN) -> str:
        return self._render(True, limit)

    def to_plain(self, limit: int = MAX_MESSAGE_LEN) -> str:
        return self._render(False, limit)


def _validate_api_base(base: str) -> str:
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme == "https" and parsed.hostname:
        return base.rstrip("/")
    if parsed.scheme == "http" and parsed.hostname:
        host = parsed.hostname
        try:
            if host == "localhost" or ipaddress.ip_address(host).is_loopback:
                return base.rstrip("/")
        except ValueError:
            pass
    raise NotifyError(f"{API_BASE_ENV} must be an https:// URL (http:// is only allowed for loopback)")


class TelegramNotifier:
    """Minimal Telegram Bot API client."""

    def __init__(
        self,
        token: str,
        chat_id: str,
        timeout: float = 20.0,
        api_base: Optional[str] = None,
    ):
        self._token = token
        self.chat_id = chat_id
        self.timeout = timeout
        self._base = _validate_api_base(api_base or os.environ.get(API_BASE_ENV) or DEFAULT_API_BASE)

    def __repr__(self) -> str:
        return f"TelegramNotifier(chat_id={self.chat_id!r}, token=<redacted>)"

    def _scrub(self, text: str) -> str:
        return text.replace(self._token, "<redacted>") if self._token else text

    def _call(self, method: str, payload: Dict[str, Any]) -> Any:
        url = f"{self._base}/bot{self._token}/{method}"
        body = json.dumps(payload).encode("utf-8")
        last_error = "unknown error"
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            request = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # noqa: S310 - scheme validated
                    data = json.loads(resp.read(1_000_000).decode("utf-8"))
            except urllib.error.HTTPError as exc:
                try:
                    data = json.loads(exc.read(100_000).decode("utf-8"))
                except ValueError:
                    data = {"ok": False, "description": f"HTTP {exc.code}"}
                description = self._scrub(str(data.get("description", f"HTTP {exc.code}")))
                if exc.code == 429 and attempt < _MAX_ATTEMPTS:
                    retry_after = (data.get("parameters") or {}).get("retry_after", 5)
                    delay = min(float(retry_after), 60.0)
                    log.warning("Telegram rate limit hit; retrying %s in %.0fs", method, delay)
                    time.sleep(delay)
                    last_error = description
                    continue
                if exc.code >= 500 and attempt < _MAX_ATTEMPTS:
                    last_error = description
                    time.sleep(2**attempt)
                    continue
                raise NotifyError(f"Telegram {method} failed: {description}") from None
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_error = self._scrub(str(getattr(exc, "reason", exc)))
                if attempt < _MAX_ATTEMPTS:
                    log.debug("Telegram %s attempt %d failed: %s", method, attempt, last_error)
                    time.sleep(2**attempt)
                    continue
                break
            if not isinstance(data, dict) or not data.get("ok"):
                description = self._scrub(str(data.get("description", "unknown error")))
                raise NotifyError(f"Telegram {method} failed: {description}")
            return data.get("result")
        raise NotifyError(f"Telegram {method} failed after {_MAX_ATTEMPTS} attempts: {last_error}")

    # -- Bot API methods ----------------------------------------------------
    def get_me(self) -> Dict[str, Any]:
        result = self._call("getMe", {})
        return result if isinstance(result, dict) else {}

    def send_message(self, text: str, parse_mode: Optional[str] = "MarkdownV2") -> int:
        payload: Dict[str, Any] = {
            "chat_id": self.chat_id,
            "text": text,
            "link_preview_options": {"is_disabled": True},
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        result = self._call("sendMessage", payload)
        return int(result.get("message_id", 0)) if isinstance(result, dict) else 0

    def send_alert(self, alert: Alert) -> int:
        """Send *alert*; fall back to plain text if Telegram rejects the markup."""
        try:
            return self.send_message(alert.to_markdown())
        except NotifyError as exc:
            if "parse entities" not in str(exc).lower():
                raise
            log.warning("Telegram rejected MarkdownV2 (%s); resending as plain text", exc)
            return self.send_message(alert.to_plain(), parse_mode=None)

    def discover_chats(self) -> List[Tuple[str, str]]:
        """Return ``(chat_id, description)`` for chats that recently messaged the bot."""
        updates = self._call("getUpdates", {"timeout": 0, "allowed_updates": []}) or []
        chats: Dict[str, str] = {}
        for update in updates:
            for key in ("message", "channel_post", "my_chat_member", "edited_message"):
                chat = (update.get(key) or {}).get("chat")
                if not chat or "id" not in chat:
                    continue
                name = (
                    chat.get("title")
                    or " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
                    or chat.get("username")
                    or "unnamed"
                )
                chats[str(chat["id"])] = f"{name} [{chat.get('type', '?')}]"
        return sorted(chats.items())
