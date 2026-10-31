"""Telegram delivery for ping-shield alerts.

Standard library only: a security monitor should not drag a third-party HTTP
stack into its own supply chain. Messages are rendered as Telegram HTML with
inline URL buttons (with automatic plain-text and button-less fallbacks),
rate limits are honoured, and the bot token never appears in logs or
exception messages.
"""

from __future__ import annotations

import dataclasses
import html
import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from . import __version__

log = logging.getLogger(__name__)

API_BASE_ENV = "PING_SHIELD_TELEGRAM_API_BASE"
DEFAULT_API_BASE = "https://api.telegram.org"
USER_AGENT = f"ping-shield/{__version__} (+https://pypi.org/project/ping-shield/)"
MAX_MESSAGE_LEN = 4096
BRAND = "🛡 ping-shield"
_MAX_ATTEMPTS = 4


def esc(text: str) -> str:
    """Escape *text* for Telegram HTML."""
    return html.escape(text, quote=False)


def local_time(moment: Optional[datetime] = None) -> str:
    """Format *moment* (default: now) in the machine's local timezone, e.g. '31 Oct 2026, 14:05 EAT'."""
    moment = (moment or datetime.now(timezone.utc)).astimezone()
    return moment.strftime("%d %b %Y, %H:%M %Z").lstrip("0")


def hashtag(text: str) -> str:
    return re.sub(r"[^0-9A-Za-z_]+", "_", text).strip("_").lower()


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


def _cap(text: str, length: int) -> str:
    return text if len(text) <= length else text[: length - 1].rstrip() + "…"


@dataclasses.dataclass
class Field:
    icon: str
    label: str
    value: str
    mono: bool = False


@dataclasses.dataclass
class Button:
    """An inline keyboard button: opens *url*, or sends *callback* to ``ping-shield --bot``."""

    text: str
    url: str = ""
    callback: str = ""

    def to_api(self) -> Optional[Dict[str, str]]:
        if self.url.startswith(("https://", "http://")):
            return {"text": self.text, "url": self.url}
        if self.callback and len(self.callback.encode()) <= 64:
            return {"text": self.text, "callback_data": self.callback}
        return None


@dataclasses.dataclass
class Alert:
    """A structured alert, rendered to Telegram HTML or plain text within the size limit.

    Layout (every part optional except the title)::

        <banner>
        <icon> <title>
        <target>                 monospace
        <headline>               bold
        <quote>                  expandable blockquote
        <icon> <label>: <value>  one line per field
        • <bullet>
        <code block>
        <note_title> <note>
        #tags · 🛡 ping-shield
        [ button ] [ button ]    inline keyboard
    """

    title: str
    icon: str = "🛡"
    banner: str = ""
    target: str = ""
    headline: str = ""
    quote: str = ""
    fields: List[Field] = dataclasses.field(default_factory=list)
    bullets: List[str] = dataclasses.field(default_factory=list)
    code: str = ""
    code_lang: str = ""
    note_title: str = ""
    note: str = ""
    tags: List[str] = dataclasses.field(default_factory=list)
    buttons: List[List[Button]] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        self.title = _cap(self.title, 200)
        self.target = _cap(self.target, 300)
        self.headline = _cap(self.headline, 400)
        self.quote = _cap(self.quote, 1200)
        self.note = _cap(self.note, 400)
        self.fields = [dataclasses.replace(f, value=_cap(f.value, 300)) for f in self.fields[:8]]
        self.bullets = [_cap(b, 300) for b in self.bullets[:8]]

    def _footer(self) -> str:
        tags = " ".join(f"#{t}" for t in (hashtag(t) for t in self.tags) if t)
        return f"{tags} · {BRAND}" if tags else BRAND

    def _render(self, rich: bool, limit: int, inline_links: bool) -> str:
        e = esc if rich else (lambda s: s)
        bold = (lambda s: f"<b>{esc(s)}</b>") if rich else (lambda s: s)
        mono = (lambda s: f"<code>{esc(s)}</code>") if rich else (lambda s: s)

        head: List[str] = []
        if self.banner:
            head += [f"<i>{esc(self.banner)}</i>" if rich else self.banner, ""]
        head.append(f"{self.icon} {bold(self.title)}")
        if self.target:
            head.append(mono(self.target))
        if self.headline:
            head += ["", bold(self.headline)]
        if self.quote:
            head += ["", f"<blockquote expandable>{esc(self.quote)}</blockquote>" if rich else self.quote]
        if self.fields:
            head.append("")
            for f in self.fields:
                value = mono(f.value) if f.mono else e(f.value)
                head.append(f"{f.icon} {bold(f.label + ':')} {value}")
        if self.bullets:
            head.append("")
            head += [f"• {e(b)}" for b in self.bullets]

        tail: List[str] = []
        if self.note or self.note_title:
            tail += ["", " ".join(p for p in (bold(self.note_title) if self.note_title else "", e(self.note)) if p)]
        if inline_links:
            links = [b for row in self.buttons for b in row if b.url]
            if links:
                tail.append("")
                tail += [f'{e(b.text)}: <a href="{html.escape(b.url)}">{esc(b.url)}</a>' if rich
                         else f"{b.text}: {b.url}" for b in links]
        tail += ["", self._footer()]

        text_head, text_tail = "\n".join(head), "\n".join(tail)
        code = ""
        if self.code:
            opener = f'\n\n<pre><code class="language-{esc(self.code_lang)}">' if rich and self.code_lang else (
                "\n\n<pre>" if rich else "\n\n")
            closer = "</code></pre>" if rich and self.code_lang else ("</pre>" if rich else "")
            budget = limit - len(text_head) - len(text_tail) - len(opener) - len(closer) - 8
            if budget > 80:
                raw = self.code.splitlines()
                lines = _fit_lines([esc(l) for l in raw] if rich else raw, budget)
                code = opener + "\n".join(lines) + closer
        text = text_head + code + "\n" + text_tail
        if not rich and len(text) > limit:
            text = text[: limit - 1] + "…"
        # Rich text needs no final cut: every part is capped in __post_init__ and
        # Telegram counts the limit after entity parsing, so raw HTML overestimates.
        return text

    def to_html(self, limit: int = MAX_MESSAGE_LEN, inline_links: bool = False) -> str:
        return self._render(True, limit, inline_links)

    def to_plain(self, limit: int = MAX_MESSAGE_LEN) -> str:
        return self._render(False, limit, inline_links=True)

    def reply_markup(self) -> Optional[Dict[str, Any]]:
        rows = [[api for api in (b.to_api() for b in row) if api] for row in self.buttons]
        rows = [r for r in rows if r]
        return {"inline_keyboard": rows} if rows else None


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

    def _call(self, method: str, payload: Dict[str, Any], timeout: Optional[float] = None) -> Any:
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
                with urllib.request.urlopen(request, timeout=timeout or self.timeout) as resp:  # noqa: S310 - scheme validated
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

    def send_message(
        self,
        text: str,
        parse_mode: Optional[str] = "HTML",
        reply_markup: Optional[Dict[str, Any]] = None,
        reply_to: Optional[int] = None,
        chat_id: Optional[Any] = None,
    ) -> int:
        payload: Dict[str, Any] = {
            "chat_id": chat_id if chat_id is not None else self.chat_id,
            "text": text,
            "link_preview_options": {"is_disabled": True},
        }
        if parse_mode:
            payload["parse_mode"] = parse_mode
        if reply_markup:
            payload["reply_markup"] = reply_markup
        if reply_to:
            payload["reply_parameters"] = {"message_id": reply_to, "allow_sending_without_reply": True}
        result = self._call("sendMessage", payload)
        return int(result.get("message_id", 0)) if isinstance(result, dict) else 0

    def send_alert(self, alert: Alert) -> int:
        """Send *alert*, degrading gracefully if Telegram rejects the markup or a button."""
        markup = alert.reply_markup()
        try:
            return self.send_message(alert.to_html(), reply_markup=markup)
        except NotifyError as exc:
            reason = str(exc).lower()
            if markup and "button" in reason:
                log.warning("Telegram rejected an inline button (%s); sending links inline", exc)
                return self.send_message(alert.to_html(inline_links=True))
            if "parse entities" in reason:
                log.warning("Telegram rejected the HTML (%s); resending as plain text", exc)
                return self.send_message(alert.to_plain(), parse_mode=None)
            raise

    def get_updates(self, offset: Optional[int], poll_seconds: int = 50) -> List[Dict[str, Any]]:
        payload: Dict[str, Any] = {"timeout": poll_seconds, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            payload["offset"] = offset
        result = self._call("getUpdates", payload, timeout=poll_seconds + 15)
        return result if isinstance(result, list) else []

    def answer_callback(self, callback_id: str, text: str = "", alert: bool = False) -> None:
        self._call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:200], "show_alert": alert})

    def edit_reply_markup(self, chat_id: Any, message_id: int, markup: Optional[Dict[str, Any]]) -> None:
        self._call("editMessageReplyMarkup", {"chat_id": chat_id, "message_id": message_id,
                                              "reply_markup": markup or {"inline_keyboard": []}})

    def set_commands(self, commands: List[Tuple[str, str]]) -> None:
        self._call("setMyCommands", {"commands": [{"command": c, "description": d} for c, d in commands]})

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
