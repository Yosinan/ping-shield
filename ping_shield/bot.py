"""Interactive Telegram bot (``ping-shield --bot``).

Long-polls the Bot API and handles:

* alert buttons: "✅ It was me", "🚨 Not me" (replies with a response
  checklist), "🔕 Mute <keyword>";
* commands: /status, /scan, /sources, /catalog, /addsource, /removesource,
  /mute, /unmute, /help.

Only the chat configured in ``config.json`` is served; everyone else gets a
refusal, so a stranger who finds the bot cannot run scans or change sources.
"""

from __future__ import annotations

import hashlib
import html
import logging
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import sources
from .config import Config, load_config, save_config, state_path
from .intel import add_sources, detect_distro_ids, remove_sources
from .notify import BRAND, NotifyError, TelegramNotifier, esc, local_time

log = logging.getLogger(__name__)

COMMANDS: List[Tuple[str, str]] = [
    ("status", "Monitored targets, sources and timer status"),
    ("scan", "Run a scan right now"),
    ("sources", "List your news sources"),
    ("catalog", "Browse official sources and channels to add"),
    ("addsource", "Add a source: URL, t.me/channel or catalog id"),
    ("removesource", "Remove a source"),
    ("mute", "Stop news alerts that only match a keyword"),
    ("unmute", "Re-enable a muted keyword"),
    ("help", "Show what this bot can do"),
]

PLAYBOOKS: Dict[str, Tuple[str, List[str]]] = {
    "ssh": ("SSH key you didn't add", [
        "Remove the unknown line: <code>nano ~/.ssh/authorized_keys</code>",
        "Check recent logins: <code>last -a | head -20</code> and "
        "<code>journalctl -u sshd -u ssh --since -7d | grep Accepted</code>",
        "Look for other persistence: <code>crontab -l</code> and "
        "<code>systemctl --user list-unit-files --state=enabled</code>",
        "Rotate your SSH keys and any secrets stored on this machine.",
        "Run <code>ping-shield --run</code> to confirm the file is clean.",
    ]),
    "persistence": ("Auto-start entry you didn't create", [
        "Open the file named in the alert and note every command and URL it runs.",
        "Disable it: <code>systemctl --user disable --now NAME</code>, <code>crontab -e</code>, "
        "or delete the <code>.desktop</code> / rc-file line.",
        "Look for what it started: <code>ps -ef --forest</code> and <code>ss -tunap</code>",
        "Check <code>~/.ssh/authorized_keys</code> and your shell rc files for related changes.",
        "If the code ran, rotate credentials stored on this machine (cloud CLIs, tokens, .env files).",
    ]),
    "extensions": ("IDE extension you didn't expect", [
        "Uninstall it: <code>code --uninstall-extension ID</code> or "
        "<code>cursor --uninstall-extension ID</code>",
        "Check the publisher and recent reports about it on the marketplace.",
        "Extensions often drop persistence: check SSH keys, systemd user units and crontab.",
        "Rotate tokens your IDE could read: GitHub, cloud CLIs, <code>.env</code> files.",
    ]),
}

HELP = f"""<b>{BRAND}</b> · interactive controls

<b>Alerts</b>
✅ <b>It was me</b> marks a change as expected
🚨 <b>Not me</b> sends a step-by-step response checklist
🔕 <b>Mute</b> stops news that only matches that keyword

<b>Commands</b>
""" + "\n".join(f"/{c} · {esc(d)}" for c, d in COMMANDS)


def _source_hash(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:10]


def _pre(text: str) -> str:
    text = text.strip() or "(no output)"
    if len(text) > 3500:
        text = text[:3500] + "\n…"
    return f"<pre>{esc(text)}</pre>"


class Bot:
    def __init__(
        self,
        notifier: TelegramNotifier,
        config_loader: Callable[[], Config] = load_config,
        cli: Optional[List[str]] = None,
    ):
        self.notifier = notifier
        self.config_loader = config_loader
        self.cli = cli or [sys.executable, "-m", "ping_shield"]

    # -- helpers --------------------------------------------------------------
    def _authorized(self, chat: Dict[str, Any], config: Config) -> bool:
        wanted = config.telegram_chat_id.strip()
        if str(chat.get("id")) == wanted:
            return True
        username = chat.get("username")
        return bool(username) and wanted.lower() == f"@{username}".lower()

    def _reply(self, text: str, reply_to: Optional[int] = None,
               markup: Optional[Dict[str, Any]] = None) -> None:
        self.notifier.send_message(text, reply_markup=markup, reply_to=reply_to)

    def _run_cli(self, *args: str, timeout: int = 600) -> str:
        proc = subprocess.run([*self.cli, *args], capture_output=True, text=True, timeout=timeout, check=False)
        return proc.stdout + (("\n" + proc.stderr) if proc.returncode and proc.stderr else "")

    @staticmethod
    def _replace_button(markup: Dict[str, Any], data: str, new: Dict[str, Any],
                        whole_row: bool = False) -> Dict[str, Any]:
        rows = []
        for row in (markup or {}).get("inline_keyboard", []):
            if any(b.get("callback_data") == data for b in row):
                rows.append([new] if whole_row else [new if b.get("callback_data") == data else b for b in row])
            else:
                rows.append(row)
        return {"inline_keyboard": rows}

    # -- update dispatch ------------------------------------------------------
    def handle(self, update: Dict[str, Any]) -> None:
        config = self.config_loader()
        if "callback_query" in update:
            self._handle_callback(update["callback_query"], config)
            return
        message = update.get("message") or {}
        text = (message.get("text") or "").strip()
        if not text.startswith("/"):
            return
        if not self._authorized(message.get("chat", {}), config):
            log.warning("ignored command from unauthorized chat %s", message.get("chat", {}).get("id"))
            self.notifier.send_message(
                "⛔ This is a private ping-shield bot. Run your own: <code>pip install ping-shield</code>",
                chat_id=message["chat"]["id"],
            )
            return
        command, _, arg = text.partition(" ")
        command = command[1:].split("@", 1)[0].lower()
        handler = getattr(self, f"cmd_{command}", None)
        if handler is None:
            self._reply(f"Unknown command /{esc(command)}. Send /help for the list.")
            return
        handler(arg.strip(), config, message.get("message_id"))

    def _handle_callback(self, query: Dict[str, Any], config: Config) -> None:
        message = query.get("message") or {}
        chat = message.get("chat", {})
        data = query.get("data", "")
        if not self._authorized(chat, config):
            self.notifier.answer_callback(query["id"], "⛔ Not authorized", alert=True)
            return
        who = query.get("from", {}).get("first_name", "you")
        when = local_time().split(", ", 1)[-1]
        markup = message.get("reply_markup", {})
        message_id = message.get("message_id")
        action, _, value = data.partition(":")

        if action == "noop":
            self.notifier.answer_callback(query["id"], "Already handled ✔️")
            return
        if action == "ack":
            done = {"text": f"✅ Confirmed by {who} · {when}", "callback_data": "noop"}
            self.notifier.edit_reply_markup(chat["id"], message_id, self._replace_button(markup, data, done, True))
            self.notifier.answer_callback(query["id"], "Marked as expected ✅")
            return
        if action == "sus":
            flagged = {"text": f"🚨 Flagged by {who} · {when}", "callback_data": "noop"}
            self.notifier.edit_reply_markup(chat["id"], message_id, self._replace_button(markup, data, flagged, True))
            title, steps = PLAYBOOKS.get(value, PLAYBOOKS["persistence"])
            body = "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
            self._reply(f"🧯 <b>Response checklist · {esc(title)}</b>\n\n{body}\n\n<i>{BRAND}</i>",
                        reply_to=message_id)
            self.notifier.answer_callback(query["id"], "Response checklist sent 🧯")
            return
        if action == "mute":
            fresh = load_config(apply_env=False)
            if value.lower() not in (k.lower() for k in fresh.muted_keywords):
                fresh.muted_keywords.append(value)
                save_config(fresh)
            muted = {"text": f"🔕 Muted “{value}”", "callback_data": "noop"}
            self.notifier.edit_reply_markup(chat["id"], message_id, self._replace_button(markup, data, muted))
            self.notifier.answer_callback(query["id"], f"🔕 “{value}” muted. Undo with /unmute {value}")
            return
        if action == "add":
            result = add_sources(load_config(apply_env=False), [value], state_path())[0]
            label = f"✅ {result.name or value}" if result.ok else f"⚠️ {result.name or value}"
            self.notifier.edit_reply_markup(chat["id"], message_id,
                                            self._replace_button(markup, data, {"text": label, "callback_data": "noop"}))
            self.notifier.answer_callback(query["id"], f"{result.name or value}: {result.message}", alert=not result.ok)
            return
        if action == "rm":
            fresh = load_config(apply_env=False)
            url = next((f for f in fresh.feeds if _source_hash(f) == value), None)
            if url:
                remove_sources(fresh, [url])
            label = f"🗑 Removed {sources.display_name(url)}" if url else "Already removed"
            self.notifier.edit_reply_markup(chat["id"], message_id,
                                            self._replace_button(markup, data, {"text": label, "callback_data": "noop"}))
            self.notifier.answer_callback(query["id"], label)
            return
        self.notifier.answer_callback(query["id"], "This button has expired.")

    # -- commands -------------------------------------------------------------
    def cmd_start(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        self.cmd_help(arg, config, message_id)

    def cmd_help(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        self._reply(HELP)

    def cmd_status(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        self._reply("📋 <b>Status</b>\n" + _pre(self._run_cli("--status", timeout=60)), reply_to=message_id)

    def cmd_scan(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        self._reply("⏳ Scanning… alerts arrive as separate messages.", reply_to=message_id)
        self._reply("🔍 <b>Scan finished</b>\n" + _pre(self._run_cli("--run")), reply_to=message_id)

    def cmd_sources(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        if not config.feeds:
            self._reply("No sources yet. Browse /catalog or use /addsource.")
            return
        lines = [f"{i}. {esc(sources.display_name(u))}" for i, u in enumerate(config.feeds, 1)]
        rows = [[{"text": f"🗑 {sources.display_name(u)}"[:60], "callback_data": f"rm:{_source_hash(u)}"}]
                for u in config.feeds]
        self._reply("📡 <b>Your sources</b>\n\n" + "\n".join(lines)
                    + "\n\nTap a button to remove a source, or browse /catalog to add more.",
                    markup={"inline_keyboard": rows})

    def cmd_catalog(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        recommended = {s.id for s in sources.recommended(detect_distro_ids())}
        available = [s for s in sources.CATALOG if s.url not in config.feeds]
        if not available:
            self._reply("You're subscribed to every catalog source. Add your own with /addsource.")
            return
        blocks, rows = [], []
        for group, title in sources.GROUP_TITLES.items():
            entries = [s for s in available if s.group == group]
            if not entries:
                continue
            blocks.append(f"<b>{title}</b>")
            for s in entries:
                star = " ⭐" if s.id in recommended else ""
                blocks.append(f"• {esc(s.name)}{star}: <i>{esc(s.description)}</i>")
                rows.append([{"text": f"➕ {s.name}{star}"[:60], "callback_data": f"add:{s.id}"}])
            blocks.append("")
        self._reply("🗂 <b>Source catalog</b>\n⭐ recommended for this machine\n\n" + "\n".join(blocks)
                    + "Tap to subscribe. Any public channel works too: <code>/addsource t.me/name</code>",
                    markup={"inline_keyboard": rows})

    def cmd_addsource(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        if not arg:
            self._reply("Usage: <code>/addsource https://example.com/feed.xml</code>, "
                        "<code>/addsource t.me/channel</code> or a /catalog id")
            return
        self._reply("⏳ Checking source…", reply_to=message_id)
        lines = []
        for r in add_sources(load_config(apply_env=False), arg.split(), state_path()):
            icon = "✅" if r.ok else "⚠️"
            lines.append(f"{icon} <b>{esc(r.name or r.value)}</b>: {esc(r.message)}")
        self._reply("\n".join(lines), reply_to=message_id)

    def cmd_removesource(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        if not arg:
            self.cmd_sources(arg, config, message_id)
            return
        lines = []
        for r in remove_sources(load_config(apply_env=False), arg.split()):
            icon = "🗑" if r.ok else "⚠️"
            lines.append(f"{icon} <b>{esc(r.name or r.value)}</b>: {esc(r.message)}")
        self._reply("\n".join(lines), reply_to=message_id)

    def cmd_mute(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        fresh = load_config(apply_env=False)
        if not arg:
            muted = ", ".join(fresh.muted_keywords) or "nothing"
            self._reply(f"🔕 Muted: {esc(muted)}\nUsage: <code>/mute keyword</code>")
            return
        if arg.lower() not in (k.lower() for k in fresh.muted_keywords):
            fresh.muted_keywords.append(arg)
            save_config(fresh)
        self._reply(f"🔕 News that only matches “{esc(arg)}” won't alert anymore.", reply_to=message_id)

    def cmd_unmute(self, arg: str, config: Config, message_id: Optional[int]) -> None:
        fresh = load_config(apply_env=False)
        before = len(fresh.muted_keywords)
        fresh.muted_keywords = [k for k in fresh.muted_keywords if k.lower() != arg.lower()]
        if len(fresh.muted_keywords) != before:
            save_config(fresh)
            self._reply(f"🔔 “{esc(arg)}” is active again.", reply_to=message_id)
        else:
            self._reply(f"“{esc(arg)}” wasn't muted. Muted: {esc(', '.join(fresh.muted_keywords) or 'nothing')}")

    # -- main loop ------------------------------------------------------------
    def run_forever(self) -> None:
        try:
            self.notifier.set_commands(COMMANDS)
        except NotifyError as exc:
            log.warning("could not register bot commands: %s", exc)
        offset: Optional[int] = None
        log.info("bot listening for commands and button presses")
        while True:
            try:
                updates = self.notifier.get_updates(offset)
            except NotifyError as exc:
                delay = 30 if "conflict" in str(exc).lower() else 10
                log.warning("getUpdates failed (%s); retrying in %ss", exc, delay)
                time.sleep(delay)
                continue
            for update in updates:
                offset = update["update_id"] + 1
                try:
                    self.handle(update)
                except Exception as exc:  # noqa: BLE001 - one bad update must not kill the bot
                    log.exception("failed to handle update %s", update.get("update_id"))
                    query = update.get("callback_query")
                    if query:
                        try:
                            self.notifier.answer_callback(query["id"], f"⚠️ {html.unescape(str(exc))[:150]}")
                        except NotifyError:
                            pass
