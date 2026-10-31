"""Host integrity auditing: SSH trust, persistence vectors and IDE extensions.

Every monitored location is a *target*. A target produces a :class:`Snapshot`
(a canonical, JSON-serialisable description plus a SHA-256 fingerprint). The
first snapshot of a target becomes its baseline; afterwards an alert is sent
only when the fingerprint changes, and the baseline is advanced only after
Telegram confirms delivery. A change is therefore reported exactly once:
never lost on a network failure, never repeated after it was delivered.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import json
import logging
import os
import re
import shutil
import socket
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import Config, StateStore, config_home, disabled
from .notify import Alert, Button, Field, NotifyError, TelegramNotifier, local_time

log = logging.getLogger(__name__)

MAX_TEXT_BYTES = 512 * 1024  # larger files are fingerprinted but not diffed
MAX_HASH_BYTES = 64 * 1024 * 1024
MAX_TREE_ENTRIES = 2000
MAX_DIFF_LINES = 400

# category -> (icon, title, why it matters)
CATEGORIES = {
    "ssh": ("🚨", "SSH Trust Change", "this file controls who can log in to your account over SSH."),
    "persistence": ("⚙️", "Persistence Change", "this location runs code automatically at login, boot or in every new shell."),
    "extensions": ("🧩", "IDE Extension Change", "extensions run inside your IDE with your full user privileges."),
}

_SECRET_PATTERNS = (
    # FOO_TOKEN=..., password: ..., export API_KEY="..."
    re.compile(
        r"(?i)\b([A-Z0-9_.-]*(?:TOKEN|SECRET|PASSW(?:OR)?D|PASSPHRASE|API[_-]?KEY|ACCESS[_-]?KEY|"
        r"PRIVATE[_-]?KEY|CREDENTIALS?|AUTH)[A-Z0-9_.-]*[\"']?\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"
    ),
    # scheme://user:password@host
    re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)([^\s@/]+)(?=@)"),
)
_TOKEN_SHAPES = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|"
    r"\d{5,16}:[A-Za-z0-9_-]{35})\b"
)
REDACTED = "«redacted»"


def redact(text: str) -> str:
    """Mask credential-looking values so diffs of shell rc files never leak secrets to Telegram."""
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
    return _TOKEN_SHAPES.sub(REDACTED, text)


def _fingerprint(data: Any) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def diff_stats(diff: str) -> str:
    """Summarise a rendered diff, e.g. '🟢 2 added · 🔴 1 removed'."""
    lines = diff.splitlines()
    added = sum(1 for l in lines if l.startswith("+") and not l.startswith("+++"))
    removed = sum(1 for l in lines if l.startswith("-") and not l.startswith("---"))
    modified = sum(1 for l in lines if l.startswith("!"))
    parts = [f"{icon} {n} {word}" for icon, n, word in
             (("🟢", added, "added"), ("🔴", removed, "removed"), ("🟡", modified, "modified")) if n]
    return " · ".join(parts) or "metadata only"


def _display(path: Path) -> str:
    home = str(Path.home())
    text = str(path)
    return "~" + text[len(home):] if text == home or text.startswith(home + os.sep) else text


# --------------------------------------------------------------------------- #
# Snapshots
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Snapshot:
    kind: str  # "text" | "tree" | "inventory"
    data: Dict[str, Any]
    warnings: List[str] = dataclasses.field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.data)


def _hash_file(path: Path, limit: int = MAX_HASH_BYTES) -> Optional[str]:
    digest = hashlib.sha256()
    remaining = limit
    with open(path, "rb") as fh:
        while remaining > 0:
            chunk = fh.read(min(1 << 20, remaining))
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
            remaining -= len(chunk)
    return None  # larger than the hashing budget


def _read_text_entry(path: Path) -> Dict[str, Any]:
    """Describe a single regular file: hash, mode, owner and (if small) its lines."""
    st = path.stat()
    entry: Dict[str, Any] = {
        "mode": format(stat.S_IMODE(st.st_mode), "04o"),
        "uid": st.st_uid,
        "size": st.st_size,
    }
    if st.st_size <= MAX_TEXT_BYTES:
        raw = path.read_bytes()
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        entry["lines"] = raw.decode("utf-8", errors="replace").splitlines()
    else:
        entry["sha256"] = _hash_file(path) or f"oversize:{st.st_size}"
        entry["lines"] = None
    return entry


def _permission_warnings(path: Path, entry: Dict[str, Any]) -> List[str]:
    warnings = []
    mode = int(entry["mode"], 8)
    if mode & 0o022:
        warnings.append(f"{_display(path)} is writable by group/others (mode {entry['mode']})")
    if entry["uid"] != os.getuid():
        warnings.append(f"{_display(path)} is owned by uid {entry['uid']}, not by you")
    return warnings


def collect_text_file(path: Path, check_permissions: bool = False) -> Snapshot:
    data: Dict[str, Any] = {"exists": False}
    warnings: List[str] = []
    if path.is_symlink():
        data["symlink"] = os.readlink(path)
    if path.exists():
        if not path.is_file():
            data.update({"exists": True, "type": "not-a-regular-file"})
            warnings.append(f"{_display(path)} exists but is not a regular file")
        else:
            data["exists"] = True
            data.update(_read_text_entry(path))
            if check_permissions:
                warnings += _permission_warnings(path, data)
    return Snapshot("text", data, warnings)


def collect_tree(root: Path) -> Snapshot:
    """Snapshot every file and symlink under *root* (e.g. ~/.config/systemd/user)."""
    files: Dict[str, Any] = {}
    warnings: List[str] = []
    if not root.is_dir():
        return Snapshot("tree", {"files": files})
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for name in list(dirnames):
            if (base / name).is_symlink():
                dirnames.remove(name)
                filenames.append(name)
        dirnames.sort()
        for name in sorted(filenames):
            if len(files) >= MAX_TREE_ENTRIES:
                warnings.append(f"{_display(root)} has more than {MAX_TREE_ENTRIES} entries; list truncated")
                return Snapshot("tree", {"files": files, "truncated": True}, warnings)
            full = base / name
            rel = str(full.relative_to(root))
            try:
                if full.is_symlink():
                    files[rel] = {"link": os.readlink(full)}
                elif full.is_file():
                    files[rel] = _read_text_entry(full)
                    if int(files[rel]["mode"], 8) & 0o022:
                        warnings += _permission_warnings(full, files[rel])
            except OSError as exc:
                files[rel] = {"error": exc.strerror or str(exc)}
    return Snapshot("tree", {"files": files}, warnings)


def collect_crontab() -> Optional[Snapshot]:
    """Snapshot ``crontab -l``; returns None when cron is not installed."""
    binary = shutil.which("crontab")
    if not binary:
        return None
    proc = subprocess.run(
        [binary, "-l"],
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "LC_ALL": "C"},
        check=False,
    )
    if proc.returncode == 0:
        return Snapshot("text", {"exists": True, "lines": proc.stdout.splitlines()})
    if "no crontab" in proc.stderr.lower():
        return Snapshot("text", {"exists": False})
    raise RuntimeError(f"crontab -l failed: {proc.stderr.strip() or proc.returncode}")


def _extension_entry(ext_dir: Path) -> Dict[str, Any]:
    digest = hashlib.sha256()
    entry: Dict[str, Any] = {"id": ext_dir.name, "version": "?"}
    manifest = ext_dir / "package.json"
    if not manifest.is_file():
        entry["sha256"] = None
        return entry
    raw = manifest.read_bytes()[: 8 * 1024 * 1024]
    digest.update(raw)
    try:
        meta = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        meta = {}
    if isinstance(meta, dict):
        publisher, name = meta.get("publisher"), meta.get("name")
        if isinstance(publisher, str) and isinstance(name, str):
            entry["id"] = f"{publisher}.{name}".lower()
        if isinstance(meta.get("version"), str):
            entry["version"] = meta["version"]
        # Hash the code the IDE actually executes on activation.
        for key in ("main", "browser"):
            rel = meta.get(key)
            if not isinstance(rel, str) or not rel:
                continue
            root = ext_dir.resolve()
            candidates = [ext_dir / rel] + ([ext_dir / f"{rel}.js"] if not rel.endswith(".js") else [])
            for candidate in candidates:
                resolved = candidate.resolve()
                if resolved.is_file() and (resolved == root or root in resolved.parents):
                    file_hash = _hash_file(resolved)
                    digest.update(f"\0{key}\0{file_hash}".encode())
                    break
    entry["sha256"] = digest.hexdigest()
    return entry


def collect_extensions(directory: Path) -> Snapshot:
    """Inventory installed extensions: id, version and a hash of manifest + entry point."""
    items: Dict[str, Any] = {}
    if directory.is_dir():
        for child in sorted(directory.iterdir()):
            if child.name.startswith("."):
                continue
            try:
                if child.is_symlink():
                    items[child.name] = {"id": child.name, "version": "?", "link": os.readlink(child)}
                elif child.is_dir():
                    items[child.name] = _extension_entry(child)
            except OSError as exc:
                items[child.name] = {"id": child.name, "version": "?", "error": exc.strerror or str(exc)}
    return Snapshot("inventory", {"items": items})


# --------------------------------------------------------------------------- #
# Diff rendering
# --------------------------------------------------------------------------- #
def _meta_line(key: str, old: Dict[str, Any], new: Dict[str, Any]) -> Optional[str]:
    if old.get(key) != new.get(key):
        return f"# {key}: {old.get(key, '-')} → {new.get(key, '-')}"
    return None


def _text_diff(old: Dict[str, Any], new: Dict[str, Any], label: str) -> List[str]:
    out: List[str] = []
    if old.get("exists") != new.get("exists"):
        out.append(f"# {label} was {'created' if new.get('exists') else 'deleted'}")
    for key in ("symlink", "type", "mode", "uid"):
        line = _meta_line(key, old, new)
        if line and old.get("exists") and new.get("exists"):
            out.append(line)
    old_lines, new_lines = old.get("lines"), new.get("lines")
    if old.get("exists") and new.get("exists") and (old_lines is None or new_lines is None):
        if old.get("sha256") != new.get("sha256"):
            out.append(f"# content changed (too large to diff): sha256 {old.get('sha256')} → {new.get('sha256')}")
        return out
    out += list(
        difflib.unified_diff(
            old_lines or [], new_lines or [], fromfile=f"a/{label}", tofile=f"b/{label}", lineterm="", n=2
        )
    )
    return out


def _tree_diff(old: Dict[str, Any], new: Dict[str, Any], label: str) -> List[str]:
    out: List[str] = []
    old_files, new_files = old.get("files", {}), new.get("files", {})
    for rel in sorted(set(old_files) | set(new_files)):
        before, after = old_files.get(rel), new_files.get(rel)
        if before == after:
            continue
        path = f"{label}/{rel}"
        if before is None:
            out.append(f"# NEW {path}")
        elif after is None:
            out.append(f"# REMOVED {path}")
        if (before or {}).get("link") or (after or {}).get("link"):
            out.append(f"# link {path}: {(before or {}).get('link', '-')} → {(after or {}).get('link', '-')}")
            continue
        old_entry = {"exists": before is not None, **(before or {})}
        new_entry = {"exists": after is not None, **(after or {})}
        diff = _text_diff(old_entry, new_entry, path)
        out += [line for line in diff if not line.startswith(f"# {path} was ")]
    return out


def _inventory_diff(old: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    old_items, new_items = old.get("items", {}), new.get("items", {})
    removed = {k: old_items[k] for k in set(old_items) - set(new_items)}
    added = {k: new_items[k] for k in set(new_items) - set(old_items)}
    out: List[str] = []
    # A normal update removes publisher.name-1.0 and adds publisher.name-1.1.
    removed_by_id = {v.get("id"): (k, v) for k, v in removed.items()}
    for key in sorted(added):
        item = added[key]
        previous = removed_by_id.pop(item.get("id"), None)
        if previous:
            del removed[previous[0]]
            out.append(f"! {item.get('id')}: updated {previous[1].get('version')} → {item.get('version')}")
        else:
            suffix = f" (symlink → {item['link']})" if item.get("link") else ""
            out.append(f"+ {item.get('id')}@{item.get('version')} installed ({key}){suffix}")
    for key in sorted(removed):
        out.append(f"- {removed[key].get('id')}@{removed[key].get('version')} removed ({key})")
    for key in sorted(set(old_items) & set(new_items)):
        if old_items[key] != new_items[key]:
            item = new_items[key]
            out.append(
                f"! {item.get('id')}@{item.get('version')}: files modified in place "
                f"without a version change (possible tampering)"
            )
    return out


def render_diff(kind: str, old: Dict[str, Any], new: Dict[str, Any], label: str) -> str:
    if kind == "text":
        lines = _text_diff(old, new, label)
    elif kind == "tree":
        lines = _tree_diff(old, new, label)
    else:
        lines = _inventory_diff(old, new)
    if len(lines) > MAX_DIFF_LINES:
        lines = lines[:MAX_DIFF_LINES] + [f"… {len(lines) - MAX_DIFF_LINES} more line(s)"]
    return redact("\n".join(lines))


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Target:
    id: str
    label: str
    category: str
    collect: Callable[[], Optional[Snapshot]]


_IDE_NAMES = {
    ".vscode": "VS Code",
    ".cursor": "Cursor",
    ".vscode-oss": "VSCodium",
    ".windsurf": "Windsurf",
    ".vscode-server": "VS Code Server",
}

_SHELL_FILES = (
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".xprofile",
    ".config/fish/config.fish",
)


def default_targets(config: Config) -> List[Target]:
    home = Path.home()
    ssh = home / ".ssh"
    xdg = config_home()
    targets: List[Target] = []

    def text(target_id: str, path: Path, category: str, perms: bool = False) -> None:
        targets.append(Target(target_id, _display(path), category, lambda: collect_text_file(path, perms)))

    def tree(target_id: str, path: Path) -> None:
        targets.append(Target(target_id, _display(path), "persistence", lambda: collect_tree(path)))

    text("ssh.authorized_keys", ssh / "authorized_keys", "ssh", perms=True)
    text("ssh.authorized_keys2", ssh / "authorized_keys2", "ssh", perms=True)
    text("ssh.rc", ssh / "rc", "ssh", perms=True)
    text("ssh.environment", ssh / "environment", "ssh", perms=True)

    targets.append(Target("cron.user", "user crontab", "persistence", collect_crontab))
    tree("systemd.user", xdg / "systemd" / "user")
    tree("autostart", xdg / "autostart")
    tree("environment.d", xdg / "environment.d")
    tree("shell.bashrc.d", home / ".bashrc.d")
    for rel in _SHELL_FILES:
        slug = rel.split("/")[-1].lstrip(".").replace(".", "_")
        text(f"shell.{slug}", home / rel, "persistence")

    for raw in config.extension_dirs:
        path = Path(os.path.expanduser(raw))
        parent = path.parent.name if path.name == "extensions" else path.name
        name = _IDE_NAMES.get(parent, parent or str(path))
        slug = re.sub(r"[^a-z0-9]+", "-", parent.lower()).strip("-") or "custom"
        targets.append(
            Target(f"ext.{slug}", f"{name} extensions ({_display(path)})", "extensions",
                   lambda p=path: collect_extensions(p))
        )
    return [t for t in targets if not disabled(t.id, config.disabled_checks)]


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Event:
    target: Target
    diff: str
    warnings: List[str]
    alert: Alert
    delivered: bool = False
    message_id: int = 0
    error: Optional[str] = None


@dataclasses.dataclass
class ScanReport:
    baselined: List[str] = dataclasses.field(default_factory=list)
    unchanged: int = 0
    events: List[Event] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)

    @property
    def undelivered(self) -> List[Event]:
        return [e for e in self.events if not e.delivered]


class Monitor:
    def __init__(
        self,
        config: Config,
        state: StateStore,
        notifier: Optional[TelegramNotifier],
        banner: str = "",
        interactive: bool = False,
    ):
        self.config = config
        self.state = state
        self.notifier = notifier
        self.banner = banner
        self.interactive = interactive  # add callback buttons handled by `ping-shield --bot`
        self.targets = default_targets(config)
        self.hostname = socket.gethostname()

    def target(self, target_id: str) -> Target:
        for t in self.targets:
            if t.id == target_id:
                return t
        raise KeyError(target_id)

    def _record(self, snapshot: Snapshot) -> Dict[str, Any]:
        return {
            "fingerprint": snapshot.fingerprint,
            "kind": snapshot.kind,
            "data": snapshot.data,
            "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def _build_alert(self, target: Target, diff: str, warnings: Sequence[str], baseline: bool) -> Alert:
        icon, title, why = CATEGORIES.get(target.category, ("🔔", "Change Detected", ""))
        fields = [Field("🖥", "Host", self.hostname, mono=True), Field("🕒", "Detected", local_time())]
        if baseline:
            return Alert(
                icon="🔓",
                title="Insecure Configuration",
                target=target.label,
                banner=self.banner,
                fields=fields,
                bullets=list(warnings),
                note_title="🛠 Fix:",
                note="tighten the permissions (e.g. chmod 600) so no other user can modify it.",
                tags=[target.category, self.hostname],
            )
        fields.append(Field("📊", "Changes", diff_stats(diff)))
        return Alert(
            icon=icon,
            title=title,
            target=target.label,
            banner=self.banner,
            fields=fields,
            bullets=[f"⚠️ {w}" for w in warnings],
            code=diff,
            code_lang="diff",
            note_title="⚠️ Not you?",
            note=f"Investigate immediately: {why}" if why else "Investigate immediately.",
            tags=[target.category, self.hostname],
            buttons=[[Button("✅ It was me", callback="ack"),
                      Button("🚨 Not me", callback=f"sus:{target.category}")]] if self.interactive else [],
        )

    def _deliver(self, event: Event) -> None:
        if self.notifier is None:
            event.error = "Telegram is not configured"
            return
        try:
            event.message_id = self.notifier.send_alert(event.alert)
            event.delivered = True
        except NotifyError as exc:
            event.error = str(exc)
            log.error("could not deliver alert for %s: %s", event.target.id, exc)

    def scan(self, targets: Optional[Sequence[Target]] = None) -> ScanReport:
        report = ScanReport()
        section = self.state.section("monitor")
        for target in targets if targets is not None else self.targets:
            try:
                snapshot = target.collect()
            except Exception as exc:  # noqa: BLE001 - one broken target must not stop the scan
                report.errors.append(f"{target.id}: {exc}")
                log.warning("check %s failed: %s", target.id, exc)
                continue
            if snapshot is None:
                continue
            previous = section.get(target.id)
            if previous is None:
                if snapshot.warnings:
                    event = Event(target, "", snapshot.warnings,
                                  self._build_alert(target, "", snapshot.warnings, baseline=True))
                    self._deliver(event)
                    report.events.append(event)
                    if not event.delivered:
                        continue  # retry the warning on the next run
                section[target.id] = self._record(snapshot)
                self.state.save()
                report.baselined.append(target.id)
                continue
            if previous.get("fingerprint") == snapshot.fingerprint:
                report.unchanged += 1
                continue
            diff = render_diff(snapshot.kind, previous.get("data", {}), snapshot.data, target.label)
            event = Event(target, diff, snapshot.warnings,
                          self._build_alert(target, diff, snapshot.warnings, baseline=False))
            self._deliver(event)
            report.events.append(event)
            if event.delivered:
                # Advance the baseline only once Telegram has the alert:
                # undelivered changes are retried, delivered ones never repeat.
                section[target.id] = self._record(snapshot)
                self.state.save()
        return report

    def rebaseline(self, target_ids: Optional[Sequence[str]] = None) -> List[str]:
        """Accept the current state of targets as trusted without alerting."""
        section = self.state.section("monitor")
        done = []
        for target in self.targets:
            if target_ids is not None and target.id not in target_ids:
                continue
            try:
                snapshot = target.collect()
            except Exception as exc:  # noqa: BLE001
                log.warning("check %s failed: %s", target.id, exc)
                continue
            if snapshot is not None:
                section[target.id] = self._record(snapshot)
                done.append(target.id)
        self.state.save()
        return done
