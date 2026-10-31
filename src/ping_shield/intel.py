"""Threat intelligence: RSS/Atom scraping, environment-aware filtering and caching.

An item is alerted only when it mentions **both** a high-severity term
("actively exploited", "backdoor", "CVSS 9.8", ...) **and** something that
exists on this machine (the distro, OpenSSH, Python/PyPI, VS Code, ...).

Anti-spam guarantees:

* every feed item is remembered by GUID once processed;
* the same story syndicated by several outlets is suppressed by normalised
  title and by CVE id, so one threat produces one alert;
* items are marked as alerted only after Telegram accepts them;
* conditional GETs (ETag / Last-Modified) avoid re-downloading unchanged feeds.
"""

from __future__ import annotations

import dataclasses
import hashlib
import html
import logging
import re
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from . import __version__
from .config import Config, StateStore
from .notify import Alert, Button, Field, NotifyError, TelegramNotifier, local_time

log = logging.getLogger(__name__)

USER_AGENT = f"ping-shield/{__version__} (+https://pypi.org/project/ping-shield/)"
MAX_FEED_BYTES = 10 * 1024 * 1024
SUMMARY_CHARS = 600
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
CVSS_CRITICAL_RE = re.compile(r"\bCVSS(?:v?[234](?:\.\d)?)?\b[^0-9]{0,25}(9\.\d|10(?:\.0)?)\b", re.IGNORECASE)

# Signals that make an item "critical" rather than "high".
CRITICAL_SIGNALS = frozenset({
    "actively exploited", "exploited in the wild", "under active exploitation", "zero-day", "zero day",
    "0-day", "backdoor", "backdoored", "wormable", "rootkit", "known exploited vulnerabilities",
})

# Executable on PATH -> keywords it implies.
_TOOL_KEYWORDS: Dict[str, Sequence[str]] = {
    "ssh": ("OpenSSH", "SSH"),
    "sshd": ("OpenSSH", "sshd"),
    "sudo": ("sudo",),
    "python3": ("Python", "PyPI", "pip"),
    "node": ("Node.js", "npm"),
    "npm": ("npm",),
    "docker": ("Docker",),
    "podman": ("Podman",),
    "code": ("VS Code", "VSCode", "Visual Studio Code"),
    "cursor": ("Cursor",),
    "git": ("Git",),
    "systemctl": ("systemd",),
    "xz": ("xz", "XZ Utils", "liblzma"),
    "openssl": ("OpenSSL",),
    "firefox": ("Firefox",),
    "google-chrome": ("Chrome",),
    "chromium": ("Chromium",),
    "flatpak": ("Flatpak",),
    "snap": ("Snap", "Snapcraft"),
    "kubectl": ("Kubernetes",),
    "gnome-shell": ("GNOME",),
    "plasmashell": ("KDE",),
    "rsync": ("rsync",),
    "cupsd": ("CUPS",),
    "lpstat": ("CUPS",),
    "polkitd": ("polkit",),
    "pkexec": ("polkit", "pkexec"),
    "nginx": ("nginx",),
    "apache2": ("Apache",),
    "httpd": ("Apache",),
}

_DISTRO_KEYWORDS: Dict[str, Sequence[str]] = {
    "fedora": ("Fedora",),
    "rhel": ("Red Hat", "RHEL"),
    "centos": ("CentOS",),
    "rocky": ("Rocky Linux",),
    "almalinux": ("AlmaLinux",),
    "ubuntu": ("Ubuntu",),
    "debian": ("Debian",),
    "linuxmint": ("Linux Mint",),
    "pop": ("Pop!_OS",),
    "arch": ("Arch Linux",),
    "manjaro": ("Manjaro",),
    "opensuse": ("openSUSE", "SUSE"),
    "suse": ("SUSE",),
    "gentoo": ("Gentoo",),
    "nixos": ("NixOS",),
    "alpine": ("Alpine Linux",),
}


def _read_os_release() -> Dict[str, str]:
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(candidate).read_text(encoding="utf-8")
        except OSError:
            continue
        values = {}
        for line in text.splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip("\"'")
        return values
    return {}


def detect_distro_ids() -> List[str]:
    info = _read_os_release()
    return [i.lower() for i in (info.get("ID", "") + " " + info.get("ID_LIKE", "")).split() if i]


def environment_keywords() -> List[str]:
    """Infer keywords describing this machine: distro, kernel, services and dev tooling."""
    keywords: Set[str] = {"Linux", "Linux kernel", "glibc"}
    for distro in detect_distro_ids():
        keywords.update(_DISTRO_KEYWORDS.get(distro, (distro,)))
    for tool, words in _TOOL_KEYWORDS.items():
        if shutil.which(tool) or shutil.which(tool, path="/usr/sbin:/sbin"):
            keywords.update(words)
    home = Path.home()
    if (home / ".vscode").exists():
        keywords.update(_TOOL_KEYWORDS["code"])
    if (home / ".cursor").exists():
        keywords.update(_TOOL_KEYWORDS["cursor"])
    return sorted(keywords, key=str.lower)


def _phrase_regex(phrase: str) -> "re.Pattern[str]":
    body = r"\s+".join(re.escape(part) for part in phrase.split())
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)


@dataclasses.dataclass
class NewsItem:
    guid: str
    title: str
    link: str = ""
    summary: str = ""
    published: Optional[datetime] = None
    source: str = ""

    @property
    def key(self) -> str:
        return hashlib.sha256(f"{self.source}\0{self.guid}".encode("utf-8")).hexdigest()[:32]

    @property
    def title_key(self) -> str:
        normalised = re.sub(r"[^a-z0-9]+", " ", self.title.lower()).strip()
        return hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:32]

    @property
    def cves(self) -> Set[str]:
        return {c.upper() for c in CVE_RE.findall(f"{self.title} {self.summary}")}


@dataclasses.dataclass
class Match:
    severity: List[str]
    environment: List[str]


class KeywordMatcher:
    def __init__(self, severity: Iterable[str], environment: Iterable[str]):
        self.severity = sorted(set(severity), key=str.lower)
        self.environment = sorted(set(environment), key=str.lower)
        self._severity = [(k, _phrase_regex(k)) for k in self.severity]
        self._environment = [(k, _phrase_regex(k)) for k in self.environment]

    @classmethod
    def from_config(cls, config: Config) -> "KeywordMatcher":
        env = list(config.keywords) if config.keywords else environment_keywords()
        return cls(config.severity_keywords, env + list(config.extra_keywords))

    def match(self, item: NewsItem) -> Optional[Match]:
        text = f"{item.title}\n{item.summary}"
        severity = [k for k, rx in self._severity if rx.search(text)]
        cvss = CVSS_CRITICAL_RE.search(text)
        if cvss:
            severity.append(f"CVSS {cvss.group(1)}")
        if not severity:
            return None
        environment = [k for k, rx in self._environment if rx.search(text)]
        if not environment:
            return None
        return Match(severity, environment)


# --------------------------------------------------------------------------- #
# Fetching and parsing
# --------------------------------------------------------------------------- #
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower() if isinstance(tag, str) else ""


def _child_text(element: ET.Element, *names: str) -> str:
    for name in names:
        for child in element:
            if _local(child.tag) == name:
                if name == "link" and child.get("href"):
                    rel = child.get("rel", "alternate")
                    if rel == "alternate":
                        return child.get("href", "").strip()
                    continue
                text = "".join(child.itertext()).strip()
                if text:
                    return text
    return ""


def _clean(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html.unescape(text))
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _parse_date(value: str) -> Optional[datetime]:
    value = value.strip()
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_feed(data: bytes, source: str) -> List[NewsItem]:
    """Parse RSS 2.0, RSS 1.0 (RDF) or Atom into :class:`NewsItem` objects."""
    head = data[:16384]
    if b"<!ENTITY" in head:
        raise ValueError("feed declares XML entities; refusing to parse")
    root = ET.fromstring(data)
    items: List[NewsItem] = []
    for element in root.iter():
        if _local(element.tag) not in ("item", "entry"):
            continue
        title = _clean(_child_text(element, "title"))
        link = _child_text(element, "link")
        guid = _child_text(element, "guid", "id") or link or title
        if not guid or not title:
            continue
        summary = _clean(_child_text(element, "description", "summary", "encoded", "content"))
        published = _parse_date(_child_text(element, "pubdate", "published", "updated", "date"))
        if len(summary) > SUMMARY_CHARS:
            summary = summary[:SUMMARY_CHARS].rsplit(" ", 1)[0] + "…"
        items.append(NewsItem(guid=guid, title=title, link=link, summary=summary,
                              published=published, source=source))
    return items


def fetch_feed(url: str, cache: Dict[str, Any], timeout: float) -> Optional[bytes]:
    """Download *url*, using and updating the ETag/Last-Modified *cache*.

    Returns None when the server answers 304 Not Modified.
    """
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"unsupported feed URL scheme: {url}")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"}
    if cache.get("etag"):
        headers["If-None-Match"] = cache["etag"]
    if cache.get("last_modified"):
        headers["If-Modified-Since"] = cache["last_modified"]
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - scheme checked
            data = resp.read(MAX_FEED_BYTES + 1)
            if len(data) > MAX_FEED_BYTES:
                raise ValueError(f"feed larger than {MAX_FEED_BYTES // (1024 * 1024)} MiB")
            cache["etag"] = resp.headers.get("ETag", "")
            cache["last_modified"] = resp.headers.get("Last-Modified", "")
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None
        raise


def feed_name(url: str) -> str:
    host = urllib.parse.urlsplit(url).hostname or url
    return {
        "feeds.feedburner.com": "The Hacker News",
        "www.bleepingcomputer.com": "BleepingComputer",
        "www.cisa.gov": "CISA",
    }.get(host, host)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class IntelReport:
    fetched: int = 0
    sent: List[NewsItem] = dataclasses.field(default_factory=list)
    matched_keywords: Dict[str, Match] = dataclasses.field(default_factory=dict)
    duplicates: int = 0
    ignored: int = 0
    stale: int = 0
    deferred: int = 0
    errors: List[str] = dataclasses.field(default_factory=list)
    undelivered: int = 0


class IntelEngine:
    RETENTION_DAYS_MIN = 60
    MAX_REMEMBERED = 20000

    def __init__(
        self,
        config: Config,
        state: StateStore,
        notifier: Optional[TelegramNotifier],
        banner: str = "",
        matcher: Optional[KeywordMatcher] = None,
    ):
        self.config = config
        self.state = state
        self.notifier = notifier
        self.banner = banner
        self.matcher = matcher or KeywordMatcher.from_config(config)
        self.hostname = socket.gethostname()
        section = state.section("intel")
        self.seen: Dict[str, str] = section.setdefault("seen", {})
        self.titles: Dict[str, str] = section.setdefault("titles", {})
        self.cves: Dict[str, str] = section.setdefault("cves", {})
        self.feed_cache: Dict[str, Dict[str, str]] = section.setdefault("feeds", {})

    def run(self) -> IntelReport:
        items: List[NewsItem] = []
        report = IntelReport()
        for url in self.config.feeds:
            cache = self.feed_cache.setdefault(url, {})
            try:
                data = fetch_feed(url, cache, self.config.request_timeout)
                if data is None:
                    log.debug("%s not modified", url)
                    continue
                parsed = parse_feed(data, feed_name(url))
                log.debug("%s: %d items", url, len(parsed))
                items += parsed
            except (urllib.error.URLError, OSError, ValueError, ET.ParseError) as exc:
                reason = getattr(exc, "reason", exc)
                report.errors.append(f"{url}: {reason}")
                log.warning("feed %s failed: %s", url, reason)
                cache.clear()  # force a full download next time
        return self.process_items(items, report)

    def _alert(self, item: NewsItem, match: Match) -> Alert:
        critical = any(s.lower() in CRITICAL_SIGNALS or s.startswith("CVSS") for s in match.severity)
        cves = sorted(item.cves)
        fields = [
            Field("🎯", "Affects you", " · ".join(match.environment)),
            Field("🏷", "Signals", " · ".join(match.severity)),
        ]
        if cves:
            fields.append(Field("🔖", "CVE", ", ".join(cves), mono=True))
        fields.append(Field("🗞", "Source", item.source or "unknown"))
        if item.published:
            fields.append(Field("📅", "Published", local_time(item.published)))
        buttons = []
        if item.link.startswith(("https://", "http://")):
            buttons.append([Button("📖 Read full article", item.link)])
        if cves:
            buttons.append([Button(f"🔎 {cve} on NVD", f"https://nvd.nist.gov/vuln/detail/{cve}")
                            for cve in cves[:2]])
        return Alert(
            icon="🔴" if critical else "🟠",
            title="Critical Threat" if critical else "High-Severity Threat",
            banner=self.banner,
            headline=item.title,
            quote=item.summary,
            fields=fields,
            tags=["threat_intel", match.environment[0]],
            buttons=buttons,
        )

    def _prune(self) -> None:
        retention = max(self.RETENTION_DAYS_MIN, self.config.news_max_age_days * 3)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention)).isoformat()
        for store in (self.seen, self.titles, self.cves):
            for key in [k for k, ts in store.items() if ts < cutoff]:
                del store[key]
            if len(store) > self.MAX_REMEMBERED:
                for key in sorted(store, key=store.__getitem__)[: len(store) - self.MAX_REMEMBERED]:
                    del store[key]

    def process_items(self, items: Sequence[NewsItem], report: Optional[IntelReport] = None) -> IntelReport:
        """Filter, deduplicate and alert *items*. Also the injection point for ``--test``."""
        report = report or IntelReport()
        report.fetched += len(items)
        now = datetime.now(timezone.utc)
        stamp = now.isoformat(timespec="seconds")
        max_age = timedelta(days=self.config.news_max_age_days)
        oldest_first = sorted(items, key=lambda i: i.published or now)
        for item in oldest_first:
            if item.key in self.seen:
                report.duplicates += 1
                continue
            if item.published and now - item.published > max_age:
                self.seen[item.key] = stamp
                report.stale += 1
                continue
            match = self.matcher.match(item)
            if match is None:
                self.seen[item.key] = stamp
                report.ignored += 1
                continue
            cves = item.cves
            if item.title_key in self.titles or (cves and cves.issubset(self.cves)):
                # Same threat already reported (possibly by another outlet).
                self.seen[item.key] = stamp
                report.duplicates += 1
                continue
            if len(report.sent) >= self.config.max_news_alerts_per_run:
                report.deferred += 1  # left unseen; delivered on a later run
                continue
            if self.notifier is None:
                report.undelivered += 1
                continue
            try:
                self.notifier.send_alert(self._alert(item, match))
            except NotifyError as exc:
                report.errors.append(f"alert '{item.title[:60]}': {exc}")
                report.undelivered += 1
                log.error("could not deliver news alert: %s", exc)
                continue
            self.seen[item.key] = stamp
            self.titles[item.title_key] = stamp
            for cve in cves:
                self.cves[cve] = stamp
            report.sent.append(item)
            report.matched_keywords[item.key] = match
            self.state.save()
        self._prune()
        self.state.save()
        return report
