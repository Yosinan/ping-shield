"""Threat-intel sources: a curated catalog, user-supplied URLs and public Telegram channels.

A source is either an RSS/Atom feed URL or a public Telegram channel
(``https://t.me/<channel>``). Telegram bots cannot subscribe to channels they
do not administer, so channels are read from their public web preview
(``https://t.me/s/<channel>``), which needs no login, account or API key.
Private channels are not supported.
"""

from __future__ import annotations

import dataclasses
import re
import urllib.parse
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from typing import Dict, List, Optional, Sequence, Tuple

_TG_URL_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,31})/?$", re.IGNORECASE
)
_TG_SHORT_RE = re.compile(r"^(?:tg:|@)([A-Za-z][A-Za-z0-9_]{3,31})$")


@dataclasses.dataclass(frozen=True)
class Source:
    id: str
    name: str
    url: str
    group: str
    description: str
    distro: str = ""


CATALOG: Tuple[Source, ...] = (
    # Security news
    Source("thn", "The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "news",
           "Breaking security news and research"),
    Source("bleepingcomputer", "BleepingComputer", "https://www.bleepingcomputer.com/feed/", "news",
           "Security news, malware and breach reports"),
    Source("krebs", "Krebs on Security", "https://krebsonsecurity.com/feed/", "news",
           "Investigative security journalism"),
    Source("darkreading", "Dark Reading", "https://www.darkreading.com/rss.xml", "news",
           "Enterprise security news"),
    # Official advisories
    Source("cisa", "CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml",
           "official", "US government cybersecurity advisories"),
    Source("cisa-news", "CISA News", "https://www.cisa.gov/news.xml", "official",
           "CISA announcements, including new known-exploited vulnerabilities"),
    Source("oss-security", "oss-security mailing list", "https://seclists.org/rss/oss-sec.rss", "official",
           "Where open-source vulnerabilities are disclosed first"),
    Source("github-security", "GitHub Security Blog", "https://github.blog/security/feed/", "official",
           "Supply-chain and open-source security from GitHub"),
    Source("pypi", "PyPI Blog", "https://blog.pypi.org/feed_rss_created.xml", "official",
           "Python package index incidents and security changes"),
    Source("socket", "Socket Research", "https://socket.dev/api/blog/feed.atom", "official",
           "Malicious npm/PyPI package research"),
    # Distribution security advisories
    Source("ubuntu-usn", "Ubuntu Security Notices", "https://ubuntu.com/security/notices/rss.xml", "distro",
           "Official Ubuntu security notices", distro="ubuntu"),
    Source("debian-dsa", "Debian Security Advisories", "https://www.debian.org/security/dsa", "distro",
           "Official Debian security advisories", distro="debian"),
    Source("fedora-security", "Fedora Security Updates",
           "https://bodhi.fedoraproject.org/rss/updates/?type=security&status=stable", "distro",
           "Security updates pushed to Fedora stable", distro="fedora"),
    Source("arch-asa", "Arch Linux Security Advisories", "https://security.archlinux.org/advisory/feed.atom",
           "distro", "Official Arch Linux security advisories", distro="arch"),
    # Public Telegram channels
    Source("tg-thehackernews", "The Hacker News (Telegram)", "https://t.me/thehackernews", "telegram",
           "@thehackernews channel"),
    Source("tg-bleepingcomputer", "BleepingComputer (Telegram)", "https://t.me/bleepingcomputer", "telegram",
           "@bleepingcomputer channel"),
    Source("tg-cvenotify", "CVE Notify (Telegram)", "https://t.me/cveNotify", "telegram",
           "@cveNotify: every newly published CVE (high volume, filtered by your keywords)"),
)

GROUP_TITLES = {
    "news": "📰 Security news",
    "official": "🏛 Official advisories",
    "distro": "🐧 Distribution advisories",
    "telegram": "✈️ Telegram channels",
}

_BY_ID: Dict[str, Source] = {s.id: s for s in CATALOG}


def telegram_channel(value: str) -> Optional[str]:
    """Return the channel name if *value* refers to a public Telegram channel."""
    value = value.strip()
    match = _TG_URL_RE.match(value) or _TG_SHORT_RE.match(value)
    return match.group(1) if match else None


def normalize(value: str) -> str:
    """Turn a catalog id, ``@channel``, ``t.me/channel`` or feed URL into a canonical source URL."""
    value = value.strip()
    if value.lower() in _BY_ID:
        return _BY_ID[value.lower()].url
    channel = telegram_channel(value)
    if channel:
        return f"https://t.me/{channel}"
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"'{value}' is not a catalog id, Telegram channel (t.me/name or @name) or http(s) feed URL"
        )
    return value


def lookup(url: str) -> Optional[Source]:
    key = url.rstrip("/").lower()
    for source in CATALOG:
        if source.url.rstrip("/").lower() == key:
            return source
    return None


def display_name(url: str) -> str:
    source = lookup(url)
    if source:
        return source.name
    channel = telegram_channel(url)
    if channel:
        return f"@{channel} (Telegram)"
    return urllib.parse.urlsplit(url).hostname or url


def recommended(distro_ids: Sequence[str]) -> List[Source]:
    return [s for s in CATALOG if s.distro and s.distro in distro_ids]


def canonical_link(url: str) -> str:
    """Normalise an article URL so the same story from RSS and Telegram compares equal."""
    parts = urllib.parse.urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    host = host[4:] if host.startswith("www.") else host
    return f"{host}{parts.path.rstrip('/')}".lower()


# --------------------------------------------------------------------------- #
# Public Telegram channel preview parser
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class ChannelPost:
    post: str  # "<channel>/<id>"
    text: str = ""
    links: List[str] = dataclasses.field(default_factory=list)
    published: Optional[datetime] = None

    @property
    def url(self) -> str:
        return f"https://t.me/{self.post}"


class _ChannelParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.posts: List[ChannelPost] = []
        self._current: Optional[ChannelPost] = None
        self._text_depth = 0  # >0 while inside the message text <div>
        self._parts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr = {k: v or "" for k, v in attrs}
        classes = attr.get("class", "").split()
        if tag == "div" and "tgme_widget_message" in classes and attr.get("data-post"):
            self._finish()
            self._current = ChannelPost(post=attr["data-post"])
            return
        if self._current is None:
            return
        if self._text_depth:
            if tag == "div":
                self._text_depth += 1
            elif tag == "br":
                self._parts.append("\n")
            elif tag == "a" and attr.get("href", "").startswith(("http://", "https://")):
                self._current.links.append(attr["href"])
            return
        if tag == "div" and "tgme_widget_message_text" in classes:
            self._text_depth = 1
        elif tag == "time" and attr.get("datetime") and self._current.published is None:
            try:
                parsed = datetime.fromisoformat(attr["datetime"].replace("Z", "+00:00"))
                self._current.published = parsed.astimezone(timezone.utc)
            except ValueError:
                pass

    def handle_endtag(self, tag: str) -> None:
        if self._text_depth and tag == "div":
            self._text_depth -= 1
            if not self._text_depth and self._current is not None:
                self._current.text = "".join(self._parts).strip()
                self._parts = []

    def handle_data(self, data: str) -> None:
        if self._text_depth:
            self._parts.append(data)

    def _finish(self) -> None:
        if self._current is not None and self._current.text:
            self.posts.append(self._current)
        self._current = None
        self._text_depth = 0
        self._parts = []

    def close(self) -> None:
        super().close()
        self._finish()


def parse_channel(html_text: str) -> List[ChannelPost]:
    parser = _ChannelParser()
    parser.feed(html_text)
    parser.close()
    return parser.posts


def split_post(post: ChannelPost) -> Tuple[str, str, str]:
    """Return (title, summary, article_link) for a channel post."""
    lines = [unescape(l).strip() for l in post.text.splitlines()]
    lines = [l for l in lines if l]
    title = re.sub(r"^[^\w(\[]+", "", lines[0]) if lines else ""
    url_re = re.compile(r"https?://\S+")
    body = " ".join(url_re.sub("", l).strip() for l in lines[1:])
    body = re.sub(r"\s+", " ", body.replace("Details ↓", "")).strip()
    links = [unescape(l) for l in post.links]
    article = next((l for l in links if urllib.parse.urlsplit(l).hostname not in ("t.me", "telegram.me")), "")
    return title or post.post, body, article
