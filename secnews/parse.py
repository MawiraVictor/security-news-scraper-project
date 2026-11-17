"""Turn raw feed bytes into Article objects, and clean up HTML."""
import logging
import re
import warnings
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import feedparser
from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
from dateutil import parser as dateparser

from .models import Article

log = logging.getLogger(__name__)

SUMMARY_MAX = 400
_WS = re.compile(r"\s+")
_TRACKING_PARAMS = re.compile(r"^(utm_|fbclid$|gclid$|mc_|ref$|_hs)", re.I)

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


def clean_html(html: str, limit: int = SUMMARY_MAX) -> str:
    """Strip tags/scripts, collapse whitespace and truncate on a word boundary."""
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    for tag in soup(["script", "style", "img", "figure", "iframe"]):
        tag.decompose()
    text = _WS.sub(" ", soup.get_text(" ")).strip()
    # Many feeds append "The post X appeared first on Y." - drop it.
    text = re.sub(r"\s*The post .{0,200}? appeared first on .{0,100}?\.?$", "", text)
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"
    return text


def normalize_url(url: str) -> str:
    """Lower-case scheme/host, drop fragments, tracking params and trailing slashes."""
    parts = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                       if not _TRACKING_PARAMS.match(k)])
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def parse_date(entry) -> datetime | None:
    for key in ("published_parsed", "updated_parsed"):
        st = entry.get(key)
        if st:
            return datetime(*st[:6], tzinfo=timezone.utc)
    for key in ("published", "updated", "dc_date"):
        raw = entry.get(key)
        if raw:
            try:
                dt = dateparser.parse(raw)
            except (ValueError, OverflowError):
                continue
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


def is_web_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme.lower() in ("http", "https") and bool(parts.netloc)


def parse_feed(raw: bytes, source_name: str, base_url: str = "") -> list[Article]:
    """Parse feed bytes. base_url (the feed's final URL) resolves relative article links."""
    headers = {"content-location": base_url} if base_url else None
    feed = feedparser.parse(raw, response_headers=headers)
    if feed.bozo and not feed.entries:
        log.warning("%s: could not parse feed (%s)", source_name, feed.get("bozo_exception"))
        return []

    articles = []
    for e in feed.entries:
        title = _WS.sub(" ", BeautifulSoup(e.get("title", ""), "lxml").get_text()).strip()
        link = urljoin(base_url, (e.get("link") or "").strip()) if base_url else (e.get("link") or "").strip()
        if not title or not is_web_url(link):
            continue  # skip untitled entries and javascript:/data:/relative-without-base links
        summary_html = e.get("summary") or ""
        if not summary_html and e.get("content"):
            summary_html = e["content"][0].get("value", "")
        articles.append(Article(
            title=title,
            url=normalize_url(link),
            source=source_name,
            published=parse_date(e),
            summary=clean_html(summary_html),
            author=e.get("author", ""),
        ))
    return articles


def meta_description(html: str) -> str:
    """Best-effort article description from an HTML page (og:description / description)."""
    soup = BeautifulSoup(html, "lxml")
    for attrs in ({"property": "og:description"}, {"name": "description"}, {"name": "twitter:description"}):
        tag = soup.find("meta", attrs=attrs)
        if tag and tag.get("content"):
            return clean_html(tag["content"])
    p = soup.find("article")
    p = p.find("p") if p else soup.find("p")
    return clean_html(str(p)) if p else ""
