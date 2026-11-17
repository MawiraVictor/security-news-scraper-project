"""HTTP fetching: one polite session with timeouts, retries and robots.txt checks."""
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib import robotparser
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__
from .models import Source

log = logging.getLogger(__name__)

USER_AGENT = (
    f"secnews/{__version__} "
    "(+https://github.com/MawiraVictor/security-news-scraper-project)"
)
TIMEOUT = 15  # seconds


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, text/html;q=0.8, */*;q=0.5",
    })
    retry = Retry(total=3, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504),
                  allowed_methods=("GET",), respect_retry_after_header=True)
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


class RobotsCache:
    """Caches robots.txt per host. If robots.txt can't be fetched, access is allowed."""

    def __init__(self, session: requests.Session):
        self.session = session
        self._parsers: dict[str, robotparser.RobotFileParser | None] = {}

    def allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        host = f"{parts.scheme}://{parts.netloc}"
        if host not in self._parsers:
            rp = robotparser.RobotFileParser()
            try:
                r = self.session.get(host + "/robots.txt", timeout=TIMEOUT)
                if r.status_code >= 400:
                    rp = None  # no robots.txt -> everything allowed
                else:
                    rp.parse(r.text.splitlines())
            except requests.RequestException:
                rp = None
            self._parsers[host] = rp
        rp = self._parsers[host]
        return rp is None or rp.can_fetch(USER_AGENT, url)


@dataclass
class FeedResult:
    source: Source
    body: bytes
    url: str  # final URL after redirects; base for relative links


def fetch_feed(session: requests.Session, source: Source) -> FeedResult | None:
    """Download one feed. Returns None on failure (logged, not raised)."""
    try:
        r = session.get(source.url, timeout=TIMEOUT)
        r.raise_for_status()
        return FeedResult(source, r.content, r.url)
    except requests.RequestException as e:
        log.warning("%s: failed to fetch feed (%s)", source.name, e)
        return None


def fetch_all(session: requests.Session, sources: list[Source], workers: int = 6) -> list[FeedResult]:
    """Fetch feeds concurrently. Results keep the input order; failed feeds are omitted.

    Results are paired with their Source object (not keyed by name), so two feeds
    that share a name don't overwrite each other.
    """
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return [r for r in pool.map(lambda s: fetch_feed(session, s), sources) if r is not None]


# ---------------------------------------------------------------- article pages (--enrich)

class BlockedURL(Exception):
    """Raised when a URL is refused (non-web scheme, private address, or robots.txt)."""


def is_public_url(url: str) -> bool:
    """True if url is http(s) and every address its host resolves to is globally routable.

    Article URLs come from third-party feeds, so without this check a malicious
    feed could make us request internal services (SSRF), e.g. 127.0.0.1,
    192.168.x.x, or the 169.254.169.254 cloud-metadata endpoint.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, ValueError):
        return False
    return bool(infos) and all(ipaddress.ip_address(info[4][0].split("%")[0]).is_global for info in infos)


def safe_get(session: requests.Session, url: str, robots: RobotsCache,
             max_redirects: int = 5) -> requests.Response:
    """GET an article page, re-checking the address and robots.txt on every redirect hop."""
    for _ in range(max_redirects + 1):
        if not is_public_url(url):
            raise BlockedURL(f"not a public http(s) address: {url}")
        if not robots.allowed(url):
            raise BlockedURL(f"robots.txt disallows {url}")
        r = session.get(url, timeout=TIMEOUT, allow_redirects=False)
        if r.is_redirect and r.headers.get("Location"):
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        return r
    raise BlockedURL(f"too many redirects: {url}")
