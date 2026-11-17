"""HTTP fetching: one polite session with timeouts, retries and robots.txt checks."""
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib import robotparser
from urllib.parse import urlsplit

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


def fetch_feed(session: requests.Session, source: Source) -> bytes | None:
    """Download one feed. Returns raw bytes, or None on failure (logged, not raised)."""
    try:
        r = session.get(source.url, timeout=TIMEOUT)
        r.raise_for_status()
        return r.content
    except requests.RequestException as e:
        log.warning("%s: failed to fetch feed (%s)", source.name, e)
        return None


def fetch_all(session: requests.Session, sources: list[Source], workers: int = 6) -> dict[str, bytes]:
    """Fetch feeds concurrently. Returns {source name: raw feed bytes} for those that succeeded."""
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = pool.map(lambda s: (s.name, fetch_feed(session, s)), sources)
        return {name: body for name, body in results if body is not None}
