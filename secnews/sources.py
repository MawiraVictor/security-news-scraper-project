"""Default news sources. All are public feeds published for syndication.

Add your own with --feed NAME=URL on the command line, or --sources-file
pointing at a JSON list of {"name": ..., "url": ...} objects.
"""
import json
from pathlib import Path

from .models import Source

DEFAULT_SOURCES = [
    Source("The Hacker News", "https://feeds.feedburner.com/TheHackersNews", "https://thehackernews.com"),
    Source("BleepingComputer", "https://www.bleepingcomputer.com/feed/", "https://www.bleepingcomputer.com"),
    Source("Krebs on Security", "https://krebsonsecurity.com/feed/", "https://krebsonsecurity.com"),
    Source("SecurityWeek", "https://www.securityweek.com/feed/", "https://www.securityweek.com"),
    Source("Dark Reading", "https://www.darkreading.com/rss.xml", "https://www.darkreading.com"),
    Source("The Record", "https://therecord.media/feed", "https://therecord.media"),
    Source("Schneier on Security", "https://www.schneier.com/feed/atom/", "https://www.schneier.com"),
    Source("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml", "https://www.cisa.gov"),
]


def load_sources_file(path: str | Path) -> list[Source]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON list of sources")
    sources = []
    for i, item in enumerate(data):
        if not isinstance(item, dict) or not item.get("name") or not item.get("url"):
            raise ValueError(f"{path}: entry {i} needs 'name' and 'url'")
        sources.append(Source(item["name"], item["url"], item.get("homepage", "")))
    return sources


def parse_feed_arg(arg: str) -> Source:
    """Parse a 'NAME=URL' command-line value."""
    name, sep, url = arg.partition("=")
    if not sep or not name.strip() or not url.strip().startswith(("http://", "https://")):
        raise ValueError(f"--feed expects NAME=URL, got {arg!r}")
    return Source(name.strip(), url.strip())
