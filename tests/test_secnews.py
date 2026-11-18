import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from secnews import cli, fetch
from secnews.classify import dedupe, extract_cves, filter_articles, sort_newest, tag_article
from secnews.fetch import BlockedURL, FeedResult, fetch_all, is_public_url, safe_get
from secnews.models import Article, Source
from secnews.parse import clean_html, meta_description, normalize_url, parse_feed
from secnews.render import FORMATS, render
from secnews.sources import load_sources_file, parse_feed_arg
from secnews.store import Store

RSS = b"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>Test RSS</title>
<item>
  <title>Critical Fortinet flaw CVE-2024-21762 actively exploited</title>
  <link>https://example.com/fortinet?utm_source=rss&amp;id=7#comments</link>
  <pubDate>Mon, 17 Nov 2026 10:00:00 GMT</pubDate>
  <description><![CDATA[<p>Attackers exploit <b>CVE-2024-21762</b> and cve-2024-21762 again.</p>
  <script>alert(1)</script><img src="x.png">The post Fortinet appeared first on Test.]]></description>
</item>
<item>
  <title>LockBit ransomware gang hits hospital</title>
  <link>https://example.com/lockbit/</link>
  <pubDate>Sun, 16 Nov 2026 08:00:00 GMT</pubDate>
  <description>Hospital data leaked after ransomware attack.</description>
</item>
<item><title></title><link>https://example.com/no-title</link></item>
</channel></rss>"""

ATOM = b"""<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Test Atom</title>
<entry>
  <title>Phishing campaign targets banks</title>
  <link href="https://blog.example.org/phishing"/>
  <updated>2026-11-15T12:30:00Z</updated>
  <author><name>Jane</name></author>
  <content type="html">&lt;p&gt;New phishing kit spotted.&lt;/p&gt;</content>
</entry>
</feed>"""

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def art(title, url=None, hours_ago=1, summary="", source="S"):
    return Article(title=title, url=url or f"https://x.test/{abs(hash(title))}", source=source,
                   published=NOW - timedelta(hours=hours_ago), summary=summary)


# ---------------------------------------------------------------- parsing

def test_parse_rss():
    arts = parse_feed(RSS, "Test RSS")
    assert [a.title for a in arts] == [
        "Critical Fortinet flaw CVE-2024-21762 actively exploited",
        "LockBit ransomware gang hits hospital",
    ]  # entry without a title is skipped
    a = arts[0]
    assert a.url == "https://example.com/fortinet?id=7"     # tracking + fragment removed
    assert a.published == datetime(2026, 11, 17, 10, 0, tzinfo=timezone.utc)
    assert "alert" not in a.summary and "<" not in a.summary
    assert "appeared first" not in a.summary
    assert arts[1].url == "https://example.com/lockbit"     # trailing slash removed


def test_parse_atom_uses_content_and_author():
    [a] = parse_feed(ATOM, "Test Atom")
    assert a.summary == "New phishing kit spotted."
    assert a.author == "Jane"
    assert a.published.isoformat() == "2026-11-15T12:30:00+00:00"


def test_parse_garbage_returns_empty():
    assert parse_feed(b"this is not xml", "Bad") == []


def test_clean_html_truncates_on_word_boundary():
    text = clean_html("<p>" + "word " * 200 + "</p>", limit=50)
    assert len(text) <= 51 and text.endswith("…") and "  " not in text


def test_normalize_url():
    assert normalize_url("HTTPS://Example.COM/a/?utm_medium=x&b=2&fbclid=z#top") == "https://example.com/a?b=2"


def test_meta_description_prefers_og():
    html = '<html><head><meta name="description" content="plain"><meta property="og:description" content="og text"></head></html>'
    assert meta_description(html) == "og text"
    assert meta_description("<article><p>First para.</p><p>Second</p></article>") == "First para."


# ---------------------------------------------------------------- classify

def test_extract_cves_unique_and_normalized():
    assert extract_cves("cve-2024-1234 and CVE-2024-1234, CVE-2023-123456") == ["CVE-2024-1234", "CVE-2023-123456"]
    assert extract_cves("CVE-24-1") == []


def test_tagging():
    a = tag_article(parse_feed(RSS, "T")[0])
    assert a.cves == ["CVE-2024-21762"]
    assert {"zero-day", "vulnerability"} <= set(a.tags)
    b = tag_article(parse_feed(RSS, "T")[1])
    assert {"ransomware", "data-breach"} <= set(b.tags)


def test_dedupe_by_url_and_similar_title():
    items = [
        art("Microsoft patches 60 flaws in November update", url="https://a/1"),
        art("Microsoft patches 60 flaws in November update!", url="https://b/2"),  # near-identical title
        art("Something else entirely", url="https://a/1"),                        # same URL
        art("Google fixes Chrome zero-day", url="https://c/3"),
    ]
    assert [a.url for a in dedupe(items)] == ["https://a/1", "https://c/3"]


def test_filters():
    items = [tag_article(a) for a in [
        art("Ransomware hits city", hours_ago=2),
        art("Patch for CVE-2025-0001 released", hours_ago=30),
        art("Undated story", hours_ago=0),
    ]]
    items[2].published = None
    assert len(filter_articles(items, since_hours=24, now=NOW)) == 1          # undated excluded too
    assert [a.title for a in filter_articles(items, keywords=["CITY"], now=NOW)] == ["Ransomware hits city"]
    assert [a.title for a in filter_articles(items, tags=["vulnerability"], now=NOW)] == ["Patch for CVE-2025-0001 released"]
    assert len(filter_articles(items, cve_only=True, now=NOW)) == 1


def test_sort_newest_puts_undated_last():
    a, b, c = art("a", hours_ago=5), art("b", hours_ago=1), art("c")
    c.published = None
    assert [x.title for x in sort_newest([a, c, b])] == ["b", "a", "c"]


# ---------------------------------------------------------------- store

def test_store_add_new_and_search(tmp_path):
    db = tmp_path / "n.db"
    arts = [tag_article(a) for a in parse_feed(RSS, "T")]
    with Store(db) as s:
        assert len(s.add_new(arts)) == 2
        assert s.add_new(arts) == []          # second run: nothing new
        assert s.count() == 2
        [hit] = s.search("CVE-2024-21762")
        assert hit.cves == ["CVE-2024-21762"] and hit.published.tzinfo is not None


# ---------------------------------------------------------------- render

@pytest.mark.parametrize("fmt", FORMATS)
def test_render_all_formats(fmt):
    arts = [tag_article(a) for a in parse_feed(RSS, "T")]
    out = render(arts, fmt)
    assert "Fortinet" in out


def test_render_json_roundtrip_and_html_escaping():
    a = art('<script>alert("x")</script> & co', summary="<b>bold</b>")
    data = json.loads(render([a], "json"))
    assert data[0]["title"].startswith("<script>")
    html = render([a], "html")
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_render_empty():
    assert render([], "table") == "No articles found."
    assert json.loads(render([], "json")) == []


# ---------------------------------------------------------------- sources

def test_parse_feed_arg():
    assert parse_feed_arg("My Blog=https://blog.test/feed") == Source("My Blog", "https://blog.test/feed")
    with pytest.raises(ValueError):
        parse_feed_arg("no-url-here")


def test_load_sources_file(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps([{"name": "A", "url": "https://a/feed"}]))
    assert load_sources_file(f) == [Source("A", "https://a/feed")]
    f.write_text(json.dumps([{"name": "A"}]))
    with pytest.raises(ValueError):
        load_sources_file(f)


# ---------------------------------------------------------------- CLI (network mocked)

@pytest.fixture
def fake_network(monkeypatch):
    feeds = {"Test RSS": RSS, "Test Atom": ATOM}
    monkeypatch.setattr(cli, "DEFAULT_SOURCES", [Source(n, f"https://{n}.test/feed") for n in feeds])
    monkeypatch.setattr(cli, "fetch_all", lambda session, sources, workers: [
        FeedResult(s, feeds[s.name], s.url) for s in sources if s.name in feeds])


def test_cli_end_to_end(fake_network, capsys, tmp_path):
    assert cli.main(["-f", "json"]) == 0
    titles = [a["title"] for a in json.loads(capsys.readouterr().out)]
    assert titles[0].startswith("Critical Fortinet") and len(titles) == 3

    assert cli.main(["--tag", "ransomware", "-f", "json"]) == 0
    assert [a["title"] for a in json.loads(capsys.readouterr().out)] == ["LockBit ransomware gang hits hospital"]

    out = tmp_path / "d.md"
    assert cli.main(["--source", "atom", "-f", "markdown", "-o", str(out)]) == 0
    assert "Phishing campaign targets banks" in out.read_text(encoding="utf-8")


def test_cli_new_only(fake_network, capsys, tmp_path):
    db = str(tmp_path / "a.db")
    cli.main(["--db", db, "--new-only", "-f", "json"])
    assert len(json.loads(capsys.readouterr().out)) == 3
    cli.main(["--db", db, "--new-only", "-f", "json"])
    assert json.loads(capsys.readouterr().out) == []
    assert cli.main(["search", "phishing", "--db", db, "-f", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)) == 1


def test_cli_errors(fake_network, monkeypatch, capsys):
    with pytest.raises(SystemExit):
        cli.main(["--new-only"])                      # needs --db
    monkeypatch.setattr(cli, "fetch_all", lambda *a: {})
    assert cli.main([]) == 1                          # nothing fetched


# ---------------------------------------------------------------- review regressions (PR #3)

def _feed_with_link(link: str, title: str = "Story") -> bytes:
    return f"""<?xml version="1.0"?><rss version="2.0"><channel><title>T</title>
<item><title>{title}</title><link>{link}</link></item></channel></rss>""".encode()


@pytest.mark.parametrize("link", ["javascript:alert(document.cookie)", "data:text/html,hi", "ftp://x.test/a"])
def test_non_web_links_are_dropped(link):
    assert parse_feed(_feed_with_link(link), "T") == []


def test_renderers_never_emit_unsafe_hrefs():
    a = art("Click me", url="javascript:alert(1)")
    assert "javascript:" not in render([a], "html")
    assert "javascript:" not in render([a], "markdown")


def test_markdown_escapes_text_and_url():
    a = art("Bad [title](x) <img src=x onerror=alert(1)>", url="https://x.test/a_(b) c")
    md = render([a], "markdown")
    heading = [l for l in md.splitlines() if l.startswith("### ")][0]
    assert heading.endswith("(<https://x.test/a_(b)%20c>)")
    assert "\\<img" in md
    assert not re.search(r"(?<!\\)<img", md)          # every '<' before img is escaped
    assert "\\[title\\]" in heading


def test_relative_links_resolved_against_feed_url():
    [a] = parse_feed(_feed_with_link("/news/story-1"), "T", base_url="https://site.test/feeds/rss")
    assert a.url == "https://site.test/news/story-1"
    assert parse_feed(_feed_with_link("/news/story-1"), "T") == []   # no base -> unusable, dropped


def test_blank_query_values_preserved():
    assert normalize_url("https://x.test/story?edition=&utm_source=a") == "https://x.test/story?edition="


def test_dedupe_keeps_distinct_non_latin_titles():
    items = [art("安全漏洞", url="https://a/1"), art("数据泄露", url="https://a/2")]
    assert len(dedupe(items)) == 2


def test_dedupe_keeps_advisories_with_different_cves():
    items = [tag_article(art("Security update fixes CVE-2025-1234", url="https://a/1")),
             tag_article(art("Security update fixes CVE-2025-1235", url="https://a/2"))]
    assert len(dedupe(items)) == 2


def test_fetch_all_keeps_feeds_with_duplicate_names(monkeypatch):
    class Resp:
        def __init__(self, url): self.url, self.content = url, url.encode()
        def raise_for_status(self): pass
    class Sess:
        def get(self, url, timeout): return Resp(url)
    srcs = [Source("News", "https://a.test/feed"), Source("News", "https://b.test/feed")]
    results = fetch_all(Sess(), srcs, workers=2)
    assert [r.body for r in results] == [b"https://a.test/feed", b"https://b.test/feed"]


def _fake_dns(monkeypatch, table):
    def getaddrinfo(host, port, proto=0):
        if host not in table:
            raise fetch.socket.gaierror("unknown")
        return [(2, 1, 6, "", (ip, 0)) for ip in table[host]]
    monkeypatch.setattr(fetch.socket, "getaddrinfo", getaddrinfo)


def test_is_public_url_blocks_internal_addresses(monkeypatch):
    _fake_dns(monkeypatch, {"news.test": ["93.184.216.34"], "meta.test": ["169.254.169.254"],
                            "lan.test": ["192.168.1.10"], "mixed.test": ["93.184.216.34", "127.0.0.1"]})
    assert is_public_url("https://news.test/a")
    for url in ["http://meta.test/latest", "http://lan.test/", "https://mixed.test/",
                "http://127.0.0.1/", "file:///etc/passwd", "https://nowhere.test/"]:
        assert not is_public_url(url), url


class _Robots:
    def __init__(self, disallowed=()): self.disallowed = set(disallowed)
    def allowed(self, url): return url not in self.disallowed


class _RedirectSession:
    def __init__(self, hops): self.hops, self.requested = hops, []
    def get(self, url, timeout, allow_redirects):
        assert allow_redirects is False
        self.requested.append(url)
        class R:
            ok = True
            headers = {"Location": self.hops[url]} if url in self.hops else {"Content-Type": "text/html"}
            is_redirect = url in self.hops
            def close(self): pass
        return R()


def test_safe_get_checks_every_redirect_hop(monkeypatch):
    _fake_dns(monkeypatch, {"news.test": ["93.184.216.34"], "meta.test": ["169.254.169.254"]})
    s = _RedirectSession({"https://news.test/a": "http://meta.test/latest"})
    with pytest.raises(BlockedURL):
        safe_get(s, "https://news.test/a", _Robots())
    assert s.requested == ["https://news.test/a"]             # internal hop never requested

    s = _RedirectSession({"https://news.test/a": "/private/b"})
    with pytest.raises(BlockedURL, match="robots"):
        safe_get(s, "https://news.test/a", _Robots({"https://news.test/private/b"}))
    assert s.requested == ["https://news.test/a"]

    s = _RedirectSession({"https://news.test/a": "/b"})
    assert safe_get(s, "https://news.test/a", _Robots()).ok
    assert s.requested == ["https://news.test/a", "https://news.test/b"]


def test_store_search_orders_by_instant_across_timezones(tmp_path):
    from datetime import timezone as tz
    plus2 = tz(timedelta(hours=2))
    older = Article("match older", "https://x/1", "S", datetime(2026, 11, 17, 10, 0, tzinfo=plus2))  # 08:00Z
    newer = Article("match newer", "https://x/2", "S", datetime(2026, 11, 17, 9, 0, tzinfo=tz.utc))  # 09:00Z
    with Store(tmp_path / "t.db") as s:
        s.add_new([older, newer])
        assert [a.title for a in s.search("match", limit=1)] == ["match newer"]


def test_csv_neutralises_formulas():
    import csv as _csv
    a = art('=HYPERLINK("https://evil.test","click")', summary="+cmd|' /C calc'!A0", source="@src")
    row = list(_csv.reader(render([a], "csv").splitlines()))[1]
    assert row[1] == "'@src" and row[2].startswith("'=HYPERLINK") and row[6].startswith("'+cmd")
    assert list(_csv.reader(render([art("Normal title")], "csv").splitlines()))[1][2] == "Normal title"


@pytest.mark.parametrize("args", [
    ["--limit", "0"], ["--limit", "-5"], ["--workers", "0"], ["--since", "-1"],
    ["--since", "abc"], ["search", "x", "--limit", "0"],
])
def test_cli_rejects_non_positive_numbers(args, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(args)
    assert exc.value.code == 2
    assert "error: argument" in capsys.readouterr().err


def test_cli_accepts_positive_numbers():
    ns = cli.build_parser().parse_args(["--limit", "5", "--workers", "2", "--since", "0.5"])
    assert (ns.limit, ns.workers, ns.since) == (5, 2, 0.5)
