"""Command-line interface.

  python -m secnews                         # latest news from all sources, as a table
  python -m secnews --since 24 --tag ransomware
  python -m secnews --keyword fortinet --format markdown -o digest.md
  python -m secnews --new-only --db news.db # only articles not seen on earlier runs
  python -m secnews search CVE-2024-3400 --db news.db
  python -m secnews sources
"""
import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__
from .classify import TAG_RULES, dedupe, filter_articles, sort_newest, tag_article
from .fetch import BlockedURL, RobotsCache, fetch_all, make_session, safe_get
from .models import Article, Source
from .parse import meta_description, parse_feed
from .render import FORMATS, render
from .sources import DEFAULT_SOURCES, load_sources_file, parse_feed_arg
from .store import Store

log = logging.getLogger("secnews")


def collect(sources: list[Source], workers: int = 6, enrich: bool = False) -> list[Article]:
    """Fetch, parse, tag, sort and de-duplicate articles from all sources."""
    session = make_session()
    articles: list[Article] = []
    for res in fetch_all(session, sources, workers):
        parsed = parse_feed(res.body, res.source.name, base_url=res.url)
        log.info("%s: %d articles", res.source.name, len(parsed))
        articles.extend(parsed)
    if enrich:
        fill_missing_summaries(session, articles, workers)
    articles = [tag_article(a) for a in articles]
    return dedupe(sort_newest(articles))


def fill_missing_summaries(session, articles: list[Article], workers: int) -> None:
    """For articles whose feed had no summary, read the page's meta description.

    Only public http(s) addresses are fetched, and robots.txt is checked on every redirect hop.
    """
    robots = RobotsCache(session)
    todo = [a for a in articles if not a.summary]

    def work(a: Article):
        try:
            r = safe_get(session, a.url, robots)
            if r.ok and "html" in r.headers.get("Content-Type", ""):
                a.summary = meta_description(r.text)
        except BlockedURL as e:
            log.info("skipped %s", e)
        except Exception as e:  # noqa: BLE001 - enrichment is best-effort
            log.info("could not enrich %s (%s)", a.url, e)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(work, todo))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secnews",
        description="Aggregate, tag and de-duplicate cybersecurity news from public RSS/Atom feeds.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("\n", 2)[2],
    )
    p.add_argument("--version", action="version", version=f"secnews {__version__}")
    p.add_argument("-v", "--verbose", action="store_true", help="log progress per source")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("sources", help="list the configured news sources")

    s = sub.add_parser("search", help="search articles saved in the database")
    s.add_argument("term")
    s.add_argument("--db", default="secnews.db")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("-f", "--format", choices=FORMATS, default="table")

    # Options for the default "fetch" action live on the main parser.
    g = p.add_argument_group("fetch options")
    g.add_argument("--since", type=float, metavar="HOURS", help="only articles published in the last N hours")
    g.add_argument("-k", "--keyword", action="append", help="only articles mentioning this word (repeatable)")
    g.add_argument("-t", "--tag", action="append", choices=sorted(TAG_RULES), help="only articles with this tag (repeatable)")
    g.add_argument("--cve-only", action="store_true", help="only articles that mention a CVE ID")
    g.add_argument("-s", "--source", action="append", help="only use sources whose name contains this text (repeatable)")
    g.add_argument("--feed", action="append", metavar="NAME=URL", help="add an extra feed (repeatable)")
    g.add_argument("--sources-file", help="JSON file with a list of {name, url} sources (replaces defaults)")
    g.add_argument("-n", "--limit", type=int, help="maximum number of articles to output")
    g.add_argument("-f", "--format", choices=FORMATS, default="table")
    g.add_argument("-o", "--output", help="write to this file instead of stdout")
    g.add_argument("--db", help="SQLite file to archive articles in (enables --new-only)")
    g.add_argument("--new-only", action="store_true", help="only output articles not already in --db")
    g.add_argument("--enrich", action="store_true", help="fetch article pages to fill in missing summaries")
    g.add_argument("--workers", type=int, default=6, help="parallel downloads (default 6)")
    return p


def resolve_sources(args) -> list[Source]:
    sources = load_sources_file(args.sources_file) if args.sources_file else list(DEFAULT_SOURCES)
    for f in args.feed or []:
        sources.append(parse_feed_arg(f))
    if args.source:
        wanted = [w.lower() for w in args.source]
        sources = [s for s in sources if any(w in s.name.lower() for w in wanted)]
    return sources


def write_output(text: str, path: str | None) -> None:
    if path:
        Path(path).write_text(text, encoding="utf-8")
        print(f"Wrote {path}", file=sys.stderr)
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")

    if args.command == "sources":
        for s in DEFAULT_SOURCES:
            print(f"{s.name:22s} {s.url}")
        return 0

    if args.command == "search":
        if not Path(args.db).exists():
            parser.error(f"database {args.db} does not exist; run with --db first")
        with Store(args.db) as store:
            write_output(render(store.search(args.term, args.limit), args.format), None)
        return 0

    if args.new_only and not args.db:
        parser.error("--new-only needs --db")
    try:
        sources = resolve_sources(args)
    except (ValueError, OSError) as e:
        parser.error(str(e))
    if not sources:
        parser.error("no sources selected")

    articles = collect(sources, args.workers, args.enrich)
    if not articles:
        print("No articles could be fetched. Check your internet connection or use -v for details.",
              file=sys.stderr)
        return 1

    if args.db:
        with Store(args.db) as store:
            new = store.add_new(articles)
            log.info("%d new articles archived (%d total)", len(new), store.count())
        if args.new_only:
            articles = new

    articles = filter_articles(articles, since_hours=args.since, keywords=args.keyword,
                               tags=args.tag, cve_only=args.cve_only)
    if args.limit:
        articles = articles[: args.limit]
    write_output(render(articles, args.format), args.output)
    return 0
