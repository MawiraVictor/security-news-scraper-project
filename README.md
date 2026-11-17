# secnews: Security News Scraper

[![tests](https://github.com/MawiraVictor/security-news-scraper-project/actions/workflows/tests.yml/badge.svg)](https://github.com/MawiraVictor/security-news-scraper-project/actions/workflows/tests.yml)
[![daily digest](https://github.com/MawiraVictor/security-news-scraper-project/actions/workflows/daily-digest.yml/badge.svg)](https://github.com/MawiraVictor/security-news-scraper-project/actions/workflows/daily-digest.yml)

A command-line tool that collects cybersecurity news from trusted public feeds, **tags each
story by topic**, **extracts CVE IDs**, **removes duplicates across sources**, and outputs a
terminal list, JSON, CSV, Markdown, or a filterable HTML digest.

```
$ secnews --since 24 --tag ransomware
2026-11-17 07:25  [BleepingComputer]  Ransomware affiliate suspect extradited to US, faces 27 years in prison
    #ransomware #law-enforcement
    https://www.bleepingcomputer.com/news/security/alleged-inc-lynx-ransomware-affiliate-extradited-...
```

## Features

- **8 sources out of the box:** The Hacker News, BleepingComputer, Krebs on Security, SecurityWeek,
  Dark Reading, The Record, Schneier on Security and CISA advisories. Add your own with `--feed`.
- **Topic tags:** ransomware, zero-day, vulnerability, data-breach, malware, phishing, apt,
  supply-chain, ddos, cloud, ai, law-enforcement, advisory
- **CVE extraction**, with links to NVD in the Markdown and HTML output
- **Cross-source de-duplication** by normalised URL (tracking parameters stripped) and near-identical titles
- **Filters** by time window, keyword, tag, source, or "mentions a CVE"
- **SQLite archive** (`--db`) so scheduled runs can show only new stories (`--new-only`) and you can search history offline
- **Polite by design:** RSS feeds first, concurrent downloads with timeouts, retries with backoff
  (respects `Retry-After`), a descriptive User-Agent, and robots.txt checks before any article page is fetched
- **Daily digest via GitHub Actions:** an HTML/Markdown/JSON digest built every morning

## Installation

```bash
git clone https://github.com/MawiraVictor/security-news-scraper-project.git
cd security-news-scraper-project
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -e .
```

This installs the `secnews` command. You can also use `python -m secnews` without installing.

## Usage

```bash
secnews                                   # latest stories from all sources
secnews --since 24                        # last 24 hours
secnews -t zero-day -t vulnerability      # by tag (repeatable)
secnews -k fortinet -k ivanti             # by keyword (repeatable)
secnews --cve-only -f csv -o cves.csv     # stories mentioning a CVE, as CSV
secnews -s krebs -s record                # only some sources
secnews --since 24 -f html -o digest.html # shareable HTML digest (click tags to filter)
secnews --feed "Unit 42=https://unit42.paloaltonetworks.com/feed/"   # add a source
secnews --enrich                          # fill missing summaries from article pages
secnews sources                           # list default sources
```

### Only what's new since the last run

```bash
secnews --db news.db --new-only           # first run: everything; later runs: only new stories
secnews search CVE-2024-3400 --db news.db # search the archive
```

Run it on a schedule (cron, or Windows Task Scheduler) to get a running feed of new stories.

### Custom source list

```json
[
  {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/"},
  {"name": "Talos",   "url": "https://blog.talosintelligence.com/rss/"}
]
```

```bash
secnews --sources-file my_sources.json
```

## Output formats

| `-f`       | Use it for                                             |
|------------|--------------------------------------------------------|
| `table`    | Reading in the terminal (default)                      |
| `json`     | Feeding other tools, SIEM ingestion, dashboards        |
| `csv`      | Spreadsheets                                           |
| `markdown` | Notes, GitHub issues, team chat                        |
| `html`     | A self-contained page with tag filters and dark mode   |

## How it works

```
feeds ──► fetch (parallel, retries) ──► parse RSS/Atom ──► clean HTML ──► tag + CVEs
                                                                            │
          output ◄── filter (time/keyword/tag) ◄── archive (SQLite) ◄── de-duplicate
```

| Module                | Responsibility                                               |
|-----------------------|--------------------------------------------------------------|
| `secnews/sources.py`  | Default feeds, `--feed` and `--sources-file` parsing          |
| `secnews/fetch.py`    | HTTP session, retries, timeouts, robots.txt cache             |
| `secnews/parse.py`    | feedparser → `Article`, HTML cleaning, URL normalisation      |
| `secnews/classify.py` | Tag rules, CVE regex, de-duplication, filters                 |
| `secnews/store.py`    | SQLite archive for `--new-only` and `search`                  |
| `secnews/render.py`   | table / JSON / CSV / Markdown / HTML output                   |
| `secnews/cli.py`      | Command-line interface                                        |

## Daily digest (GitHub Actions)

`.github/workflows/daily-digest.yml` runs every day at 06:00 UTC (09:00 Nairobi) and can also be
started manually from the **Actions** tab. The Markdown digest appears on the run's summary page,
and the HTML/Markdown/JSON files can be downloaded under **Artifacts**.

## Development

```bash
pip install -e ".[dev]"
pytest -q
```

The tests run fully offline: feeds are sample RSS/Atom documents, and the network layer is mocked
in the CLI tests.

## Responsible use

secnews reads feeds that publishers provide for syndication, and links back to the original
articles rather than copying them. If you add sources, check their terms of use, keep request
rates low, and don't republish full article text.

## License

MIT. See [LICENSE](LICENSE).
