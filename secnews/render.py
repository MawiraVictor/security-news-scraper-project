"""Output formats: terminal table, JSON, CSV, Markdown and a standalone HTML digest."""
import csv
import html
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .models import Article

FORMATS = ("table", "json", "csv", "markdown", "html")


def _date(a: Article, fmt: str = "%Y-%m-%d %H:%M") -> str:
    return a.published.strftime(fmt) if a.published else "unknown"


def _plural(n: int) -> str:
    return f"{n} article" if n == 1 else f"{n} articles"


def render(articles: list[Article], fmt: str) -> str:
    return {
        "table": to_table, "json": to_json, "csv": to_csv,
        "markdown": to_markdown, "html": to_html,
    }[fmt](articles)


def to_table(articles: list[Article]) -> str:
    if not articles:
        return "No articles found."
    lines = []
    for a in articles:
        extra = []
        if a.cves:
            extra.append(", ".join(a.cves[:3]) + ("…" if len(a.cves) > 3 else ""))
        if a.tags:
            extra.append("#" + " #".join(a.tags))
        lines.append(f"{_date(a)}  [{a.source}]  {a.title}")
        if extra:
            lines.append("    " + "  ".join(extra))
        lines.append(f"    {a.url}")
    lines.append(f"\n{_plural(len(articles))}")
    return "\n".join(lines)


def to_json(articles: list[Article]) -> str:
    return json.dumps([a.to_dict() for a in articles], indent=2, ensure_ascii=False)


def to_csv(articles: list[Article]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["published", "source", "title", "url", "cves", "tags", "summary"])
    for a in articles:
        w.writerow([a.published.isoformat() if a.published else "", _csv_cell(a.source),
                    _csv_cell(a.title), _csv_cell(a.url), " ".join(a.cves), " ".join(a.tags),
                    _csv_cell(a.summary)])
    return buf.getvalue()


def _csv_cell(value: str) -> str:
    """Stop spreadsheets from evaluating feed text as a formula (CSV injection, CWE-1236)."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def _safe_url(url: str) -> str:
    """Only http(s) links are emitted; anything else (javascript:, data:, ...) becomes '#'."""
    return url if urlsplit(url).scheme.lower() in ("http", "https") else "#"


_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>#|])")


def _md_escape(s: str) -> str:
    """Escape Markdown syntax and raw HTML so feed text renders as plain text."""
    return _MD_SPECIAL.sub(r"\\\1", s)


def _md_url(url: str) -> str:
    # Angle-bracket destinations allow ')' and spaces; '<' '>' must be percent-encoded.
    return "<" + _safe_url(url).replace("<", "%3C").replace(">", "%3E").replace(" ", "%20") + ">"


def to_markdown(articles: list[Article]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = [f"# Security News Digest", "", f"_Generated {now} · {_plural(len(articles))}_", ""]
    tag_counts = Counter(t for a in articles for t in a.tags)
    if tag_counts:
        out += ["**Top topics:** " + ", ".join(f"{t} ({n})" for t, n in tag_counts.most_common(8)), ""]
    cves = sorted({c for a in articles for c in a.cves})
    if cves:
        out += [f"**CVEs mentioned ({len(cves)}):** " + ", ".join(
            f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in cves), ""]
    for a in articles:
        out.append(f"### [{_md_escape(a.title)}]({_md_url(a.url)})")
        meta = f"{_md_escape(a.source)} · {_date(a)}"
        if a.tags:
            meta += " · " + " ".join(f"`{t}`" for t in a.tags)
        out.append(meta)
        if a.summary:
            out += ["", _md_escape(a.summary)]
        out.append("")
    return "\n".join(out)


def to_html(articles: list[Article]) -> str:
    e = html.escape
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tag_counts = Counter(t for a in articles for t in a.tags)
    chips = "".join(
        f'<button class="chip" data-tag="{e(t)}">{e(t)} <span>{n}</span></button>'
        for t, n in tag_counts.most_common()
    )
    items = []
    for a in articles:
        cves = "".join(
            f'<a class="cve" href="https://nvd.nist.gov/vuln/detail/{e(c)}" rel="noopener">{e(c)}</a>'
            for c in a.cves
        )
        tags = "".join(f'<span class="tag">{e(t)}</span>' for t in a.tags)
        items.append(f"""
<article data-tags="{e(' '.join(a.tags))}">
  <h2><a href="{e(_safe_url(a.url))}" rel="noopener noreferrer">{e(a.title)}</a></h2>
  <p class="meta">{e(a.source)} · <time>{e(_date(a))}</time></p>
  {f'<p>{e(a.summary)}</p>' if a.summary else ''}
  <p class="labels">{cves}{tags}</p>
</article>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security News Digest</title>
<style>
  :root {{ --bg:#f7f7f8; --card:#fff; --text:#1d1d1f; --muted:#6b6b76; --accent:#0b62d6; --line:#e3e3e8; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg:#111214; --card:#1b1c1f; --text:#ececf1; --muted:#9a9aa6; --accent:#6aa8ff; --line:#2c2d31; }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, sans-serif; }}
  main {{ max-width:820px; margin:0 auto; padding:24px 16px 64px; }}
  h1 {{ margin:0 0 4px; font-size:1.6rem; }}
  .sub {{ color:var(--muted); margin:0 0 16px; }}
  .chips {{ display:flex; flex-wrap:wrap; gap:6px; margin-bottom:20px; }}
  .chip {{ border:1px solid var(--line); background:var(--card); color:var(--text); border-radius:999px;
          padding:4px 10px; font:inherit; font-size:.85rem; cursor:pointer; }}
  .chip span {{ color:var(--muted); }}
  .chip[aria-pressed="true"] {{ background:var(--accent); color:#fff; border-color:var(--accent); }}
  .chip[aria-pressed="true"] span {{ color:#fff; }}
  article {{ background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:12px; }}
  article h2 {{ font-size:1.05rem; margin:0 0 4px; }}
  article a {{ color:var(--accent); text-decoration:none; }}
  article a:hover {{ text-decoration:underline; }}
  .meta {{ color:var(--muted); font-size:.85rem; margin:0 0 6px; }}
  article p {{ margin:6px 0; }}
  .labels {{ display:flex; flex-wrap:wrap; gap:6px; }}
  .tag, .cve {{ font-size:.75rem; padding:1px 8px; border-radius:999px; border:1px solid var(--line); color:var(--muted); }}
  .cve {{ font-family:ui-monospace, monospace; }}
</style>
</head>
<body>
<main>
  <h1>Security News Digest</h1>
  <p class="sub">Generated {e(now)} · <span id="count">{len(articles)}</span> article(s)</p>
  <div class="chips">{chips}</div>
  {''.join(items) if items else '<p>No articles found.</p>'}
</main>
<script>
  const chips = document.querySelectorAll('.chip');
  const cards = document.querySelectorAll('article');
  let active = null;
  chips.forEach(c => c.addEventListener('click', () => {{
    active = active === c.dataset.tag ? null : c.dataset.tag;
    chips.forEach(x => x.setAttribute('aria-pressed', String(x.dataset.tag === active)));
    let n = 0;
    cards.forEach(a => {{
      const show = !active || a.dataset.tags.split(' ').includes(active);
      a.hidden = !show; if (show) n++;
    }});
    document.getElementById('count').textContent = n;
  }}));
</script>
</body>
</html>
"""
