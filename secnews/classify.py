"""Tagging, CVE extraction, filtering and de-duplication."""
import re
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from .models import Article

CVE_RE = re.compile(r"\bCVE-(\d{4})-(\d{4,7})\b", re.I)

# tag -> regex. Matched against title + summary, case-insensitive.
TAG_RULES: dict[str, re.Pattern] = {name: re.compile(rx, re.I) for name, rx in {
    "ransomware":     r"\bransomware\b|\b(lockbit|blackcat|alphv|clop|akira|black ?basta|play ransomware)\b",
    "zero-day":       r"\bzero[- ]?day\b|\b0-?day\b|actively exploited|exploited in the wild",
    "vulnerability":  r"\bvulnerabilit(y|ies)\b|\bCVE-\d{4}-\d+|\bpatch(es|ed)?\b|\bflaw\b|\bRCE\b|remote code execution",
    "data-breach":    r"\bdata breach\b|\bbreach(ed)?\b|\bleak(ed|s)?\b|exposed (data|records)|stolen data",
    "malware":        r"\bmalware\b|\btrojan\b|\bbotnet\b|\binfostealer\b|\bstealer\b|\bspyware\b|\bbackdoor\b|\brootkit\b|\bloader\b",
    "phishing":       r"\bphishing\b|\bsmishing\b|\bvishing\b|business email compromise|\bBEC\b",
    "apt":            r"\bAPT ?\d+\b|state[- ]sponsored|nation[- ]state|\b(lazarus|sandworm|fancy bear|cozy bear|volt typhoon|salt typhoon)\b",
    "supply-chain":   r"supply[- ]chain|\bnpm\b|\bPyPI\b|malicious packages?",
    "ddos":           r"\bDDoS\b|denial[- ]of[- ]service",
    "cloud":          r"\b(AWS|Azure|GCP|Google Cloud|Kubernetes|S3 bucket)\b",
    "ai":             r"\bAI\b|\bLLM\b|artificial intelligence|machine learning|\bChatGPT\b|\bdeepfake",
    "law-enforcement": r"\barrest(ed)?\b|\bindict(ed|ment)\b|\bsentenced\b|\bextradit|\btakedown\b|\bseized?\b|\bEuropol\b|\bFBI\b",
    "advisory":       r"\badvisory\b|\bCISA\b|\bKEV\b|known exploited",
}.items()}


def extract_cves(text: str) -> list[str]:
    seen, out = set(), []
    for m in CVE_RE.finditer(text):
        cve = f"CVE-{m.group(1)}-{m.group(2)}"
        if cve not in seen:
            seen.add(cve)
            out.append(cve)
    return out


def tag_article(a: Article) -> Article:
    text = f"{a.title} {a.summary}"
    a.cves = extract_cves(text)
    a.tags = [name for name, rx in TAG_RULES.items() if rx.search(text)]
    return a


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", t.lower())


def dedupe(articles: list[Article], threshold: float = 0.85) -> list[Article]:
    """Remove repeats: same URL, or near-identical titles across sources.

    Keeps the first occurrence, so sort by preference (e.g. newest) beforehand.
    """
    seen_urls: set[str] = set()
    kept: list[Article] = []
    kept_titles: list[str] = []
    for a in articles:
        if a.url in seen_urls:
            continue
        nt = _norm_title(a.title)
        if any(SequenceMatcher(None, nt, kt).ratio() >= threshold for kt in kept_titles):
            continue
        seen_urls.add(a.url)
        kept_titles.append(nt)
        kept.append(a)
    return kept


def filter_articles(
    articles: list[Article],
    *,
    since_hours: float | None = None,
    keywords: list[str] | None = None,
    tags: list[str] | None = None,
    cve_only: bool = False,
    now: datetime | None = None,
) -> list[Article]:
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=since_hours) if since_hours else None
    kws = [k.lower() for k in keywords or []]
    want_tags = set(tags or [])

    out = []
    for a in articles:
        if cutoff and (a.published is None or a.published < cutoff):
            continue
        if kws:
            hay = f"{a.title} {a.summary}".lower()
            if not any(k in hay for k in kws):
                continue
        if want_tags and not want_tags.intersection(a.tags):
            continue
        if cve_only and not a.cves:
            continue
        out.append(a)
    return out


def sort_newest(articles: list[Article]) -> list[Article]:
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    return sorted(articles, key=lambda a: a.published or epoch, reverse=True)
