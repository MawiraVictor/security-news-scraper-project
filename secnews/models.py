from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass
class Source:
    name: str
    url: str          # RSS / Atom feed URL
    homepage: str = ""


@dataclass
class Article:
    title: str
    url: str
    source: str
    published: datetime | None = None
    summary: str = ""
    author: str = ""
    cves: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["published"] = self.published.isoformat() if self.published else None
        return d
