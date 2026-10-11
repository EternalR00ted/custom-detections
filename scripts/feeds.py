"""Ingest: Nimble live web research, allowlisted feeds, analyst write-ups in inputs/, or one article URL.

Code does all the fetching. The models only ever see cleaned article text,
never a URL to visit. With NIMBLE_API_KEY set, Nimble Search finds new
reports on trusted domains and Nimble Extract returns each page's main
content (rendering JavaScript when a page needs it). Without it, code fetches
pages itself and drops hidden content before any model sees it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from defusedxml import ElementTree

from . import observability
from .common import CONFIG_DIR, ROOT, Fail, load_yaml, log_warning, settings

MAX_BYTES = 5_000_000
USER_AGENT = "custom-detections-drafter/1.0 (+https://github.com)"
TRACKING = re.compile(r"^(utm_\w+|fbclid|gclid|mc_cid|mc_eid|ref|source)$", re.IGNORECASE)
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0", re.IGNORECASE)
ATOM = "{http://www.w3.org/2005/Atom}"


@dataclass
class Article:
    url: str
    title: str
    text: str = ""
    feed: str = ""
    domain: str = ""  # empty for an article URL a person typed in


def normalize(url: str) -> str:
    parts = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if not TRACKING.match(k)])
    host = (parts.hostname or "").lower()
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), host, path, query, ""))


def on_domain(url: str, domain: str) -> bool:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    domain = domain.lower().lstrip(".")
    return parts.scheme == "https" and (host == domain or host.endswith("." + domain))


def _get(session: requests.Session, url: str, domain: str) -> requests.Response:
    """GET with redirects followed by hand, so every hop stays on the allowed domain."""
    for _ in range(6):
        if domain and not on_domain(url, domain):
            raise Fail(f"{url} isn't on {domain}")
        if not domain and urlsplit(url).scheme != "https":
            raise Fail(f"{url} isn't https")
        response = session.get(url, timeout=30, stream=True, allow_redirects=False,
                               headers={"User-Agent": USER_AGENT})
        if response.is_redirect:
            url = urljoin(url, response.headers.get("Location", ""))
            continue
        response.raise_for_status()
        chunks, size = [], 0
        for chunk in response.iter_content(65536):
            size += len(chunk)
            if size > MAX_BYTES:
                raise Fail(f"{url} is larger than {MAX_BYTES:,} bytes")
            chunks.append(chunk)
        response._content = b"".join(chunks)
        return response
    raise Fail(f"{url} redirects too many times")


def _date(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        value = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        try:
            value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def parse_feed(xml: bytes) -> list[tuple[str, str, datetime | None]]:
    root = ElementTree.fromstring(xml)
    items = []
    for item in root.iter("item"):
        items.append((item.findtext("title") or "", (item.findtext("link") or "").strip(),
                      _date(item.findtext("pubDate"))))
    for entry in root.iter(f"{ATOM}entry"):
        link = ""
        for candidate in entry.findall(f"{ATOM}link"):
            if candidate.get("rel", "alternate") == "alternate":
                link = candidate.get("href", "")
                break
        items.append((entry.findtext(f"{ATOM}title") or "", link.strip(),
                      _date(entry.findtext(f"{ATOM}published") or entry.findtext(f"{ATOM}updated"))))
    return items


def feed_articles(session: requests.Session, now: datetime | None = None) -> list[Article]:
    limits = settings()["limits"]
    now = now or datetime.now(timezone.utc)
    oldest = now - timedelta(days=limits["max_age_days"])
    found: list[Article] = []
    for feed in load_yaml(CONFIG_DIR / "feeds.yaml")["feeds"]:
        try:
            xml = _get(session, feed["url"], "").content
            entries = parse_feed(xml)
        except Exception as error:  # noqa: BLE001  one broken feed shouldn't stop the others
            log_warning(f"Feed {feed['name']} failed: {error}")
            observability.capture(error, "warning")
            continue
        kept = 0
        for title, link, published in entries:
            if kept >= limits["feed_items"]:
                break
            if published and published < oldest:
                continue
            if not on_domain(link, feed["domain"]):
                log_warning(f"Skipped a {feed['name']} item that isn't on {feed['domain']}: {link}")
                continue
            found.append(Article(normalize(link), title.strip(), feed=feed["name"], domain=feed["domain"]))
            kept += 1
    return found


def research_articles(nimble) -> list[Article]:
    """New reports found by Nimble Search, only from the trusted domains in config/research.yaml."""
    config = load_yaml(CONFIG_DIR / "research.yaml")
    domains = [d.lower() for d in config["domains"]]
    found: dict[str, Article] = {}
    for query in config["queries"]:
        try:
            results = nimble.search(query, domains, config.get("time_range", "week"),
                                    int(config.get("results_per_query", 5)))
        except Exception as error:  # noqa: BLE001  one failed search shouldn't stop the others
            log_warning(f"Nimble search '{query}' failed: {error}")
            observability.capture(error, "warning")
            continue
        for item in results:
            domain = next((d for d in domains if on_domain(item["url"], d)), "")
            if not domain:
                log_warning(f"Skipped a Nimble result that isn't on a trusted domain: {item['url']}")
                continue
            url = normalize(item["url"])
            text = item["content"][: settings()["limits"]["article_chars"]]
            found.setdefault(url, Article(url, item["title"].strip(), text if len(text) >= 500 else "",
                                          feed=f"Nimble search: {query}", domain=domain))
    return list(found.values())


def clean_html(html: str) -> tuple[str, str]:
    """Visible text only: scripts, styles, hidden elements and comments are dropped."""
    from bs4 import BeautifulSoup, Comment

    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    for tag in soup(["script", "style", "noscript", "template", "iframe", "svg", "canvas", "form",
                     "nav", "footer", "header", "aside", "button", "input", "select", "textarea", "head"]):
        tag.decompose()
    for comment in soup.find_all(string=lambda value: isinstance(value, Comment)):
        comment.extract()
    for tag in soup.find_all(True):
        if tag.decomposed:
            continue
        attrs = tag.attrs or {}
        if ("hidden" in attrs or str(attrs.get("aria-hidden", "")).lower() == "true"
                or HIDDEN_STYLE.search(str(attrs.get("style", "")))):
            tag.decompose()
    root = soup.find("article") or soup.find("main") or soup.body or soup
    text = root.get_text("\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return title, text


def fetch_article(session: requests.Session, article: Article, nimble=None) -> Article:
    if nimble is not None:
        final_url, markdown = nimble.extract(article.url)
        if article.domain and not on_domain(final_url, article.domain):
            raise Fail(f"{article.url} redirected to {final_url}, which isn't on {article.domain}")
        if not article.domain and urlsplit(final_url).scheme != "https":
            raise Fail(f"{final_url} isn't https")
        article.text = markdown[: settings()["limits"]["article_chars"]]
        if len(article.text) < 500:
            raise Fail(f"{article.url} has too little text to draft from")
        return article
    response = _get(session, article.url, article.domain)
    kind = response.headers.get("Content-Type", "")
    if "html" not in kind and "text" not in kind:
        raise Fail(f"{article.url} isn't a web page ({kind or 'no content type'})")
    encoding = response.encoding if response.encoding and response.encoding.lower() != "iso-8859-1" else "utf-8"
    title, text = clean_html(response.content.decode(encoding, errors="replace"))
    article.title = article.title or title
    article.text = text[: settings()["limits"]["article_chars"]]
    if len(article.text) < 500:
        raise Fail(f"{article.url} has too little text to draft from")
    return article


def analyst_inputs(file_url) -> list[Article]:
    """Markdown write-ups under inputs/, each treated like an article."""
    found = []
    for path in sorted((ROOT / "inputs").glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        text = path.read_text(encoding="utf-8")
        first = next((line.lstrip("# ").strip() for line in text.splitlines() if line.strip()), path.stem)
        found.append(Article(file_url(f"inputs/{path.name}"), first, text[: settings()["limits"]["article_chars"]],
                             feed="Analyst write-up"))
    return found


def shield_attack(session: requests.Session, credential, endpoint: str, text: str) -> bool:
    """Azure AI Content Safety Prompt Shields. True when it sees an injection attack."""
    token = credential.get_token("https://cognitiveservices.azure.com/.default").token
    url = endpoint.rstrip("/") + "/contentsafety/text:shieldPrompt?api-version=2024-09-01"
    chunks = [text[i:i + 10000] for i in range(0, min(len(text), 50000), 10000)] or [""]
    response = session.post(url, timeout=60, headers={"Authorization": f"Bearer {token}"},
                            json={"userPrompt": "", "documents": chunks})
    response.raise_for_status()
    return any(item.get("attackDetected") for item in response.json().get("documentsAnalysis", []))


class Seen:
    """Articles already handled. Kept in the pipeline cache between runs."""

    def __init__(self, path: Path):
        self.path = path
        self.urls: dict[str, str] = {}
        if path.exists():
            try:
                self.urls = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                self.urls = {}

    def __contains__(self, url: str) -> bool:
        return normalize(url) in self.urls

    def add(self, url: str, outcome: str) -> None:
        self.urls[normalize(url)] = outcome

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.urls, indent=1, sort_keys=True), encoding="utf-8")


def urls_in_pull_requests(prs: list[dict]) -> set[str]:
    """Source URLs already drafted, read from the 'Source:' line of every pull request description."""
    found = set()
    for pr in prs:
        for match in re.finditer(r"^Source: <?(https://\S+?)>?\s*$", pr.get("description") or "", re.MULTILINE):
            found.add(normalize(match.group(1)))
    return found
