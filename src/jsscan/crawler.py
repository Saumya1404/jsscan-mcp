"""Collect the JavaScript a target loads.

Sources: <script src>, inline <script>, modulepreload links, and string
references to other .js files inside already-fetched scripts (webpack chunks,
dynamic imports). Pages are crawled breadth-first, same allowlist rules apply
to every request. Scripts on out-of-scope hosts are NOT fetched; they are
returned as passive assets so their URLs can still be checked for known
library versions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit

from .fetcher import ScopedFetcher
from .scope import Scope


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.inline: list[str] = []
        self.links: list[str] = []
        self._in_script = False
        self._buf: list[str] = []
        self._script_has_src = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "script":
            self._in_script = True
            self._buf = []
            self._script_has_src = bool(a.get("src"))
            if a.get("src"):
                self.scripts.append(a["src"])
        elif tag == "link" and a.get("rel") in ("modulepreload", "preload") and a.get("href"):
            if a.get("as") == "script" or a.get("rel") == "modulepreload":
                self.scripts.append(a["href"])
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._buf).strip()
            if text and not self._script_has_src:
                self.inline.append(text)


_JS_REF = re.compile(
    r"""["'`]((?:\.{1,2}/|/)?[\w\-./@~]*?[\w\-]+\.m?js)(?:\?[^"'`\s]*)?["'`]"""
)
_ABS_REF = re.compile(r"""["'`](https?://[^"'`\s]{6,300}?\.m?js)(?:\?[^"'`\s]*)?["'`]""")


def js_references(text: str, base_url: str) -> list[str]:
    """Other scripts referenced from inside a script."""
    out: list[str] = []
    for m in _JS_REF.finditer(text[:3_000_000]):
        ref = m.group(1)
        if ref.startswith(("./", "../", "/")) or "chunk" in ref or re.search(r"[.\-][0-9a-f]{8,}\.m?js$", ref):
            out.append(urljoin(base_url, ref))
    for m in _ABS_REF.finditer(text[:3_000_000]):
        out.append(m.group(1))
    return list(dict.fromkeys(out))


@dataclass
class JsAsset:
    url: str                    # for inline scripts: page_url#inline-N
    kind: str                   # external | inline | passive
    page: str | None = None     # page that loaded it
    index: int = 0              # inline index within page
    text: str = ""
    status: int = 0
    size: int = 0
    note: str = ""


@dataclass
class CrawlResult:
    pages: list[str] = field(default_factory=list)
    assets: list[JsAsset] = field(default_factory=list)
    blocked_hosts: dict[str, int] = field(default_factory=dict)
    failed: list[str] = field(default_factory=list)


def _norm(url: str) -> str:
    return urldefrag(url)[0]


async def crawl(fetcher: ScopedFetcher, scope: Scope, start_url: str, scan_id: str,
                max_pages: int = 10, max_js: int = 60) -> CrawlResult:
    res = CrawlResult()
    seen_pages: set[str] = set()
    seen_js: set[str] = set()
    queue: list[str] = [_norm(start_url)]

    def note_blocked(url: str) -> None:
        host = urlsplit(url).netloc.lower()
        res.blocked_hosts[host] = res.blocked_hosts.get(host, 0) + 1

    async def fetch_script(url: str, page: str | None) -> list[str]:
        """Fetch one external script, return further references to follow."""
        if len(seen_js) >= max_js:
            return []
        seen_js.add(url)
        if not scope.check(url, "script", scan_id, log_allowed=False):
            note_blocked(url)
            res.assets.append(JsAsset(url, "passive", page, note="out of scope, not fetched"))
            return []
        f = await fetcher.get(url, "script", scan_id)
        if f.error or f.status >= 400:
            res.failed.append(f"{url} ({f.error or f.status})")
            return []
        res.assets.append(JsAsset(url, "external", page, text=f.text, status=f.status,
                                  size=len(f.text), note="truncated" if f.truncated else ""))
        return js_references(f.text, f.final_url)

    while queue and len(res.pages) < max_pages:
        page = queue.pop(0)
        if page in seen_pages:
            continue
        seen_pages.add(page)
        f = await fetcher.get(page, "page", scan_id)
        if f.error or f.status >= 400:
            res.failed.append(f"{page} ({f.error or f.status})")
            continue
        ctype = f.content_type.lower()
        if "javascript" in ctype or page.split("?")[0].endswith((".js", ".mjs")):
            # the target itself is a script
            seen_js.add(page)
            res.assets.append(JsAsset(page, "external", None, text=f.text, status=f.status, size=len(f.text)))
            continue
        res.pages.append(page)
        parser = _PageParser()
        try:
            parser.feed(f.text)
        except Exception:
            pass
        for i, code in enumerate(parser.inline):
            res.assets.append(JsAsset(f"{page}#inline-{i}", "inline", page, i, code, f.status, len(code)))
        pending = [urljoin(f.final_url, s) for s in parser.scripts]
        # follow chunk references breadth-first, bounded by max_js
        while pending and len(seen_js) < max_js:
            url = _norm(pending.pop(0))
            if url in seen_js:
                continue
            pending.extend(await fetch_script(url, page))
        for href in parser.links:
            link = _norm(urljoin(f.final_url, href))
            if link in seen_pages or not link.startswith(("http://", "https://")):
                continue
            if scope.check(link, "link", scan_id, log_allowed=False):
                queue.append(link)
            else:
                note_blocked(link)
    return res
