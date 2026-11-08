"""Known-vulnerable library detection.

Uses the Retire.js repository format (Apache-2.0): per-library extractor regexes
for URL, filename and file content, plus version ranges with advisories. A
snapshot ships with the package; refresh_vuln_db pulls the latest.

Confidence comes from how many independent signals agree on the version:
file content banner > filename > URL path. Two kinds agreeing is the strongest.
"""
from __future__ import annotations

import hashlib
import json
import re

import regex
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

PLACEHOLDER = "\u00a7\u00a7version\u00a7\u00a7"
VERSION_RE = r"[0-9][0-9.a-z_\-]+"
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONTENT_CAP = 3_000_000

_PREFIX = re.compile(r"^\d+(?:\.\d+){0,3}(?:[-.]?(?:alpha|beta|rc|pre|a|b)\.?\d*)?", re.I)


def clean_version(v: str) -> str | None:
    v = v.strip(".-_")
    v = re.sub(r"(?:[.\-_](?:min|slim|prod|production|debug|bundle))+(?:\.js)?$", "", v)
    v = re.sub(r"\.m?js$", "", v)
    m = _PREFIX.match(v)
    return m.group(0).strip(".-_") if m else None


def vkey(v: str) -> tuple:
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return ((0,), 0, 0)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums))
    rest = m.group(2).strip(".-_").lower()
    if not rest:
        return (nums, 1, 0)
    n = re.search(r"\d+", rest)
    order = 0
    for i, tag in enumerate(("alpha", "a", "beta", "b", "pre", "rc")):
        if rest.startswith(tag):
            order = i
            break
    return (nums, 0, order * 1000 + (int(n.group()) if n else 0))


def in_range(version: str, vuln: dict) -> bool:
    k = vkey(version)
    if "atOrAbove" in vuln and k < vkey(vuln["atOrAbove"]):
        return False
    if "below" in vuln and k >= vkey(vuln["below"]):
        return False
    return "below" in vuln or "atOrAbove" in vuln


@dataclass
class Signal:
    kind: str       # uri | filename | filecontent
    version: str
    offset: int | None = None
    length: int = 0


@dataclass
class Detection:
    lib: str
    version: str
    signals: list[Signal]
    confidence: int
    conflict: str | None
    vulns: list[dict]

    @property
    def offset(self) -> int | None:
        for s in self.signals:
            if s.kind == "filecontent":
                return s.offset
        return None


@dataclass
class _Lib:
    name: str
    vulns: list[dict]
    rx: dict[str, list] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)


# Supplemental content extractors for builds the upstream repository cannot identify.
# Applied on top of whichever database is loaded, so refreshes do not drop them.
EXTRA_EXTRACTORS: dict[str, list[str]] = {
    # minified lodash: ...VERSION="4.17.15",x("bind bindKey curry curryRight ...
    "lodash": [r'\.VERSION="(' + PLACEHOLDER + r')",[\w$]+\("bind bindKey curry curryRight'],
}


def _compile(p: str):
    """Retire patterns use variable-width lookbehind, which only the `regex` module supports."""
    try:
        return regex.compile(p.replace(PLACEHOLDER, VERSION_RE))
    except regex.error:
        return None


def _search(rx, text: str):
    try:
        return rx.search(text, timeout=3.0)  # bound pathological backtracking
    except TimeoutError:
        return None


class VulnDB:
    def __init__(self, raw: dict):
        self.libs: list[_Lib] = []
        for name, entry in raw.items():
            if name == "retire-example":
                continue
            ex = entry.get("extractors", {})
            patterns = {k: list(ex.get(k, [])) for k in ("uri", "filename", "filecontent")}
            patterns["filecontent"] += EXTRA_EXTRACTORS.get(name, [])
            rx = {k: [c for c in map(_compile, v) if c] for k, v in patterns.items()}
            self.libs.append(_Lib(name, entry.get("vulnerabilities", []), rx, ex.get("hashes", {})))

    @classmethod
    def load(cls, cache: Path | None = None) -> "VulnDB":
        if cache and cache.exists():
            try:
                return cls(json.loads(cache.read_text()))
            except (json.JSONDecodeError, OSError):
                pass
        snap = resources.files("jsscan").joinpath("data/retire-snapshot.json").read_text()
        return cls(json.loads(snap))

    def detect(self, url: str, text: str | None, inline: bool = False) -> list[Detection]:
        filename = urlsplit(url).path.rsplit("/", 1)[-1]
        uri = url.split("#", 1)[0]
        out: list[Detection] = []
        for lib in self.libs:
            sigs: list[Signal] = []
            if not inline:
                for rx in lib.rx["uri"]:
                    m = _search(rx, uri)
                    if m and (v := clean_version(m.group(1))):
                        sigs.append(Signal("uri", v))
                        break
                for rx in lib.rx["filename"]:
                    m = _search(rx, filename)
                    if m and (v := clean_version(m.group(1))):
                        sigs.append(Signal("filename", v))
                        break
            if text and lib.hashes:
                digest = hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()
                if digest in lib.hashes:
                    sigs.append(Signal("hash", lib.hashes[digest]))
            if text:
                body = text[:CONTENT_CAP]
                for rx in lib.rx["filecontent"]:
                    m = _search(rx, body)
                    if m and (v := clean_version(m.group(1))):
                        sigs.append(Signal("filecontent", v, m.start(1), len(m.group(1))))
                        break
            if not sigs:
                continue
            content = [s for s in sigs if s.kind in ("hash", "filecontent")]
            version = (content or sigs)[0].version
            agree = {s.kind for s in sigs if s.version == version}
            conflict = None
            others = {s.version for s in sigs} - {version}
            if others:
                conflict = f"signals disagree ({', '.join(sorted(others))} vs {version}); trusting " + \
                           ("file content or hash" if content else "first signal")
            conf = 60
            if "filecontent" in agree:
                conf = 80
            if "hash" in agree:
                conf = 97
            if len(agree) >= 2:
                conf = 95
            if conflict:
                conf = min(conf, 55)
            vulns = [v for v in lib.vulns if in_range(version, v)]
            out.append(Detection(lib.name, version, sigs, conf, conflict, vulns))
        return out


def summarize_vulns(vulns: list[dict]) -> dict:
    """Compact advisory summary: highest severity, ids, one-line summaries, fixed-in."""
    sev = max((v.get("severity", "medium") for v in vulns), key=lambda s: SEV_RANK.get(s, 2))
    items = []
    for v in vulns:
        ident = v.get("identifiers", {})
        ids = ident.get("CVE") or ([ident["githubID"]] if ident.get("githubID") else []) or ["no-cve"]
        items.append({"id": ids[0], "severity": v.get("severity", "medium"),
                      "summary": ident.get("summary", "")[:140], "fixed_in": v.get("below")})
    items.sort(key=lambda i: -SEV_RANK.get(i["severity"], 2))
    for i in items:  # Retire marks "no patched release in this line" with a 999.999 bound
        if i["fixed_in"] and re.search(r"\.999\.999$", i["fixed_in"]):
            i["fixed_in"] = None
    fixed = max((i["fixed_in"] for i in items if i["fixed_in"]), key=vkey, default=None)
    return {"severity": sev, "vulns": items, "fixed_in": fixed}
