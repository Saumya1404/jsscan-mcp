"""Orchestrates crawl, scan, verification and persistence."""
from __future__ import annotations

import asyncio
import time
import uuid

from .config import Settings
from .crawler import JsAsset, _PageParser, crawl
from .deps import VulnDB, summarize_vulns
from .fetcher import ScopedFetcher
from .scope import Scope
from .secrets import scan_text
from .store import Store

STATUS_FROM_CONF = lambda c: "confirmed" if c >= 90 else "likely" if c >= 70 else "unverified"  # noqa: E731


def _snippet(before: str, match: str, after: str) -> dict:
    return {"before": before[-70:], "match": match, "after": after[:70]}


def analyze_asset(asset: JsAsset, db: VulnDB) -> tuple[list[dict], list[str]]:
    """Return (findings, libraries) for one asset. Pure CPU, safe to run in a thread."""
    findings: list[dict] = []
    libs: list[str] = []
    passive = asset.kind == "passive"
    if not passive:
        for h in scan_text(asset.text):
            v = h.verdict
            findings.append({
                "type": "secret", "rule_id": h.rule.id, "title": h.rule.name,
                "severity": v.severity, "status": v.status, "confidence": v.confidence,
                "asset_url": asset.url, "line": h.line, "col": h.col,
                "fingerprint": h.fingerprint, "occurrences": 1,
                "data": {"preview": h.preview, "length": len(h.value), "key_name": h.key_name,
                         "checks": v.checks, "meta": v.meta, "also_in": [],
                         "snippet": _snippet(h.before, h.preview, h.after)},
            })
    from .secrets import LineIndex
    idx = LineIndex(asset.text) if asset.text else None
    for d in db.detect(asset.url, None if passive else asset.text, inline=asset.kind == "inline"):
        libs.append(f"{d.lib}@{d.version}")
        if not d.vulns:
            continue
        s = summarize_vulns(d.vulns)
        conf = d.confidence
        line = col = 0
        snippet = None
        if d.offset is not None and idx:
            line, col = idx.locate(d.offset)
            snippet = _snippet(asset.text[max(0, d.offset - 60):d.offset].replace("\n", " "), d.version,
                               asset.text[d.offset + len(d.version):d.offset + 60].replace("\n", " "))
        evidence = "url only, file not fetched (out of scope)" if passive else None
        if passive:
            conf = min(conf, 55)
        n = len(d.vulns)
        findings.append({
            "type": "dependency", "rule_id": f"{d.lib}@{d.version}",
            "title": f"{d.lib} {d.version}: {n} known {'vulnerability' if n == 1 else 'vulnerabilities'}",
            "severity": s["severity"], "status": "unverified" if passive else STATUS_FROM_CONF(conf),
            "confidence": conf, "asset_url": asset.url, "line": line, "col": col,
            "fingerprint": f"{d.lib}@{d.version}", "occurrences": 1,
            "data": {"library": d.lib, "version": d.version, "vulns": s["vulns"][:8],
                     "fixed_in": s["fixed_in"], "conflict": d.conflict, "evidence": evidence,
                     "signals": [{"kind": x.kind, "version": x.version} for x in d.signals],
                     "snippet": snippet, "also_in": []},
        })
    return findings, libs


def _merge(drafts: list[dict]) -> list[dict]:
    """Collapse the same secret seen in several places into one finding."""
    merged: dict[tuple, dict] = {}
    for f in drafts:
        key = (f["type"], f["rule_id"], f["fingerprint"])
        if key in merged:
            m = merged[key]
            m["occurrences"] += 1
            if len(m["data"]["also_in"]) < 5:
                m["data"]["also_in"].append(f"{f['asset_url']}:{f['line']}")
        else:
            merged[key] = f
    return list(merged.values())


def where(f: dict) -> str:
    return f"{f['asset_url']}:{f['line']}:{f['col']}" if f["line"] else f["asset_url"]


def compact(f: dict) -> dict:
    d = f["data"]
    out = {"id": f["id"], "type": f["type"], "severity": f["severity"], "status": f["status"],
           "confidence": f["confidence"], "title": f["title"], "where": where(f)}
    if f["type"] == "secret":
        out["preview"] = d["preview"]
    else:
        out["fixed_in"] = d.get("fixed_in")
        out["cves"] = [v["id"] for v in d["vulns"][:3]]
    if f["occurrences"] > 1:
        out["occurrences"] = f["occurrences"]
    return out


class Scanner:
    def __init__(self, settings: Settings, scope: Scope, store: Store, db: VulnDB):
        self.settings, self.scope, self.store, self.db = settings, scope, store, db

    def dashboard(self, scan_id: str) -> str | None:
        if not self.settings.web_enabled:
            return None
        return f"http://{self.settings.web_host}:{self.settings.web_port}/scans/{scan_id}"

    async def _crawl(self, url: str, scan_id: str, max_pages: int, max_js: int):
        fetcher = ScopedFetcher(self.scope, self.settings)
        try:
            return await crawl(fetcher, self.scope, url, scan_id, max_pages, max_js)
        finally:
            await fetcher.aclose()

    def _refuse(self, url: str) -> dict | None:
        if self.scope.check(url, "target"):
            return None
        return {"error": "out_of_scope", "detail": self.scope.decide(url)[1],
                "allowed_hosts": self.scope.allowed_hosts,
                "note": "refused and logged; scope can only be changed by whoever launches the server"}

    @staticmethod
    def _asset_row(a: JsAsset) -> dict:
        return {"url": a.url, "kind": a.kind, "page": a.page, "idx": a.index,
                "status": a.status, "size": a.size, "note": a.note}

    @staticmethod
    def _asset_counts(res) -> dict:
        kinds = [a.kind for a in res.assets]
        return {"external": kinds.count("external"), "inline": kinds.count("inline"),
                "passive_out_of_scope": kinds.count("passive"), "failed": len(res.failed)}

    async def crawl_only(self, url: str, max_pages: int, max_js: int) -> dict:
        if (r := self._refuse(url)):
            return r
        scan_id = uuid.uuid4().hex[:8]
        self.store.new_scan(scan_id, url, "crawl")
        res = await self._crawl(url, scan_id, max_pages, max_js)
        self.store.add_assets(scan_id, [self._asset_row(a) for a in res.assets])
        summary = {"pages": len(res.pages), "scripts": self._asset_counts(res), "blocked_hosts": res.blocked_hosts}
        self.store.finish_scan(scan_id, "crawled", summary)
        return {"scan_id": scan_id, **summary,
                "assets": [{"url": a.url, "kind": a.kind, "bytes": a.size, "note": a.note}
                           for a in res.assets[:60]],
                "failed": res.failed[:10]}

    async def scan(self, url: str, max_pages: int, max_js: int) -> dict:
        if (r := self._refuse(url)):
            return r
        t0 = time.time()
        scan_id = uuid.uuid4().hex[:8]
        self.store.new_scan(scan_id, url, "scan")
        try:
            res = await self._crawl(url, scan_id, max_pages, max_js)
            self.store.add_assets(scan_id, [self._asset_row(a) for a in res.assets])
            results = await asyncio.gather(*(asyncio.to_thread(analyze_asset, a, self.db) for a in res.assets))
        except Exception as e:  # keep the scan record honest
            self.store.finish_scan(scan_id, "failed", {"error": f"{type(e).__name__}: {e}"})
            return {"error": "scan_failed", "detail": f"{type(e).__name__}: {e}", "scan_id": scan_id}
        drafts = _merge([f for fs, _ in results for f in fs])
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        drafts.sort(key=lambda f: (f["status"] == "rejected", rank[f["severity"]], -f["confidence"]))
        for i, f in enumerate(drafts, 1):
            f["id"], f["scan_id"] = f"{scan_id}-{i:03d}", scan_id
        self.store.add_findings(drafts)
        libs = sorted({l for _, ls in results for l in ls})
        counts = self.store.counts(scan_id)
        summary = {"pages": len(res.pages), "scripts": self._asset_counts(res),
                   "blocked_hosts": res.blocked_hosts, "libraries_detected": libs[:20],
                   **counts, "seconds": round(time.time() - t0, 1)}
        self.store.finish_scan(scan_id, "done", summary)
        shown = [f for f in drafts if f["status"] != "rejected"][:5]
        return {"scan_id": scan_id, "target": url, **summary,
                "top": [compact(f) for f in shown], "dashboard": self.dashboard(scan_id)}

    async def verify(self, finding_id: str) -> dict:
        f = self.store.get_finding(finding_id)
        if not f:
            return {"error": "not_found", "detail": f"no finding {finding_id}"}
        asset = self.store.get_asset(f["scan_id"], f["asset_url"])
        if not asset or asset["kind"] == "passive":
            return {"error": "not_verifiable", "detail": "asset was never fetched (out of scope); evidence is URL only"}
        fetcher = ScopedFetcher(self.scope, self.settings)
        try:
            src = asset["page"] if asset["kind"] == "inline" else asset["url"]
            got = await fetcher.get(src, "verify", f["scan_id"])
        finally:
            await fetcher.aclose()
        if got.error:
            return {"error": "fetch_failed", "detail": got.error, "blocked": got.blocked}
        text = got.text
        if asset["kind"] == "inline":
            p = _PageParser()
            p.feed(text)
            text = p.inline[asset["idx"]] if asset["idx"] < len(p.inline) else ""
        before = {"status": f["status"], "confidence": f["confidence"]}
        reproduced, checks = False, f["data"].get("checks", [])
        if f["type"] == "secret":
            match = next((h for h in scan_text(text)
                          if h.fingerprint == f["fingerprint"] and h.rule.id == f["rule_id"]), None)
            if match:
                reproduced, checks = True, match.verdict.checks
                f["status"], f["confidence"] = match.verdict.status, match.verdict.confidence
                f["data"]["meta"] = match.verdict.meta
                f["line"], f["col"] = match.line, match.col
        else:
            match = next((d for d in self.db.detect(asset["url"], text, asset["kind"] == "inline")
                          if d.lib == f["data"]["library"] and d.version == f["data"]["version"]), None)
            if match:
                reproduced = True
                f["confidence"] = match.confidence
                f["status"] = STATUS_FROM_CONF(match.confidence)
        if not reproduced:
            f["status"] = "not_reproduced"
        f["data"]["checks"] = checks
        f["data"]["verified_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self.store.update_finding(finding_id, f["status"], f["confidence"], f["data"])
        return {"id": finding_id, "reproduced": reproduced, "before": before,
                "after": {"status": f["status"], "confidence": f["confidence"]},
                "where": where(f), "checks": checks[:8]}
