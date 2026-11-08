"""Read-only web view of scan findings, grouped by type and severity.

Everything rendered here originates from untrusted target content, so every
value is HTML-escaped, the page needs no JavaScript, and a strict CSP blocks
scripts and external loads. Binds to localhost and rejects foreign Host headers.
"""
from __future__ import annotations

import html
import json
import threading
import time
from urllib.parse import urlencode

import uvicorn
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from .config import Settings, get_settings
from .scope import AuditLog
from .store import Store

e = html.escape
SEVS = ["critical", "high", "medium", "low", "info"]
TYPES = {"secret": "Exposed secrets", "dependency": "Vulnerable libraries"}
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
}

CSS = """
:root{--bg:#f4f5f7;--panel:#fff;--ink:#17202b;--mute:#5d6875;--rule:#d9dde3;--code:#0f1720;--codeink:#d8e0ea;
--critical:#b3261e;--high:#c2490c;--medium:#9a6b00;--low:#2b6a9e;--info:#66727f;--focus:#0b5fff;--redact:#f5d547}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--panel:#171e26;--ink:#e6ebf1;--mute:#98a4b1;--rule:#2a3441;
--code:#0a0f14;--codeink:#cfd8e3;--critical:#ff6b61;--high:#ff9a57;--medium:#e3b341;--low:#6cb2ee;--info:#9aa5b1;--focus:#7aa8ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Avenir Next","Segoe UI",system-ui,sans-serif}
a{color:inherit}a:focus-visible,summary:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px 64px}
header.top{border-bottom:1px solid var(--rule);background:var(--panel)}
header.top .wrap{display:flex;gap:24px;align-items:baseline;padding-top:14px;padding-bottom:14px}
.brand{font-weight:700;letter-spacing:.01em;text-decoration:none}
nav a{margin-right:16px;color:var(--mute);text-decoration:none}nav a:hover{color:var(--ink)}
h1{font-size:22px;line-height:1.3;margin:28px 0 4px;word-break:break-all}
h2{font-size:18px;margin:36px 0 4px}
h3{font-size:14px;margin:18px 0 8px;display:flex;gap:8px;align-items:center;font-weight:600}
.meta{color:var(--mute);margin:0 0 20px}
.bar{display:flex;height:14px;border-radius:3px;overflow:hidden;background:var(--rule);margin:14px 0 8px}
.bar i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--mute);font-size:13px}
.legend b{color:var(--ink);font-weight:600}
.dot{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px}
.filters{margin:18px 0 0;font-size:13px;color:var(--mute);display:flex;flex-wrap:wrap;gap:6px 14px}
.filters a{padding:1px 0;border-bottom:1px solid transparent}.filters a.on{color:var(--ink);border-color:var(--ink)}
details.f{background:var(--panel);border:1px solid var(--rule);border-left:4px solid var(--c,var(--info));border-radius:4px;margin:0 0 8px}
details.f>summary{list-style:none;cursor:pointer;padding:10px 14px;display:grid;grid-template-columns:auto 1fr auto;gap:2px 14px;align-items:baseline}
details.f>summary::-webkit-details-marker{display:none}
.sev{font-weight:700;color:var(--c);min-width:62px}
.title{font-weight:600}.where{grid-column:2;color:var(--mute);font:12.5px ui-monospace,"SF Mono",Menlo,Consolas,monospace;word-break:break-all}
.conf{color:var(--mute);font-size:13px;white-space:nowrap}
.body{padding:2px 14px 14px;border-top:1px solid var(--rule)}
pre.code{background:var(--code);color:var(--codeink);padding:12px 14px;border-radius:4px;overflow-x:auto;margin:12px 0;font:12.5px/1.6 ui-monospace,"SF Mono",Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-all}
pre.code .ln{color:#6c7a89;user-select:none;margin-right:12px}
mark{background:var(--redact);color:#1a1400;padding:1px 5px;border-radius:2px;font-weight:600}
ul.checks{list-style:none;margin:8px 0;padding:0;font-size:13.5px}
ul.checks li{padding:2px 0}.pass{color:var(--low)}.fail{color:var(--critical)}
.k{color:var(--mute);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:8px 0}
td,th{text-align:left;padding:5px 10px 5px 0;border-bottom:1px solid var(--rule);vertical-align:top}th{color:var(--mute);font-weight:500}
.empty{color:var(--mute);padding:14px 0}
.scans a.row{display:grid;grid-template-columns:1fr auto;gap:4px 16px;padding:12px 14px;background:var(--panel);border:1px solid var(--rule);border-radius:4px;margin-bottom:8px;text-decoration:none}
.scans a.row:hover{border-color:var(--mute)}
@media (max-width:600px){details.f>summary{grid-template-columns:1fr}.where{grid-column:1}}
"""


def page(title: str, body: str) -> HTMLResponse:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title><style>{CSS}</style></head>
<body><header class="top"><div class="wrap"><a class="brand" href="/">jsscan</a>
<nav><a href="/">Scans</a><a href="/audit">Scope audit log</a></nav></div></header>
<main class="wrap">{body}</main></body></html>"""
    return HTMLResponse(doc, headers=HEADERS)


def sev_color(s: str) -> str:
    return f"var(--{s if s in SEVS else 'info'})"


def render_snippet(f: dict) -> str:
    s = f["data"].get("snippet")
    if not s:
        return ""
    ln = f'<span class="ln">{f["line"]}</span>' if f["line"] else ""
    return (f'<pre class="code">{ln}{e(s["before"])}<mark>{e(s["match"])}</mark>{e(s["after"])}</pre>')


def render_finding(f: dict) -> str:
    d = f["data"]
    where = f'{f["asset_url"]}:{f["line"]}:{f["col"]}' if f["line"] else f["asset_url"]
    parts = [render_snippet(f)]
    if f["type"] == "secret":
        parts.append(f'<div class="k">Rule {e(f["rule_id"])}, value {e(d["preview"])}, fingerprint {e(f["fingerprint"])}</div>')
        if d.get("checks"):
            li = "".join(
                f'<li class="{"pass" if c["ok"] else "fail"}">{"Passed" if c["ok"] else "Flagged"}: {e(c["check"])}'
                f'{": " + e(c["detail"]) if c.get("detail") else ""}</li>' for c in d["checks"])
            parts.append(f'<ul class="checks">{li}</ul>')
        if d.get("meta"):
            parts.append(f'<div class="k">Decoded: {e(json.dumps(d["meta"]))}</div>')
    else:
        rows = "".join(
            f'<tr><td>{e(v["id"])}</td><td style="color:{sev_color(v["severity"])}">{e(v["severity"])}</td>'
            f'<td>{e(v["summary"])}</td><td>{e(str(v.get("fixed_in") or ""))}</td></tr>' for v in d["vulns"])
        parts.append(f'<table><tr><th>Advisory</th><th>Severity</th><th>Summary</th><th>Fixed before</th></tr>{rows}</table>')
        sig = ", ".join(f'{x["kind"]} {x["version"]}' for x in d["signals"])
        parts.append(f'<div class="k">Version evidence: {e(sig)}. Upgrade to {e(str(d.get("fixed_in") or "latest"))} or later.</div>')
        if d.get("conflict"):
            parts.append(f'<div class="k fail">{e(d["conflict"])}</div>')
        if d.get("evidence"):
            parts.append(f'<div class="k">{e(d["evidence"])}</div>')
    if f["occurrences"] > 1:
        more = ", ".join(e(x) for x in d.get("also_in", []))
        parts.append(f'<div class="k">Seen {f["occurrences"]} times. Also at: {more}</div>')
    if d.get("verified_at"):
        parts.append(f'<div class="k">Re-verified {e(d["verified_at"])}: {e(f["status"])}</div>')
    return (f'<details class="f" style="--c:{sev_color(f["severity"])}"><summary>'
            f'<span class="sev">{e(f["severity"])}</span><span class="title">{e(f["title"])}</span>'
            f'<span class="conf">{e(f["status"])}, {f["confidence"]}%</span>'
            f'<span class="where">{e(where)}</span></summary><div class="body">{"".join(parts)}</div></details>')


def link(base: str, params: dict, label: str, on: bool) -> str:
    q = {k: v for k, v in params.items() if v}
    return f'<a class="{"on" if on else ""}" href="{base}?{e(urlencode(q))}">{e(label)}</a>'


def scans_index(store: Store) -> HTMLResponse:
    rows = []
    for s in store.list_scans(50):
        sm = s["summary"]
        sevs = sm.get("by_severity", {})
        stat = ", ".join(f"{sevs[k]} {k}" for k in SEVS if sevs.get(k)) or ("no findings" if s["status"] == "done" else s["status"])
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started"]))
        rows.append(f'<a class="row" href="/scans/{e(s["id"])}"><span>{e(s["target"])}</span>'
                    f'<span class="k">{e(when)}</span><span class="k">{e(s["kind"])} {e(s["id"])}</span>'
                    f'<span class="k">{e(stat)}</span></a>')
    body = "<h1>Scans</h1><p class='meta'>Most recent first.</p><div class='scans'>" + \
           ("".join(rows) or "<div class='empty'>No scans yet. Ask your agent to run scan_target.</div>") + "</div>"
    return page("jsscan scans", body)


def scan_view(store: Store, scan_id: str, q: dict) -> Response:
    scan = store.get_scan(scan_id)
    if not scan:
        missing = page("Not found", "<h1>Scan not found</h1>")
        missing.status_code = 404
        return missing
    sel_type, sel_sev = q.get("type", ""), q.get("severity", "")
    show_rej = q.get("rejected") == "1"
    findings, _ = store.query_findings(scan_id, sel_type or None, sel_sev or None, 0, show_rej, 2000, 0)
    counts = store.counts(scan_id)
    total = sum(counts["by_severity"].values()) or 1
    bar = "".join(f'<i style="width:{counts["by_severity"][s] / total * 100:.2f}%;background:{sev_color(s)}"></i>'
                  for s in SEVS if counts["by_severity"].get(s))
    legend = "".join(f'<span><i class="dot" style="background:{sev_color(s)}"></i><b>{counts["by_severity"].get(s, 0)}</b> {s}</span>'
                     for s in SEVS)
    base = f"/scans/{e(scan_id)}"
    cur = {"type": sel_type, "severity": sel_sev, "rejected": "1" if show_rej else ""}
    filters = ("<div class='filters'><span>Type</span>" + link(base, {**cur, "type": ""}, "all", not sel_type) +
               "".join(link(base, {**cur, "type": t}, TYPES[t], sel_type == t) for t in TYPES) +
               "<span>Severity</span>" + link(base, {**cur, "severity": ""}, "all", not sel_sev) +
               "".join(link(base, {**cur, "severity": s}, s, sel_sev == s) for s in SEVS) +
               link(base, {**cur, "rejected": "" if show_rej else "1"},
                    f"{'hide' if show_rej else 'show'} {counts['suppressed_false_positives']} suppressed false positives", show_rej) +
               "</div>")
    sections = []
    for t, label in TYPES.items():
        group = [f for f in findings if f["type"] == t]
        if sel_type and sel_type != t:
            continue
        out = [f"<h2>{label} <span class='k'>({len(group)})</span></h2>"]
        if not group:
            out.append("<div class='empty'>Nothing found in this group.</div>")
        for s in SEVS + ["rejected"]:
            items = [f for f in group if (f["status"] == "rejected") == (s == "rejected") and
                     (s == "rejected" or f["severity"] == s)]
            if not items:
                continue
            head = "suppressed as false positives" if s == "rejected" else s
            out.append(f'<h3 style="color:{sev_color(s)}">{head} <span class="k">({len(items)})</span></h3>')
            out.extend(render_finding(f) for f in items)
        sections.append("".join(out))
    sm = scan["summary"]
    sc = sm.get("scripts", {})
    blocked = ", ".join(f"{e(h)} ({n})" for h, n in sm.get("blocked_hosts", {}).items())
    meta = (f"Scan {e(scan_id)}, {sm.get('pages', 0)} pages, {sc.get('external', 0)} scripts fetched, "
            f"{sc.get('inline', 0)} inline, {sc.get('passive_out_of_scope', 0)} out-of-scope scripts not fetched")
    if blocked:
        meta += f". Refused hosts: {blocked}"
    body = (f"<h1>{e(scan['target'])}</h1><p class='meta'>{meta}</p>"
            f"<div class='bar' role='img' aria-label='findings by severity'>{bar}</div><div class='legend'>{legend}</div>"
            f"{filters}{''.join(sections)}")
    return page(f"jsscan {scan_id}", body)


def audit_view(audit: AuditLog, q: dict) -> HTMLResponse:
    decision = q.get("decision") or None
    rows = audit.tail(200, decision)[::-1]
    tr = "".join(f'<tr><td>{e(r["ts"])}</td><td>{e(r["decision"])}</td><td>{e(r.get("purpose", ""))}</td>'
                 f'<td style="word-break:break-all">{e(r["url"])}</td><td>{e(r.get("reason", ""))}</td></tr>' for r in rows)
    flt = ("<div class='filters'>" + link("/audit", {}, "all", not decision) +
           link("/audit", {"decision": "deny"}, "refused only", decision == "deny") +
           link("/audit", {"decision": "allow"}, "allowed only", decision == "allow") + "</div>")
    body = (f"<h1>Scope audit log</h1><p class='meta'>Every request is checked against the allowlist. Refusals are logged.</p>{flt}"
            f"<table><tr><th>Time</th><th>Decision</th><th>Purpose</th><th>URL</th><th>Reason</th></tr>{tr}</table>")
    return page("jsscan audit", body)


def build_app(settings: Settings | None = None) -> Starlette:
    st = settings or get_settings()
    store, audit = Store(st.db_path), AuditLog(st.audit_path)

    async def index(request: Request):
        return scans_index(store)

    async def scan(request: Request):
        return scan_view(store, request.path_params["scan_id"], dict(request.query_params))

    async def api(request: Request):
        sid = request.path_params["scan_id"]
        rows, _ = store.query_findings(sid, include_rejected=True, limit=5000)
        return JSONResponse({"scan": store.get_scan(sid), "findings": rows}, headers=HEADERS)

    async def audit_page(request: Request):
        return audit_view(audit, dict(request.query_params))

    return Starlette(
        routes=[Route("/", index), Route("/scans/{scan_id}", scan), Route("/api/scans/{scan_id}", api),
                Route("/audit", audit_page)],
        middleware=[Middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", st.web_host])],
    )


def start_in_thread(settings: Settings) -> threading.Thread:
    cfg = uvicorn.Config(build_app(settings), host=settings.web_host, port=settings.web_port,
                         log_level="warning", access_log=False)
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, name="jsscan-web", daemon=True)
    t.start()
    return t


def main() -> None:
    st = get_settings()
    uvicorn.run(build_app(st), host=st.web_host, port=st.web_port, log_level="info")


if __name__ == "__main__":
    main()
