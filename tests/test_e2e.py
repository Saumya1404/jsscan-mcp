import json

from starlette.testclient import TestClient

from jsscan.web import build_app
import conftest


async def run(env, site):
    return await env["scanner"].scan(f"{site['base']}/index.html", 10, 60)


async def test_scan_finds_expected_and_suppresses_noise(env, site):
    r = await run(env, site)
    rows, _ = env["store"].query_findings(r["scan_id"], include_rejected=True, limit=100)
    kept = {(f["rule_id"]) for f in rows if f["status"] != "rejected"}
    for rule in ("github-token", "private-key", "jwt", "stripe-secret-key", "aws-access-key-id",
                 "slack-token", "db-connection-string", "jquery@3.3.1", "lodash@4.17.15", "bootstrap@3.3.7"):
        assert rule in kept, rule
    rejected = {f["rule_id"] for f in rows if f["status"] == "rejected"}
    assert {"aws-access-key-id", "db-connection-string", "generic-credential"} <= rejected
    assert r["suppressed_false_positives"] >= 4


async def test_same_secret_in_two_files_is_merged(env, site):
    r = await run(env, site)
    gh = [f for f in env["store"].query_findings(r["scan_id"], limit=100)[0] if f["rule_id"] == "github-token"]
    assert len(gh) == 1 and gh[0]["occurrences"] == 2 and gh[0]["data"]["also_in"]


async def test_out_of_scope_hosts_never_requested_and_logged(env, site):
    r = await run(env, site)
    assert "cdnjs.cloudflare.com" in r["blocked_hosts"] and "example.org" in r["blocked_hosts"]
    deny_urls = " ".join(e["url"] for e in env["audit"].tail(50, "deny"))
    assert "cdnjs.cloudflare.com" in deny_urls and "example.org" in deny_urls
    # the CDN script is still analysed from its URL alone
    assert any(l.startswith("moment.js@2.18.1") for l in r["libraries_detected"])


async def test_refuses_out_of_scope_target(env):
    r = await env["scanner"].scan("https://example.org/", 5, 5)
    assert r["error"] == "out_of_scope"
    assert env["audit"].tail(5, "deny")


async def test_raw_secrets_never_appear_in_outputs_store_or_web(env, site):
    r = await run(env, site)
    sid = r["scan_id"]
    raw = [site["secrets"]["github"], site["secrets"]["aws"]]
    rows, _ = env["store"].query_findings(sid, include_rejected=True, limit=100)
    blob = json.dumps(r) + json.dumps(rows) + env["settings"].db_path.read_bytes().decode("latin1")
    client = TestClient(build_app(env["settings"]), base_url="http://127.0.0.1")
    for path in (f"/scans/{sid}", f"/scans/{sid}?rejected=1", f"/api/scans/{sid}", "/", "/audit"):
        blob += client.get(path).text
    for s in raw:
        assert s not in blob


async def test_verify_reproduces_and_detects_change(env, site):
    r = await run(env, site)
    f = next(x for x in env["store"].query_findings(r["scan_id"], type="secret", limit=50)[0] if x["rule_id"] == "github-token")
    v = await env["scanner"].verify(f["id"])
    assert v["reproduced"] and v["after"]["status"] == "confirmed"
    passive = next(x for x in env["store"].query_findings(r["scan_id"], type="dependency", limit=50)[0] if "moment" in x["rule_id"])
    assert (await env["scanner"].verify(passive["id"]))["error"] == "not_verifiable"


async def test_web_view_groups_and_escapes(env, site):
    r = await run(env, site)
    sid = r["scan_id"]
    # inject hostile content as a title to prove output encoding
    env["store"].add_findings([{"id": f"{sid}-999", "scan_id": sid, "type": "secret", "rule_id": "x",
        "title": "<script>alert(1)</script>", "severity": "low", "status": "likely", "confidence": 70,
        "asset_url": "http://x/<img src=x onerror=alert(1)>.js", "line": 1, "col": 1, "fingerprint": "f",
        "occurrences": 1, "data": {"preview": "<b>", "checks": [], "snippet": {"before": "<i>", "match": "<m>", "after": "</i>"}}}])
    c = TestClient(build_app(env["settings"]), base_url="http://127.0.0.1")
    page = c.get(f"/scans/{sid}").text
    assert "<script>alert(1)" not in page and "&lt;script&gt;" in page and "<img src=x" not in page
    assert "Exposed secrets" in page and "Vulnerable libraries" in page
    assert "default-src 'none'" in c.get(f"/scans/{sid}").headers["content-security-policy"]
    assert c.get(f"/scans/{sid}", headers={"host": "evil.test"}).status_code == 400  # DNS rebinding guard
