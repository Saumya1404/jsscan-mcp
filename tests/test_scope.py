from jsscan.fetcher import ScopedFetcher
from jsscan.scope import AuditLog, Scope


def mk(tmp_path, allowed):
    return Scope(allowed, AuditLog(tmp_path / "a.jsonl"))


def test_empty_allowlist_denies_everything(tmp_path):
    assert not mk(tmp_path, []).is_allowed("https://example.com/")


def test_default_port_only_without_explicit_port(tmp_path):
    s = mk(tmp_path, ["example.com"])
    assert s.is_allowed("https://example.com/x")
    assert s.is_allowed("http://example.com/x")
    assert not s.is_allowed("https://example.com:8443/x")


def test_explicit_port_and_wildcard(tmp_path):
    s = mk(tmp_path, ["localhost:3000", "*.acme.test"])
    assert s.is_allowed("http://localhost:3000/")
    assert not s.is_allowed("http://localhost:3001/")
    assert s.is_allowed("https://cdn.acme.test/a.js")
    assert not s.is_allowed("https://acme.test/")          # wildcard excludes apex
    assert not s.is_allowed("https://evil-acme.test/")      # no suffix tricks
    assert not s.is_allowed("https://acme.test.evil.com/")


def test_non_http_schemes_denied(tmp_path):
    s = mk(tmp_path, ["example.com"])
    assert not s.is_allowed("file:///etc/passwd")
    assert not s.is_allowed("ftp://example.com/")


def test_userinfo_trick_denied(tmp_path):
    s = mk(tmp_path, ["example.com"])
    assert not s.is_allowed("https://example.com@evil.com/")


async def test_denials_are_logged_once_per_host(env):
    sc = env["scope"]
    for _ in range(3):
        sc.check("https://evil.test/a.js", "script", "s1")
    denies = env["audit"].tail(10, "deny")
    assert len(denies) == 1 and denies[0]["url"].startswith("https://evil.test")


async def test_redirect_to_out_of_scope_host_is_refused(env, site):
    f = ScopedFetcher(env["scope"], env["settings"])
    try:
        r = await f.get(f"{site['base']}/redirect-out", "page", "s1")
    finally:
        await f.aclose()
    assert r.blocked and "localhost" in r.error
    assert "/app.js" not in __import__("conftest").Handler.requested
    assert any(e["decision"] == "deny" for e in env["audit"].tail(10))
