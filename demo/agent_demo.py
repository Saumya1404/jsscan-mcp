"""Scripted 'agent' that drives the jsscan MCP server over stdio.

Self-contained: generates the vulnerable fixture, serves it on localhost, launches the
server with a scope that only allows that host, then walks the tools the way an agent would.

    python demo/agent_demo.py                # synthetic library banners
    python demo/agent_demo.py --real-libs    # real jQuery/lodash/Bootstrap from npm
    python demo/agent_demo.py --hold         # keep the web view up afterwards
"""
from __future__ import annotations

import argparse
import asyncio
import functools
import http.server
import json
import os
import sys
import tempfile
import threading
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fixtures"))
import make_fixture  # noqa: E402

PORT = 8011


def serve(directory: Path) -> http.server.ThreadingHTTPServer:
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
    handler.log_message = lambda *a, **k: None  # type: ignore[attr-defined]
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def call(session: ClientSession, name: str, **args) -> dict:
    print(f"\n> {name}({', '.join(f'{k}={v!r}' for k, v in args.items())})")
    res = await session.call_tool(name, args)
    data = res.structuredContent or json.loads(res.content[0].text)
    data = data.get("result", data) if isinstance(data, dict) and set(data) == {"result"} else data
    text = json.dumps(data, indent=1)
    print(text if len(text) < 2600 else text[:2600] + "\n  ...")
    return data


async def main(real_libs: bool, hold: bool) -> None:
    site = Path(tempfile.mkdtemp(prefix="jsscan-site-"))
    make_fixture.build(site, real_libs)
    serve(site)
    home = tempfile.mkdtemp(prefix="jsscan-home-")
    env = {**os.environ, "JSSCAN_HOME": home, "JSSCAN_ALLOWED_HOSTS": f"127.0.0.1:{PORT}"}
    params = StdioServerParameters(command=sys.executable, args=["-m", "jsscan.server"], env=env)
    target = f"http://127.0.0.1:{PORT}/index.html"
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = [t.name for t in (await s.list_tools()).tools]
        print("tools:", ", ".join(tools))
        await call(s, "get_scope")
        await call(s, "scan_target", url="https://example.org/")          # refused
        scan = await call(s, "scan_target", url=target)
        sid = scan["scan_id"]
        crit = await call(s, "list_findings", scan_id=sid, severity="critical")
        await call(s, "get_finding", finding_id=crit["findings"][0]["id"])
        await call(s, "verify_finding", finding_id=crit["findings"][0]["id"])
        await call(s, "list_findings", scan_id=sid, type="dependency")
        await call(s, "get_audit_log", decision="deny")
        print(f"\nWeb view: {scan.get('dashboard')}")
        if hold:
            input("Web view is live. Press Enter to stop... ")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--real-libs", action="store_true")
    ap.add_argument("--hold", action="store_true")
    a = ap.parse_args()
    asyncio.run(main(a.real_libs, a.hold))
