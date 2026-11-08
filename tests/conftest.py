import functools
import http.server
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "fixtures"))
import make_fixture  # noqa: E402

from jsscan.config import Settings  # noqa: E402
from jsscan.deps import VulnDB  # noqa: E402
from jsscan.scanner import Scanner  # noqa: E402
from jsscan.scope import AuditLog, Scope  # noqa: E402
from jsscan.store import Store  # noqa: E402


class Handler(http.server.SimpleHTTPRequestHandler):
    requested: list[str] = []

    def log_message(self, *a, **k):
        pass

    def do_GET(self):
        Handler.requested.append(self.path)
        if self.path == "/redirect-out":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.server.server_port}/app.js")
            self.end_headers()
            return
        super().do_GET()


@pytest.fixture(scope="session")
def site(tmp_path_factory):
    d = tmp_path_factory.mktemp("site")
    secrets = make_fixture.build(d)
    handler = functools.partial(Handler, directory=str(d))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"base": f"http://127.0.0.1:{srv.server_port}", "port": srv.server_port, "secrets": secrets}
    srv.shutdown()


@pytest.fixture
def env(tmp_path, site):
    st = Settings(home=tmp_path, allowed_hosts=[f"127.0.0.1:{site['port']}"], web_enabled=False)
    audit = AuditLog(st.audit_path)
    scope = Scope(st.allowed_hosts, audit)
    store = Store(st.db_path)
    scanner = Scanner(st, scope, store, VulnDB.load())
    Handler.requested.clear()
    return {"settings": st, "audit": audit, "scope": scope, "store": store, "scanner": scanner}
