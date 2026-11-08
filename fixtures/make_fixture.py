"""Generate a deliberately vulnerable demo site. Every credential is fabricated.

Secrets are generated at run time instead of committed, so push protection on
code hosts does not trip and nothing here is ever a live credential.

    python fixtures/make_fixture.py fixtures/out            # synthetic library banners
    python fixtures/make_fixture.py fixtures/out --real-libs # real jQuery/lodash/Bootstrap via npm pack
    python -m http.server 8000 --directory fixtures/out
"""
from __future__ import annotations

import argparse
import base64
import json
import random
import string
import subprocess
import sys
import tarfile
import tempfile
import zlib
from pathlib import Path

rng = random.Random(1404)
ALNUM = string.ascii_letters + string.digits


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def b62(n: int) -> str:
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = chars[r] + out
    return out


def github_token() -> str:
    body = rand(30)
    return "ghp_" + body + b62(zlib.crc32(body.encode())).rjust(6, "0")


def aws_key_id(account: int = 123456789012) -> str:
    raw = ((account << 7) | rng.randrange(128)).to_bytes(6, "big") + bytes(rng.randrange(256) for _ in range(4))
    return "AKIA" + base64.b32encode(raw).decode()


def jwt(payload: dict) -> str:
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
    return f'{enc({"alg": "HS256", "typ": "JWT"})}.{enc(payload)}.{rand(43, ALNUM + "-_")}'


def fake_pem() -> str:
    der = b"\x30\x82\x02\x5c" + bytes(rng.randrange(256) for _ in range(300))
    b64 = base64.b64encode(der).decode()
    lines = "\\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN RSA PRIVATE KEY-----\\n{lines}\\n-----END RSA PRIVATE KEY-----"


def banners() -> dict[str, str]:
    return {
        "jquery-3.3.1.min.js": '/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){"use strict";window.jQuery=t}(window,{});\n',
        "lodash.min.js": "/**\n * @license\n * Lodash <https://lodash.com/>\n * Copyright OpenJS Foundation\n */\n;(function(){var VERSION = '4.17.15';window._={VERSION:VERSION};}());\n",
        "bootstrap.min.js": "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n * Copyright 2011-2016 Twitter, Inc.\n */\n+function(){}();\n",
    }


def real_libs(dest: Path) -> dict[str, str]:
    out = {}
    wanted = {"jquery@3.3.1": ("package/dist/jquery.min.js", "jquery-3.3.1.min.js"),
              "lodash@4.17.15": ("package/lodash.min.js", "lodash.min.js"),
              "bootstrap@3.3.7": ("package/dist/js/bootstrap.min.js", "bootstrap.min.js")}
    with tempfile.TemporaryDirectory() as tmp:
        for spec, (member, name) in wanted.items():
            tgz = subprocess.run(["npm", "pack", spec, "--silent"], cwd=tmp, capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
            with tarfile.open(Path(tmp) / tgz) as t:
                out[name] = t.extractfile(member).read().decode()
    return out


def build(out: Path, use_real_libs: bool = False) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    (out / "vendor").mkdir(exist_ok=True)
    libs = real_libs(out) if use_real_libs else banners()
    for name, body in libs.items():
        (out / "vendor" / name).write_text(body)
    gh = github_token()
    key_id = aws_key_id()
    app = f"""// Demo app. Every credential here is fabricated for scanner testing.
var config = {{
  aws: {{ accessKeyId: "{key_id}", region: "us-east-1" }},
  docsExample: {{ accessKeyId: "AKIAIOSFODNN7EXAMPLE" }},
  githubToken: "{gh}",
  stripeSecret: "sk_live_{rand(24)}",
  stripePublic: "pk_live_{rand(24)}",
  supabaseAnon: "{jwt({"iss": "supabase", "role": "anon", "exp": 4102444800})}",
  adminToken: "{jwt({"iss": "demo-api", "role": "service_role", "exp": 4102444800})}",
  ordersDb: "postgres://app:{rand(10)}@orders-db.prod.acme-demo.io:5432/orders",
  devDb: "postgres://postgres:postgres@localhost:5432/dev",
  apiSecret: "{rand(20)}",
  i18n: {{ password: "password.required", token: "auth.token.expired" }},
  integrity: {{ secret: "your-secret-here" }}
}};
var signingKey = "{fake_pem()}";
import("./chunk-ab12cd34.js");
"""
    chunk = f'// lazy chunk\nwindow.__lazy={{gh:"{gh}",aws:"{aws_key_id(210987654321)}"}};\n'
    inline = f'window.__BOOT__={{"slack":"xoxb-{rand(12, string.digits)}-{rand(12, string.digits)}-{rand(24)}"}};'
    index = f"""<!doctype html><html><head><title>Demo shop</title>
<script src="/vendor/jquery-3.3.1.min.js"></script>
<script src="/vendor/lodash.min.js"></script>
<script src="/vendor/bootstrap.min.js"></script>
<script src="/app.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.18.1/moment.min.js"></script>
</head><body><h1>Demo shop</h1><a href="https://example.org/partner">partner</a>
<a href="/about.html">about</a><script>{inline}</script></body></html>"""
    (out / "app.js").write_text(app)
    (out / "chunk-ab12cd34.js").write_text(chunk)
    (out / "index.html").write_text(index)
    (out / "about.html").write_text('<html><body><script src="/vendor/jquery-3.3.1.min.js"></script>About</body></html>')
    return {"github": gh, "aws": key_id}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--real-libs", action="store_true")
    a = ap.parse_args()
    build(Path(a.out), a.real_libs)
    print(f"fixture written to {a.out}", file=sys.stderr)
