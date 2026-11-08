import base64
import json
import zlib

from jsscan.secrets import scan_text
from jsscan.verify import _b62, aws_account_id, github_checksum_ok


def gh(body="a" * 0 + "Qw3rTy9uIoPlKjHgFdSaZxCvBnMq1W"):
    return "ghp_" + body + _b62(zlib.crc32(body.encode())).rjust(6, "0")


def jwt(payload):
    e = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
    return f'{e({"alg": "HS256"})}.{e(payload)}.c2lnbmF0dXJlLWJ5dGVzLWhlcmU'


def one(text, rule):
    hits = [h for h in scan_text(text) if h.rule.id == rule]
    assert len(hits) == 1, hits
    return hits[0]


def test_github_checksum_confirms_and_bad_checksum_downgrades():
    good = one(f'x="{gh()}"', "github-token")
    assert good.verdict.status == "confirmed" and github_checksum_ok(gh())
    bad = one('x="ghp_Qw3rTy9uIoPlKjHgFdSaZxCvBnMq1WAAAAAA"', "github-token")
    assert bad.verdict.status != "confirmed" and bad.verdict.confidence < 65


def test_aws_docs_example_is_rejected_as_placeholder():
    assert one('k="AKIAIOSFODNN7EXAMPLE"', "aws-access-key-id").verdict.status == "rejected"


def test_aws_account_id_roundtrip():
    raw = ((123456789012 << 7) | 5).to_bytes(6, "big") + b"\x01\x02\x03\x04"
    key = "AKIA" + base64.b32encode(raw).decode()
    assert aws_account_id(key) == 123456789012
    h = one(f'k="{key}"', "aws-access-key-id")
    assert h.verdict.status == "confirmed" and h.verdict.meta["aws_account"] == "123456789012"


def test_jwt_severity_follows_privilege():
    anon = one(f'a="{jwt({"iss": "supabase", "role": "anon"})}"', "jwt")
    svc = one(f'a="{jwt({"role": "service_role"})}"', "jwt")
    expired = one(f'a="{jwt({"role": "user", "exp": 1000})}"', "jwt")
    assert (anon.verdict.severity, svc.verdict.severity, expired.verdict.severity) == ("info", "critical", "low")


def test_generic_false_positives_are_rejected():
    noise = 'var a={password:"password.required",token:"auth.token.expired",secret:"your-secret-here",apiKey:"https://x.io/key"}'
    assert all(h.verdict.status == "rejected" for h in scan_text(noise))


def test_generic_real_looking_credential_is_kept():
    h = one('cfg={apiSecret:"k8Jd92Lq0XvPz4mNb7Rt"}', "generic-credential")
    assert h.verdict.status in ("likely", "unverified") and h.verdict.confidence >= 55


def test_localhost_db_with_default_password_rejected_but_external_kept():
    assert one('u="postgres://postgres:postgres@localhost:5432/d"', "db-connection-string").verdict.status == "rejected"
    ext = one('u="postgres://app:Xk29fQ7zLm@orders.prod.acme-demo.io:5432/o"', "db-connection-string")
    assert ext.verdict.status == "likely"


def test_neighbouring_secrets_never_echoed_in_context():
    a, b = gh(), gh("Zx9cVbNm8LkJhGfDsAqWeRtYuIoPp1")
    hits = [h for h in scan_text(f'a="{a}";b="{b}";') if h.rule.id == "github-token"]
    for h in hits:
        assert a not in h.before + h.after and b not in h.before + h.after


def test_line_and_column_are_one_based():
    h = one('\n\nvar x="' + gh() + '"', "github-token")
    assert (h.line, h.col) == (3, 8)
