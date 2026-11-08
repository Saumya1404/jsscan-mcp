"""Offline verifiers that turn a regex hit into a verdict.

No secret is ever sent to a third party. A hit is judged on structure
(checksums, decodable payloads), entropy, placeholder patterns and nearby
context. Each verdict carries the list of checks that produced it so an agent
(or a human) can see why a hit was kept or dropped.

Status values:
  confirmed   structure validated by a checksum or a decodable payload
  likely      strong format match, plausible entropy, nothing suspicious
  unverified  weak signal, keep for triage but do not trust
  rejected    placeholder, template, hash-like or otherwise not a secret
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
import zlib
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass
class Verdict:
    status: str
    confidence: int
    severity: str
    checks: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"check": name, "ok": ok, "detail": detail})


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|fake|placeholder|changeme|change[_-]?me|replace[_-]?me|"
    r"your[_-]?(?:api|key|token|secret|password)|insert[_-]?|redacted|x{6,}|\*{4,}|<[^>]+>|\$\{|\{\{|%s|\.\.\.|0{8,}|1234567890)"
)
_CONTEXT_HINT = re.compile(r"(?i)\b(example|sample|dummy|fake|placeholder|lorem|todo|e\.g\.|docs?)\b")


def _repeated(s: str) -> bool:
    return bool(s) and Counter(s).most_common(1)[0][1] / len(s) > 0.5


def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


# ---------------------------------------------------------------- structural

_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b62(n: int) -> str:
    out = ""
    while n:
        n, r = divmod(n, 62)
        out = _B62[r] + out
    return out


def github_checksum_ok(token: str) -> bool:
    """Classic GitHub tokens: prefix_ + 30 random chars + 6 char base62 CRC32 of the random part."""
    body = token.split("_", 1)[1]
    if len(body) != 36:
        return False
    rnd, chk = body[:30], body[30:]
    return _b62(zlib.crc32(rnd.encode())).rjust(6, "0") == chk


def aws_account_id(key_id: str) -> int | None:
    """Decode the account id embedded in an AWS access key id."""
    try:
        raw = base64.b32decode(key_id[4:])
    except (binascii.Error, ValueError):
        return None
    a = int.from_bytes(raw[:6], "big")
    return (a & 0x7FFFFFFFFF80) >> 7


# ------------------------------------------------------------------ verifiers

def _base(v: Verdict, value: str, before: str, after: str, *, check_entropy: float | None = 3.0) -> bool:
    """Checks shared by every rule. Returns False when the hit must be rejected."""
    if _PLACEHOLDER.search(value):
        v.add("placeholder", False, "value looks like a placeholder or template")
        return False
    v.add("placeholder", True)
    if _repeated(value):
        v.add("repetition", False, "one character dominates the value")
        return False
    if check_entropy is not None:
        e = entropy(value)
        ok = e >= check_entropy
        v.add("entropy", ok, f"{e:.2f} bits/char (min {check_entropy})")
        if not ok:
            return False
    ctx = (before[-60:] + " " + after[:60])
    if _CONTEXT_HINT.search(ctx):
        v.confidence -= 25
        v.add("context", False, "nearby text mentions example/sample/dummy")
    return True


def _finish(v: Verdict) -> Verdict:
    v.confidence = max(0, min(100, v.confidence))
    if v.status != "rejected":
        if v.status != "confirmed":
            v.status = "likely" if v.confidence >= 65 else "unverified"
    return v


def _reject(v: Verdict) -> Verdict:
    v.status, v.confidence = "rejected", min(v.confidence, 10)
    return v


def verify_hit(rule_id: str, verifier: str, severity: str, value: str, key_name: str | None,
               before: str, after: str) -> Verdict:
    v = Verdict(status="likely", confidence=75, severity=severity)
    fn = _VERIFIERS.get(verifier, _v_default)
    return fn(v, rule_id, value, key_name, before, after)


def _v_default(v, rule_id, value, key_name, before, after):
    if not _base(v, value, before, after):
        return _reject(v)
    return _finish(v)


def _v_github(v, rule_id, value, key_name, before, after):
    if not _base(v, value.split("_", 1)[1], before, after):
        return _reject(v)
    if value.startswith("github_pat_"):
        v.add("format", True, "fine-grained PAT layout")
        v.confidence = 80
        return _finish(v)
    ok = github_checksum_ok(value)
    v.add("checksum", ok, "crc32 base62 suffix matches" if ok else "crc32 suffix does not match; likely fabricated")
    if ok:
        v.status, v.confidence = "confirmed", 95
        return v
    v.confidence = 35
    return _finish(v)


def _v_aws_key(v, rule_id, value, key_name, before, after):
    if not _base(v, value[4:], before, after, check_entropy=2.5):
        return _reject(v)
    acct = aws_account_id(value)
    ok = acct is not None and 0 < acct < 10**12
    v.add("account_id", ok, f"decodes to account {acct:012d}" if ok else "embedded account id is implausible")
    if ok:
        v.meta["aws_account"] = f"{acct:012d}"
        v.confidence = 90
        v.status = "confirmed"
    else:
        v.confidence = 40
    if value.startswith("ASIA"):
        v.add("temporary", True, "ASIA prefix means short-lived STS credentials")
        v.severity = "medium"
    return v if v.status == "confirmed" else _finish(v)


def _v_aws_secret(v, rule_id, value, key_name, before, after):
    if not _base(v, value, before, after, check_entropy=4.0):
        return _reject(v)
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        v.add("shape", False, "40 hex chars is a SHA-1, not an AWS secret")
        return _reject(v)
    v.add("shape", True)
    return _finish(v)


def _v_jwt(v, rule_id, value, key_name, before, after):
    try:
        h, p, _ = value.split(".")
        header, payload = json.loads(_b64url(h)), json.loads(_b64url(p))
        assert isinstance(header, dict) and "alg" in header and isinstance(payload, dict)
    except Exception:
        v.add("decode", False, "header/payload do not decode as JWT JSON")
        return _reject(v)
    v.add("decode", True, f"alg={header.get('alg')}")
    v.status, v.confidence = "confirmed", 90
    role = str(payload.get("role", "")).lower()
    iss = str(payload.get("iss", ""))
    v.meta.update({k: payload[k] for k in ("iss", "role", "exp", "sub") if k in payload and k != "sub"})
    if header.get("alg") == "none":
        v.add("alg_none", False, "unsigned token (alg none)")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and exp < time.time():
        v.add("expiry", True, "token already expired")
        v.severity = "low"
    elif role == "service_role":
        v.severity = "critical"
        v.add("privilege", False, "service_role token grants full backend access")
    elif role == "anon" or "supabase" in iss:
        v.severity = "info"
        v.add("privilege", True, "anon role token, public by design")
    else:
        v.severity = "medium"
        v.add("signature", True, "signature cannot be checked offline")
    return v


def _v_stripe(v, rule_id, value, key_name, before, after):
    body = value.split("_", 2)[2]
    if not _base(v, body, before, after):
        return _reject(v)
    if value.startswith("pk_"):
        v.severity = "info"
        v.add("kind", True, "publishable key, meant to be public")
    elif "_test_" in value:
        v.severity = "low"
        v.add("kind", True, "test mode secret key")
    else:
        v.add("kind", True, "live mode secret key")
    return _finish(v)


def _v_slack(v, rule_id, value, key_name, before, after):
    if not _base(v, value.split("-", 1)[1], before, after, check_entropy=2.5):
        return _reject(v)
    ok = bool(re.fullmatch(r"xox[bpr]-\d{9,13}-\d{9,13}(?:-\d{9,13})?-[A-Za-z0-9]{24,}", value)
              or re.fullmatch(r"xox[ae]-\d?-?[0-9A-Za-z-]{20,}", value) or value.startswith("xoxs-"))
    v.add("layout", ok, "matches known Slack token layout" if ok else "unusual layout")
    v.confidence = 85 if ok else 50
    return _finish(v)


def _v_pem(v, rule_id, value, key_name, before, after):
    body = re.sub(r"-----(?:BEGIN|END)[^-]*-----|\\n|\\r|\s", "", value)
    try:
        der = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except (binascii.Error, ValueError):
        v.add("decode", False, "body is not base64")
        return _reject(v)
    ok = len(der) >= 90 and der[:1] in (b"0", b"\x30", b"b")
    v.add("decode", ok, f"{len(der)} bytes of key material" if ok else "too short for a real key")
    if not ok:
        return _reject(v)
    if "ENCRYPTED" in value[:60]:
        v.severity = "high"
        v.add("encrypted", True, "passphrase protected")
    v.status, v.confidence = "confirmed", 95
    return v


_DB_PLACEHOLDER_PW = {"password", "pass", "pwd", "secret", "changeme", "example", "yourpassword",
                      "123456", "root", "admin", "postgres", "test", "user", "mypassword"}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "db", "postgres", "mysql", "redis"}


def _v_dbconn(v, rule_id, value, key_name, before, after):
    parts = urlsplit(value)
    pw = parts.password or ""
    if not pw or pw.lower() in _DB_PLACEHOLDER_PW or _PLACEHOLDER.search(pw):
        v.add("password", False, "password is empty, default or a template")
        return _reject(v)
    v.add("password", True)
    host = (parts.hostname or "").lower()
    if host in _LOCAL_HOSTS or host.endswith((".local", ".internal", ".example.com")):
        v.add("host", True, f"points at local or internal host '{host}'")
        v.severity = "low"
    else:
        v.add("host", True, f"external host '{host}'")
    return _finish(v)


def _v_google_key(v, rule_id, value, key_name, before, after):
    if not _base(v, value[4:], before, after):
        return _reject(v)
    v.add("note", True, "browser API keys are public by design; risk depends on referrer and API restrictions")
    v.severity = "low"
    return _finish(v)


_STRONG_NAME = re.compile(r"(?i)(secret|passw|private[_-]?key|api[_-]?key|auth[_-]?key|access[_-]?token)")


def _v_generic(v, rule_id, value, key_name, before, after):
    v.confidence = 45
    n = len(value)
    if re.match(r"^(https?:|/|\./|\.\./|data:|#|mailto:)", value) or "://" in value:
        v.add("shape", False, "value is a URL or path")
        return _reject(v)
    if re.fullmatch(r"[a-z]+(?:[._\-/][a-z]+)+", value, re.I) and not re.search(r"\d", value):
        v.add("shape", False, "looks like a translation key or identifier")
        return _reject(v)
    if value.isalpha():
        v.add("shape", False, "letters only, looks like a word or enum value")
        return _reject(v)
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 2:
        v.add("shape", False, "single character class")
        return _reject(v)
    v.add("shape", True)
    if not _base(v, value, before, after, check_entropy=3.5 if n >= 20 else 3.0):
        return _reject(v)
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
        v.add("hash_like", False, "hex digest length, may be a hash constant")
        v.confidence -= 15
    if key_name and _STRONG_NAME.search(key_name):
        v.confidence += 20
        v.add("name", True, f"variable name '{key_name}' signals a credential")
    if key_name and re.search(r"(?i)(public|publishable|site[_-]?key|client[_-]?id)", key_name):
        v.severity = "info"
        v.add("public_name", True, "name suggests a public identifier")
    if entropy(value) >= 4.2:
        v.confidence += 10
    return _finish(v)


_VERIFIERS = {
    "github": _v_github, "aws_key": _v_aws_key, "aws_secret": _v_aws_secret, "jwt": _v_jwt,
    "stripe": _v_stripe, "slack": _v_slack, "pem": _v_pem, "dbconn": _v_dbconn,
    "google_key": _v_google_key, "generic": _v_generic, "default": _v_default,
}
