"""Scope allowlist and audit log.

Rules:
  * Empty allowlist means deny everything (fail closed).
  * "host" matches only the default port of the URL scheme (80 or 443).
  * "host:port" matches exactly that port.
  * "*.example.com" matches subdomains of example.com, not the apex.
  * Only http and https are ever allowed.
Every denial is written to the audit log. Allowed requests are logged too, so
the log doubles as a record of exactly what the tool touched.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


class ScopeError(Exception):
    def __init__(self, url: str, reason: str):
        super().__init__(f"out of scope: {url} ({reason})")
        self.url = url
        self.reason = reason


@dataclass(frozen=True)
class _Entry:
    raw: str
    host: str
    port: int | None
    wildcard: bool

    def matches(self, host: str, port: int, scheme: str) -> bool:
        if self.port is None:
            if port != DEFAULT_PORTS.get(scheme):
                return False
        elif port != self.port:
            return False
        if self.wildcard:
            return host.endswith("." + self.host)
        return host == self.host


def _parse_entry(raw: str) -> _Entry:
    s = raw.strip().lower()
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0]
    wildcard = s.startswith("*.")
    if wildcard:
        s = s[2:]
    port = None
    if s.count(":") == 1 and not s.startswith("["):
        s, p = s.split(":")
        port = int(p)
    return _Entry(raw=raw, host=s, port=port, wildcard=wildcard)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._seen: set[tuple] = set()

    def write(self, **fields) -> None:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **fields}
        with self._lock, self.path.open("a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")

    def write_once(self, key: tuple, **fields) -> None:
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
        self.write(**fields)

    def tail(self, limit: int = 20, decision: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if decision and rec.get("decision") != decision:
                continue
            out.append(rec)
        return out[-limit:]


class Scope:
    def __init__(self, allowed: list[str], audit: AuditLog):
        self.entries = [_parse_entry(a) for a in allowed]
        self.audit = audit

    @property
    def allowed_hosts(self) -> list[str]:
        return [e.raw for e in self.entries]

    def decide(self, url: str) -> tuple[bool, str]:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower()
            scheme = parts.scheme.lower()
            port = parts.port or DEFAULT_PORTS.get(scheme, 0)
        except ValueError:
            return False, "unparseable url"
        if scheme not in DEFAULT_PORTS:
            return False, f"scheme '{scheme}' not allowed"
        if not host:
            return False, "no host"
        if not self.entries:
            return False, "allowlist is empty"
        if any(e.matches(host, port, scheme) for e in self.entries):
            return True, "matched allowlist"
        return False, f"host '{host}:{port}' not in allowlist"

    def is_allowed(self, url: str) -> bool:
        return self.decide(url)[0]

    def check(self, url: str, purpose: str, scan_id: str | None = None, log_allowed: bool = True) -> bool:
        ok, reason = self.decide(url)
        host = urlsplit(url).netloc.lower()
        if ok:
            if log_allowed:
                self.audit.write(decision="allow", url=url, purpose=purpose, scan_id=scan_id)
        else:
            # one denial entry per (scan, host, purpose) keeps the log readable
            self.audit.write_once(
                ("deny", scan_id, host, purpose),
                decision="deny", url=url, purpose=purpose, reason=reason, scan_id=scan_id,
            )
        return ok

    def require(self, url: str, purpose: str, scan_id: str | None = None) -> None:
        if not self.check(url, purpose, scan_id):
            raise ScopeError(url, self.decide(url)[1])
