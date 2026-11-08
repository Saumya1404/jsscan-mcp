"""HTTP client that cannot leave scope.

Redirects are followed by hand so every hop is checked against the allowlist.
A redirect to an out-of-scope host is refused and logged, never requested.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from .config import Settings
from .scope import Scope, ScopeError

MAX_REDIRECTS = 5
logging.getLogger("httpx").setLevel(logging.WARNING)


@dataclass
class Fetched:
    url: str
    final_url: str
    status: int = 0
    content_type: str = ""
    text: str = ""
    truncated: bool = False
    error: str | None = None
    blocked: bool = False


class ScopedFetcher:
    def __init__(self, scope: Scope, settings: Settings):
        self.scope = scope
        self.settings = settings
        self._sem = asyncio.Semaphore(settings.concurrency)
        self._client = httpx.AsyncClient(
            follow_redirects=False,
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent, "Accept": "*/*"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get(self, url: str, purpose: str, scan_id: str | None = None) -> Fetched:
        current = url
        async with self._sem:
            for _ in range(MAX_REDIRECTS + 1):
                try:
                    self.scope.require(current, purpose, scan_id)
                except ScopeError as e:
                    return Fetched(url, current, error=str(e), blocked=True)
                if self.settings.request_delay:
                    await asyncio.sleep(self.settings.request_delay)
                try:
                    async with self._client.stream("GET", current) as r:
                        if r.is_redirect and r.headers.get("location"):
                            current = urljoin(current, r.headers["location"])
                            continue
                        body = bytearray()
                        truncated = False
                        async for chunk in r.aiter_bytes():
                            body += chunk
                            if len(body) > self.settings.max_bytes_per_file:
                                truncated = True
                                break
                        return Fetched(
                            url, current, status=r.status_code,
                            content_type=r.headers.get("content-type", ""),
                            text=bytes(body).decode("utf-8", errors="replace"),
                            truncated=truncated,
                        )
                except httpx.HTTPError as e:
                    return Fetched(url, current, error=f"{type(e).__name__}: {e}")
            return Fetched(url, current, error="too many redirects")
