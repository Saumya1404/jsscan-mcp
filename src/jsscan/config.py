"""Runtime configuration, read once from the environment.

Scope is deliberately NOT settable through any MCP tool. Whoever launches the
server decides what may be touched; the agent only works inside that boundary.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


def _home() -> Path:
    p = Path(os.environ.get("JSSCAN_HOME", Path.home() / ".jsscan"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def _load_allowlist() -> list[str]:
    entries: list[str] = []
    scope_file = os.environ.get("JSSCAN_SCOPE_FILE")
    if scope_file:
        data = json.loads(Path(scope_file).read_text())
        entries += [str(e) for e in data.get("allowed_hosts", [])]
    env = os.environ.get("JSSCAN_ALLOWED_HOSTS", "")
    entries += [e.strip() for e in env.split(",") if e.strip()]
    return entries


@dataclass
class Settings:
    home: Path = field(default_factory=_home)
    allowed_hosts: list[str] = field(default_factory=_load_allowlist)
    web_host: str = "127.0.0.1"
    web_port: int = field(default_factory=lambda: int(os.environ.get("JSSCAN_WEB_PORT", "8765")))
    web_enabled: bool = field(default_factory=lambda: os.environ.get("JSSCAN_NO_WEB", "") == "")
    max_bytes_per_file: int = 5 * 1024 * 1024
    request_timeout: float = 15.0
    concurrency: int = 6
    request_delay: float = field(default_factory=lambda: float(os.environ.get("JSSCAN_REQUEST_DELAY", "0")))
    user_agent: str = "jsscan-mcp/0.1 (authorized security testing)"

    @property
    def db_path(self) -> Path:
        return self.home / "jsscan.db"

    @property
    def audit_path(self) -> Path:
        return self.home / "audit.jsonl"

    @property
    def vuln_cache_path(self) -> Path:
        return self.home / "retire-db.json"


def get_settings() -> Settings:
    return Settings()
