"""Secret detection rules and the scanner that applies them to JavaScript text."""
from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass

from .verify import Verdict, verify_hit

_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    pattern: re.Pattern
    severity: str
    verifier: str = "default"
    group: int = 1
    name_group: int | None = None
    generic: bool = False


def _r(id, name, pat, sev, verifier="default", group=1, name_group=None, generic=False, flags=0):
    return Rule(id, name, re.compile(pat, flags), sev, verifier, group, name_group, generic)


RULES: list[Rule] = [
    _r("aws-access-key-id", "AWS access key id", r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", "high", "aws_key"),
    _r("aws-secret-access-key", "AWS secret access key",
       r"""(?i)aws.{0,25}?(?:secret|sk).{0,25}?['"]([A-Za-z0-9/+=]{40})['"]""", "critical", "aws_secret"),
    _r("github-token", "GitHub token", r"\b((?:gh[pousr]_[A-Za-z0-9]{36}))\b", "critical", "github"),
    _r("github-fine-grained-pat", "GitHub fine-grained token", r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b", "critical", "github"),
    _r("gitlab-pat", "GitLab personal access token", r"\b(glpat-[A-Za-z0-9_\-]{20})\b", "high"),
    _r("slack-token", "Slack token", r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b", "high", "slack"),
    _r("slack-webhook", "Slack webhook URL",
       r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})", "medium"),
    _r("stripe-secret-key", "Stripe secret key", r"\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,99})\b", "critical", "stripe"),
    _r("stripe-publishable-key", "Stripe publishable key", r"\b(pk_(?:live|test)_[A-Za-z0-9]{20,99})\b", "info", "stripe"),
    _r("google-api-key", "Google API key", r"\b(AIza[0-9A-Za-z_\-]{35})\b", "low", "google_key"),
    _r("google-oauth-secret", "Google OAuth client secret", r"\b(GOCSPX-[A-Za-z0-9_\-]{28})\b", "high"),
    _r("sendgrid-key", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "high"),
    _r("openai-key", "OpenAI API key",
       r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})\b", "critical"),
    _r("anthropic-key", "Anthropic API key", r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})\b", "critical"),
    _r("npm-token", "npm access token", r"\b(npm_[A-Za-z0-9]{36})\b", "high"),
    _r("private-key", "Private key (PEM)",
       r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s\\nr]{60,6000}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)",
       "critical", "pem"),
    _r("jwt", "JSON Web Token",
       r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b", "medium", "jwt"),
    _r("db-connection-string", "Database URL with credentials",
       r"""\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:'"@/]+:[^\s'"@/]{3,}@[^\s'"/]+)""", "high", "dbconn"),
    _r("generic-credential", "Hardcoded credential",
       r"""(?i)['"]?([a-z0-9_.\-]*(?:api[_-]?key|secret|passw(?:or)?d|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)[a-z0-9_.\-]*)['"]?\s*[:=]\s*['"]([^'"\s]{12,100})['"]""",
       "medium", "generic", group=2, name_group=1, generic=True),
]


@dataclass
class Hit:
    rule: Rule
    value: str
    key_name: str | None
    start: int
    end: int
    verdict: Verdict
    line: int
    col: int
    before: str
    after: str

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.value.encode()).hexdigest()[:12]

    @property
    def preview(self) -> str:
        return redact(self.value)


def redact(value: str) -> str:
    if value.startswith("-----BEGIN"):
        return value.split("-----")[1].join(["-----", "-----"]) + "…[redacted]"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


def _clean(s: str) -> str:
    return _CTRL.sub(" ", s)


class LineIndex:
    def __init__(self, text: str):
        self.starts = [0] + [m.end() for m in re.finditer(r"\n", text)]

    def locate(self, offset: int) -> tuple[int, int]:
        i = bisect.bisect_right(self.starts, offset) - 1
        return i + 1, offset - self.starts[i] + 1


def _context(text: str, lo: int, hi: int, spans: list[tuple[int, int, str]]) -> str:
    """Slice text[lo:hi], replacing any other secret inside the window with its redacted preview."""
    out, pos = [], lo
    for s, e, preview in spans:
        if e <= lo or s >= hi:
            continue
        s2, e2 = max(s, lo, pos), min(e, hi)
        if s2 >= e2:
            continue
        out.append(text[pos:s2])
        out.append(preview if s >= lo and e <= hi else "[redacted]")
        pos = e2
    out.append(text[pos:hi])
    return _clean("".join(out))


def scan_text(text: str, window: int = 80) -> list[Hit]:
    """Run every rule, drop generic hits that overlap a specific rule, verify the rest."""
    if not text:
        return []
    raw: list[tuple[Rule, str, str | None, int, int]] = []
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            raw.append((rule, m.group(rule.group), m.group(rule.name_group) if rule.name_group else None,
                        m.start(rule.group), m.end(rule.group)))
    specific = [(s, e) for r, _, _, s, e in raw if not r.generic]
    spans = sorted({(s, e, redact(v)) for _, v, _, s, e in raw})
    idx = LineIndex(text)
    hits: list[Hit] = []
    for rule, value, key, s, e in raw:
        if rule.generic and any(s < e2 and e > s2 for s2, e2 in specific):
            continue
        others = [sp for sp in spans if sp[1] <= s or sp[0] >= e]  # never echo other secrets
        before = _context(text, max(0, s - window), s, others)
        after = _context(text, e, e + window, others)
        verdict = verify_hit(rule.id, rule.verifier, rule.severity, value, key, before, after)
        line, col = idx.locate(s)
        hits.append(Hit(rule, value, key, s, e, verdict, line, col, before, after))
    return hits
