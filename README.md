# jsscan-mcp

An MCP server that lets an AI agent discover JavaScript in a web app and scan it for exposed secrets and known vulnerable libraries. Findings include verification evidence and a source URL, with a line and column when the scanner can locate the match in the source. A local dashboard groups findings by type and severity.

The MCP tools return compact structured results and finding IDs. Target requests use a host allowlist and an audit log.

Only scan systems you own or have written permission to test, or a deliberately vulnerable app such as OWASP Juice Shop or DVWA. The allowlist exists to make that rule enforceable, not to replace it.

## Setup

Python 3.10 or newer.

```
git clone https://github.com/Saumya1404/jsscan-mcp && cd jsscan-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

On Windows PowerShell, use:

```powershell
py -3 -m venv .venv
$env:PYTHONUTF8 = "1"
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

The scanner currently needs UTF-8 mode on Windows to read the bundled advisory database. Set `PYTHONUTF8=1` in the MCP client's server environment too.

Scope is set by whoever launches the server. An empty allowlist refuses all scan targets.

```
export JSSCAN_ALLOWED_HOSTS="localhost:3000"     # comma separated
# or: export JSSCAN_SCOPE_FILE=scope.json        # {"allowed_hosts": ["localhost:3000"]}
jsscan-mcp                                       # stdio transport, web view on 127.0.0.1:8765
```

Register it with a client. For Claude Code:

```
claude mcp add jsscan -e JSSCAN_ALLOWED_HOSTS=localhost:3000 -- jsscan-mcp
```

For any client that takes a JSON config:

```json
{
  "mcpServers": {
    "jsscan": {
      "command": "/path/to/.venv/bin/jsscan-mcp",
      "env": { "JSSCAN_ALLOWED_HOSTS": "localhost:3000" }
    }
  }
}
```

Other settings: `JSSCAN_HOME` (database and audit log, default `~/.jsscan`), `JSSCAN_WEB_PORT` (default 8765), `JSSCAN_NO_WEB=1` to disable the web view, `JSSCAN_REQUEST_DELAY` (seconds between requests).

### Try the local demo

```
python demo/agent_demo.py --hold
```

On Windows, run `.\.venv\Scripts\python.exe demo\agent_demo.py --hold` with the UTF-8 setting above. The script generates a local fixture with fabricated credentials and sample library version banners, serves it on port 8011, and calls the MCP tools over stdio. Open the dashboard link it prints before pressing Enter. Add `--real-libs` to download the old library packages instead. That option requires npm and registry access.

To use an AI agent, generate the fixture separately with `python fixtures/make_fixture.py fixtures/out` and serve it with `python -m http.server 8011 --bind 127.0.0.1 --directory fixtures/out`. Use the virtual environment's Python for both commands. Register the scanner with the client using the configuration above, changing the allowlist to `127.0.0.1:8011`. On Windows, set the command to the absolute path to `.venv/Scripts/python.exe` and add `"args": ["-m", "jsscan.server"]`. Ask the agent to call `scan_target` for `http://127.0.0.1:8011/index.html`, then use the returned scan ID with `list_findings`.

## Tools

| Tool | Purpose |
| --- | --- |
| `get_scope` | Show the allowlist and limits. Read only. |
| `check_scope` | Dry run: is this URL allowed? Makes no request. |
| `crawl_target` | List the JavaScript a target loads, without scanning. |
| `scan_target` | Crawl, scan and verify in one call. Returns counts, the top five findings and a dashboard link. |
| `list_findings` | Filter by type, severity and confidence. Most severe first, paginated. |
| `get_finding` | Finding evidence, including location, verification checks, and advisory details where available. |
| `verify_finding` | Re-fetch the source and re-run verification. Updates the stored status. |
| `list_scans`, `get_audit_log` | History, and what was allowed or refused. |
| `refresh_vuln_db` | Fetch updated Retire.js data from GitHub. This request currently bypasses the target allowlist. |

A finding looks like this, which is the shape an agent sees in lists:

```json
{"id": "009afddd-001", "type": "secret", "severity": "critical", "status": "confirmed",
 "confidence": 95, "title": "GitHub token", "where": "http://127.0.0.1:8011/app.js:5:17",
 "preview": "ghp_…ql (40 chars)", "occurrences": 2}
```

## How it works

The crawler fetches pages breadth first and collects external scripts, inline scripts, modulepreload links, and script references found inside already fetched scripts (webpack chunks, dynamic imports). Each script goes through two analyzers.

The secret analyzer applies 19 rules (cloud keys, GitHub, GitLab, Slack, Stripe, Google, SendGrid, OpenAI, Anthropic, npm, PEM private keys, JWTs, database URLs with credentials, and a generic credential assignment rule). The dependency analyzer uses the Retire.js repository format: version extractors for URL, filename, file content and file hash, matched against version ranges with advisories.

### Verification

A regex hit is only a candidate. Each one runs through a verifier for its type and gets a status, a confidence from 0 to 100, and the list of checks that produced it.

- confirmed: structure validated by something stronger than a pattern. A GitHub token whose CRC32 suffix matches, an AWS key id whose embedded account id decodes to a plausible account, a JWT whose header and payload decode, a PEM body that base64 decodes to key-sized DER.
- likely: strong format, plausible entropy, nothing suspicious.
- unverified: weak signal, kept for triage.
- rejected: placeholder, template, repeated characters, low entropy, translation key, hash constant, default database password. Hidden by default but counted, and one click away in the web view.

Context changes severity as well as status. A JWT with role `anon` is info, with `service_role` critical, and an expired one low. A Stripe publishable key is info. A database URL pointing at localhost is low. Library findings take the highest advisory severity and report the version that fixes it.

Library confidence depends on how many independent signals agree. A hash match is strongest, a banner in the file plus the filename is next, a URL alone is weakest. Signals that disagree are flagged and the file content wins.

`verify_finding` goes back to the live source, reproduces the match by fingerprint, and refreshes the verdict. A finding that no longer reproduces is marked `not_reproduced` instead of silently kept.

## Design choices

**Target requests use a scoped fetcher.** The crawler and finding rechecks use a fetcher that checks the allowlist before each request, including redirect hops. Entries without a port match the scheme's default port. Wildcards match subdomains, and only HTTP and HTTPS are allowed. The JSONL audit log records allowed requests and groups refusals by scan, host and purpose. The advisory refresh tool currently uses a separate HTTP client outside this scope enforcement. The local demo uses the bundled snapshot.

**Out-of-scope scripts are not fetched, but their URLs are still read.** A page that loads `cdnjs.cloudflare.com/.../moment.js/2.18.1/...` tells you the version without any request to the CDN. Those findings are capped at 55 confidence, marked unverified, and say plainly that the file was not fetched.

**Secret findings use redacted previews.** The secret analyzer stores a short fingerprint and redacts neighboring detected secrets in its snippets. Dependency snippets currently copy nearby source text, and scan records and audit logs can include raw URLs. Keep local scan data out of Git.

**Verification is offline.** Checking whether a key is live means sending it to a third party, which breaks the scope guarantee and may be unauthorized use of the credential. The checks here are structural and statistical, and the live-validation step is left to a human with the owner's consent.

**Scanned content is treated as untrusted.** Snippets come from the target and can contain instructions aimed at the agent. The server returns them as data and tells the agent to treat them as untrusted. The web view escapes finding content, uses a content security policy that blocks scripts and external loads, binds to localhost, and rejects foreign Host headers.

**Retire.js data, with a safety net.** A snapshot of the Retire.js repository ships in the package (Apache-2.0, see THIRD_PARTY_NOTICES.md) and `refresh_vuln_db` updates it. Its patterns use variable-width lookbehind, so the matcher uses the `regex` module with a per-search timeout against pathological backtracking. A small supplemental extractor table covers builds upstream cannot identify; minified lodash 4.17.15 was the case that surfaced it.

**One process, one SQLite file.** The MCP server and the web view share a database. Simple to run, easy to inspect. Scans run inside the tool call, bounded by page and file limits.

## Results so far

On the generated demo site: all planted credential types found, the AWS docs example key, a localhost database URL with a default password, translation keys and a "your-secret-here" value rejected as false positives, the same GitHub token in two files merged into one finding with two occurrences, and four libraries flagged (jQuery, lodash, Bootstrap, and moment from a refused CDN host, URL evidence only).

An earlier local run against the OWASP Juice Shop v20.3.0 frontend bundle reported 18 scripts, 28 MB and zero findings in about 10 seconds. The result describes what the scanner detected in that run.

## Limits

- No source map resolution. Locations are in the bundled file, and minified bundles mean long lines, so the column matters.
- No JavaScript execution. Scripts injected at run time, or chunk URLs built by string concatenation, are not discovered. Single page apps with hash routing expose one page to the crawler.
- Unauthenticated crawling only.
- Reverification updates the stored verdict, but a moved match can leave the stored location and snippet stale.
- Libraries are found only if Retire.js (or the supplemental table) can identify them. Heavily bundled or renamed copies can slip through.
- The GitHub checksum follows GitHub's published token format description and is tested for self consistency, not against a real token. A mismatch lowers confidence instead of rejecting the hit, so a wrong assumption cannot hide a real token.
- Entropy and shape heuristics for generic credentials will still let some noise through and can miss low-entropy real passwords.
- Not tested against any third-party site, by design.

## Layout

```
src/jsscan/   config, scope (allowlist and audit), fetcher, crawler, secrets, verify, deps, store, scanner, server (MCP), web
tests/        scope and redirect enforcement, verifiers, version logic, end to end, secret leakage, web escaping
fixtures/     generator for the vulnerable demo site (credentials created at run time, never committed)
demo/         scripted agent client and recording script
```

See the [recording guide](demo/SCRIPT.md) for the demo walkthrough. <!-- Add the public demo video link here. -->
