# DKCISSP Privacy Posture Assessment

Enter a website, get an instant privacy/cookie-consent compliance read — mapped to the specific
article/section of **GDPR, CCPA/CPRA, CIPA, India DPDP, and PDPA (Singapore)** that's implicated,
with concrete remediation steps. Runs entirely on your own machine.

## Why

Most "is my site GDPR compliant?" checks are a vague checklist. This tool actually loads the page
(optionally in a real local browser) and observes what happens *before* consent is given: which
trackers fire, which cookies get set, whether "Reject All" actually blocks anything — then cites the
exact clause each finding breaches and how to fix it.

**Only assess domains you own or are authorized to test.** This tool loads pages the same way an
ordinary visitor's browser would — it never logs in, submits forms, brute-forces anything, or does
anything beyond that. It is a compliance-posture checker, not a scanner for someone else's site.

## What it checks

- **Pre-consent tracking** — does Google Analytics / Meta Pixel / etc. fire before the visitor
  consents? (The single most common GDPR/CIPA violation on the open web.)
- **Trap-and-trace & wiretap exposure** — trackers that capture IP/device identifiers (CIPA
  §638.51) or record session replay/chat input (CIPA §631).
- **Cookie-consent banner / CMP** — is one present, does it offer an equally-prominent "Reject
  All", and (dynamic scan only) does rejecting actually stop the trackers?
- **Cookies** — non-essential cookies set before consent, and missing Secure/HttpOnly flags.
- **Privacy policy** — found and linked? Does it disclose retention, legal basis, international
  transfers, data-subject rights, and a DPO/privacy contact?
- **"Do Not Sell or Share" link** — required under CCPA/CPRA when advertising trackers are present.
- **Forms** — PII-collecting forms without a visible consent checkbox.
- **Device fingerprinting** — canvas/WebGL/audio API probing used to build a persistent identifier.
- **Transport security** — HTTPS enforced, HSTS present, and TLS certificate actually validates.

## Two scan modes

- **Dynamic (preferred)** — drives a locally-installed Chrome/Chromium via the Chrome DevTools
  Protocol directly (no Playwright/Selenium needed) to observe real pre-consent network beacons and
  test the Reject-All flow. This is what proves a CMP is decorative rather than functional.
- **Static** — a plain HTTPS GET, used automatically when no local Chromium is found, or if you pass
  `--no-headless` / check "skip the headless-browser scan".

## Install — one command

**macOS / Linux**:
```bash
curl -fsSL https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.sh | bash
```

**Windows (PowerShell)**:
```powershell
iwr -useb https://raw.githubusercontent.com/deepakkumarcissp/Public-Website-Privacy-Posture-Assessment/main/install.ps1 | iex
```

That downloads the project, sets up a private virtual environment, installs dependencies, starts
the local web UI, and opens your browser at `http://127.0.0.1:1009`. Run the same command again any
time to update and relaunch.

Prefer not to pipe a script into your shell? Download the repo and double-click `run.sh` (Linux),
`run.command` (macOS), or `run.bat` (Windows) instead.

For the **dynamic scan**, have Google Chrome or Chromium installed locally — the tool finds it
automatically. Without it, the static scan still runs and covers most of the same checks (it just
can't prove the Reject-All flow actually works).

## Use it — command line

```bash
pip install -e .
dkcissp-privacy-assessment example.com
```

Live progress is printed to stderr as the scan runs; add `--json` for machine-readable output
(useful for CI/scripting):

```bash
dkcissp-privacy-assessment example.com --json > report.json
```

Exit code is `0` for a Low-risk result and `1` otherwise.

## Use it — local web UI

```bash
pip install -e ".[web,dynamic-scan]"
dkcissp-privacy-assessment-web
```

Open **http://127.0.0.1:1009**, enter a domain, and click **Run Assessment**. A live activity log
streams while the scan runs (page load, tracker detection, consent-flow test, clause mapping), then
the full result renders below it.

## Use it — as a library

```python
from privacy_posture import assess_website

result = assess_website("example.com")
print(result["risk"], result["score"])
for finding in result["findings"]:
    print(finding["sev"], finding["title"], finding["laws"])
```

## Configuration

| Option (cfg dict key) | Purpose |
|---|---|
| `headless` | `True` (default) tries the dynamic Chromium scan first, falling back to static. Set `False` to always use the static scan. |
| `settle` | Seconds to wait for network activity to settle during the dynamic scan (default `4.0`). |

## Safety

- Never submits forms, logs in, or interacts with the page beyond what a normal visitor's browser
  does (a page load, plus clicking a visible "Reject All" button if one exists — to prove whether it
  actually works).
- Never follows the site's outbound tracker/ad links to their destination.
- Nothing is sent to any third party by this tool itself — the only network traffic is your machine
  talking directly to the domain you entered.
- Refuses to assess a domain that resolves to a cloud-provider instance-metadata address or a
  link-local address (e.g. `169.254.169.254`) — these are never legitimate assessment targets and
  this closes the clearest SSRF-abuse path. General private/internal addresses (your own intranet,
  a local dev server) are still assessable, since testing your own internal site before it goes live
  is a legitimate use of this tool.
- The local web UI is unauthenticated by design (no login, for zero-friction local use), so it
  binds to `127.0.0.1` only, rejects any request whose `Host` header isn't exactly
  `127.0.0.1:<port>`/`localhost:<port>` (defeats DNS-rebinding), and requires a random per-run
  session token on every scan-triggering request (defeats a malicious page in another browser tab
  silently triggering scans via your browser). Don't expose this server beyond localhost.

## License

GNU GPLv3 — see [LICENSE](LICENSE).

---

Built by [DKCISSP](https://dkcissp.com) for the community: a free, local, no-account-needed way to
check a website's privacy compliance before a regulator (or a plaintiff's attorney) does.
