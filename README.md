<p align="center">
  <img src="https://img.shields.io/badge/phantomcreds-v0.1.0-0f766e?style=for-the-badge" alt="phantomcreds">
  <img src="https://img.shields.io/badge/python-3.13-blue?style=for-the-badge" alt="Python 3.13">
  <img src="https://img.shields.io/badge/license-Apache--2.0-green?style=for-the-badge" alt="Apache 2.0">
  <img src="https://img.shields.io/badge/CI-GitHub%20Actions-orange?style=for-the-badge" alt="GitHub Actions">
  <img src="https://img.shields.io/badge/runs-daily-brightgreen?style=for-the-badge" alt="Daily">
</p>

<h1 align="center">phantomcreds</h1>
<p align="center"><strong>Automated detection and tracking of credential-harvesting and unsafe credential-storage repos on GitHub</strong></p>
<p align="center">
  A <a href="https://labs.jamessawyer.co.uk/">JS Labs</a> project -
  part of the <a href="https://labs.jamessawyer.co.uk/ai-slop-intelligence-dashboards/">AI Slop Intelligence</a> initiative.<br>
  Runs every day. Scores suspicious repos. Captures evidence. Files issues only when the code looks fixable.
</p>

---

## Why this exists

The counterintuitive move here is restraint.

The easy version of this project is a giant crawler that flags every repo mentioning `token`, `cookie`, or `OAuth`. That path loses trust immediately because the maintenance tax becomes larger than the signal. Legitimate software stores tokens. Legitimate tools proxy requests. Legitimate integrations use OAuth callbacks.

The useful version is narrower: detect repos whose docs and code jointly suggest credential harvesting, unsafe persistence, replay posture, or exposed management surfaces. Record the evidence every day. File issues only when the target still looks like a maintainable software project rather than an overt abuse kit.

That is what **phantomcreds** does.

It is built around one premise: operator trust is the product. If the scanner cannot explain *why* a repo was flagged and *which lines* created that judgment, it is not finished.

---

## What it does

**phantomcreds** runs a daily GitHub Actions job that:

1. Searches GitHub repositories for posture phrases such as `multi-account`, `no API key needed`, `auth file`, and `shared subscription`
2. Searches code for strong credential-risk fingerprints such as `SaveTokenToFile`, raw `Authorization` forwarding, management auth bypass wrappers, wildcard management CORS, and callback listeners bound to `0.0.0.0`
3. Fetches targeted file contents directly from the GitHub API
4. Scores each repo against a repo-level evidence model rather than a keyword count
5. Writes append-only ledgers to this repo:
   - [`data/repos.jsonl`](data/repos.jsonl) for per-repo scan outcomes
   - [`data/findings.jsonl`](data/findings.jsonl) for concrete findings with evidence
6. Updates the README dashboard automatically
7. Opens or updates one issue per target repo **only** when the findings are specific and fixable
8. Leaves overt abuse-oriented repos as `report_only` records instead of spamming them with issues

No servers. No database. No dashboard backend.

---

## Detection model

The scanner combines four evidence classes:

| Evidence class | What it means |
|---|---|
| Harvest posture | README or description markets shared subscriptions, relays, auth-file import, or "no API key needed" positioning |
| Credential persistence | Code writes token-like material to local auth files or serialized session stores |
| Unsafe exposure | Callback listeners bind broadly, management routes use wildcard CORS, or auth bypass wrappers weaken the control plane |
| Centralized leakage | Request logging or telemetry paths appear to forward raw credential-bearing headers |

Not every hit is issue-worthy.

The product rule is deliberate:

- `file_issue`: concrete technical defect with defensible evidence and a plausible maintainer remediation path
- `report_only`: repo posture looks overtly abusive, or the scan can defend the risk but issue filing is unlikely to improve behavior
- `watch`: suspicious signals exist, but the evidence is not strong enough for automated external action

This is the main maintenance-tax control. It avoids treating every suspicious repo as a workflow target.

---

## Code smell and maintenance tax

Three uncomfortable truths drive the design:

1. The biggest failure mode is not false negatives. It is false-positive automation with weak evidence. That destroys the product faster than missing a repo.
2. Repo families matter more than individual repos. Once one credential-harvesting codebase is confirmed, the next high-leverage step is searching for reused paths and symbol names across derivatives.
3. The project should prefer append-only evidence over complicated state machines. Daily JSONL ledgers and deterministic README updates are lower-maintenance than a bespoke datastore.

### Devil's-advocate view

The comfortable answer is "scan everything and file everything."

Why that loses:

- GitHub code search is rate-limited and noisy.
- Most repositories that mention tokens are normal software.
- Bulk issue creation on overt abuse repos creates work without changing outcomes.
- A complex crawler increases breakage surface and lowers operator confidence.

The winning move is smaller:

- search-first discovery
- targeted file fetches
- repo-level scoring
- one issue per repo at most
- explicit `report_only` for abuse-heavy cases

That is less dramatic and more durable.

---

## What you will regret not knowing later

- Which repo families cloned the same unsafe credential paths
- Which findings were recurring but never issue-worthy
- Which wording in README posture was a leading indicator before the code confirmed it

The data model is structured so those questions can be answered from the ledger later without redesigning the project.

---

## Three questions to ask next

1. Which clone-family fingerprints should graduate from "interesting" to "hard finding" after recurring across multiple repos?
2. Which issue classes actually lead to maintainer response, and which are operational dead ends that should stay `report_only`?
3. At what scale does GitHub Search API noise justify adding a local corpus or scheduled seed list?

---

## Live dashboard

<!-- STATS:START -->
| Date | Scanned | Flagged | High Risk | Issue-Worthy | Report Only | New High Risk |
|------|---------|---------|-----------|--------------|-------------|---------------|
| 2026-05-18 | 160 | 94 | 43 | 74 | 39 | 43 |
<!-- STATS:END -->

---

## Highest-risk repos today

<!-- REPO_STATS:START -->
| Repo | Score | Findings | Action | Stars | Updated |
|------|-------|----------|--------|-------|---------|
| kaitranntt/CLIProxyAPIPlus | 1.000 | 7 | report_only | 83 | 2026-05-18 |
| Finesssee/ProxyPilot | 1.000 | 7 | report_only | 220 | 2026-05-17 |
| tikhomirov/cliapi-webui | 1.000 | 7 | report_only | 0 | 2026-05-14 |
| fxzer/CLIProxyAPI | 1.000 | 7 | report_only | 0 | 2026-05-14 |
| router-for-me/CLIProxyAPI | 1.000 | 7 | report_only | 33344 | 2026-05-18 |
| HsnSaboor/CLIProxyAPIPlus | 1.000 | 7 | report_only | 61 | 2026-05-17 |
| Finesssee/ProxyPilot | 1.000 | 7 | report_only | 221 | 2026-05-18 |
| tikhomirov/cliapi-webui | 1.000 | 7 | report_only | 0 | 2026-05-14 |
| kaitranntt/CLIProxyAPIPlus | 1.000 | 7 | report_only | 83 | 2026-05-18 |
| fxzer/CLIProxyAPI | 1.000 | 7 | report_only | 0 | 2026-05-14 |
| router-for-me/CLIProxyAPI | 1.000 | 6 | report_only | 33287 | 2026-05-18 |
| vannek110/CLIProxyAPI | 1.000 | 6 | report_only | 0 | 2026-02-06 |
| Sastraaaa/proxypilot | 1.000 | 6 | file_issue | 0 | 2026-04-29 |
| rituprodhan-ops/c-channel-engine | 1.000 | 6 | file_issue | 0 | 2026-05-17 |
| NguyenSiTrung/CLIProxyAPI | 1.000 | 6 | report_only | 1 | 2026-05-07 |
| daishuge/playful-proxy-api-panel | 1.000 | 6 | report_only | 39 | 2026-05-16 |
| CodexNexor/VoltGate | 1.000 | 6 | report_only | 4 | 2026-04-27 |
| zhangrr/CLIProxyAPI | 1.000 | 6 | file_issue | 13 | 2026-05-11 |
| tamaproject360/clipproxyhybrid | 1.000 | 6 | report_only | 0 | 2026-01-05 |
| Sakuralaaa/CLIProxyAPI | 1.000 | 6 | report_only | 0 | 2026-03-06 |
| SahandTava/CLIProxyAPI | 1.000 | 6 | report_only | 0 | 2026-01-02 |
| nextransit/CLIProxyAPI | 1.000 | 6 | report_only | 0 | 2026-05-16 |
| kdjahdiel-code/c-pipe-engine | 1.000 | 6 | file_issue | 0 | 2026-05-17 |
| edlsh/CLIProxyAPIPlus-HsnSaboor | 1.000 | 6 | report_only | 0 | 2026-05-02 |
| Camier/CLIProxyAPI | 1.000 | 6 | report_only | 0 | 2026-02-11 |
<!-- REPO_STATS:END -->

---

## Data format

**repos.jsonl** - one row per scanned repo per run:

```json
{
  "full_name": "owner/repo",
  "composite": 0.82,
  "classification": "high_risk",
  "action": "file_issue",
  "finding_count": 4,
  "issue_worthy_count": 3,
  "stars": 431,
  "scan_date": "2026-05-18",
  "created_at": "2026-04-29T20:14:00Z",
  "updated_at": "2026-05-18T08:42:11Z",
  "discovery_sources": ["auth-bypass", "callback-exposure", "shared-subscription-posture"],
  "finding_types": ["callback_exposure", "credential_persistence", "management_auth_bypass"]
}
```

**findings.jsonl** - one row per concrete finding:

```json
{
  "repo_full_name": "owner/repo",
  "finding_type": "raw_auth_forwarding",
  "title": "Home request logging forwards raw Authorization headers",
  "severity": "high",
  "confidence": "confirmed",
  "summary": "Downstream request headers appear to be cloned into centralized request-log transport without secret redaction.",
  "issue_worthy": true,
  "scan_date": "2026-05-18",
  "evidence": [
    "internal/logging/request_logger.go:204 - Headers: cloneHeaders(headers),",
    "internal/logging/request_logger_home_test.go:42 - \"Authorization\": {\"Bearer secret\"},"
  ]
}
```

---

## Setup

### 1. Create or fork the repo

This repo commits its own ledgers back to `main` after each successful scan.

### 2. Add a GitHub PAT secret

Create a **classic** Personal Access Token with scopes:

- `public_repo`
- `read:user`

Add it as `GH_TOKEN` under:

**Settings -> Secrets and variables -> Actions -> New repository secret**

### 3. Enable Actions

The workflow runs at **07:00 UK time daily** using the `Europe/London` clock:

- `06:00 UTC` during British Summer Time
- `07:00 UTC` during Greenwich Mean Time

GitHub cron is UTC-only, so the workflow triggers at both UTC hours and only proceeds when local London time is `07`.

Manual trigger:

**Actions -> Daily Phantomcreds Scan -> Run workflow**

### 4. Run locally

```bash
git clone https://github.com/YOUR_USERNAME/phantomcreds.git
cd phantomcreds
python -m venv venv && source venv/bin/activate
pip install -e .
GH_TOKEN=ghp_your_token python -m phantomcreds.main
```

---

## False positives and exclusions

If a repo is repeatedly benign but matches the search posture, add it to [`data/allowlist.txt`](data/allowlist.txt), one `owner/repo` per line. Allowlisted repos are skipped entirely in future runs.

This is a repo-level scanner. It does not store individual user identities, and it does not attempt attribution beyond public repository content.
