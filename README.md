<p align="center">
  <img src="https://img.shields.io/badge/phantomcreds-v0.1.0-0f766e?style=for-the-badge" alt="phantomcreds">
  <img src="https://img.shields.io/badge/python-3.14-blue?style=for-the-badge" alt="Python 3.14">
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

1. Searches GitHub repositories for posture phrases such as `multi-account`, `no API key needed`, `auth file`, `shared subscription`, session reuse, provider relays, and imported browser-auth language
2. Searches code across Go, Python, JavaScript, and TypeScript for credential-risk fingerprints such as token or session persistence, raw `Authorization` forwarding, management auth bypass wrappers, wildcard management exposure, callback listeners bound to `0.0.0.0`, and committed secret-bearing `.env`, `.netrc`, `.pypirc`, Docker auth config, Terraform credential, private-key, service-account, and connection-string material
3. Fetches targeted high-signal files plus a bounded sweep of broadly text-like repo files directly from the GitHub API
4. Scores each repo against a repo-level evidence model that prefers multi-family matches over single-query noise, then biases toward recently pushed non-archived non-fork repos
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
| Direct secret exposure | Current repo files appear to contain committed cloud, model-provider, CI, package-registry, webhook, SSH, service-account, registry-auth, Terraform, or database-connection credentials; evidence is redacted in stored findings and issue bodies |
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
- multi-language query families
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
| 2026-06-13 | 35 | 16 | 10 | 13 | 8 | 0 |
| 2026-06-12 | 36 | 16 | 10 | 13 | 8 | 1 |
| 2026-06-11 | 37 | 18 | 10 | 13 | 7 | 1 |
| 2026-06-10 | 36 | 18 | 10 | 15 | 8 | 0 |
| 2026-06-09 | 33 | 17 | 10 | 14 | 6 | 1 |
| 2026-06-08 | 38 | 17 | 10 | 14 | 5 | 0 |
| 2026-06-07 | 33 | 15 | 11 | 13 | 6 | 0 |
| 2026-06-06 | 34 | 15 | 10 | 12 | 5 | 0 |
| 2026-06-05 | 38 | 12 | 8 | 10 | 5 | 0 |
| 2026-06-04 | 32 | 13 | 11 | 11 | 5 | 1 |
| 2026-06-03 | 30 | 15 | 12 | 13 | 8 | 0 |
| 2026-06-02 | 31 | 17 | 11 | 14 | 7 | 0 |
| 2026-06-01 | 30 | 19 | 12 | 16 | 8 | 0 |
| 2026-05-31 | 29 | 16 | 12 | 15 | 8 | 0 |
| 2026-05-30 | 31 | 18 | 12 | 16 | 8 | 1 |
| 2026-05-29 | 41 | 19 | 14 | 17 | 9 | 2 |
| 2026-05-27 | 36 | 17 | 13 | 14 | 5 | 0 |
| 2026-05-26 | 34 | 19 | 13 | 16 | 6 | 0 |
| 2026-05-25 | 39 | 20 | 11 | 17 | 5 | 0 |
| 2026-05-24 | 33 | 17 | 11 | 14 | 5 | 1 |
| 2026-05-23 | 33 | 18 | 14 | 17 | 9 | 0 |
| 2026-05-22 | 34 | 15 | 13 | 14 | 7 | 0 |
| 2026-05-21 | 33 | 18 | 12 | 17 | 7 | 0 |
| 2026-05-20 | 30 | 14 | 11 | 14 | 5 | 0 |
| 2026-05-19 | 55 | 21 | 14 | 16 | 7 | 1 |
| 2026-05-18 | 115 | 69 | 45 | 46 | 28 | 45 |
<!-- STATS:END -->

---

## Highest-risk repos today

<!-- REPO_STATS:START -->
| Repo | Score | Findings | Action | Stars | Updated |
|------|-------|----------|--------|-------|---------|
| zsecducna/cli-cache-proxy-api | 1.000 | 8 | report_only | 0 | 2026-06-12 |
| jay6697117/CLIProxyAPIPlus | 1.000 | 7 | report_only | 7 | 2026-06-11 |
| kaitranntt/CLIProxyAPIPlus | 1.000 | 7 | report_only | 136 | 2026-06-11 |
| BlueSkyXN/CPA-Core-LTS | 1.000 | 7 | report_only | 3 | 2026-06-10 |
| router-for-me/CLIProxyAPI | 1.000 | 7 | report_only | 37369 | 2026-06-13 |
| fxzer/cpa-core | 1.000 | 6 | file_issue | 0 | 2026-06-11 |
| 6enta0/CPAplus | 1.000 | 6 | file_issue | 18 | 2026-06-13 |
| Sastraaaa/proxypilot | 1.000 | 6 | file_issue | 0 | 2026-04-29 |
| daishuge/playful-proxy-api-panel | 1.000 | 6 | report_only | 45 | 2026-06-10 |
| kittors/CliRelay | 1.000 | 5 | file_issue | 788 | 2026-06-12 |
| waylandun/tokenStore | 0.560 | 2 | file_issue | 0 | 2026-06-12 |
| Wei-Shaw/claude-relay-service | 0.410 | 2 | report_only | 12075 | 2026-06-13 |
| zylos-ai/zylos-core | 0.410 | 2 | file_issue | 1174 | 2026-06-12 |
| jlcodes99/cockpit-tools | 0.390 | 2 | report_only | 11273 | 2026-06-13 |
| xingkaixin/agent-dump | 0.390 | 2 | watch | 3 | 2026-06-12 |
| zcz-user/codex-auth-session-refresh | 0.390 | 2 | watch | 1 | 2026-06-10 |
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
  "finding_type": "exposed_secret",
  "title": "Secret-bearing credential material appears committed in current repository files",
  "severity": "high",
  "confidence": "confirmed",
  "summary": "Current repository files appear to contain committed cloud, model-provider, CI, package-registry, webhook, SSH, or service-account credential material. Evidence is redacted in the report output.",
  "issue_worthy": true,
  "scan_date": "2026-05-18",
  "evidence": [
    ".env:1 - OPENAI_API_KEY=[REDACTED:sk-pro...3456]",
    "deploy/id_rsa:1 - [REDACTED:-----BEGIN OPENSSH PRIVATE KEY-----]"
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

Safe local test run:

```bash
git clone https://github.com/YOUR_USERNAME/phantomcreds.git
cd phantomcreds
python -m venv venv && source venv/bin/activate
pip install -e .[dev]
PHANTOMCREDS_LOCAL_MODE=1 GH_TOKEN=ghp_your_token phantomcreds
```

This uses the same scan logic locally but:
- disables external GitHub issue creation by default
- does not rewrite the main `README.md`
- writes results under `.local/phantomcreds/`
- keeps the same GitHub API fetch, heuristic scoring, and issue-decision logic as the hosted run

Production-style local run:

```bash
GH_TOKEN=ghp_your_token \
PHANTOMCREDS_NOTIFY_EXTERNAL=1 \
PHANTOMCREDS_UPDATE_README=1 \
phantomcreds
```

Useful local overrides:
- `PHANTOMCREDS_OUTPUT_DIR=/tmp/phantomcreds-run`
- `PHANTOMCREDS_NOTIFY_EXTERNAL=0|1`
- `PHANTOMCREDS_UPDATE_README=0|1`
- `PHANTOMCREDS_REPORTS_FILE=/tmp/repos.jsonl`
- `PHANTOMCREDS_FINDINGS_FILE=/tmp/findings.jsonl`
- `PHANTOMCREDS_README_PATH=/tmp/README.md`

Operational difference from GitHub Actions:
- same discovery, fetch, scoring, and notification code paths
- no scheduler wrapper
- no Actions step summary unless `GITHUB_STEP_SUMMARY` is set
- local mode is the safer way to test scanner changes before allowing external issue creation

---

## False positives and exclusions

If a repo is repeatedly benign but matches the search posture, add it to [`data/allowlist.txt`](data/allowlist.txt), one `owner/repo` per line. Allowlisted repos are skipped entirely in future runs.

The scanner also applies built-in context filters before raising secret findings:
- redacted evidence snippets are ignored
- test, fixture, and docs paths are not treated as live secret exposure
- template files such as `.env.example` remain non-issues when they contain placeholders, but still raise findings if they contain real credential material
- Docker auth evidence must decode to printable `user:password` material before it is treated as a committed secret
- credential-persistence findings require nearby write or serialization behavior, not just words like `session` or `cookie`

This is a repo-level scanner. It does not store individual user identities, and it does not attempt attribution beyond public repository content.
