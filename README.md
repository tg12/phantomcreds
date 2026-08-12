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
   - [`data/notifications.jsonl`](data/notifications.jsonl) for every external-contact
     decision, including the ones that were blocked and why
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
| 2026-08-12 | 43 | 6 | 2 | 2 | 2 | 0 |
| 2026-08-11 | 41 | 7 | 2 | 3 | 2 | 0 |
| 2026-08-10 | 43 | 8 | 2 | 3 | 4 | 0 |
| 2026-08-09 | 37 | 7 | 2 | 3 | 3 | 0 |
| 2026-08-08 | 33 | 7 | 2 | 3 | 3 | 0 |
| 2026-08-07 | 33 | 7 | 2 | 3 | 3 | 0 |
| 2026-08-06 | 34 | 11 | 3 | 6 | 6 | 0 |
| 2026-08-05 | 38 | 13 | 3 | 7 | 4 | 0 |
| 2026-08-04 | 42 | 15 | 4 | 11 | 5 | 0 |
| 2026-08-03 | 35 | 11 | 2 | 7 | 2 | 0 |
| 2026-07-31 | 34 | 14 | 6 | 9 | 5 | 0 |
| 2026-07-30 | 30 | 10 | 3 | 5 | 6 | 0 |
| 2026-07-29 | 32 | 8 | 1 | 5 | 3 | 0 |
| 2026-07-28 | 31 | 10 | 2 | 6 | 2 | 0 |
| 2026-07-27 | 35 | 12 | 5 | 10 | 3 | 0 |
| 2026-07-26 | 32 | 16 | 7 | 13 | 5 | 0 |
| 2026-07-25 | 34 | 15 | 6 | 12 | 6 | 0 |
| 2026-07-24 | 37 | 15 | 5 | 12 | 6 | 0 |
| 2026-07-22 | 40 | 15 | 6 | 11 | 6 | 0 |
| 2026-07-20 | 27 | 14 | 5 | 10 | 6 | 0 |
| 2026-07-19 | 24 | 8 | 3 | 5 | 3 | 1 |
| 2026-07-18 | 29 | 10 | 5 | 7 | 4 | 0 |
| 2026-07-17 | 29 | 10 | 5 | 7 | 4 | 0 |
| 2026-07-16 | 30 | 12 | 5 | 8 | 4 | 2 |
| 2026-07-15 | 33 | 13 | 5 | 10 | 5 | 1 |
| 2026-07-14 | 34 | 14 | 4 | 10 | 3 | 0 |
| 2026-07-12 | 34 | 15 | 8 | 12 | 5 | 2 |
| 2026-07-11 | 38 | 12 | 4 | 9 | 4 | 2 |
| 2026-07-10 | 31 | 13 | 3 | 6 | 4 | 2 |
| 2026-07-08 | 30 | 15 | 5 | 7 | 5 | 5 |
<!-- STATS:END -->

---

## Highest-risk repos today

<!-- REPO_STATS:START -->
| Repo | Score | Findings | Action | Stars | Updated |
|------|-------|----------|--------|-------|---------|
| BlueSkyXN/CPA-Core-LTS | 1.000 | 7 | report_only | 9 | 2026-08-10 |
| kaitranntt/CLIProxyAPIPlus | 1.000 | 6 | report_only | 225 | 2026-08-11 |
| moltis-org/moltis | 0.390 | 2 | watch | 2819 | 2026-08-12 |
| xingkaixin/agent-dump | 0.390 | 2 | watch | 5 | 2026-08-10 |
| yutaro0915/cloudflare-os | 0.390 | 2 | watch | 0 | 2026-08-09 |
| witqq/agent-session-exporter | 0.390 | 2 | watch | 0 | 2026-08-10 |
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

**notifications.jsonl** - one row per external-contact decision:

```json
{
  "repo_full_name": "owner/repo",
  "event": "created",
  "issue_number": 42,
  "title": "[phantomcreds] Exposed secrets detected in this repository",
  "scan_date": "2026-08-06",
  "recorded_at": "2026-08-06T07:03:11.482913+00:00"
}
```

`event` is one of `created`, `commented`, `skipped_closed`, `skipped_duplicate`,
`blocked_allowlist`, or `blocked_rate_limit`. Blocked decisions are recorded so the
reason a repo was *not* contacted is auditable, and `created` rows are what the rolling
24-hour ceiling counts.

---

## Setup

### 1. Create or fork the repo

This repo commits its own ledgers back to `main` after each successful scan.

### 2. Add a GitHub PAT secret

Use a **fine-grained** Personal Access Token, scoped to the repositories you intend to
contact, with:

- Repository access: **Only select repositories**
- Repository permissions: **Issues: Read and write**, **Metadata: Read-only**
- An expiry, re-approved on rotation

Add it as `GH_TOKEN` under:

**Settings -> Secrets and variables -> Actions -> New repository secret**

A **classic** token with `public_repo` also works and is what broad discovery needs,
but be clear about what it means: `public_repo` grants issue-creation rights on *every
public repository on GitHub*, so the blast radius of a scorer bug or a leaked CI secret
is the entire platform rather than the day's candidate set. The scanner has three
independent controls that do not depend on the token being narrow:

- `MAX_ISSUES_PER_SCAN` (10) caps one run
- `MAX_ISSUES_PER_ROLLING_WINDOW` (15 per 24h, counted from
  [`data/notifications.jsonl`](data/notifications.jsonl)) caps all runs and all repos,
  and is enforced outside the heuristic scorer
- [`data/allowlist.txt`](data/allowlist.txt) is re-checked at notify time, not only at
  scan time

Prefer the fine-grained token unless platform-wide discovery is a hard requirement. If
it is, a GitHub App installation is the better long-term model: installation is granted
and revoked per-repository by the target maintainer.

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
- `PHANTOMCREDS_NOTIFICATIONS_FILE=/tmp/notifications.jsonl`
- `PHANTOMCREDS_README_PATH=/tmp/README.md`

Local mode intentionally does **not** redirect the notification ledger: the rolling
24-hour issue ceiling is always counted against `data/notifications.jsonl`, so a local
run cannot be used to reset it.

Do not run the GitHub Actions and GitLab pipelines against the same target set
concurrently. There is no cross-system lock, so the pre-create re-check narrows but does
not eliminate the duplicate-issue race between two independent CI backends. Within
GitHub Actions the `concurrency` group already serializes scheduled and dispatched runs.

Operational difference from GitHub Actions:
- same discovery, fetch, scoring, and notification code paths
- no scheduler wrapper
- no Actions step summary unless `GITHUB_STEP_SUMMARY` is set
- local mode is the safer way to test scanner changes before allowing external issue creation

---

## Opting out before you are ever contacted

This tool contacts maintainers who did not ask for it. That is worth stating plainly
rather than burying. There is no pre-scan handshake with GitHub's search API, so the
honest control available is a **pre-emptive, documented opt-out that takes effect before
analysis** — not only after first contact.

Any one of these excludes a repository. All are checked before files are fetched, so an
opted-out repo is never analyzed and never appears in the ledger:

| Signal | How |
|---|---|
| Repository topic | Add `no-phantomcreds`, `phantomcreds-opt-out`, or `no-automated-issues` |
| Marker file | Commit an empty `.phantomcreds-opt-out`, `.github/phantomcreds-opt-out`, or `.well-known/phantomcreds-opt-out` |
| Closing an issue | A closed phantomcreds issue is treated as a refusal. The repo is never re-filed on and never re-commented on, even if the finding persists |
| Allowlist request | Ask on [the tracker](https://github.com/tg12/phantomcreds/issues) to be added to [`data/allowlist.txt`](data/allowlist.txt) |

Every issue phantomcreds opens carries these instructions in its body.

What this deliberately is **not**: opt-in. Requiring a marker file before scanning would
reduce the tool to scanning repos that already know about it, which detects nothing.
The trade made here is that discovery stays broad, external contact is gated hard, and
withdrawal is cheap, pre-emptive, and permanent.

---

## False positives and exclusions

If a repo is repeatedly benign but matches the search posture, add it to [`data/allowlist.txt`](data/allowlist.txt), one `owner/repo` per line. Allowlisted repos are skipped entirely in future runs and are re-checked before any issue is filed.

The scanner applies built-in context filters before raising secret findings:
- redacted evidence snippets are ignored
- test, fixture, and docs paths are not treated as live secret exposure
- template files such as `.env.example` remain non-issues when they contain placeholders, but still raise findings if they contain real credential material
- Docker auth evidence must decode to printable `user:password` material before it is treated as a committed secret
- credential-persistence findings require nearby write or serialization behavior, not just words like `session` or `cookie`
- prefix-less patterns (Vercel, Cloudflare, AWS session/secret keys) additionally require the matched value to survive an entropy, digest-shape, and sequential-run check, so a SHA-1 digest or `AKIA1234567890ABCDEF` is not read as a credential
- connection strings are classified by context: loopback and single-label service hosts, CI workflow definitions, prose files, shell/Compose interpolation, and identical `user:password` pairs are configuration, not exposure
- a hostname containing regex metacharacters is a detector's own source text, not a DSN
- OAuth callback findings require callback semantics **and** evidence of host publication, independently. Two containers binding `0.0.0.0` is neither

### What is allowed to reach a maintainer

Two confidence levels are recorded:

| Confidence | Meaning | Can open an issue |
|---|---|---|
| `confirmed` | Provider-prefixed token, private-key block, service-account blob, or a credential pair | Yes |
| `needs_review` | Shape-only match: a bare `scheme://user:password@host` DSN, or a prefix-less token assignment | No |

External contact requires either a `confirmed` secret finding, or at least two distinct
issue-worthy finding types, or a `high_risk` composite. A lone watchlist-grade regex hit
is recorded in the ledger and goes no further.

This is a repo-level scanner. It does not store individual user identities, and it does not attempt attribution beyond public repository content.
