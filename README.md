# Qualys Data Analytics

A locally-run Flask web application that ingests vulnerability and asset data from
Qualys (CSAM assets, VM host detections, VM host list) into SQLite and provides
a rich dashboard for analysis, trend tracking, and ad-hoc querying. Designed for
a single analyst or a small team — no external database or orchestrator required.

## Features

- **Dashboard** — total vulns, critical/high counts, coverage %, and five
  clickable KPI cards (Patchable %, MTTR, SLA Compliance, Scan Coverage,
  Reopen Rate) that each open the SQL tab with the exact formula pre-loaded.
- **Cyber 6-Pack** — enterprise summary + per-group breakdown (by owner, tag,
  or OS) with **month-over-month trend charts** (avg vuln age, SLA breaches).
- **KPIs page** — operational KPIs aligned with SANS guidance.
- **Query Builder** — filter detections by IP, severity, status (pill
  checkboxes), QID, tag, and date range; dynamic charts; CSV export.
- **Tags** — tag coverage and per-tag detection drilldowns.
- **Trends** — weekly and monthly rollups charted across up to 52 weeks and
  12 months (GFS retention).
- **Hosts** — browse joined CSAM + VM host records.
- **Ownership** — CRUD + CSV import for IP / IP-range / tag / OS-pattern
  ownership rules.
- **SQL tab (powered by pandas)** — read-only SQL editor over the
  `v_detections` / `v_hosts` / `v_assets` / `v_changes` views. Post-process
  results in-place with pandas (Describe, Group By, Pivot, Rolling Average,
  Percentiles, Correlation). Export to CSV or Excel (.xlsx).
- **Scheduled refresh** — APScheduler runs the full refresh weekly on Monday
  at 06:00 (configurable) inside the Flask process. No external cron needed.

## Requirements

- Python 3.11+
- A Qualys account with API access to both VM and CSAM (EU Platform 1 by
  default — edit `config/.config` for other platforms).

Key Python packages (from `requirements.txt`):

| Package | Used for |
|---------|----------|
| `flask`  | web framework |
| `requests` | Qualys API client |
| `apscheduler` | weekly refresh job |
| `pandas` | **SQL tab post-processing (Describe / Group / Pivot / Rolling / Percentiles / Correlation)** |
| `openpyxl` | **Excel (`.xlsx`) export** |

`pandas` is **lazy-imported** inside the two routes that need it
(`/api/query/postprocess` and `/api/query/export/xlsx`), so dashboard pages do
not pay the import cost at startup.

## Install

```bash
git clone <repo-url>
cd qualys-da

# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
# python3 -m venv .venv
# source .venv/bin/activate

pip install -r requirements.txt

# Copy the example config and fill in credentials
copy config\.config.example config\.config    # Windows
# cp config/.config.example config/.config    # macOS / Linux
# edit config\.config — set username, password, and (optionally) urls
```

## First run

```bash
python cli.py health       # verify both VM and CSAM auth succeed
python cli.py refresh      # pull real data from Qualys

# Or load demo data (120 hosts, ~2,700 detections, 52 weeks of rollups):
python seed_data.py --reset

python app.py              # launches on http://localhost:5001
```

Open **http://localhost:5001** — the Dashboard should populate with metric
cards, KPI cards, and charts.

By default the server binds to **localhost only**. To reach the dashboard
from another machine on your LAN (e.g. share it with a teammate), either:

```bash
python app.py --public                 # bind to all interfaces
python app.py --host 10.0.0.5          # bind to a specific machine IP
python app.py --port 8080              # change port
```

…or set them permanently in `config/.config`:

```ini
[server]
host = 0.0.0.0    # or a specific IP; default is localhost
port = 5001
```

On startup the log prints the exact URL(s) the server is reachable at,
including your machine's LAN IP when bound publicly.

## Using the SQL tab with pandas

Navigate to **SQL** (`/sql`). Every KPI card on the Dashboard also deep-links
here with the corresponding formula pre-loaded (`/sql?formula=patchable`, etc.).

1. **Pick a template or write SQL.** Six built-in templates cover common
   views (top hosts by vulns, sev-5 open > 7 days, unscanned 30+ days, etc.).
   Only `SELECT` queries are accepted — writes are rejected server-side.
2. **Execute** (`Ctrl+Enter` or the Execute button). Results render in the
   table beneath the editor.
3. **Post-process with pandas.** The "Post-Processing (powered by pandas)"
   card drives a real server-side pandas pipeline:
   - **Describe** — `count/mean/std/min/25%/50%/75%/max` for each column.
   - **Group By** — pick a group column + aggregate (count / sum / mean /
     min / max) + value column.
   - **Pivot** — pick index, columns, values, and an aggregator → get a
     cross-tab.
   - **Rolling Average** — smooths a numeric column over a window of N rows.
   - **Percentiles** — `P50 / P90 / P95 / P99` for a numeric column.
   - **Correlation** — numeric correlation matrix.
   The status line to the right of **Apply** shows
   "Post-processed via pandas — N rows" once a result is back.
4. **Export.**
   - **Export CSV** — dumps the raw query result.
   - **Export Excel** — sends the most recent pandas post-processed result
     (or the raw query if none yet) to `/api/query/export/xlsx`, which builds
     an `.xlsx` via `pandas.ExcelWriter(engine='openpyxl')`.

### Worked example

1. Open `/sql`, pick the *"Top 20 hosts by vulns"* template, click **Execute**.
2. Pandas toolbar → Operation = *Group By*, Group column = `severity`,
   Aggregate = *mean*, Value column = `vuln_count` → **Apply**.
3. Click **Export Excel** — a `query_results.xlsx` downloads containing the
   grouped result.

## Scheduled refresh

APScheduler runs `DataManager.refresh_all()` weekly. Settings live in
`config/.config`:

```ini
[scheduler]
enabled = true
refresh_day = monday
refresh_hour = 6
```

To confirm it's active, look for a `Scheduler started` line in `logs/app.log`
after `python app.py` starts.

Manual refresh anytime:

```bash
python cli.py refresh              # all sources
python cli.py refresh --source csam
python cli.py refresh --source vm-hosts
python cli.py refresh --source vm-detections
```

## GFS retention

The DB uses a Grandfather-Father-Son retention policy to keep disk usage
bounded while preserving full history for trend analysis:

- Daily snapshots: **30 days**
- Weekly rollups (`weekly_rollups`): **52 weeks**
- Monthly rollups (`monthly_rollups`): kept indefinitely

Configure in `[retention]` section of `config/.config`. Automatic pruning runs
after every refresh. Manually: `python cli.py purge`.

## Deploy (local / internal)

Designed to run locally on a laptop or a single internal VM. For a slightly
more robust setup:

**Windows** — `run.bat` in the project root:
```bat
@echo off
cd /d %~dp0
call .venv\Scripts\activate
python app.py
```

**Linux** — sample systemd unit (`/etc/systemd/system/qualys-da.service`):
```ini
[Unit]
Description=Qualys Data Analytics
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/qualys-da
ExecStart=/opt/qualys-da/.venv/bin/python app.py
Restart=on-failure
User=qualys-da

[Install]
WantedBy=multi-user.target
```

For production-grade hosting, front Flask with `waitress` (Windows) or
`gunicorn` (Linux):

```bash
pip install waitress
waitress-serve --listen=127.0.0.1:5000 app:app
```

Because APScheduler runs inside the Flask process, **do not run multiple
workers** — one process keeps the weekly job from firing multiple times.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: pandas` when clicking Apply on SQL tab | `pip install -r requirements.txt` — pandas + openpyxl are now listed. |
| Dashboard empty after install | Run `python cli.py refresh` (real data) or `python seed_data.py --reset` (demo data). |
| `AuthError` on `python cli.py health` | Check `username` / `password` in `config/.config`; confirm platform URLs match (EU Platform 1 is the default). |
| SQL tab returns `Only SELECT queries are allowed` | Correct — the endpoint strips everything except read-only SELECT. |
| Excel download returns JSON error | `openpyxl` not installed — `pip install openpyxl`. |
| Trend charts show only a few points | Historical rollups haven't accumulated yet — run `python seed_data.py --reset` to load 52 weeks / 12 months of demo data. |

## Project layout

```
qualys-da/
├── app.py                 # Flask entry point + all routes
├── cli.py                 # health / refresh / export / purge / status
├── seed_data.py           # demo data generator
├── requirements.txt
├── config/
│   ├── .config            # credentials (git-ignored)
│   └── .config.example
├── data/qualys_da.db      # SQLite store
├── logs/app.log
├── src/
│   ├── config_loader.py
│   ├── database.py        # tables, views, GFS retention
│   ├── api_client.py      # dual auth (VM Basic + CSAM JWT)
│   ├── analytics.py       # metrics + 6-pack + pandas-free SQL aggregations
│   └── data_manager.py    # coordinator
├── templates/             # Jinja2 templates (base, index, six_pack, ...)
├── static/                # style.css + app.js
└── tests/                 # unittest QA suite
```

## Database schema

All data lives in a single SQLite file (`data/qualys_da.db`). The schema is
created and migrated idempotently by `QualysDADatabase._init_schema()` in
[`src/database.py`](src/database.py). Tables fall into five groups:

1. **Raw snapshots** — one row per entity per pull, stamped with `fetched_at`
   so that every pull is a full point-in-time copy (the dashboard reads the
   most recent `fetched_at` via `SELECT MAX(fetched_at)`). Older snapshots
   are pruned by GFS retention.
2. **Configuration** — user-maintained lookup tables (ownership, SLA, saved
   queries) that are *not* stamped with `fetched_at`.
3. **Derived history** — weekly and monthly rollups computed after each
   refresh; these outlive raw snapshots under GFS.
4. **Change log** — row-per-diff stream used for the "what changed this
   week" view.
5. **Operational state** — refresh log and CSAM pull checkpoint.

### Architecture diagram — API to database data flow

The diagram below shows how data flows from the three Qualys API endpoints
through the refresh pipeline into SQLite, and how derived tables are computed
post-refresh. Browse real data at runtime via the **Data Explorer** page
(`/data-explorer`).

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           QUALYS PLATFORM (EU1)                            │
│                                                                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  CSAM Asset API   │  │  VM Host List    │  │  VM Detection API        │  │
│  │  POST /rest/2.0/  │  │  POST /api/3.0/  │  │  POST /api/5.0/fo/      │  │
│  │  search/am/asset  │  │  fo/asset/host/  │  │  asset/host/vm/         │  │
│  │  (JSON, JWT)      │  │  (XML, Basic)    │  │  detection/ (XML,Basic) │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────────┬─────────────┘  │
│           │                     │                          │                │
└───────────┼─────────────────────┼──────────────────────────┼────────────────┘
            │                     │                          │
            ▼                     ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    REFRESH PIPELINE (data_manager.py)                       │
│              ThreadPoolExecutor — 3 parallel workers                        │
│                                                                            │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────────┐  │
│  │  CSAM Worker      │  │  VM Hosts Worker │  │  VM Detections Worker    │  │
│  │                   │  │                  │  │                          │  │
│  │ • Pages of 1000   │  │ • Pages of 1000  │  │ • Pages of 1000          │  │
│  │ • Resume from     │  │ • In-memory      │  │ • In-memory buffer       │  │
│  │   checkpoint      │  │   buffer         │  │ • on_page progress       │  │
│  │ • Per-page save   │  │ • on_page        │  │                          │  │
│  │   to DB           │  │   progress       │  │                          │  │
│  │ • 3-tier throttle │  │                  │  │                          │  │
│  │   (50/10/2)       │  │                  │  │                          │  │
│  └────────┬─────────┘  └────────┬─────────┘  └────────────┬─────────────┘  │
│           │                     │                          │                │
│           │  ┌──────────────────┴──────────────────────────┘                │
│           │  │  Per-API failure isolation: one API failing                  │
│           │  │  does NOT cancel the others. Status: success/partial/failed  │
│           │  │                                                             │
└───────────┼──┼─────────────────────────────────────────────────────────────┘
            │  │
            ▼  ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SQLite — data/qualys_da.db                            │
│                                                                            │
│  RAW SNAPSHOTS (fetched_at-stamped, dashboard reads MAX(fetched_at))       │
│  ┌───────────────┐ ┌───────────────┐ ┌────────────────┐ ┌──────────────┐  │
│  │  csam_assets   │ │  vm_hosts     │ │ vm_detections  │ │  host_tags   │  │
│  │               │ │               │ │                │ │              │  │
│  │ asset_id  ◄───┼─┼── ip_address ─┼─┼── ip_address ──┼─┼► ip_address  │  │
│  │ name          │ │ host_id   ◄───┼─┼── host_id      │ │ host_id      │  │
│  │ ip_address    │ │ dns           │ │ qid            │ │ tag_id       │  │
│  │ os            │ │ os            │ │ severity       │ │ tag_name     │  │
│  │ tags (JSON)   │ │ trurisk_score │ │ status         │ │ source       │  │
│  │ hardware(JSON)│ │ last_scan_date│ │ first_found    │ │ (csam / vm)  │  │
│  │ software(JSON)│ │ tracking      │ │ cve_id         │ │              │  │
│  │ raw_data      │ │ raw_data      │ │ cvss_base      │ │              │  │
│  │ fetched_at    │ │ fetched_at    │ │ fetched_at     │ │ fetched_at   │  │
│  └───────────────┘ └───────────────┘ └────────────────┘ └──────────────┘  │
│        ▲                   ▲                  ▲                ▲            │
│        │      JOIN: ip_address (cross-source) │                │            │
│        └───────────────────┴──────────────────┘                │            │
│                            │                                   │            │
│  DERIVED (post-refresh)    │     CONFIGURATION                 │            │
│  ┌──────────────────┐      │     ┌──────────────────┐          │            │
│  │ detection_changes │      │     │  asset_owners    │          │            │
│  │ (diff stream)     │◄─────┘     │  match_type:     │──────────┘            │
│  │ new/fixed/reopen  │            │  ip / ip_range / │                       │
│  └──────┬───────────┘            │  tag / os_pattern│                       │
│         │                        └──────────────────┘                       │
│         ▼                        ┌──────────────────┐                       │
│  ┌──────────────────┐            │  sla_targets     │                       │
│  │ weekly_rollups   │            │  severity → days  │                       │
│  │ (52 weeks)       │            └──────────────────┘                       │
│  └──────┬───────────┘            ┌──────────────────┐                       │
│         ▼                        │  saved_queries   │                       │
│  ┌──────────────────┐            └──────────────────┘                       │
│  │ monthly_rollups  │                                                       │
│  │ (indefinite)     │   OPERATIONAL STATE                                   │
│  └──────────────────┘   ┌──────────────────┐  ┌──────────────────┐          │
│                         │  refresh_log     │  │  csam_checkpoint │          │
│                         │  status: running │  │  resume_from_id  │          │
│                         │  /success/partial│  │  snapshot_        │          │
│                         │  /failed         │  │  fetched_at      │          │
│                         └──────────────────┘  └──────────────────┘          │
│                                                                            │
│  VIEWS (read by SQL tab + dashboard)                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │ v_detections = vm_detections ⋈ vm_hosts ⋈ asset_owners            │    │
│  │ v_hosts      = vm_hosts ⋈ asset_owners                             │    │
│  │ v_assets     = csam_assets ⋈ asset_owners                          │    │
│  │ v_changes    = detection_changes ⋈ vm_hosts                        │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                            │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key design points:**

- **Snapshot model:** Every refresh creates a full point-in-time copy under a
  single `fetched_at` timestamp. The dashboard always queries
  `WHERE fetched_at = (SELECT MAX(fetched_at) FROM <table>)`. Old snapshots
  are pruned by GFS retention (30 days daily, 52 weeks weekly, monthly
  indefinite).
- **Cross-source join:** CSAM and VM data are linked only through
  `ip_address`. There are no foreign keys — all relationships are implicit.
- **Tag normalization:** Tags appear in `csam_assets.tags` (JSON) and in the
  VM host/detection XML. They're extracted and unified into `host_tags` with
  a `source` column (`csam` / `vm`) so ownership rules and analytics can
  match on tag names without parsing JSON.
- **CSAM resilience:** CSAM pages are saved to DB individually (per-page
  commit via `on_page` callback). A crash or rate limit mid-pull leaves
  resumable state in `csam_checkpoint`, and the next run continues under the
  same `snapshot_fetched_at`.
- **Per-API failure isolation:** Each of the three parallel workers has its
  own try/except. A failure in CSAM does not cancel VM hosts or detections.
  The `refresh_log` row records per-API outcomes so the operator can see
  exactly which source to re-run.

### Raw snapshots

#### `csam_assets` — CSAM asset inventory
One row per asset per pull. The five JSON columns store original list/dict
payloads verbatim so the SQL tab can `json_extract(...)` any field without a
schema change.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | autoincrement |
| `asset_id` | TEXT | Qualys CSAM asset ID |
| `name` | TEXT | asset name |
| `ip_address` | TEXT | indexed |
| `os` | TEXT | operating system string |
| `hardware` | TEXT | JSON — manufacturer / model / serial |
| `software` | TEXT | JSON array — installed software inventory |
| `tags` | TEXT | JSON array — raw tag payload (also normalized into `host_tags`) |
| `ports` | TEXT | JSON array — open ports |
| `network_interfaces` | TEXT | JSON array — NICs / MACs |
| `last_seen` | TEXT | ISO timestamp |
| `created` | TEXT | ISO timestamp |
| `raw_data` | TEXT | full API payload (JSON) — fallback for fields not surfaced above |
| `fetched_at` | TEXT NOT NULL | snapshot timestamp |
| UNIQUE | `(asset_id, fetched_at)` | |

#### `vm_hosts` — VM host inventory
One row per VM host per pull.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `host_id` | INTEGER NOT NULL | Qualys VM host ID — join key for detections and tags |
| `ip_address` | TEXT | indexed |
| `dns` | TEXT | DNS hostname |
| `netbios` | TEXT | NetBIOS name |
| `os` | TEXT | |
| `trurisk_score` | INTEGER | host-level TruRisk (0–1000) |
| `last_scan_date` | TEXT | most recent scan of any type |
| `last_vm_scanned_date` | TEXT | most recent VM scan specifically |
| `last_activity_date` | TEXT | last time the host was seen alive |
| `tracking_method` | TEXT | `IP` / `DNS` / `NETBIOS` / `AGENT` |
| `raw_data` | TEXT | full API payload |
| `fetched_at` | TEXT NOT NULL | |
| UNIQUE | `(host_id, fetched_at)` | |

#### `vm_detections` — per-host vulnerability detections
One row per (host, QID) per pull. The bulk of the database.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `host_id` | INTEGER NOT NULL | joins to `vm_hosts.host_id` |
| `ip_address` | TEXT | denormalized for indexing |
| `qid` | INTEGER NOT NULL | Qualys QID |
| `detection_type` | TEXT | `Confirmed` / `Potential` / `Information` |
| `severity` | INTEGER | 1–5 |
| `status` | TEXT | `New` / `Active` / `Fixed` / `Re-Opened` |
| `is_disabled` | INTEGER | 0/1 — filtered out of dashboards by default |
| `qds` | INTEGER | Qualys Detection Score (0–100) |
| `cve_id` | TEXT | comma-joined list of CVEs |
| `cvss_base` | REAL | |
| `cvss_temporal` | REAL | |
| `cvss_vector` | TEXT | CVSS v3 vector string |
| `patchable` | INTEGER | 0/1 — drives Patchable % KPI |
| `vendor` | TEXT | e.g. `Microsoft`, `Red Hat` |
| `product` | TEXT | e.g. `Windows Server 2019` |
| `package_name` | TEXT | affected package / component |
| `package_version` | TEXT | version currently installed |
| `fix_version` | TEXT | version that resolves the detection |
| `title` | TEXT | human-readable QID title |
| `first_found` | TEXT | drives MTTR + aging buckets |
| `last_found` | TEXT | |
| `last_fixed` | TEXT | |
| `last_test` | TEXT | last time the QID was tested on this host |
| `times_found` | INTEGER | |
| `results` | TEXT | scan output string — indicator of what matched |
| `raw_data` | TEXT | full API payload |
| `fetched_at` | TEXT NOT NULL | |
| UNIQUE | `(host_id, qid, fetched_at)` | |

#### `host_tags` — normalized tag assignments
Tags are also present as JSON inside `csam_assets.tags`, but this normalized
table makes `JOIN … WHERE tag_name = ?` cheap.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `host_id` | INTEGER | nullable — for pure-CSAM assets that aren't in VM |
| `ip_address` | TEXT | |
| `tag_id` | INTEGER NOT NULL | Qualys tag ID |
| `tag_name` | TEXT NOT NULL | display name |
| `criticality_score` | INTEGER | tag-level criticality (if set) |
| `source` | TEXT NOT NULL | `csam` or `vm` — same tag may come from both |
| `fetched_at` | TEXT NOT NULL | |
| UNIQUE | `(host_id, tag_id, source, fetched_at)` | |

### Configuration (not snapshot-scoped)

#### `asset_owners` — ownership rules
Applied via left joins in the `v_*` views to attach owner/BU to every
detection, host, and asset.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `match_type` | TEXT NOT NULL | `ip` / `ip_range` / `tag` / `os_pattern` |
| `match_value` | TEXT NOT NULL | e.g. `10.0.0.0/24`, `Production`, `Windows%` |
| `owner` | TEXT NOT NULL | |
| `business_unit` | TEXT | |
| `notes` | TEXT | |
| `created_at` / `updated_at` | TEXT NOT NULL | |
| UNIQUE | `(match_type, match_value)` | |

#### `sla_targets` — days-to-fix per severity
Seeded at first run with `{5: 7, 4: 30, 3: 90, 2: 180, 1: 365}`.

| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `severity` | INTEGER UNIQUE NOT NULL (1–5) |
| `days` | INTEGER NOT NULL |
| `updated_at` | TEXT NOT NULL |

#### `saved_queries` — user-saved SQL from the SQL tab

| Column | Type |
|--------|------|
| `id` | INTEGER PK |
| `name` | TEXT NOT NULL |
| `description` | TEXT |
| `sql_text` | TEXT NOT NULL |
| `created_at` | TEXT NOT NULL |
| `last_run_at` | TEXT |

### Derived history (survives GFS pruning)

#### `weekly_rollups` — one row per ISO week (52-week retention)
Written by `AnalyticsEngine` after every refresh. `tag_metrics` is a JSON
blob of per-tag counts so the Tags page can show 52 weeks of history without
another table.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `week_start` | TEXT UNIQUE NOT NULL | ISO Monday date |
| `total_vulns` | INTEGER | |
| `sev5_count` … `sev1_count` | INTEGER | per-severity totals |
| `status_new` / `_active` / `_fixed` / `_reopened` | INTEGER | |
| `new_this_week` / `fixed_this_week` | INTEGER | drives MoM / WoW trends |
| `avg_trurisk` / `max_trurisk` | REAL / INTEGER | |
| `avg_qds` | REAL | |
| `total_hosts` / `csam_hosts` / `vm_hosts` / `both_hosts` | INTEGER | coverage decomposition |
| `coverage_pct` | REAL | `both / (csam ∪ vm)` |
| `aging_30d` / `aging_60d` / `aging_90d` | INTEGER | vulns older than N days |
| `tag_metrics` | TEXT | JSON `{tag: {count, sev5, ...}}` |
| `computed_at` | TEXT NOT NULL | |

#### `monthly_rollups` — one row per month (kept indefinitely)
Same shape as `weekly_rollups` but keyed on `month_start` with
`new_this_month` / `fixed_this_month`.

### Change log

#### `detection_changes` — diff stream between consecutive pulls

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `host_id` | INTEGER NOT NULL | |
| `ip_address` | TEXT | |
| `qid` | INTEGER NOT NULL | |
| `change_type` | TEXT NOT NULL | `new` / `fixed` / `reopened` / `severity_changed` / `status_changed` |
| `old_value` / `new_value` | TEXT | before / after (severity, status, etc.) |
| `severity` | INTEGER | |
| `detected_at` | TEXT NOT NULL | when the diff was observed (not the Qualys timestamp) |

### Operational state

#### `refresh_log` — one row per refresh attempt
Row-level `status` is the rollup; the three per-API `*_status` columns tell
the Status Page which specific pull failed so the operator can retry just
that source.

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK | |
| `started_at` / `completed_at` | TEXT | `completed_at` NULL while running |
| `source` | TEXT NOT NULL | `all` / `csam` / `vm-hosts` / `vm-detections` |
| `csam_count` / `vm_host_count` / `vm_detection_count` | INTEGER | actual rows written |
| `csam_expected` / `vm_host_expected` / `vm_detection_expected` | INTEGER | total reported by the API — lets the UI render a progress bar mid-pull |
| `changes_detected` | INTEGER | rows written to `detection_changes` |
| `status` | TEXT NOT NULL | `running` / `success` / `partial` / `error` |
| `error` | TEXT | |
| `csam_status` / `vm_host_status` / `vm_detection_status` | TEXT | per-API outcome |

#### `csam_checkpoint` — single-row resume state for CSAM pulls
CSAM pulls are paginated and can span many minutes. If one fails halfway,
the next run resumes from `last_asset_id` under the *same* `snapshot_fetched_at`
so the two halves land in one coherent snapshot instead of being split
across two `fetched_at` values (which would halve the host count on the
dashboard).

| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK CHECK(id = 1) | enforces single row |
| `last_asset_id` | TEXT | next `startFromId` |
| `assets_pulled` | INTEGER DEFAULT 0 | |
| `started_at` / `updated_at` | TEXT | |
| `completed` | INTEGER DEFAULT 0 | flipped to 1 on clean finish |
| `lookback_days` | INTEGER | pull-time parameter |
| `note` | TEXT | human-readable context for the UI |
| `snapshot_fetched_at` | TEXT | the `fetched_at` value shared by every page of the in-flight pull |

### Views (read by the SQL tab)

All four views scope their join-key raw tables to the most-recent
`fetched_at`, and left-join `asset_owners` so `owner` / `business_unit`
appear on every row. The SQL tab's allow-list is exactly these views:

| View | Built from | Purpose |
|------|------------|---------|
| `v_detections` | `vm_detections` ⋈ `vm_hosts` ⋈ `asset_owners` | latest detections with host + owner columns attached |
| `v_hosts` | `vm_hosts` ⋈ `asset_owners` | latest VM hosts with owner |
| `v_assets` | `csam_assets` ⋈ `asset_owners` | latest CSAM assets with owner |
| `v_changes` | `detection_changes` ⋈ `vm_hosts` | change log with host DNS/OS attached |

### Indexes

All high-traffic columns are indexed. Notable composites:

- `idx_vmhosts_fetched_ip (fetched_at, ip_address)` — drives the Hosts page lookup.
- `idx_detect_fetched_sev (fetched_at, severity, status)` — drives the Dashboard severity+status panels.
- `idx_detect_fetched_ip (fetched_at, ip_address)` — drives per-host detection drilldowns.
- `idx_detect_cve (cve_id, fetched_at)` / `idx_detect_cvss (cvss_base, fetched_at)` / `idx_detect_patchable (patchable, fetched_at)` — KPI cards.
- `idx_tags_name (tag_name, fetched_at)` — Tags page.

## Dashboard formulas

Every number shown on the dashboard, 6-Pack, KPIs, Tags, Trends, and Ownership
pages is computed by a method on `AnalyticsEngine` (`src/analytics.py`). The
full reference — including the SQL each method runs and the formulas derived
from the results — lives in [`docs/FORMULAS.md`](docs/FORMULAS.md).

The reference is kept honest by
`tests/test_formulas_doc.py::test_every_analytics_method_is_documented`, which
fails whenever a new public method is added to `AnalyticsEngine` without a
matching entry in the doc. It runs as part of the standard suite (see below).

## Running tests

```bash
python -m unittest discover tests
```
