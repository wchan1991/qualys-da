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
