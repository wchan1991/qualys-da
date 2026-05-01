# CSAM API Rate-Limit Handling

How the app stays within Qualys's CSAM rate limits — and how it ingests
fleets larger than a single rate-limit window allows.

## The constraints (Qualys side)

CSAM responses include four headers we react to:

| Header | Meaning |
|---|---|
| `X-RateLimit-Limit` | Total per-window call budget (e.g. `300`) |
| `X-RateLimit-Remaining` | Calls left in the current window |
| `X-RateLimit-ToWait-Sec` | Seconds until the window resets |
| `X-Concurrency-Limit-{Limit,Running}` | Concurrent in-flight cap |

There's also an undocumented **per-window asset throughput cap** (~40k assets
on observed tenants). When you hit it, Qualys returns a 429 with a
`ToWait-Sec` value like `2810` (~47 min until reset).

## The three-tier throttle (`_csam_apply_server_throttle`)

Runs after every 2xx response. Reacts to `Remaining` *before* it bites:

| `Remaining` | Behaviour | Log |
|---|---|---|
| `< 50` | One-shot WARN per window — surfaces pressure to operators *before* it slows the pull | WARN (deduped per window) |
| `≤ 10` | Inject 0.5s sleep between requests | WARN |
| `≤ 2` | Honour `ToWait-Sec` (or 2s if absent) — full hard wait | INFO |

Window dedup keys on `int((now + ToWait-Sec) // 60)` so a 100-page pull
doesn't produce 100 identical warnings.

## The window-hop loop (`_csam_request`)

When a 429 is returned anyway, the request loop sleeps `ToWait-Sec` and
retries — up to `csam_max_window_hops` times in a row:

```
Page 40: 429, ToWait-Sec=2810
  ↓
sleep 2810s (≈47 min)
  ↓
Page 40 retry: 200 — window reset, continue pagination
  ↓
... 40k assets later ...
Page 80: 429, ToWait-Sec=1798
  ↓
sleep 1798s
  ↓
Page 80 retry: 200 — done
```

This lets a single `refresh_all()` ride through multiple rate-limit windows
unattended. A 100k-asset fleet that needs 3 windows now completes in one
~2-hour run instead of needing manual re-triggers.

The 429 sleep is clamped to the `csam_max_window_wait` ceiling per hop so a
malformed/extreme `ToWait-Sec` value can't hang the refresh forever.

## Crash safety during the wait

If the app dies during a multi-hour wait (kill, OS reboot, network blip),
**no data is lost**:

- Each page is saved to `csam_assets` immediately via the `on_page` callback,
  under a stable `snapshot_fetched_at` allocated when the pull began.
- The `csam_checkpoint` table tracks `last_asset_id` and the same
  `snapshot_fetched_at`.
- The next refresh detects the incomplete checkpoint, resumes from
  `last_asset_id` using `startFromId`, and writes new pages under the
  *same* `snapshot_fetched_at` — so the dashboard sees one coherent
  snapshot once the pull completes, not two halves.

## Preflight count

Before pagination starts, `count_csam_assets()` calls
`POST /rest/2.0/count/am/asset` to learn the expected total. The number
flows into:

- `refresh_log.csam_expected` — drives the dashboard banner's "0 of 85,000"
  denominator from page 1 onward.
- Periodic progress logs every 10 pages: `fetched 32,000 of 85,000`.
- A drift warning at the end if the pulled count differs from the expected.

## Configuration

In `config/.config` under `[api]`:

```ini
csam_page_size = 1000             # Max page size (Qualys cap = 1000)
csam_lookback_days = 90           # Server-side filter on lastCheckedIn (0 = none)
csam_resume_enabled = true        # Resume mid-pull crashes via checkpoint
csam_max_window_hops = 3          # # of rate-limit windows to wait through per refresh
csam_max_window_wait = 3600       # Per-hop wait ceiling (s) — clamps malformed headers
```

`csam_max_window_hops = 1` reverts to the old single-retry behaviour. Set
higher (e.g. `5`) for very large fleets that need 4+ windows.

## What operators see

**During a pull:**
- Dashboard banner ticks live: `CSAM 32,418 / 85,000`.
- During a window-hop sleep the banner pauses at the last count for ~47 min.
- Connection-dot stays green the whole time (heartbeat is a separate path).
- `tail -f logs/app.log` shows the throttle decisions:
  ```
  WARNING  CSAM quota low: 47 of 300 calls left, window resets in 1820s
  WARNING  CSAM 429 — window 1/3: sleeping 1798s then retrying
  INFO     Fetched 85,000 CSAM assets total
  ```

**After completion:**
- A "Refresh #N complete (after: ... — Δ +12 / -2 / +418)" line shows the DB
  delta.
- `refresh_log.csam_status` is `success` or `partial` (latter if hops were
  exhausted but some pages landed).

## Related files

| File | Role |
|---|---|
| `src/api_client.py::_csam_apply_server_throttle` | Three-tier throttle |
| `src/api_client.py::_csam_request` | 429 window-hop loop |
| `src/api_client.py::fetch_csam_assets` | Page loop + on_page callback |
| `src/api_client.py::count_csam_assets` | Preflight count endpoint |
| `src/data_manager.py::_fetch_csam_with_checkpoint` | Resume + per-page persistence |
| `src/database.py` (`csam_checkpoint`) | Resume cursor + snapshot timestamp |
| `tests/test_csam_resume.py` | Resume-path invariants |
| `tests/test_parallel_refresh.py::ThrottleTiersTest` | Three-tier throttle invariants |
