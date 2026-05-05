# CSAM Pagination — Cursor Contract

How `fetch_csam_assets` paginates through the CSAM Asset Host Data API,
how the loop knows when to stop, and how it handles edge cases.

## The Qualys CSAM cursor contract

Endpoint: `POST /rest/2.0/search/am/asset` (CSAM v2 search).

Every successful response includes:

| Field | Type | Meaning |
|---|---|---|
| `count` | int | Number of assets in *this* response |
| `lastSeenAssetId` | str / int / null | Cursor: the assetId to use as `startFromId` on the next call |
| `hasMoreRecords` | int (1 or 0) | `1` = more pages exist, `0` = pull complete |
| `data.asset[]` | array | The asset payloads |

**Only one termination signal is correct:** `hasMoreRecords == 0`. The
loop must NOT stop on page count, asset count, empty `asset[]`, or any
other heuristic. Each of those can legitimately appear with more pages
still to come.

## How the loop runs

```
Call 1   POST without startFromId
         → hasMoreRecords=1, lastSeenAssetId=X1

Call 2   POST with startFromId=X1
         → hasMoreRecords=1, lastSeenAssetId=X2

...

Call N   POST with startFromId=X(N-1)
         → hasMoreRecords=0       ← clean termination
```

Each successful page fires the `on_page` callback, which:
1. Saves the page's assets to `csam_assets` under the snapshot's
   `fetched_at` timestamp.
2. Updates `csam_checkpoint.last_asset_id` to the response's
   `lastSeenAssetId`.
3. Live-updates `refresh_log.csam_count` so the in-progress banner ticks.

A `kill -9` between any two pages leaves all three in a consistent state
because the order is: save rows → update checkpoint → update progress.
The next refresh reads the checkpoint and resumes from `last_asset_id`
under the same `snapshot_fetched_at`.

## Defensive exits (logged at WARNING)

The loop always terminates eventually, even if Qualys returns garbage.
These are the defensive exits, in priority order:

| Condition | Behaviour |
|---|---|
| `hasMoreRecords` field missing entirely | Treat as 0, log `WARNING: response missing hasMoreRecords field — treating as completion`, exit |
| `hasMoreRecords == 1` and `lastSeenAssetId` is null/empty | Log `WARNING: hasMore=1 but lastSeenAssetId is null — invalid cursor, aborting`, exit |
| `lastSeenAssetId` repeats from previous page | Log `WARNING: cursor stalled at lastSeenAssetId=X for two consecutive pages — aborting`, exit |
| `max_pages` safety cap hit (default 10 000) | Log `WARNING: CSAM pull stopped at safety cap N pages — pagination did not reach hasMore=0`, exit |

The safety cap is a runaway guard, not a normal limit. At default
10 000 pages × 300 assets per page that's ~3 M assets — far above
any plausible tenant. If a real fleet of that size needs to be pulled,
raise `max_pages` in the call site rather than relaxing the cap.

## Page size

Default is **300 assets per page** (`csam_page_size = 300` in
`config/.config`). Qualys's API documentation says the maximum is
1000, but on observed tenants any value above ~300 is silently clamped
to ~100. The clamping was the root of a 50 000-asset hard cap that bit
production until 2026-05-04: with `max_pages=500` × clamped 100/page,
every pull terminated at exactly 50 000 regardless of true fleet size.

300 is the value Qualys's own [QualysETL][1] reference implementation
uses and appears to be honoured without clamping. Bumping it higher
gives diminishing returns once Qualys's per-window asset throughput cap
(~40 000 assets per rate-limit window) kicks in — see
[`CSAM_RATE_LIMIT.md`](CSAM_RATE_LIMIT.md).

## Resume across runs

The `csam_checkpoint` table holds:

```sql
last_asset_id          TEXT       -- cursor passed as startFromId on resume
assets_pulled          INTEGER    -- running total for this snapshot
completed              INTEGER    -- 1 once hasMoreRecords=0 was observed
snapshot_fetched_at    TEXT       -- ISO timestamp shared by every page of this snapshot
lookback_days          INTEGER    -- so config drift between runs can be detected
```

On the next `refresh_all` invocation, `_fetch_csam_with_checkpoint` in
`src/data_manager.py`:
1. Reads the checkpoint.
2. If `completed=0` AND `lookback_days` matches current config:
   passes `last_asset_id` as `resume_from_id` to `fetch_csam_assets`,
   reuses `snapshot_fetched_at`. The new pages land under the same
   `MAX(fetched_at)` so the dashboard sees one coherent snapshot.
3. If `completed=1` OR `lookback_days` drifted: starts fresh under a
   new `snapshot_fetched_at`.

Combined with the per-page save inside `on_page`, this means every
page is durable and resumable — a refresh interrupted at page 1 200 of
2 500 picks up at exactly page 1 201 on the next attempt.

## Interaction with rate limits

The pagination loop sits ABOVE the rate-limit machinery in
`_csam_request`. When a 429 fires mid-pull:
1. The current `_csam_request` call sleeps `X-RateLimit-ToWait-Sec`
   (interruptible via the cancel event), then retries.
2. Up to `csam_max_window_hops` waits are absorbed inside one
   `_csam_request` call.
3. If the retries exhaust, `RateLimitError` propagates up; the page
   never returns to the pagination loop, the on_page callback for
   that page never fires, and the checkpoint stays at the previous
   `last_asset_id`. The next refresh resumes from there.

So a 429 storm doesn't cause data loss or duplicate pages. See
[`CSAM_RATE_LIMIT.md`](CSAM_RATE_LIMIT.md) for the throttle and
window-hopping details.

## Operator log lines

What you'll see in `logs/app.log` during a healthy CSAM pull:

```
INFO  Fetching CSAM assets... (expected: 250,000, page_size: 300)
INFO    CSAM assets: fetched 3,000 of 250,000 (page 10, lastSeenAssetId=9912345, hasMore=1)
INFO    CSAM assets: fetched 6,000 of 250,000 (page 20, lastSeenAssetId=9928711, hasMore=1)
...
INFO  CSAM pull complete: 250,000 assets across 834 pages (hasMore=0)
```

If the pull exits early:

```
WARNING  CSAM pull stopped early: 12,300 assets across 41 pages — exit reason: cursor stalled (no advance)
```

The exit-reason string maps to the table above. Anything other than
`hasMore=0` is worth investigating.

## Files

| File | Role |
|---|---|
| `src/api_client.py::fetch_csam_assets` | The pagination loop |
| `src/data_manager.py::_fetch_csam_with_checkpoint` | Wrapper that handles resume / checkpoint |
| `src/database.py` (`csam_checkpoint`) | Resume cursor + snapshot timestamp |
| `tests/test_csam_pagination.py` | Pinning tests for the cursor contract |
| `tests/test_csam_resume.py` | Pinning tests for resume across runs |

[1]: https://github.com/qualys/qualysetl
