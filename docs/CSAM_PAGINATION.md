# CSAM Pagination — Cursor Contract + Cross-Query Continuation

How CSAM pulls work end-to-end: the inner cursor-driven page loop, the
outer cross-query continuation loop that breaks past Qualys's silent
~50,000-asset per-query cap, and how everything stays crash-safe.

## Two layers of pagination

CSAM has TWO loops working together:

```
┌─ Outer continuation loop  (DataManager._fetch_csam_with_checkpoint) ─┐
│                                                                       │
│   ┌─ Inner page loop  (QualysClient.fetch_csam_assets) ───────────┐  │
│   │   one query: paginate via lastSeenAssetId until hasMore=0     │  │
│   └────────────────────────────────────────────────────────────────┘  │
│                                                                       │
│   if total_fetched < expected - tolerance: launch another query      │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```

The **inner loop** does what the Qualys API contract documents: paginate
within one query until the server says `hasMoreRecords=0`.

The **outer loop** handles a tenant-side surprise: Qualys silently caps
a single query at ~50,000 assets even when the tenant has more. The
inner loop sees `hasMore=0` after exactly 50k and exits cleanly. Without
the outer loop, every pull on a 250k-asset tenant returns 50k and quits
"successfully." The outer loop notices the shortfall and launches
another inner-loop run starting from where the previous one stopped.

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

## Outer continuation loop (cross-query)

When the inner loop exits cleanly with `hasMoreRecords=0`, the wrapper
in `data_manager.py::_fetch_csam_with_checkpoint` runs this decision:

```
total_fetched   = checkpoint.assets_pulled  (cross-query running count)
expected_count  = preflight count_csam_assets()
tolerance       = max(100, int(expected_count * 0.01))     # 1% or 100, whichever is greater

if expected_count is None:
    # No reference value — trust hasMore=0 as the only signal we have.
    stop

elif total_fetched >= expected_count - tolerance:
    # Hit the target (or close enough). Done.
    stop

elif total_fetched <= count_at_start_of_this_iteration:
    # No new assets came back from the inner loop — server stalled.
    # Bail to avoid an infinite loop. WARNING.
    stop

elif last_seen_asset_id is None:
    # Inner loop returned hasMore=0 with null cursor. We have nothing
    # to continue with. WARNING.
    stop

else:
    # Launch another inner-loop run starting from the last cursor.
    query_iteration += 1
    fetch_csam_assets(resume_from_id=last_seen_asset_id, ...)
```

The cursor from query N's last page becomes the `startFromId` for
query N+1's first page. To Qualys it looks like a fresh "start
paginating from this asset ID" request, but our local state knows we
are continuing the same logical pull and writes new pages under the
same `snapshot_fetched_at`.

### Tolerance

`max(100, 1% of expected_count)` — covers natural fleet churn between
the count-endpoint preflight and the pull's last page. On a 250k-asset
tenant the tolerance is 2,500. On a 50k tenant it's 500. Anything
short of `expected - tolerance` triggers continuation.

### Stall guard

If the previous inner loop returned ZERO new assets, continuation
stops. This catches:

- Filter mismatch between the count endpoint and the search endpoint
  (count includes assets the filter excludes)
- Cursor stuck at end-of-list while the server still reports more
  matching assets (genuinely a tenant bug)
- A stuck pagination cursor we couldn't detect via within-loop signals

The wrapper logs a WARNING with the iteration count and `total_fetched
/ expected_count` so the operator sees what happened.

### Resume mid-continuation

`csam_checkpoint` carries `expected_count` and `query_iteration`
columns. A crash between continuation iterations leaves them in the
checkpoint; the next refresh:

1. Reads `expected_count` from the checkpoint instead of re-running
   `count_csam_assets()` (saves one API call on resume).
2. Reads `query_iteration` so the log line says "continuation: query
   #3 starting" — operationally honest about what part of the pull
   is in flight.
3. Resumes the inner loop from the saved `last_asset_id` and continues
   the outer loop from there.

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

A healthy multi-query pull on a big tenant:

```
INFO   CSAM preflight: expected_count = 250,000 (lookback: 90d)
INFO   CSAM cold start: blank database, no checkpoint
INFO   Fetching CSAM assets... (expected: 250,000, page_size: 300)
INFO     CSAM page 1: 300 assets, hasMore=1, lastSeenAssetId=9912345 (820ms)
INFO     CSAM page 2: 300 assets, hasMore=1, lastSeenAssetId=9912645 (410ms)
...
INFO   CSAM inner loop complete: hasMore=0, fetched 50,000 assets in this query (cumulative 50,000)
INFO   CSAM continuation: query #2 starting (50,000 of 250,000 fetched, continuing from lastSeenAssetId=10212345)
INFO   Fetching CSAM assets... (page_size: 300, resume_from_id: 10212345)
...
INFO   CSAM inner loop complete: hasMore=0, fetched 50,000 assets in this query (cumulative 100,000)
INFO   CSAM continuation: query #3 starting (100,000 of 250,000 fetched, continuing from lastSeenAssetId=10712345)
...
INFO   CSAM inner loop complete: hasMore=0, fetched 50,000 assets in this query (cumulative 250,000)
INFO   CSAM pull complete: 250,000 assets across 5 queries (expected: 250,000, drift: +0 = 0.0%)
```

If a continuation iteration produces no new assets:

```
WARNING  CSAM continuation made no progress on iteration 4. Stopping at 150,000 / 250,000 expected.
```

If the inner loop's defensive exit fires (cursor stall within a single
query, missing `hasMoreRecords` field, etc.):

```
WARNING  CSAM page 3: cursor stalled at lastSeenAssetId=12345 for two consecutive pages — aborting
WARNING  CSAM pull stopped early: 600 assets across 2 pages — exit reason: cursor stalled (no advance)
```

If the pull falls short of expected even after exhausting continuation:

```
WARNING  CSAM pull stopped early: 180,000 / 250,000 assets fetched (28.0% short) across 4 continuation queries. Diagnostic hints: check `csam_lookback_days`, filter QQL fallback, or enable DEBUG logging to see per-call request/response.
```

Any WARNING is worth investigating. The DEBUG-level per-page logs
(see "Per-page logging" below) will show exactly what each Qualys
response looked like.

## Per-page logging

Every page emits one INFO line (visible at default log level) and
one DEBUG line (full diagnostic detail). Set `[logging] level = DEBUG`
in `config/.config` to surface the latter. The DEBUG line includes
the request body's `startFromId` and `limitResults`, the HTTP status,
Qualys's payload-level `responseCode`, the asset count in this page
(catches silent page-size clamping like "asked 300, got 100"), the
raw `hasMoreRecords` value, the cursor, response time in ms, and the
top-level keys present in the response (catches tenant-version payload-
shape differences).

## Files

| File | Role |
|---|---|
| `src/api_client.py::fetch_csam_assets` | Inner loop: cursor-driven pagination within one query |
| `src/data_manager.py::_fetch_csam_with_checkpoint` | Outer loop: cross-query continuation, checkpoint persistence, drift logging |
| `src/database.py` (`csam_checkpoint`) | Resume cursor + snapshot timestamp + `expected_count` + `query_iteration` |
| `tests/test_csam_pagination.py` | Pinning tests for the inner cursor contract + defensive exits |
| `tests/test_csam_continuation.py` | Pinning tests for the outer continuation loop, stall guard, resume mid-continuation |
| `tests/test_csam_resume.py` | Pinning tests for resume across runs (older) |

[1]: https://github.com/qualys/qualysetl
