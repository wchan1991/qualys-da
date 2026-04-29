# Scaling Qualys DA to 1M Devices / 10M Detections

Technical analysis of performance bottlenecks, memory profiles, and
actionable recommendations for the engineering team.

**Audience:** Backend engineers, DevOps, project lead
**Baseline:** ~104k CSAM assets, ~50k VM hosts, ~800k VM detections (current production)
**Target:** 1,000,000 devices (CSAM + VM hosts), 10,000,000 detections

---

## 1. Current Architecture

```
  Qualys EU1 APIs
  (VM XML / CSAM JSON)
         |
         v
  +------------------+     ThreadPoolExecutor(3)
  |  api_client.py   |-----> fetch_vm_hosts / fetch_vm_detections / fetch_csam
  +------------------+       each paginates fully into Python list
         |
         v
  +------------------+     executemany() in 1000-row batches
  |   database.py    |-----> SQLite WAL, 64 MB cache, 30 indexes
  +------------------+
         |
         v
  +------------------+     generation-based cache
  |  analytics.py    |-----> set operations in Python, SQL aggregates
  +------------------+
         |
         v
  +----------------------------+
  |  Flask (threaded, dev srv) |
  +----------------------------+
```

Data flow per refresh cycle:

```
 API pages (1000 rows/page)
       |
       v
 all_hosts[] / all_detections[]          <-- full dataset in RAM
       |
       v
 save_vm_hosts()  batched INSERT OR REPLACE (1000 rows)
       |
       v
 get_previous_detections()               <-- full snapshot loaded again
       |
       v
 detect_changes()  dict diff in Python
       |
       v
 rollups + cache invalidation
```

---

## 2. Memory Profile at Scale

### Back-of-envelope estimates

Each row size is based on measured averages from the current dataset.

| Data structure                   | Current (800k det)  | Target (10M det)     |
|----------------------------------|---------------------|----------------------|
| `all_hosts[]` in RAM             | ~50k * 1.5 KB = 75 MB | 1M * 1.5 KB = 1.5 GB |
| `all_detections[]` in RAM        | 800k * 2 KB = 1.6 GB | 10M * 2 KB = 20 GB   |
| `old_detections` dict            | 800k * 180 B = 144 MB | 10M * 180 B = 1.8 GB |
| `csam_ips` + `vm_ips` sets      | 104k * 60 B = 6 MB   | 1M * 60 B = 60 MB    |
| SQLite DB file (WAL)             | ~500 MB              | ~8-12 GB             |
| **Peak process RSS (estimated)** | **~2.5 GB**          | **~25+ GB**          |

```
Memory high-water mark during refresh (10M target):

  0 GB  |
  5 GB  |####                         api pages accumulating
 10 GB  |########                     all_detections[] full
 15 GB  |############                 + old_detections dict loaded
 20 GB  |################             + detect_changes() temp dicts
 25 GB  |####################         peak (before GC of old_detections)
        +----------------------------------------------------> time
        t0      t1        t2          t3          t4
        fetch   fetch     load prev   diff        save+GC
        starts  complete  detections  changes     release
```

The 25 GB peak makes 10M detections infeasible on typical 16 GB servers.

---

## 3. Bottleneck Analysis

### B1. Full-dataset accumulation in api_client.py

**Location:** `src/api_client.py` line 639 (`all_hosts = []`) and line 752
(`all_detections = []`), with `.extend()` at lines 658 and 771.

Every page is appended to a single Python list. At 10M detections (2 KB
each), this list alone consumes ~20 GB. The list is held until
`save_vm_detections()` completes, and then `old_detections` is loaded
on top of it (line 313 of `data_manager.py`), pushing peak RSS past
the 25 GB mark.

**Severity:** Critical -- single largest barrier to 1M/10M scale.

### B2. get_previous_detections loads full snapshot

**Location:** `src/database.py` line 1012 (`get_previous_detections`).

Returns a dict keyed by `"{host_id}:{qid}"` for every detection in the
latest snapshot. At 10M detections this dict alone is ~1.8 GB. It is
loaded while `all_detections[]` is still live (data_manager.py line 313),
creating an overlap window of ~22 GB.

**Severity:** High -- compounds B1 and prevents streaming.

### B3. SQLite single-writer bottleneck

**Location:** `src/database.py` lines 48-51 (WAL + PRAGMA setup), batch
inserts at lines 484, 518, 552.

SQLite WAL allows concurrent readers but only one writer. The 10M-row
INSERT OR REPLACE will hold the write lock for minutes. During that
window the Flask dashboard stalls on any write (rollups, change log).
At 10M rows with 27 columns, the insert phase alone takes an estimated
12-18 minutes on SSD.

**Severity:** High -- acceptable today, blocking at 10M.

### B4. Views use correlated MAX(fetched_at) subqueries

**Location:** `src/database.py` lines 402-465 (v_detections, v_hosts,
v_assets, v_changes).

Each view filters with `WHERE d.fetched_at = (SELECT MAX(fetched_at) ...)`.
SQLite re-evaluates these scalar subqueries per row in worst case.
At 10M detections the v_detections view scan takes 8-15 seconds.

**Severity:** Medium -- causes dashboard latency, not data loss.

### B5. Python set operations for asset_coverage

**Location:** `src/analytics.py` lines 185-209 (csam_ips set at 189,
vm_ips at 190, intersection/difference at 206-209).

Two full-table `SELECT DISTINCT ip_address` queries hydrate Python sets,
then set intersection/difference is computed in Python. This works fine
at 100k IPs but at 1M IPs the sets consume ~60 MB each and the query
returns 1M rows from SQLite into Python just to count overlaps.

**Severity:** Low-Medium -- easily pushed to SQL.

### B6. CSV export has a hardcoded 100k limit

**Location:** `src/data_manager.py` lines 663, 677, 690 (`limit=100000`).

At 1M hosts or 10M detections, exports silently truncate. Users
requesting a full export for compliance or SIEM integration get
incomplete data with no warning.

**Severity:** Medium -- data integrity issue for downstream consumers.

### B7. Single-process Flask dev server

**Location:** `app.py` line 37 (`app = Flask(__name__)`), no WSGI
configuration.

Flask's built-in server is single-threaded by default (threaded mode
added by Flask, but no worker pool). Under concurrent dashboard users
during a refresh cycle, requests queue behind the GIL and the long-running
SQLite writes.

**Severity:** Medium at current scale, High at 10M.

### B8. Rate limiter shared across parallel fetchers

**Location:** `src/api_client.py` lines 47-58 (RateLimiter dataclass),
`src/config_loader.py` line 36 (`calls_per_minute: int = 60`).

The three parallel fetchers (CSAM, VM hosts, VM detections) share a
single 60 calls/minute bucket. Each fetcher competes, reducing effective
throughput per stream to ~20 calls/min. At 1000 rows/page, fetching 10M
detections requires 10,000 pages -- over 8 hours at 20 calls/min.

**Severity:** High -- fetch time alone exceeds any reasonable refresh window.

---

## 4. Recommendations

### R1. Stream-and-save: eliminate full-dataset accumulation

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B1, B2 -- 20+ GB peak RAM from holding all rows in Python |
| **Approach**   | Adopt the CSAM checkpoint pattern (data_manager.py line 73) for VM fetchers. Each page is saved to SQLite immediately via a callback, then discarded. The `all_hosts[]` / `all_detections[]` lists are eliminated entirely. Change detection uses a DB-side temp table or bloom filter instead of loading old_detections into a dict. |
| **Impact**     | Peak RAM drops from ~25 GB to ~500 MB (page buffer + overhead). |
| **Effort**     | Medium (2-3 days). Refactor fetch_vm_hosts and fetch_vm_detections to accept an `on_page` save callback (the plumbing already exists for progress tracking). Refactor detect_changes to query the DB. |
| **Risk**       | Low. CSAM already uses this pattern successfully. |

### R2. DB-side change detection

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B2 -- old_detections dict consumes 1.8 GB at 10M |
| **Approach**   | Instead of loading all previous detections into Python (database.py line 1012), use a SQL approach: (1) save new detections under a new fetched_at, (2) run a SQL diff query joining old and new snapshots on (host_id, qid), (3) insert change records directly. This keeps all data in SQLite and never materialises the full dataset in Python. |
| **Impact**     | Eliminates 1.8 GB dict. Change detection runs in ~30s via indexed SQL vs ~90s in Python at 10M scale. |
| **Effort**     | Medium (1-2 days). Write a `detect_changes_sql()` method, add a composite index on (host_id, qid, fetched_at). |
| **Risk**       | Low. Can run both paths in parallel during validation. |

### R3. Migrate to PostgreSQL for write concurrency

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B3 -- SQLite single-writer blocks dashboard during refresh |
| **Approach**   | Replace SQLite with PostgreSQL. Use COPY for bulk inserts (10-50x faster than executemany). Connection pooling via psycopg2 pool or SQLAlchemy. Keep SQLite as a fallback for single-user / dev deployments behind a database adapter interface. |
| **Impact**     | Concurrent reads during writes. COPY inserts 10M rows in ~2-4 minutes vs 12-18 minutes. Enables future horizontal scaling. |
| **Effort**     | High (5-8 days). Abstract database.py behind an interface, implement PostgreSQL adapter, migration tooling. |
| **Risk**       | Medium. Increases deployment complexity. Mitigate with Docker Compose config and a migration script. |

### R4. Materialised latest-snapshot tracking

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B4 -- correlated MAX(fetched_at) subqueries in views |
| **Approach**   | Maintain a `snapshot_metadata` table with one row per table tracking the latest fetched_at. Update it atomically at the end of each save. Replace `(SELECT MAX(fetched_at) FROM vm_detections)` in views with a join to snapshot_metadata. Alternatively, on PostgreSQL, use materialized views with REFRESH CONCURRENTLY. |
| **Impact**     | View queries drop from 8-15s to <1s at 10M rows. Dashboard loads in <2s. |
| **Effort**     | Low (0.5 day). Add table, update save methods, rewrite 4 views. |
| **Risk**       | Very low. Additive change, no data migration needed. |

### R5. Push coverage calculation to SQL

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B5 -- Python set ops on 1M IPs |
| **Approach**   | Replace the two DISTINCT queries + Python set logic (analytics.py lines 189-209) with a single SQL query using LEFT JOIN or UNION ALL with GROUP BY to compute overlap counts directly in the database engine. |
| **Impact**     | Eliminates 120 MB of Python sets. Query time drops from ~5s to <0.5s at 1M IPs. |
| **Effort**     | Low (0.5 day). Single SQL rewrite. |
| **Risk**       | Very low. |

### R6. Streaming CSV export

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B6 -- 100k row cap silently truncates exports |
| **Approach**   | Replace the `limit=100000` cap (data_manager.py lines 663/677/690) with a generator-based streaming response. Use Flask's `Response(stream_with_context(generate()))` to yield CSV rows in chunks of 5000. Add a `Content-Disposition` header with row count estimate. For very large exports (>1M rows), offer async export with a download link. |
| **Impact**     | Full exports at any scale without OOM. Users get complete data for compliance. |
| **Effort**     | Low (1 day). |
| **Risk**       | Low. Long downloads may timeout behind a reverse proxy -- add chunked transfer encoding. |

### R7. Per-stream rate limiters

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B8 -- shared bucket throttles parallel fetchers |
| **Approach**   | Create separate RateLimiter instances per API stream (CSAM, VM hosts, VM detections). Qualys EU1 rate limits are per-API-endpoint, not global. Configure per-stream limits in config_loader.py. Default: CSAM 30/min, VM hosts 30/min, VM detections 60/min (detections are the largest dataset). |
| **Impact**     | Fetch time for 10M detections drops from ~8 hours to ~2.8 hours. Combined with streaming (R1), total refresh time drops to ~3 hours. |
| **Effort**     | Low (0.5 day). |
| **Risk**       | Low. Verify actual per-endpoint limits with Qualys support. Start conservative, tune up. |

### R8. Production WSGI deployment

| Attribute      | Detail |
|----------------|--------|
| **Problem**    | B7 -- Flask dev server cannot handle concurrent users |
| **Approach**   | Deploy behind gunicorn (Linux) or waitress (Windows) with 4 sync workers. Add nginx as reverse proxy for static assets, gzip, and connection buffering. For PostgreSQL deployments, use gunicorn gevent workers for higher concurrency. |
| **Impact**     | Handles 50+ concurrent dashboard users without queueing. |
| **Effort**     | Low (0.5 day for gunicorn, 1 day with nginx). |
| **Risk**       | Very low. Standard production pattern. |

---

## 5. Impact / Effort Matrix

Priority is read top-left (high impact, low effort) to bottom-right.

```
                          EFFORT
              Low (< 1 day)         Medium (2-5 days)        High (5+ days)
         +---------------------+---------------------+---------------------+
         |                     |                      |                     |
  High   |  R4  Snapshot meta  |  R1  Stream-and-save |  R3  PostgreSQL     |
         |  R7  Per-stream     |  R2  DB-side diff    |                     |
         |      rate limiters  |                      |                     |
 IMPACT  +---------------------+---------------------+---------------------+
         |                     |                      |                     |
  Medium |  R5  SQL coverage   |  R6  Streaming CSV   |                     |
         |  R8  WSGI deploy    |                      |                     |
         |                     |                      |                     |
         +---------------------+---------------------+---------------------+
         |                     |                      |                     |
  Low    |                     |                      |                     |
         |                     |                      |                     |
         +---------------------+---------------------+---------------------+
```

**Recommended execution order:**

1. R4 + R7 + R8 (quick wins, 1.5 days total)
2. R1 + R2 (unlocks 10M scale, 3-5 days)
3. R5 + R6 (polish, 1.5 days)
4. R3 (strategic, when concurrent write pressure justifies it)

---

## 6. Storage Projections

| Metric                           | Current         | 1M / 10M target   |
|----------------------------------|----------------|--------------------|
| vm_detections rows per snapshot  | 800,000        | 10,000,000         |
| Row size (avg, with indexes)     | ~450 bytes     | ~450 bytes         |
| Single snapshot disk footprint   | ~360 MB        | ~4.5 GB            |
| 30-day retention (daily snaps)   | ~10.8 GB       | ~135 GB            |
| Weekly rollups (52 weeks)        | ~200 KB        | ~200 KB (aggregates)|
| WAL file peak during write       | ~100 MB        | ~2-3 GB            |
| **Total DB size (steady state)** | **~12 GB**     | **~150 GB**        |

At 150 GB, SQLite remains technically viable (tested to TB scale) but
PostgreSQL becomes strongly preferable for vacuuming, partitioning by
fetched_at, and tablespace management.

**Retention strategy at scale:** Partition detections by fetched_at month.
Drop entire partitions instead of DELETE + VACUUM. PostgreSQL declarative
partitioning handles this natively. For SQLite, use attached databases
per month.

---

## 7. Timing Estimates

Estimated wall-clock time for a full refresh cycle:

| Phase                    | Current (800k) | Target (10M), no changes | Target (10M), with R1-R8 |
|--------------------------|----------------|--------------------------|--------------------------|
| API fetch (all streams)  | ~25 min        | ~8 hours (shared limiter)| ~2.5 hours (R7)          |
| Parse XML/JSON           | ~3 min         | ~40 min                  | ~40 min (streaming)      |
| DB insert                | ~2 min         | ~18 min (SQLite)         | ~4 min (R3, COPY)        |
| Change detection         | ~15 sec        | ~10 min (Python dict)    | ~30 sec (R2, SQL)        |
| Rollup computation       | ~5 sec         | ~2 min                   | ~30 sec (R4)             |
| **Total refresh**        | **~30 min**    | **~9+ hours**            | **~3.5 hours**           |

The 3.5-hour target fits within a nightly maintenance window (e.g., 01:00-05:00).
For tighter windows, consider incremental/delta fetching (Qualys APIs support
`vm_processed_after` filters to pull only changes since last refresh).

---

## 8. Incremental Refresh Strategy (Future)

The current architecture does full-snapshot pulls every cycle. At 10M
detections this is wasteful when only ~2-5% of detections change daily.

```
Full refresh:       10,000,000 rows fetched every cycle
Incremental:           200,000 rows fetched (delta since last refresh)
                    ^^^^^^^^^^^^
                    50x reduction in API calls, bandwidth, and insert volume
```

**Approach:** Use the Qualys `vm_processed_after` parameter in the
detection API call to fetch only hosts whose detections changed since
the last successful refresh. CSAM already supports `lastCheckedIn`
filtering (config_loader.py line 42, `csam_lookback_days`). Extend this
pattern to VM APIs.

**Prerequisites:** R1 (streaming) and R2 (DB-side diff) should land
first, as incremental refresh still needs change detection but on a
much smaller working set.

---

## 9. Industry Comparison

Platforms managing similar data volumes at enterprise scale:

| Platform       | Storage engine    | Fetch strategy           | Scale claim        |
|----------------|-------------------|--------------------------|--------------------|
| Tenable.io     | PostgreSQL + S3   | Incremental export API   | 1M+ assets         |
| Rapid7 InsightVM | PostgreSQL      | Delta sync via API       | 500k+ assets       |
| Qualys VMDR    | Proprietary       | Streaming JSON (v2 APIs) | Multi-million      |
| Qualys DA (us) | SQLite            | Full-snapshot pagination | ~100k (current)    |

Key patterns from these platforms:

- **Delta/incremental sync** is universal at >100k assets. Full snapshots
  are used only for initial load or periodic reconciliation.
- **PostgreSQL** (or equivalent RDBMS) is the standard at >500k assets.
  No production platform at this scale uses SQLite as the primary store.
- **Streaming inserts** -- rows are written as they arrive, never buffered
  in application memory. This is exactly what R1 proposes.
- **Partitioned storage** by time dimension (fetched_at, scan_date) for
  efficient retention management.

---

## 10. Load Testing Plan

### 10.1 Synthetic Data Generation

Create a `tests/generate_load_data.py` script:

```
1. Generate 1M host dicts with realistic IP/DNS/OS distributions
2. Generate 10M detection dicts across those hosts (avg 10 detections/host)
3. Generate 1M CSAM asset dicts with overlapping IPs (80% overlap rate)
4. Write to JSON files for repeatable testing
```

Expected generation time: ~5 minutes. Disk: ~15 GB JSON.

### 10.2 Test Scenarios

| # | Scenario                        | Metric                          | Target          |
|---|----------------------------------|---------------------------------|-----------------|
| 1 | Bulk insert 10M detections       | Wall time, peak RSS, WAL size   | < 5 min, < 2 GB |
| 2 | Change detection (5% delta)      | Wall time, peak RSS             | < 60 sec, < 500 MB |
| 3 | Dashboard render under load      | p95 latency, concurrent users   | < 2 sec, 20 users |
| 4 | CSV export 10M detections        | Wall time, memory, file size    | < 3 min, < 500 MB |
| 5 | Full refresh end-to-end          | Wall time (mock API)            | < 30 min        |
| 6 | Concurrent refresh + dashboard   | Dashboard p95 during refresh    | < 5 sec         |

### 10.3 Tooling

- **Memory profiling:** `tracemalloc` snapshots at key points (after fetch,
  after save, after diff). Log peak via `tracemalloc.get_traced_memory()`.
- **Timing:** `time.perf_counter()` around each phase, logged to
  `refresh_log` table.
- **Concurrency:** `locust` or `wrk` for HTTP load against the Flask app
  during a simulated refresh.
- **Database:** `sqlite3_analyzer` (from SQLite source tree) to measure
  index overhead and page utilisation. For PostgreSQL: `pg_stat_statements`
  and `EXPLAIN (ANALYZE, BUFFERS)`.

### 10.4 Execution Approach

```
Phase 1 - Baseline (current code, synthetic 10M data)
  - Run scenarios 1-6 and record metrics
  - Identify which bottlenecks hit first (expect OOM on scenario 1)

Phase 2 - After R1+R2 (streaming + DB-side diff)
  - Re-run scenarios 1-6
  - Validate peak RSS < 2 GB target

Phase 3 - After R3 (PostgreSQL)
  - Re-run scenarios 1-6
  - Compare SQLite vs PostgreSQL on each metric

Phase 4 - After R7 (per-stream rate limiters, real API)
  - Run scenario 5 against Qualys staging/sandbox
  - Measure actual API throughput per stream
```

---

## 11. Monitoring and Alerting (Operational Readiness)

Before scaling to 1M/10M, instrument the following:

| Metric                        | Source                          | Alert threshold     |
|-------------------------------|---------------------------------|---------------------|
| Process RSS (MB)              | `psutil.Process().memory_info()`| > 4 GB              |
| Refresh duration (minutes)    | refresh_log table               | > 60 min            |
| SQLite WAL file size          | `os.path.getsize(db + '-wal')`  | > 1 GB              |
| API error rate per stream     | api_client.py retry counter     | > 5% of pages       |
| Dashboard p95 latency         | Flask middleware timer           | > 3 sec             |
| DB file size                  | `os.path.getsize(db_path)`      | > 100 GB            |
| Change detection row count    | detection_changes table          | > 500k in one cycle |

---

## 12. Risk Register

| Risk                                    | Likelihood | Impact | Mitigation                          |
|-----------------------------------------|------------|--------|-------------------------------------|
| Qualys rate limit tighter than expected | Medium     | High   | Start conservative, measure actual limits, implement exponential backoff |
| SQLite corruption under heavy WAL       | Low        | High   | Enable `PRAGMA integrity_check` weekly, maintain backup schedule |
| PostgreSQL migration breaks rollback    | Medium     | Medium | Keep SQLite adapter, feature-flag the backend |
| Incremental sync misses edge cases      | Medium     | Medium | Weekly full reconciliation run alongside daily deltas |
| Memory spike during concurrent refresh  | High       | High   | R1 (streaming) is prerequisite before scaling past 500k |

---

## 13. Summary

The current architecture works well up to ~200k devices / ~2M detections.
Beyond that, three changes are essential:

1. **Stream data to disk as it arrives** (R1) -- eliminates the 20+ GB
   memory spike that makes 10M detections impossible on commodity hardware.

2. **Move change detection to SQL** (R2) -- eliminates the second-largest
   memory consumer and runs faster than the Python dict approach.

3. **Track latest snapshot explicitly** (R4) -- eliminates the correlated
   subqueries that make dashboard loads unacceptable at scale.

Everything else (PostgreSQL, per-stream rate limiters, WSGI server,
streaming CSV) is important but secondary. R1 + R2 + R4 together cost
roughly 4-6 days of engineering effort and unlock the path to 10M
detections on a server with 4-8 GB of RAM.

---

*Document generated 2026-04-15. Based on codebase at commit e49dfff.*
