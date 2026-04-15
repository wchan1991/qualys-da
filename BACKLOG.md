# Backlog / Change Log

Running log of material changes to the codebase. Newest entries at the top.
Each entry captures *what* changed and *why*, not a diff — use `git log` for that.

Format:
```
## YYYY-MM-DD — <short title>
**Area:** <file(s) / subsystem>
**Why:** <one-to-three sentences>
```

---

## Requests / Wishlist

Operator/engineer wishlist items not yet scheduled. Move into the dated change
log once landed.

- [ ] **Field-reduction for CSAM payload** — opt-in config to request only the
  fields `save_csam_assets` actually stores, dropping the raw-JSON
  `raw_data` column. Response size should drop 60-80% on big tenants.
  Deferred 2026-04-14 (held pending debug-mode design).
- [ ] **Multi-backend storage** — `qualysetl` on PyPI (Qualys-employee
  maintained, Apache 2.0) supports SQLite / Postgres / MySQL / Snowflake /
  RedShift / Azure SQL. Verdict: *do not adopt wholesale* — our resume
  checkpoint and throttle-header machinery is more mature than theirs.
  Worth stealing only the storage-backend routing layer if we ever outgrow
  SQLite.
- [ ] **Delta-pull mode for CSAM** — use the last successful snapshot's
  timestamp as `lastCheckedIn >=` to pull only changed assets between
  runs; merge rather than replace. Biggest single lever against the 40k
  per-window CSAM ceiling.
- [ ] **Priority-first asset pull** — pull assets with open critical/high
  detections first so the dashboard recovers its most-important view even
  when a quota window caps us mid-pull.
- [ ] **Per-tag / per-asset-group CSAM sharding** — split a >40k fleet
  across multiple cron windows (operator-configurable shard key).

---

## 2026-04-14 — Parallel refresh + partial-status tests
**Area:** `tests/test_parallel_refresh.py`
**Why:** Locks the invariants the new refresh pipeline depends on: CSAM failure must not cancel the VM threads (per-API failure isolation), row-level status classifies correctly into success / partial / failed, live-updating `csam_count` moves while `status='running'`, and the three-tier CSAM throttle (WARN<50 dedup'd per window, WARN+0.5s slow-down at <=10, hard-wait ToWait-Sec at <=2) behaves as designed.

## 2026-04-14 — Status Page per-API cells + in-progress banner
**Area:** `templates/base.html`, `templates/settings.html`, `static/app.js`, `static/style.css`, `app.py`
**Why:** Added a site-wide "refresh in progress" banner that polls `/api/refresh-status` every 3s and shows live per-API counts (`CSAM 32,418 / 104,000 · Hosts 1,204 / 12,500 · Detections …`). When the pull lands, the banner flashes the final per-API outcome for 10s then dismisses — so the operator never stares at a stale dashboard without knowing a new pull is running. The refresh-history table on Settings grows a per-API outcome column using check/warn/cross icons so a `partial` row points to exactly which Refresh-<X> button to click.

## 2026-04-14 — Fully parallel refresh with per-API failure isolation
**Area:** `src/data_manager.py::refresh_all`, `src/api_client.py::fetch_vm_hosts`, `::fetch_vm_detections`
**Why:** `refresh_all` now fans out to three parallel futures (CSAM, VM hosts, VM detections) with independent `try/except` around each `.result()` — a failure in one API no longer cancels the others. Each future returns a `{status, count, data, error}` tuple; the outer function aggregates into per-API `csam_status` / `vm_host_status` / `vm_detection_status` columns on `refresh_log` plus a row-level rollup (`success` / `partial` / `failed`). VM fetchers gained the same `on_page` callback contract as CSAM so the three APIs live-update `refresh_log.*_count` via `update_refresh_progress()` during the pull.

## 2026-04-14 — Three-tier CSAM quota pacing + low-quota warning
**Area:** `src/api_client.py::_csam_apply_server_throttle`
**Why:** The old throttle only reacted when `X-RateLimit-Remaining <= 2` — going from full-speed to full-stop with no warning. New behaviour is three-tier: at `<50` remaining emit a WARNING once per quota window (dedup'd via window-end minute) so operators see pressure coming; at `<=10` inject a 0.5s slow-down per request; at `<=2` hard-wait the server's `X-RateLimit-ToWait-Sec`. The new warning includes `X-RateLimit-Limit` for context (e.g. "47 of 300 left, window resets in 412s").

## 2026-04-14 — `refresh_log` per-API status columns + live-update helper
**Area:** `src/database.py`
**Why:** Added `csam_status`, `vm_host_status`, `vm_detection_status` columns to `refresh_log` (idempotent `ALTER TABLE` migration). New `update_refresh_progress()` helper issues targeted `UPDATE` for whichever counts are passed — called from per-page callbacks so the Status Page banner shows live progress instead of flipping from 0 to final at termination.

## 2026-04-14 — `BACKLOG.md` Requests / Wishlist section
**Area:** `BACKLOG.md`
**Why:** Added a dedicated `## Requests / Wishlist` block above the dated change log for items deferred or surfaced during this session's planning: field-reduction for CSAM payload (`raw_data` drop), multi-backend storage inspired by `qualysetl`, delta-pull mode, priority-first asset pull, per-tag sharding. Keeps the change log purely historical while giving future-you a place to find "what we talked about but haven't done yet" without combing git log.

## 2026-04-14 — CSAM resume correctness tests
**Area:** `tests/test_csam_resume.py`
**Why:** Locks in the invariants that the silent-data-loss fix depends on. Seven tests cover: migration adds the new column; clean pull writes every page under one `fetched_at`; mid-pull `RateLimitError` leaves partial rows + resumable checkpoint pointing at the same snapshot; resume extends that exact snapshot rather than allocating a new one; lookback-days drift forces a fresh start; filter-fallback nulls the checkpoint's `lookback_days` so a later resume doesn't re-apply the rejected filter. Regression lock against the old tail-only-snapshot behaviour.

## 2026-04-14 — Relaxed 120s clamp on 429 retry sleep
**Area:** `src/api_client.py::_csam_request`
**Why:** When Qualys returns 429 with `X-RateLimit-ToWait-Sec: 240` (common on large tenants), the old `min(120, ...)` clamp made us retry too early and eat the second 429. Now when the server itself tells us how long to wait we clamp at 900s (hard ceiling) but honour the reported value; the 120s clamp still applies to the default/no-header path.

## 2026-04-14 — CSAM filter-fallback clears checkpoint lookback
**Area:** `src/api_client.py::fetch_csam_assets`, `src/data_manager.py::_on_filter_fallback`
**Why:** When Qualys rejects the QQL `lastCheckedIn` filter and the client retries without it, a later resume would re-apply the rejected filter from the checkpoint and fail again. `fetch_csam_assets` now accepts an `on_filter_fallback` callback; `_on_filter_fallback` in `DataManager` writes `lookback_days=NULL` to the checkpoint immediately so subsequent resumes skip the bad filter.

## 2026-04-14 — CSAM lookback-days drift detection
**Area:** `src/data_manager.py::_fetch_csam_with_checkpoint`
**Why:** If an operator changes `csam_lookback_days` between a failed and resumed pull, the two halves of the fleet are fetched under different server-side filters and can't safely share one snapshot. The resume path now compares the checkpoint's stored `lookback_days` to the live config and, on mismatch, logs a warning, resets the checkpoint pointer, and allocates a fresh `snapshot_fetched_at` — trading a duplicated pull for correctness.

## 2026-04-14 — CSAM resume silent-data-loss fix
**Area:** `src/database.py`, `src/api_client.py`, `src/data_manager.py`
**Why:** The resume checkpoint added earlier today tracked page pointers but not persisted rows — a `kill -9` mid-pull meant the in-memory head of the fleet was lost, and a resumed run called `save_csam_assets` with only the tail under a fresh `fetched_at`. `MAX(fetched_at)` then pointed at that partial snapshot and the dashboard silently halved. Fix: added `snapshot_fetched_at` column to `csam_checkpoint`; widened `fetch_csam_assets`'s `on_page` callback to pass the page's assets; moved `save_csam_assets(page, snapshot_fetched_at)` inside the per-page callback; a resume reuses the stored `snapshot_fetched_at` rather than allocating a new one, so every row of the full pull lives under one timestamp. Clean completion nulls the column; exceptions leave it in place for the next run to pick up.

## 2026-04-14 — `cyber_six_pack_trend` Python bucketing pushed into SQL
**Area:** `src/analytics.py::cyber_six_pack_trend`
**Why:** The old path pulled every open detection row for every group across the wire and re-bucketed by `first_found` month in Python. At production scale each group can have 100k+ detections. Replaced with `GROUP BY substr(first_found,1,7)` plus an inline severity-aware `CASE` for SLA breaches — now ≤ `months_back` rows per group.

## 2026-04-14 — `_six_pack_metrics_for_ips` severity loop collapsed
**Area:** `src/analytics.py::_six_pack_metrics_for_ips`
**Why:** Was 6 queries per group (1 for weighted age + 5 for per-severity SLA breach counts). Collapsed into one aggregation with a `CASE WHEN severity = N AND first_found <= :cutoff_N` branch. Cuts Cyber 6-Pack query volume by ~83% per group.

## 2026-04-14 — Batch owner resolver (`_batch_resolve_owners`)
**Area:** `src/analytics.py`
**Why:** `_six_pack_by_owner` and the owner branch of `cyber_six_pack_trend` were calling `db.get_asset_owner(ip)` once per VM host — ~104k sequential queries at production scale. New helper fetches `asset_owners` rules + `host_tags` + `vm_hosts.os` once each and resolves every IP in memory, mirroring the original precedence (direct IP → range → tag → OS pattern). Single biggest hit on the 6-Pack page.

## 2026-04-14 — Cache invalidation wired into refresh pipeline
**Area:** `src/data_manager.py` (all four `refresh_*` methods)
**Why:** `AnalyticsEngine.invalidate_cache()` is now called after every successful refresh (all, csam, vm-hosts, vm-detections). Ensures the dashboard/fetched_at caches drop stale data the moment a pull lands, so weekly scheduled refreshes don't serve stale numbers.

## 2026-04-14 — `asset_coverage()` double-call deduped
**Area:** `src/analytics.py::kpi_badges`, `dashboard_summary`
**Why:** `dashboard_summary` called `asset_coverage()` at the top level *and* indirectly via `kpi_badges` — running the full set-union over CSAM ∪ VM IPs twice per render. `kpi_badges(coverage=...)` now accepts a pre-computed dict from the caller; `dashboard_summary` passes it through.

## 2026-04-14 — `sla_compliance()` collapsed from 10 queries to 1
**Area:** `src/analytics.py::sla_compliance`
**Why:** Was a 5-iteration loop with 2 queries per severity (open-count + breach-count). Replaced with a single `GROUP BY severity` plus a per-severity `CASE WHEN severity = N AND first_found <= :cutoff_N`. Per-severity SLA cutoffs are pre-computed in Python and bound as params.

## 2026-04-14 — Generation-based cache + `_fetched_at` memoization
**Area:** `src/analytics.py` (`__init__`, `invalidate_cache`, `_fetched_at`, `dashboard_summary`)
**Why:** `dashboard_summary()` is now memoised until the next refresh; warm hits are O(1) instead of ~27 queries. `_fetched_at(table)` wraps `db.get_latest_fetched_at()` so the 30+ internal call sites collapse to one query per table per generation. The 39 `self.db.get_latest_fetched_at(...)` call sites inside analytics were rewritten to use the memoised helper.

## 2026-04-14 — "Cache lifecycle" section added to formulas doc
**Area:** `docs/FORMULAS.md`
**Why:** `invalidate_cache()` is a legitimately public method on `AnalyticsEngine` (called by `DataManager` across the package boundary). The formulas-doc drift test (`tests/test_formulas_doc.py`) flagged it the moment it was introduced — exactly its job. Added a short "Cache lifecycle" entry so the test stays green without hiding the method behind an underscore.

## 2026-04-14 — `_fetch_csam_with_checkpoint` wrapper
**Area:** `src/data_manager.py`
**Why:** Wraps `client.fetch_csam_assets()` with a DB-backed resume checkpoint. On entry, reads the checkpoint and passes `last_asset_id` as `resume_from_id` if the previous pull was interrupted. A per-page `on_page` callback persists progress after every page so a `kill -9` mid-pull still leaves resumable state. On clean exit, marks the checkpoint `completed=True` so the next refresh starts fresh.

## 2026-04-14 — CSAM resume checkpoint table + lookback filter
**Area:** `src/database.py`, `src/api_client.py`, `src/config_loader.py`, `config/.config.example`
**Why:** Addresses two related production-scale pain points for CSAM pulls. (1) `csam_checkpoint` single-row table persists `last_asset_id` / `assets_pulled` / `completed` so a rate-limited or crashed pull resumes where it left off. (2) `fetch_csam_assets()` gained `lookback_days` → adds a server-side QQL `lastCheckedIn >= <cutoff>` filter (default 90 days) to cut API volume dramatically on big tenants. Both are togglable via `[api]` config (`csam_resume_enabled`, `csam_lookback_days`).
