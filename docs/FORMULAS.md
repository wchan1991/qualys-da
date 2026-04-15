# Dashboard Formulas Reference

**Last audited:** 2026-04-14 (matches `src/analytics.py` at this commit)

Every number you see on the dashboard, 6-Pack, KPIs, Tags, Trends, and Ownership pages is computed by one of the methods on `AnalyticsEngine` in `src/analytics.py`. This document is the single source of truth for those formulas.

> **How this stays honest.** A unit test (`tests/test_formulas_doc.py::test_every_analytics_method_is_documented`) enumerates every public method on `AnalyticsEngine` and fails if any of them is not mentioned below. Whenever a new metric is added to `analytics.py`, this file MUST be updated or CI/QA will fail. See the [Recurring-check section](#recurring-check) at the end.

---

## Conventions used below

- **"Latest snapshot"** means `fetched_at = (SELECT MAX(fetched_at) FROM <table>)` — the most recent refresh, one of the SQLite indexes. Every metric reads only the latest snapshot unless it explicitly uses the rollup tables or the `detection_changes` log.
- **"Open"** detections are `status IN ('New', 'Active')` unless a formula explicitly includes `'Re-Opened'` (noted below).
- **"Non-disabled"** means `is_disabled = 0`. Disabled detections are excluded by default everywhere except `vuln_overview(include_disabled=True)`.
- **Severity bands:** 5 = Urgent/Critical, 4 = High, 3 = Medium, 2 = Low, 1 = Minimal.
- **CVSS bands (for CVE dashboard only):** Critical ≥ 9.0, High 7.0–8.9, Medium 4.0–6.9, Low > 0 and < 4.0.

---

## Overview & Dashboard

### `dashboard_summary()`
Composite payload for `/` (the main dashboard). Wraps the calls below — no independent math.
```
{
  vuln_overview,
  kpi_badges,
  asset_coverage,
  risk_distribution,
  last_refresh: <timestamp from refresh_log>,
}
```

### `vuln_overview(include_disabled=False)`
```sql
-- by severity
SELECT severity, COUNT(*) AS cnt
FROM vm_detections
WHERE fetched_at = :latest [AND is_disabled = 0]
GROUP BY severity;

-- by status
SELECT status, COUNT(*) AS cnt
FROM vm_detections
WHERE fetched_at = :latest [AND is_disabled = 0]
GROUP BY status;
```
- `total` = Σ `by_severity.values()`
- `critical_count` = severity-5 + severity-4
- `disabled_count` = separate `COUNT(*) WHERE is_disabled = 1`
- **Consumed by:** `/api/metrics/vuln-overview`, `/` (top cards)

### `kpi_badges()`
Thin composer used by the dashboard — no independent math:
```
patchable_pct        = patchable_percentage().patchable_pct
avg_mttr             = detection_age().mean_days_to_remediate
sla_compliance_pct   = _overall_sla_compliance()      # weighted across severities
scan_coverage_pct    = asset_coverage().scan_coverage_30d_pct
reopen_rate          = reopen_rate().rate_pct
```

### `risk_distribution()`
- **TruRisk histogram** (buckets of 100):
  ```sql
  SELECT CAST(trurisk_score / 100 AS INTEGER) * 100 AS bucket,
         COUNT(*) AS cnt
  FROM vm_hosts
  WHERE fetched_at = :latest AND trurisk_score > 0
  GROUP BY bucket ORDER BY bucket;
  ```
  Labels: `"0-99"`, `"100-199"`, ...
- **QDS histogram** (buckets of 20):
  ```sql
  SELECT CAST(qds / 20 AS INTEGER) * 20 AS bucket, COUNT(*) AS cnt
  FROM vm_detections
  WHERE fetched_at = :latest AND is_disabled = 0 AND qds > 0
  GROUP BY bucket ORDER BY bucket;
  ```
- **Top 10 riskiest hosts:** `ORDER BY trurisk_score DESC LIMIT 10` on latest `vm_hosts`.

### `asset_coverage()` / `scan_coverage()`
`scan_coverage()` is an alias for `asset_coverage()`.
- `csam_ips` = DISTINCT IPs in latest `csam_assets` (non-empty).
- `vm_ips`   = DISTINCT IPs in latest `vm_hosts` (non-empty).
- `both` = |csam_ips ∩ vm_ips|; `csam_only` = |csam − vm|; `vm_only` = |vm − csam|.
- `total_unique_ips` = |csam_ips ∪ vm_ips|.
- **`coverage_pct`** = `both / total_unique_ips * 100`.
- **`scanned_7d`** / **`scanned_30d`** = `COUNT(DISTINCT ip_address) FROM vm_hosts WHERE last_vm_scanned_date >= now - {7|30}d`.
- **`scan_coverage_{7,30}d_pct`** = `scanned_{7,30}d / total_unique_ips * 100`.

### `detection_age()`
- **MTTR (`mean_days_to_remediate`):**
  ```sql
  SELECT AVG(julianday(last_fixed) - julianday(first_found))
  FROM vm_detections
  WHERE fetched_at = :latest AND status = 'Fixed'
    AND last_fixed != '' AND first_found != '';
  ```
- **Aging buckets** (`aging_30d`, `aging_60d`, `aging_90d`) — for each threshold `d ∈ {30,60,90}`:
  ```sql
  SELECT COUNT(*) FROM vm_detections
  WHERE fetched_at = :latest AND status IN ('New','Active')
    AND is_disabled = 0 AND first_found <= :now - d days;
  ```
  (Open detections older than d days.)

### `os_distribution()`
```sql
SELECT h.os,
       COUNT(DISTINCT h.ip_address) AS host_count,
       COUNT(CASE WHEN d.status IN ('New','Active') AND d.is_disabled = 0 THEN 1 END) AS vuln_count
FROM vm_hosts h
LEFT JOIN vm_detections d ON h.host_id = d.host_id AND d.fetched_at = :latest_det
WHERE h.fetched_at = :latest_hosts AND h.os != ''
GROUP BY h.os
ORDER BY vuln_count DESC
LIMIT 20;
```
**`density`** = `vuln_count / max(host_count, 1)` (vulns per host for that OS).

### `app_distribution()`
1. From latest `csam_assets`: parse the `software` JSON column, build `app_name → set(ip_address)`.
2. From latest `vm_detections`: `SELECT ip_address, COUNT(*) WHERE status IN ('New','Active') AND is_disabled = 0 GROUP BY ip_address` → `ip_vulns` map.
3. Per app:
   - `host_count` = `len(ips)`
   - `vuln_count` = `Σ ip_vulns.get(ip, 0) for ip in ips`
   - **`density`** = `vuln_count / max(host_count, 1)`
4. Return top 30 by `vuln_count`.

### `top_qids(n=20)`
```sql
SELECT qid, severity,
       COUNT(*) AS count,
       COUNT(DISTINCT host_id) AS hosts_affected
FROM vm_detections
WHERE fetched_at = :latest AND status IN ('New','Active') AND is_disabled = 0
GROUP BY qid
ORDER BY count DESC
LIMIT :n;
```

---

## Operational KPIs

### `all_kpis(include_disabled=False)`
Composer — returns `{patchable, mttr_by_severity, sla_compliance, scan_coverage, detection_fix_rate, reopen_rate, detection_age, vuln_overview}`. Each child's formula is documented in its own section.

### `patchable_percentage()`
**"% of open vulns that are Confirmed (patchable) vs Potential"**
```sql
SELECT detection_type, COUNT(*) AS cnt
FROM vm_detections
WHERE fetched_at = :latest AND status IN ('New','Active') AND is_disabled = 0
GROUP BY detection_type;
```
- `confirmed` = `type_counts['Confirmed']`
- **`patchable_pct`** = `confirmed / total * 100`

### `patchable_by_severity()`
Breakdown for the Patchable dashboard.
```sql
SELECT severity,
       SUM(CASE WHEN patchable = 1 THEN 1 ELSE 0 END) AS patchable,
       SUM(CASE WHEN patchable = 0 THEN 1 ELSE 0 END) AS non_patchable
FROM vm_detections
WHERE fetched_at = :latest AND is_disabled = 0
  AND status IN ('New','Active','Re-Opened')
GROUP BY severity;
```
Per severity band: **`pct`** = `patchable / (patchable + non_patchable) * 100`.
`totals.patchable_pct` = `Σ patchable / (Σ patchable + Σ non_patchable) * 100`.

### `mttr_by_severity()`
```sql
SELECT severity,
       AVG(julianday(last_fixed) - julianday(first_found)) AS avg_days
FROM vm_detections
WHERE fetched_at = :latest AND status = 'Fixed'
  AND last_fixed != '' AND first_found != ''
GROUP BY severity;
```
Returns `{severity: avg_days_rounded_1dp}`.

### `sla_compliance()`
SLA thresholds come from the `sla_targets` table (user-editable), or fall back to config defaults (Sev5=7d, Sev4=30d, Sev3=90d, Sev2=180d, Sev1=365d).

For each severity `s`:
1. `open_count` = `COUNT(*) WHERE severity = s AND status IN ('New','Active') AND is_disabled = 0`
2. `breach_count` = same, plus `AND first_found <= now - sla_days(s)`
3. `compliant` = `open_count - breach_count`
4. **`compliance_pct(s)`** = `compliant / max(open_count, 1) * 100`

**`overall_pct`** = `Σ compliant / max(Σ open_count, 1) * 100` (weighted by open count — not a simple average of per-severity %).

### `scan_coverage()`
Alias — identical to `asset_coverage()` above.

### `detection_fix_rate(days=7)`
Reads the `detection_changes` log, not current state.
```sql
SELECT COUNT(*) FROM detection_changes
WHERE change_type = 'new'   AND detected_at >= now - :days;

SELECT COUNT(*) FROM detection_changes
WHERE change_type = 'fixed' AND detected_at >= now - :days;
```
- `net_change` = `new_count - fixed_count`
- **`fix_ratio`** = `fixed_count / max(new_count, 1) * 100`

### `reopen_rate()`
```sql
SELECT SUM(CASE WHEN status = 'Re-Opened' THEN 1 ELSE 0 END) AS reopened,
       SUM(CASE WHEN status IN ('Fixed','Re-Opened') THEN 1 ELSE 0 END) AS total
FROM vm_detections
WHERE fetched_at = :latest AND is_disabled = 0;
```
**`rate_pct`** = `reopened / max(total, 1) * 100`.

---

## CVE / CVSS Dashboard

### `cve_dashboard(months_back=12)`
Composite payload for `/cves`.

- **Summary** (single query, all banded on `cvss_base`):
  ```sql
  SELECT COUNT(DISTINCT ip_address) AS resources,
         SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) AS critical,
         SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) AS high,
         SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) AS medium,
         SUM(CASE WHEN cvss_base > 0   AND cvss_base < 4.0 THEN 1 ELSE 0 END) AS low,
         COUNT(DISTINCT cve_id) AS total_cves
  FROM vm_detections
  WHERE fetched_at = :latest AND is_disabled = 0
    AND status IN ('New','Active','Re-Opened');
  ```
- **`coverage_pct`** reconciles with the main dashboard:
  `resources_scanned / asset_coverage.total_unique_ips * 100`.
- **Trend:** 12-month series, each month is the CVSS-banded count of detections whose `first_found` falls in that month.
- **Top resources / patchable / top CVEs** are rank-ordered within the same `fetched_at`.

**Intentionally narrower than `vuln_overview.total`:** CVE dashboard counts OPEN detections only (excludes `Fixed`); `vuln_overview.total` counts all non-disabled rows.

### `cve_by_ownership(group_by='owner')`
Same CVSS banding as `cve_dashboard`, but grouped by `owner`, `business_unit`, `tag`, or `os`. IP-to-group resolution is shared with `cyber_six_pack_trend` so the two pages reconcile.

Enterprise totals are a single `GROUP BY NULL` query (NOT `Σ groups`) so overlapping groupings like `tag` don't double-count.

---

## Cyber 6-Pack

### `cyber_six_pack(group_by='owner'|'tag'|'os')`
For each group (owner / business_unit / tag / os):
- `weighted_avg_age` = Σ(age × vuln_count in that age bucket) / Σ vuln_count
- `sla_breaching` = count of open detections whose age exceeds their severity's SLA window
- `total_vulns` = open, non-disabled count scoped to the group's IPs
- `sla_compliance_pct(group)` = `(total_vulns - sla_breaching) / max(total_vulns, 1) * 100`

**Enterprise row** (sum-of-groups, weighted):
- `enterprise.weighted_avg_age` = `Σ(g.weighted_avg_age × g.total_vulns) / Σ g.total_vulns`
- `enterprise.sla_compliance_pct` = `(Σ total_vulns - Σ sla_breaching) / Σ total_vulns * 100`

### `cyber_six_pack_trend(group_by, months_back=12)`
Bucket each open detection by the month of its `first_found` date. For each of the top 8 groups and each month bucket:
- `avg_age[m]` = `mean(julianday('now') - julianday(first_found))` for detections in bucket `m`.
- `sla_breaches[m]` = count of bucket-`m` detections whose age exceeds their severity's SLA window.

Returned shape: `{months: ['YYYY-MM', ...], groups: [{name, avg_age:[...], sla_breaches:[...]}]}`.

**Directional, not exact:** this uses the *current* snapshot to simulate past cohorts, so a detection that was Fixed 3 months ago and is no longer in the current table won't appear.

### `waterfall_by_ownership(group_by, owner=None, months_back=12)`
Active-as-anchor waterfall. Per month `m`:
- `new[m]`      = count of `detection_changes` rows with `change_type = 'new'` in month m
- `fixed[m]`    = same, `change_type = 'fixed'`
- `reopened[m]` = same, `change_type = 'reopened'`
- **`net[m]` = `new[m] - fixed[m] + reopened[m]`** (signed monthly delta to Active)
- `running[m]` = `start_active + Σ net[0..m]`
- **`start_active`** is back-derived: `end_active - Σ net[all months]`. This guarantees `running[-1] == end_active`.
- **`end_active`** = current `COUNT(*) WHERE status IN ('New','Active','Re-Opened') AND is_disabled = 0`, scoped to the group's IPs when `owner` is set.
- `reconciled` = True iff `Σ net == end_active - start_active` (should always be True within the window).

---

## Tags & Ownership

### `tag_summary()`
Delegates to `database.get_tag_summary()`:
```sql
SELECT tag_name,
       COUNT(DISTINCT ip_address) AS host_count,
       <joined vuln counts from latest vm_detections>
FROM host_tags
WHERE fetched_at = :latest
GROUP BY tag_name
ORDER BY vuln_count DESC;
```

### `tag_detail(tag_name)`
1. `hosts` = `database.get_hosts_by_tag(tag_name, limit=500)` (latest `host_tags` join).
2. `vuln_summary` from:
   ```sql
   SELECT severity, status, COUNT(*) AS cnt
   FROM vm_detections
   WHERE fetched_at = :latest AND host_id IN (:host_ids)
     AND is_disabled = 0
   GROUP BY severity, status;
   ```
   Aggregated into `{total, by_severity: {sev: cnt}, by_status: {status: cnt}}`.

### `tag_comparison(tag_names)`
`tag_detail()` called per tag; returned as a list for side-by-side display.

### `monitored_tag_dashboard()`
`tag_comparison(config.monitored_tags)` — empty list if no monitored tags configured.

### `ownership_summary()`
For each owner rule with `match_type='ip'`:
```sql
SELECT COUNT(*) AS total_vulns,
       SUM(CASE WHEN severity >= 4 THEN 1 ELSE 0 END) AS critical,
       AVG(severity) AS avg_severity
FROM vm_detections
WHERE fetched_at = :latest AND ip_address IN (:owner_ips)
  AND status IN ('New','Active') AND is_disabled = 0;
```
Sorted by `total_vulns` descending.

### `os_by_ownership(group_by='owner')`
OS family is bucketed as `Windows | Linux | macOS | Other` (see `os_family()` helper — substring match on the raw OS string).

Per (group × OS-family) cell: `Σ open_detection_count` across IPs in that group matching that OS family.
Matrix shape: rows = groups, cols = OS families.

### `orphaned_assets()`
Hosts (CSAM ∪ VM) whose IP does not match any row in `asset_owners`. Each returned host carries its CSAM/VM source flags, OS, last scan, TruRisk, open vuln count, and tags. No math — pure set difference.

---

## Trends (Rollups)

### `weekly_trends(weeks_back=12)`
Direct read of the `weekly_rollups` table, newest N rows. The rollup columns themselves are written by `compute_weekly_rollup()` below.

### `monthly_trends(months_back=12)`
Direct read of `monthly_rollups`.

### `week_over_week()`
Reads last 2 `weekly_rollups`. For each tracked metric key (`total_vulns`, `sev5_count`, `sev4_count`, `status_new`, `status_active`, `status_fixed`, `avg_trurisk`, `total_hosts`):

  `delta[key] = current[key] - previous[key]`

Returns `{current, previous, deltas}`.

### `recent_changes(days_back=7)`
```sql
SELECT change_type, COUNT(*) AS cnt
FROM detection_changes
WHERE detected_at >= now - :days_back
GROUP BY change_type;
```
Flattened into `{new, fixed, reopened, severity_change}`.

### `compute_weekly_rollup()`
Aggregates the live tables into one `weekly_rollups` row keyed by Monday-of-this-week. Columns:

| Column              | Source                                                                         |
|---------------------|--------------------------------------------------------------------------------|
| `total_vulns`       | `vuln_overview().total`                                                        |
| `sev{1..5}_count`   | `vuln_overview().by_severity.get(s, 0)`                                        |
| `status_{new, active, fixed, reopened}` | `vuln_overview().by_status.get(s, 0)`                      |
| `new_this_week`     | `COUNT(*) FROM detection_changes WHERE change_type='new'   AND detected_at >= monday` |
| `fixed_this_week`   | same, `change_type='fixed'`                                                    |
| `avg_trurisk`       | `AVG(trurisk_score) FROM vm_hosts WHERE fetched_at = :latest_hosts`            |
| `max_trurisk`       | `MAX(trurisk_score)` same scope                                                |
| `avg_qds`           | `AVG(qds) FROM vm_detections WHERE is_disabled = 0 AND qds > 0`                |
| `total_hosts`, `csam_hosts`, `vm_hosts_count`, `both_hosts`, `coverage_pct` | from `asset_coverage()` |
| `aging_{30,60,90}d` | from `detection_age()`                                                         |
| `tag_metrics`       | JSON — one sub-object per monitored tag with `host_count`, `vuln_count`, `by_severity` |

### `compute_monthly_rollup()`
Takes the most recent weekly rollup, relabels `week_start → month_start` (first-of-month), renames `new_this_week → new_this_month` (same for `fixed`), and writes one `monthly_rollups` row. No re-aggregation from raw detections.

---

## Change detection & retention

### `detect_changes(old_detections, new_detections, detected_at)`
Pure Python diff driven by `key = f"{host_id}:{qid}"`:

- `key ∉ old` → record `change_type='new'` with `new_value = status`
- `key ∈ old` and `old.status = 'Fixed'` and new status in `(Active, New, Re-Opened)` → `'reopened'`
- `key ∈ old` and `old.status ≠ new.status` and `new.status = 'Fixed'` → `'fixed'`
- `key ∈ old` and `old.status ≠ new.status` otherwise → `'status_change'`
- `key ∈ old` but `key ∉ new_keys` and `old.status ≠ 'Fixed'` → synthetic `'fixed'` (vuln disappeared from the API — treated as remediated)

Rows are appended to `detection_changes`. All downstream trend/rollup queries read from this log.

### `purge_snapshots()`
GFS retention:
- `purge_daily_snapshots(config.daily_retention_days)` — default 30 days.
- `purge_weekly_rollups(config.weekly_retention_weeks)` — default 52 weeks.
- Monthly rollups kept indefinitely.

---

## Cache lifecycle

### `invalidate_cache()`
Not a metric — a cache-control hook. `AnalyticsEngine` memoises the `dashboard_summary()` payload and `db.get_latest_fetched_at()` lookups against a monotonically increasing generation counter so repeat dashboard hits are O(1) between refreshes. `DataManager.refresh_all()` (and the per-type refreshes) call this after saving new snapshots so the next page load reads fresh data. No SQL; pure in-memory reset of the generation/cache attributes.

---

<a id="recurring-check"></a>

## Recurring check

This document is paired with `tests/test_formulas_doc.py::test_every_analytics_method_is_documented`. That test:

1. Imports `AnalyticsEngine` from `src/analytics.py`.
2. Enumerates every public method (not prefixed with `_`).
3. Loads this file (`docs/FORMULAS.md`).
4. Fails if any method name is not mentioned in the file.

**When you add a new method to `AnalyticsEngine`, the test will fail until you add a section here documenting the formula.** Run it with:

```bash
python -m unittest tests.test_formulas_doc -v
```

Also re-audit this file (read end-to-end, verify the SQL matches `analytics.py`) on every release, or whenever an existing metric's SQL is edited. Update the "Last audited" date at the top of this file when you do.
