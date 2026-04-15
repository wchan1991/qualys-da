"""
Analytics Engine

Computes all metrics for dashboards, KPIs, trend analysis, and Cyber 6-Pack.
Uses SQL for fixed dashboards, pandas for custom/ad-hoc analysis.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from .database import QualysDADatabase
from .config_loader import QualysDAConfig

logger = logging.getLogger(__name__)


class AnalyticsEngine:
    """Computes vulnerability management metrics from the database."""

    def __init__(self, db: QualysDADatabase, config: QualysDAConfig):
        self.db = db
        self.config = config
        # Generation-based cache. `invalidate_cache()` bumps the generation,
        # which logically empties every cache without having to walk them.
        # Refresh pipelines call invalidate_cache() after a successful pull
        # so the next dashboard hit repopulates from fresh data.
        self._generation: int = 0
        self._fetched_at_cache: Dict[str, Optional[str]] = {}
        self._dashboard_cache: Optional[Dict[str, Any]] = None
        self._dashboard_cache_gen: int = -1

    def invalidate_cache(self) -> None:
        """Bump the generation counter and drop memoised dashboard payloads.

        Called by `DataManager` at the end of every successful refresh so the
        next page load reads live data. Cheap — just resets a few attributes.
        """
        self._generation += 1
        self._fetched_at_cache.clear()
        self._dashboard_cache = None
        self._dashboard_cache_gen = -1

    def _fetched_at(self, table: str) -> Optional[str]:
        """Memoised `db.get_latest_fetched_at(table)`.

        The raw helper is called 30+ times per dashboard render (every
        analytics method asks for it). Caching it for the life of a
        generation collapses those into one query per table per refresh.
        """
        if table not in self._fetched_at_cache:
            self._fetched_at_cache[table] = self.db.get_latest_fetched_at(table)
        return self._fetched_at_cache[table]

    # ── Dashboard ────────────────────────────────────────────────

    def dashboard_summary(self) -> Dict[str, Any]:
        """Compose all overview metrics for the dashboard page.

        Result is cached until the next refresh (`invalidate_cache()`).
        A cold dashboard now pays ~5 queries; warm hits are O(1).
        """
        if (self._dashboard_cache is not None
                and self._dashboard_cache_gen == self._generation):
            return self._dashboard_cache

        # Compute asset_coverage once and pass it to kpi_badges so we don't
        # run the same set-arithmetic twice per dashboard render.
        coverage = self.asset_coverage()
        payload = {
            "vuln_overview": self.vuln_overview(),
            "kpi_badges": self.kpi_badges(coverage=coverage),
            "asset_coverage": coverage,
            "risk_distribution": self.risk_distribution(),
            "last_refresh": self._last_refresh_info(),
        }
        self._dashboard_cache = payload
        self._dashboard_cache_gen = self._generation
        return payload

    def _last_refresh_info(self) -> Optional[Dict]:
        logs = self.db.get_refresh_log(limit=1)
        return logs[0] if logs else None

    # ── Vulnerability Overview ───────────────────────────────────

    def vuln_overview(self, include_disabled: bool = False) -> Dict[str, Any]:
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {"total": 0, "by_severity": {}, "by_status": {}, "critical_count": 0}

        disabled_clause = "" if include_disabled else "AND is_disabled = 0"

        # By severity
        rows = self.db.conn.execute(
            f"""SELECT severity, COUNT(*) as cnt FROM vm_detections
                WHERE fetched_at = ? {disabled_clause}
                GROUP BY severity""",
            (fetched,),
        ).fetchall()
        by_severity = {r["severity"]: r["cnt"] for r in rows}

        # By status
        rows = self.db.conn.execute(
            f"""SELECT status, COUNT(*) as cnt FROM vm_detections
                WHERE fetched_at = ? {disabled_clause}
                GROUP BY status""",
            (fetched,),
        ).fetchall()
        by_status = {r["status"]: r["cnt"] for r in rows}

        # Disabled count (always computed separately)
        disabled_count = 0
        if not include_disabled:
            row = self.db.conn.execute(
                "SELECT COUNT(*) FROM vm_detections WHERE fetched_at = ? AND is_disabled = 1",
                (fetched,),
            ).fetchone()
            disabled_count = row[0]

        total = sum(by_severity.values())
        critical = by_severity.get(5, 0) + by_severity.get(4, 0)

        return {
            "total": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "critical_count": critical,
            "disabled_count": disabled_count,
        }

    # ── Risk Distribution ────────────────────────────────────────

    def risk_distribution(self) -> Dict[str, Any]:
        fetched_hosts = self._fetched_at("vm_hosts")
        fetched_det = self._fetched_at("vm_detections")

        # TruRisk histogram (buckets of 100)
        trurisk_hist = []
        if fetched_hosts:
            rows = self.db.conn.execute(
                """SELECT
                     CAST(trurisk_score / 100 AS INTEGER) * 100 as bucket,
                     COUNT(*) as cnt
                   FROM vm_hosts WHERE fetched_at = ? AND trurisk_score > 0
                   GROUP BY bucket ORDER BY bucket""",
                (fetched_hosts,),
            ).fetchall()
            trurisk_hist = [{"bucket": f"{r['bucket']}-{r['bucket']+99}", "count": r["cnt"]} for r in rows]

        # QDS histogram (buckets of 20)
        qds_hist = []
        if fetched_det:
            rows = self.db.conn.execute(
                """SELECT
                     CAST(qds / 20 AS INTEGER) * 20 as bucket,
                     COUNT(*) as cnt
                   FROM vm_detections
                   WHERE fetched_at = ? AND is_disabled = 0 AND qds > 0
                   GROUP BY bucket ORDER BY bucket""",
                (fetched_det,),
            ).fetchall()
            qds_hist = [{"bucket": f"{r['bucket']}-{r['bucket']+19}", "count": r["cnt"]} for r in rows]

        # Top 10 riskiest hosts
        top_risky = []
        if fetched_hosts:
            rows = self.db.conn.execute(
                """SELECT host_id, ip_address, dns, os, trurisk_score
                   FROM vm_hosts WHERE fetched_at = ?
                   ORDER BY trurisk_score DESC LIMIT 10""",
                (fetched_hosts,),
            ).fetchall()
            top_risky = [dict(r) for r in rows]

        return {
            "trurisk_histogram": trurisk_hist,
            "qds_histogram": qds_hist,
            "top_riskiest": top_risky,
        }

    # ── Asset Coverage ───────────────────────────────────────────

    def asset_coverage(self) -> Dict[str, Any]:
        csam_fetched = self._fetched_at("csam_assets")
        vm_fetched = self._fetched_at("vm_hosts")

        csam_ips = set()
        vm_ips = set()

        if csam_fetched:
            rows = self.db.conn.execute(
                "SELECT DISTINCT ip_address FROM csam_assets WHERE fetched_at = ? AND ip_address != ''",
                (csam_fetched,),
            ).fetchall()
            csam_ips = {r[0] for r in rows}

        if vm_fetched:
            rows = self.db.conn.execute(
                "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ? AND ip_address != ''",
                (vm_fetched,),
            ).fetchall()
            vm_ips = {r[0] for r in rows}

        both = csam_ips & vm_ips
        csam_only = csam_ips - vm_ips
        vm_only = vm_ips - csam_ips
        total = csam_ips | vm_ips

        # Scan recency
        scanned_7d = 0
        scanned_30d = 0
        if vm_fetched:
            cutoff_7d = (datetime.utcnow() - timedelta(days=7)).isoformat()
            cutoff_30d = (datetime.utcnow() - timedelta(days=30)).isoformat()
            row = self.db.conn.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM vm_hosts WHERE fetched_at = ? AND last_vm_scanned_date >= ?",
                (vm_fetched, cutoff_7d),
            ).fetchone()
            scanned_7d = row[0]
            row = self.db.conn.execute(
                "SELECT COUNT(DISTINCT ip_address) FROM vm_hosts WHERE fetched_at = ? AND last_vm_scanned_date >= ?",
                (vm_fetched, cutoff_30d),
            ).fetchone()
            scanned_30d = row[0]

        total_count = len(total) or 1
        return {
            "csam_only": len(csam_only),
            "vm_only": len(vm_only),
            "both": len(both),
            "total_unique_ips": len(total),
            "coverage_pct": round(len(both) / total_count * 100, 1),
            "scanned_7d": scanned_7d,
            "scanned_30d": scanned_30d,
            "scan_coverage_7d_pct": round(scanned_7d / total_count * 100, 1),
            "scan_coverage_30d_pct": round(scanned_30d / total_count * 100, 1),
        }

    # ── Detection Age ────────────────────────────────────────────

    def detection_age(self) -> Dict[str, Any]:
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {"mean_days_to_remediate": 0, "aging_30d": 0, "aging_60d": 0, "aging_90d": 0}

        # MTTR for fixed detections
        row = self.db.conn.execute(
            """SELECT AVG(julianday(last_fixed) - julianday(first_found)) as avg_mttr
               FROM vm_detections
               WHERE fetched_at = ? AND status = 'Fixed' AND last_fixed != '' AND first_found != ''""",
            (fetched,),
        ).fetchone()
        avg_mttr = round(row["avg_mttr"], 1) if row["avg_mttr"] else 0

        # Aging buckets (open vulns)
        now = datetime.utcnow().isoformat()
        aging = {}
        for days in (30, 60, 90):
            cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
            row = self.db.conn.execute(
                """SELECT COUNT(*) FROM vm_detections
                   WHERE fetched_at = ? AND status IN ('New', 'Active')
                   AND is_disabled = 0 AND first_found <= ?""",
                (fetched, cutoff),
            ).fetchone()
            aging[f"aging_{days}d"] = row[0]

        return {
            "mean_days_to_remediate": avg_mttr,
            **aging,
        }

    # ── OS Distribution ──────────────────────────────────────────

    def os_distribution(self) -> List[Dict]:
        fetched_det = self._fetched_at("vm_detections")
        fetched_hosts = self._fetched_at("vm_hosts")
        if not fetched_det or not fetched_hosts:
            return []

        rows = self.db.conn.execute(
            """SELECT h.os,
                      COUNT(DISTINCT h.ip_address) as host_count,
                      COUNT(CASE WHEN d.status IN ('New','Active') AND d.is_disabled = 0 THEN 1 END) as vuln_count
               FROM vm_hosts h
               LEFT JOIN vm_detections d ON h.host_id = d.host_id AND d.fetched_at = ?
               WHERE h.fetched_at = ? AND h.os != ''
               GROUP BY h.os
               ORDER BY vuln_count DESC
               LIMIT 20""",
            (fetched_det, fetched_hosts),
        ).fetchall()

        return [
            {
                "os": r["os"],
                "host_count": r["host_count"],
                "vuln_count": r["vuln_count"],
                "density": round(r["vuln_count"] / max(r["host_count"], 1), 1),
            }
            for r in rows
        ]

    # ── Application Distribution ─────────────────────────────────

    def app_distribution(self) -> List[Dict]:
        """Vuln density by application from CSAM software inventory."""
        csam_fetched = self._fetched_at("csam_assets")
        det_fetched = self._fetched_at("vm_detections")
        if not csam_fetched or not det_fetched:
            return []

        # Get assets with software lists
        rows = self.db.conn.execute(
            "SELECT ip_address, software FROM csam_assets WHERE fetched_at = ? AND software != '[]'",
            (csam_fetched,),
        ).fetchall()

        # Build app → IPs mapping
        app_ips: Dict[str, set] = {}
        for r in rows:
            try:
                software_list = json.loads(r["software"]) if r["software"] else []
            except (json.JSONDecodeError, TypeError):
                continue
            for sw in software_list:
                name = sw.get("name", sw.get("fullName", "")) if isinstance(sw, dict) else str(sw)
                if name:
                    app_ips.setdefault(name, set()).add(r["ip_address"])

        if not app_ips:
            return []

        # Get vuln counts per IP
        det_rows = self.db.conn.execute(
            """SELECT ip_address, COUNT(*) as cnt
               FROM vm_detections
               WHERE fetched_at = ? AND status IN ('New','Active') AND is_disabled = 0
               GROUP BY ip_address""",
            (det_fetched,),
        ).fetchall()
        ip_vulns = {r["ip_address"]: r["cnt"] for r in det_rows}

        results = []
        for app_name, ips in app_ips.items():
            vuln_count = sum(ip_vulns.get(ip, 0) for ip in ips)
            results.append({
                "app_name": app_name,
                "host_count": len(ips),
                "vuln_count": vuln_count,
                "density": round(vuln_count / max(len(ips), 1), 1),
            })

        results.sort(key=lambda x: x["vuln_count"], reverse=True)
        return results[:30]

    # ── Top QIDs ─────────────────────────────────────────────────

    def top_qids(self, n: int = 20) -> List[Dict]:
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return []
        rows = self.db.conn.execute(
            """SELECT qid, severity, COUNT(*) as count,
                      COUNT(DISTINCT host_id) as hosts_affected
               FROM vm_detections
               WHERE fetched_at = ? AND status IN ('New','Active') AND is_disabled = 0
               GROUP BY qid
               ORDER BY count DESC
               LIMIT ?""",
            (fetched, n),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── CVE / CVSS Dashboard ─────────────────────────────────────
    #
    # CVSS banding (CVSS v3.0 qualitative ratings):
    #   Critical: 9.0-10.0, High: 7.0-8.9, Medium: 4.0-6.9, Low: 0.1-3.9, None: 0.0
    # We drop rows with no CVE on the CVE-focused widgets, but the severity
    # histogram is scored by cvss_base across all detections (null→0).

    def cve_dashboard(self, months_back: int = 12) -> Dict[str, Any]:
        """Composite payload for the CVE/CVSS dashboard page.

        Data source reconciliation (all numbers below derived from the same
        `fetched_at` snapshot as every other dashboard):
          - `resources_scanned`  = distinct IPs in vm_detections (hosts with
            at least one VM scan result). Matches /hosts page count of VM
            hosts — which is <= main dashboard's "Total Hosts" because
            Total Hosts unions CSAM∪VM and includes CSAM-only (never-scanned)
            hosts. Coverage % shown on the card reconciles the two.
          - CVSS bands (critical/high/medium/low) count OPEN detections only
            (status in New/Active/Re-Opened), excluding disabled and null-CVSS
            rows. Intentionally narrower than vuln_overview.total which counts
            ALL non-disabled detections including Fixed.
        """
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {
                "summary": {"resources_scanned": 0, "total_hosts": 0, "coverage_pct": 0,
                            "critical": 0, "high": 0, "medium": 0, "low": 0, "total_cves": 0},
                "trend": {"months": [], "critical": [], "high": [], "medium": [], "low": []},
                "top_resources": [],
                "top_patchable": [],
                "top_cves": [],
            }

        # Summary counts — banded by CVSS base
        row = self.db.conn.execute(
            """SELECT
                  COUNT(DISTINCT ip_address) AS resources,
                  SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) AS critical,
                  SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) AS high,
                  SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) AS medium,
                  SUM(CASE WHEN cvss_base > 0 AND cvss_base < 4.0 THEN 1 ELSE 0 END) AS low,
                  COUNT(DISTINCT cve_id) AS total_cves
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0 AND status IN ('New','Active','Re-Opened')""",
            (fetched,),
        ).fetchone()

        # Cross-check against asset_coverage so Resources card reconciles with
        # the main dashboard's "Total Hosts" number (CSAM∪VM).
        cov = self.asset_coverage()
        total_hosts = cov.get("total_unique_ips", 0)
        resources_scanned = row["resources"] or 0
        coverage_pct = round(100.0 * resources_scanned / total_hosts, 1) if total_hosts else 0

        summary = {
            "resources_scanned": resources_scanned,
            "total_hosts": total_hosts,
            "coverage_pct": coverage_pct,
            "critical": row["critical"] or 0,
            "high": row["high"] or 0,
            "medium": row["medium"] or 0,
            "low": row["low"] or 0,
            "total_cves": row["total_cves"] or 0,
        }

        # Trend by severity (bucketed by first_found month, CVSS-banded)
        trend_rows = self.db.conn.execute(
            """SELECT substr(first_found, 1, 7) AS ym,
                      SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) AS critical,
                      SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) AS high,
                      SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) AS medium,
                      SUM(CASE WHEN cvss_base > 0 AND cvss_base < 4.0 THEN 1 ELSE 0 END) AS low
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0
                 AND first_found IS NOT NULL AND first_found != ''
               GROUP BY ym
               ORDER BY ym""",
            (fetched,),
        ).fetchall()
        # Build last N contiguous months ending with current month
        now = datetime.utcnow()
        months = []
        y, m = now.year, now.month
        for _ in range(months_back):
            months.append(f"{y:04d}-{m:02d}")
            m -= 1
            if m == 0:
                m = 12
                y -= 1
        months.reverse()
        by_month = {r["ym"]: r for r in trend_rows}
        trend = {
            "months": months,
            "critical": [by_month.get(ym, {"critical": 0})["critical"] if ym in by_month else 0 for ym in months],
            "high":     [by_month.get(ym, {"high": 0})["high"] if ym in by_month else 0 for ym in months],
            "medium":   [by_month.get(ym, {"medium": 0})["medium"] if ym in by_month else 0 for ym in months],
            "low":      [by_month.get(ym, {"low": 0})["low"] if ym in by_month else 0 for ym in months],
        }

        # Top 10 vulnerable resources — hosts with most open vulns (any CVSS)
        top_res = self.db.conn.execute(
            """SELECT d.ip_address, h.dns, h.os,
                      COUNT(*) AS vulns,
                      MAX(d.cvss_base) AS max_cvss
               FROM vm_detections d
               LEFT JOIN vm_hosts h ON d.host_id = h.host_id
                   AND h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
               WHERE d.fetched_at = ? AND d.is_disabled = 0
                 AND d.status IN ('New','Active','Re-Opened')
               GROUP BY d.ip_address
               ORDER BY vulns DESC
               LIMIT 10""",
            (fetched,),
        ).fetchall()
        top_resources = [dict(r) for r in top_res]

        # Top 10 patchable CVEs — CVEs with a fix_version, sorted by affected hosts
        top_patch = self.db.conn.execute(
            """SELECT cve_id, fix_version,
                      MAX(title) AS title,
                      MAX(cvss_base) AS cvss,
                      COUNT(DISTINCT host_id) AS vulnerabilities
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0
                 AND status IN ('New','Active','Re-Opened')
                 AND cve_id IS NOT NULL
                 AND patchable = 1
                 AND fix_version IS NOT NULL AND fix_version NOT IN ('', 'no-fix')
               GROUP BY cve_id
               ORDER BY vulnerabilities DESC
               LIMIT 10""",
            (fetched,),
        ).fetchall()
        top_patchable = [dict(r) for r in top_patch]

        # Top 10 CVEs overall — full detail row for the main table
        top_cve_rows = self.db.conn.execute(
            """SELECT cve_id,
                      MAX(title) AS title,
                      MAX(cvss_base) AS cvss,
                      MAX(severity) AS severity,
                      MAX(package_name) AS package_name,
                      MAX(package_version) AS package_version,
                      MAX(fix_version) AS fix_version,
                      COUNT(DISTINCT host_id) AS vulnerabilities
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0
                 AND status IN ('New','Active','Re-Opened')
                 AND cve_id IS NOT NULL
               GROUP BY cve_id
               ORDER BY vulnerabilities DESC
               LIMIT 10""",
            (fetched,),
        ).fetchall()
        top_cves = [dict(r) for r in top_cve_rows]

        return {
            "summary": summary,
            "trend": trend,
            "top_resources": top_resources,
            "top_patchable": top_patchable,
            "top_cves": top_cves,
        }

    def cve_by_ownership(self, group_by: str = "owner") -> Dict[str, Any]:
        """CVE matrix broken down by ownership group.

        Returns one row per group (owner/business_unit/tag/os) with:
          - critical/high/medium/low (count of OPEN detections per CVSS band)
          - total_cves (distinct CVE IDs affecting the group)
          - unique_hosts (distinct IPs in the group)
          - max_cvss (highest CVSS base score in the group)
          - top_cve (most prevalent CVE in the group)
        Uses the same IP-to-group resolution as cyber_six_pack_trend so the
        6-Pack page is internally consistent.
        """
        det_fetched = self._fetched_at("vm_detections")
        host_fetched = self._fetched_at("vm_hosts")
        if not det_fetched:
            return {"groups": [], "enterprise": {}}

        # Build group → IPs map (mirrors cyber_six_pack_trend)
        group_ips: Dict[str, List[str]] = {}
        if group_by == "tag":
            tag_rows = self.db.conn.execute(
                """SELECT tag_name, ip_address FROM host_tags
                   WHERE fetched_at = (SELECT MAX(fetched_at) FROM host_tags)"""
            ).fetchall()
            for r in tag_rows:
                group_ips.setdefault(r["tag_name"], []).append(r["ip_address"])
        elif group_by == "os":
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address, os FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    os_name = r["os"] or "Unknown"
                    group_ips.setdefault(os_name, []).append(r["ip_address"])
        elif group_by == "business_unit":
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    ip = r["ip_address"]
                    resolved = self.db.get_asset_owner(ip)
                    bu = (resolved or {}).get("business_unit") or "Unassigned"
                    group_ips.setdefault(bu, []).append(ip)
        else:  # owner
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    ip = r["ip_address"]
                    resolved = self.db.get_asset_owner(ip)
                    name = (resolved or {}).get("owner") or "Unassigned"
                    group_ips.setdefault(name, []).append(ip)

        # Enterprise totals come from a single query (not sum-of-groups) so that
        # overlapping groupings like `tag` don't double-count the same detection.
        ent_row = self.db.conn.execute(
            """SELECT
                   SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) AS critical,
                   SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) AS high,
                   SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) AS medium,
                   SUM(CASE WHEN cvss_base > 0 AND cvss_base < 4.0 THEN 1 ELSE 0 END) AS low,
                   COUNT(DISTINCT cve_id) AS total_cves,
                   COUNT(DISTINCT ip_address) AS unique_hosts,
                   MAX(cvss_base) AS max_cvss
                FROM vm_detections
                WHERE fetched_at = ? AND is_disabled = 0
                  AND status IN ('New','Active','Re-Opened')""",
            (det_fetched,),
        ).fetchone()
        enterprise = {
            "critical": ent_row["critical"] or 0,
            "high": ent_row["high"] or 0,
            "medium": ent_row["medium"] or 0,
            "low": ent_row["low"] or 0,
            "total_cves": ent_row["total_cves"] or 0,
            "unique_hosts": ent_row["unique_hosts"] or 0,
            "max_cvss": round(ent_row["max_cvss"] or 0, 1),
        }

        groups_out: List[Dict] = []

        for name, ips in group_ips.items():
            if not ips:
                continue
            ph = ",".join("?" * len(ips))
            row = self.db.conn.execute(
                f"""SELECT
                       SUM(CASE WHEN cvss_base >= 9.0 THEN 1 ELSE 0 END) AS critical,
                       SUM(CASE WHEN cvss_base >= 7.0 AND cvss_base < 9.0 THEN 1 ELSE 0 END) AS high,
                       SUM(CASE WHEN cvss_base >= 4.0 AND cvss_base < 7.0 THEN 1 ELSE 0 END) AS medium,
                       SUM(CASE WHEN cvss_base > 0 AND cvss_base < 4.0 THEN 1 ELSE 0 END) AS low,
                       COUNT(DISTINCT cve_id) AS total_cves,
                       COUNT(DISTINCT ip_address) AS unique_hosts,
                       MAX(cvss_base) AS max_cvss
                    FROM vm_detections
                    WHERE fetched_at = ? AND is_disabled = 0
                      AND status IN ('New','Active','Re-Opened')
                      AND ip_address IN ({ph})""",
                [det_fetched] + ips,
            ).fetchone()

            # Top *critical* CVE for the group — most prevalent CVE with
            # CVSS >= 9.0 (falls back to top overall if no critical present).
            top_cve_row = self.db.conn.execute(
                f"""SELECT cve_id,
                           MAX(title) AS title,
                           COUNT(DISTINCT ip_address) AS affected_hosts,
                           MAX(cvss_base) AS cvss
                    FROM vm_detections
                    WHERE fetched_at = ? AND is_disabled = 0
                      AND status IN ('New','Active','Re-Opened')
                      AND cve_id IS NOT NULL
                      AND cvss_base >= 9.0
                      AND ip_address IN ({ph})
                    GROUP BY cve_id
                    ORDER BY affected_hosts DESC
                    LIMIT 1""",
                [det_fetched] + ips,
            ).fetchone()
            if not top_cve_row or not top_cve_row["cve_id"]:
                # Fallback: most prevalent CVE at any severity
                top_cve_row = self.db.conn.execute(
                    f"""SELECT cve_id,
                               MAX(title) AS title,
                               COUNT(DISTINCT ip_address) AS affected_hosts,
                               MAX(cvss_base) AS cvss
                        FROM vm_detections
                        WHERE fetched_at = ? AND is_disabled = 0
                          AND status IN ('New','Active','Re-Opened')
                          AND cve_id IS NOT NULL
                          AND ip_address IN ({ph})
                        GROUP BY cve_id
                        ORDER BY affected_hosts DESC
                        LIMIT 1""",
                    [det_fetched] + ips,
                ).fetchone()

            # Per-group avg TruRisk score (from vm_hosts)
            avg_trurisk = None
            if host_fetched:
                tr_row = self.db.conn.execute(
                    f"""SELECT AVG(trurisk_score) AS avg_tr
                        FROM vm_hosts
                        WHERE fetched_at = ? AND trurisk_score > 0
                          AND ip_address IN ({ph})""",
                    [host_fetched] + ips,
                ).fetchone()
                if tr_row and tr_row["avg_tr"] is not None:
                    avg_trurisk = round(tr_row["avg_tr"], 0)

            g = {
                "name": name,
                "critical": row["critical"] or 0,
                "high": row["high"] or 0,
                "medium": row["medium"] or 0,
                "low": row["low"] or 0,
                "total_cves": row["total_cves"] or 0,
                "unique_hosts": row["unique_hosts"] or 0,
                "max_cvss": round(row["max_cvss"] or 0, 1),
                "avg_trurisk": avg_trurisk,
                "top_cve": top_cve_row["cve_id"] if top_cve_row else None,
                "top_cve_title": top_cve_row["title"] if top_cve_row else None,
                "top_cve_cvss": round(top_cve_row["cvss"] or 0, 1) if top_cve_row else None,
                "top_cve_affected_hosts": top_cve_row["affected_hosts"] if top_cve_row else 0,
            }
            groups_out.append(g)

        # Sort groups: Critical desc, then High desc
        groups_out.sort(key=lambda g: (g["critical"], g["high"]), reverse=True)

        return {"groups": groups_out, "enterprise": enterprise}

    def _resolve_group_ips(self, group_by: str) -> Dict[str, List[str]]:
        """Shared helper — maps group name -> list of IPs for owner/BU/tag/OS."""
        host_fetched = self._fetched_at("vm_hosts")
        group_ips: Dict[str, List[str]] = {}
        if group_by == "tag":
            for r in self.db.conn.execute(
                """SELECT tag_name, ip_address FROM host_tags
                   WHERE fetched_at = (SELECT MAX(fetched_at) FROM host_tags)"""
            ).fetchall():
                group_ips.setdefault(r["tag_name"], []).append(r["ip_address"])
        elif group_by == "os":
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address, os FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    group_ips.setdefault(r["os"] or "Unknown", []).append(r["ip_address"])
        elif group_by == "business_unit":
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    ip = r["ip_address"]
                    resolved = self.db.get_asset_owner(ip)
                    bu = (resolved or {}).get("business_unit") or "Unassigned"
                    group_ips.setdefault(bu, []).append(ip)
        else:  # owner
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
                    (host_fetched,),
                ).fetchall():
                    ip = r["ip_address"]
                    resolved = self.db.get_asset_owner(ip)
                    name = (resolved or {}).get("owner") or "Unassigned"
                    group_ips.setdefault(name, []).append(ip)
        return group_ips

    def waterfall_by_ownership(self, group_by: str = "owner",
                                owner: Optional[str] = None,
                                months_back: int = 12) -> Dict[str, Any]:
        """Proper waterfall: Active count is the anchor; monthly deltas
        (new, fixed, reopened) flow between a starting and ending Active total.

        Returned payload (sufficient to render a floating-bar waterfall):
          - start_active: Active count at the start of the period
          - end_active:   Current Active count
          - months:       ['YYYY-MM', ...]
          - new / fixed / reopened: per-month change counts
          - net:          per-month net change to Active (= new - fixed + reopened)
          - running:      Active running total *after* each month's net is applied
                          (so running[-1] == end_active)
          - reconciled:   bool — True iff sum(net) == end_active - start_active
                          (false means changes outside [earliest, now] aren't captured)

        Note on the math: `start_active` is back-derived from current Active
        minus the sum of monthly nets. Detections that were active before the
        window opened and resolved before it closed therefore won't move the
        anchor — this is the correct behavior for a window-bounded waterfall.

        Scoping:
          owner=None → enterprise-wide
          owner='X'  → scope by IP membership in the named group
        """
        # Build the last N contiguous months ending with current month
        now = datetime.utcnow()
        months = []
        y, m = now.year, now.month
        for _ in range(months_back):
            months.append(f"{y:04d}-{m:02d}")
            m -= 1
            if m == 0:
                m = 12
                y -= 1
        months.reverse()

        # Oldest month cutoff (ISO date on first-of-month)
        earliest = months[0] + "-01"

        # Scope IPs (None → all)
        scoped_ips: Optional[List[str]] = None
        if owner:
            group_ips = self._resolve_group_ips(group_by)
            scoped_ips = group_ips.get(owner, [])
            if not scoped_ips:
                empty = [0] * len(months)
                return {
                    "months": months, "new": empty, "fixed": empty,
                    "reopened": empty, "net": empty, "running": empty,
                    "start_active": 0, "end_active": 0, "reconciled": True,
                    "group_by": group_by, "owner": owner,
                }

        # Per-month change counts (only for OPEN ↔ FIXED transitions —
        # severity_change events don't move the active anchor)
        params: List = [earliest]
        ip_clause = ""
        if scoped_ips is not None:
            ph = ",".join("?" * len(scoped_ips))
            ip_clause = f" AND ip_address IN ({ph})"
            params += scoped_ips

        rows = self.db.conn.execute(
            f"""SELECT substr(detected_at, 1, 7) AS ym,
                      change_type,
                      COUNT(*) AS cnt
               FROM detection_changes
               WHERE detected_at >= ?
                 AND change_type IN ('new','fixed','reopened'){ip_clause}
               GROUP BY ym, change_type""",
            params,
        ).fetchall()

        by_month = {ym: {"new": 0, "fixed": 0, "reopened": 0} for ym in months}
        for r in rows:
            ym = r["ym"]
            ct = r["change_type"]
            if ym in by_month and ct in ("new", "fixed", "reopened"):
                by_month[ym][ct] = r["cnt"]

        new_arr      = [by_month[ym]["new"]      for ym in months]
        fixed_arr    = [by_month[ym]["fixed"]    for ym in months]
        reopened_arr = [by_month[ym]["reopened"] for ym in months]
        # Net change to "Active" cohort each month: +new -fixed +reopened
        net_arr = [n - f + r for n, f, r in zip(new_arr, fixed_arr, reopened_arr)]

        # Current Active (= the right anchor)
        det_fetched = self._fetched_at("vm_detections")
        end_active = 0
        if det_fetched:
            active_params: List = [det_fetched]
            active_ip_clause = ""
            if scoped_ips is not None:
                ph = ",".join("?" * len(scoped_ips))
                active_ip_clause = f" AND ip_address IN ({ph})"
                active_params += scoped_ips
            end_active = self.db.conn.execute(
                f"""SELECT COUNT(*) FROM vm_detections
                    WHERE fetched_at = ? AND is_disabled = 0
                      AND status IN ('New','Active','Re-Opened')
                      {active_ip_clause}""",
                active_params,
            ).fetchone()[0] or 0

        # Back-derive start_active: end - sum(net) is the anchor at the start.
        total_net = sum(net_arr)
        start_active = max(0, end_active - total_net)

        # Running totals after each month (for floating-bar positioning).
        running: List[int] = []
        cur = start_active
        for net in net_arr:
            cur += net
            running.append(cur)

        # If the change log doesn't cover the full window, running[-1] may
        # diverge from end_active. Surface that so the UI can flag it.
        reconciled = bool(running) and running[-1] == end_active

        return {
            "months": months,
            "new": new_arr,
            "fixed": fixed_arr,
            "reopened": reopened_arr,
            "net": net_arr,
            "running": running,
            "start_active": start_active,
            "end_active": end_active,
            "reconciled": reconciled,
            "group_by": group_by,
            "owner": owner,
        }

    def os_by_ownership(self, group_by: str = "owner") -> Dict[str, Any]:
        """Stacked-bar data: vulnerability counts per OS × ownership group.

        Returns:
          {
            "groups": ["Alice Chen", "Bob Martinez", ...],
            "oses":   ["Windows Server 2022 Standard", "Ubuntu 22.04.4 LTS", ...],
            "matrix": [[wins_for_alice, ubuntu_for_alice, ...], [...], ...]
          }
        Matrix rows correspond to groups, columns correspond to OSes.
        OS strings are normalized to their family (Windows/Linux/macOS/Other)
        to keep the chart readable.
        """
        det_fetched = self._fetched_at("vm_detections")
        host_fetched = self._fetched_at("vm_hosts")
        if not det_fetched or not host_fetched:
            return {"groups": [], "oses": [], "matrix": []}

        # Build IP → OS family and IP → group name maps
        host_rows = self.db.conn.execute(
            "SELECT DISTINCT ip_address, os FROM vm_hosts WHERE fetched_at = ?",
            (host_fetched,),
        ).fetchall()

        def os_family(os_str: str) -> str:
            if not os_str:
                return "Other"
            s = os_str.lower()
            if "windows" in s:
                return "Windows"
            if any(k in s for k in ("red hat", "rhel", "centos", "oracle linux",
                                      "ubuntu", "debian", "suse", "amazon linux",
                                      "linux", "photon")):
                return "Linux"
            if "mac" in s or "darwin" in s:
                return "macOS"
            return "Other"

        ip_to_os_family = {r["ip_address"]: os_family(r["os"]) for r in host_rows}

        # Build group → IPs map (reusing the shared helper)
        group_ips = self._resolve_group_ips(group_by)

        # Open-detection counts per IP
        det_rows = self.db.conn.execute(
            """SELECT ip_address, COUNT(*) AS cnt
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0
                 AND status IN ('New','Active','Re-Opened')
               GROUP BY ip_address""",
            (det_fetched,),
        ).fetchall()
        ip_det_counts = {r["ip_address"]: r["cnt"] for r in det_rows}

        # Build matrix: rows = groups, cols = OS families
        os_families = ["Windows", "Linux", "macOS", "Other"]
        matrix: List[List[int]] = []
        group_names = []
        for name, ips in group_ips.items():
            row = [0, 0, 0, 0]
            for ip in ips:
                fam = ip_to_os_family.get(ip, "Other")
                cnt = ip_det_counts.get(ip, 0)
                if cnt:
                    row[os_families.index(fam)] += cnt
            if sum(row) > 0:
                group_names.append(name)
                matrix.append(row)

        # Sort groups by total desc, cap to top 15 for chart readability
        combined = sorted(zip(group_names, matrix),
                          key=lambda p: sum(p[1]), reverse=True)[:15]
        group_names = [c[0] for c in combined]
        matrix = [c[1] for c in combined]

        # Drop OS families that are empty across all groups
        active_idx = [i for i, fam in enumerate(os_families)
                      if any(row[i] > 0 for row in matrix)]
        oses = [os_families[i] for i in active_idx]
        matrix = [[row[i] for i in active_idx] for row in matrix]

        return {"groups": group_names, "oses": oses, "matrix": matrix}

    def patchable_by_severity(self) -> Dict[str, Any]:
        """Patchable vs non-patchable split, broken down by severity band.

        Returns:
          {
            "severities": [1,2,3,4,5],
            "patchable":       [p1, p2, p3, p4, p5],
            "non_patchable":   [n1, n2, n3, n4, n5],
            "totals": {"patchable": X, "non_patchable": Y, "patchable_pct": Z},
            "by_severity": [
              {"severity": 5, "patchable": p, "non_patchable": n, "pct": Z}, ...
            ],
          }
        Scoped to OPEN detections (New/Active/Re-Opened, non-disabled).
        """
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {
                "severities": [1, 2, 3, 4, 5],
                "patchable": [0, 0, 0, 0, 0],
                "non_patchable": [0, 0, 0, 0, 0],
                "totals": {"patchable": 0, "non_patchable": 0, "patchable_pct": 0},
                "by_severity": [],
            }
        rows = self.db.conn.execute(
            """SELECT severity,
                      SUM(CASE WHEN patchable = 1 THEN 1 ELSE 0 END) AS patchable,
                      SUM(CASE WHEN patchable = 0 THEN 1 ELSE 0 END) AS non_patchable
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0
                 AND status IN ('New','Active','Re-Opened')
               GROUP BY severity""",
            (fetched,),
        ).fetchall()
        by_sev = {r["severity"]: (r["patchable"] or 0, r["non_patchable"] or 0) for r in rows}

        severities = [1, 2, 3, 4, 5]
        patchable_arr = [by_sev.get(s, (0, 0))[0] for s in severities]
        non_patchable_arr = [by_sev.get(s, (0, 0))[1] for s in severities]

        total_p = sum(patchable_arr)
        total_np = sum(non_patchable_arr)
        total = total_p + total_np

        by_severity = []
        for s in severities:
            p, n = by_sev.get(s, (0, 0))
            t = p + n
            by_severity.append({
                "severity": s,
                "patchable": p,
                "non_patchable": n,
                "total": t,
                "pct": round(100.0 * p / t, 1) if t else 0,
            })

        return {
            "severities": severities,
            "patchable": patchable_arr,
            "non_patchable": non_patchable_arr,
            "totals": {
                "patchable": total_p,
                "non_patchable": total_np,
                "patchable_pct": round(100.0 * total_p / total, 1) if total else 0,
            },
            "by_severity": list(reversed(by_severity)),  # sev5 first for display
        }

    def orphaned_assets(self) -> Dict[str, Any]:
        """Hosts (CSAM ∪ VM) that match no ownership rule.

        Returns list of hosts with CSAM/VM source, OS, last scan, TruRisk,
        open vuln count, and tags. Intended for the Orphaned Assets page.
        """
        host_fetched = self._fetched_at("vm_hosts")
        csam_fetched = self._fetched_at("csam_assets")
        det_fetched = self._fetched_at("vm_detections")

        # Union of IPs across VM + CSAM
        ips_by_source: Dict[str, Dict[str, Any]] = {}

        if host_fetched:
            for r in self.db.conn.execute(
                """SELECT ip_address, dns, os, trurisk_score, last_scan_date
                   FROM vm_hosts WHERE fetched_at = ?""",
                (host_fetched,),
            ).fetchall():
                ip = r["ip_address"]
                if not ip:
                    continue
                ips_by_source[ip] = {
                    "ip_address": ip,
                    "dns": r["dns"],
                    "os": r["os"],
                    "trurisk_score": r["trurisk_score"],
                    "last_scan_date": r["last_scan_date"],
                    "in_vm": True,
                    "in_csam": False,
                }

        if csam_fetched:
            for r in self.db.conn.execute(
                """SELECT ip_address, name, os FROM csam_assets WHERE fetched_at = ?""",
                (csam_fetched,),
            ).fetchall():
                ip = r["ip_address"]
                if not ip:
                    continue
                entry = ips_by_source.setdefault(ip, {
                    "ip_address": ip, "dns": r["name"], "os": r["os"],
                    "trurisk_score": None, "last_scan_date": None,
                    "in_vm": False, "in_csam": False,
                })
                entry["in_csam"] = True
                entry["dns"] = entry.get("dns") or r["name"]
                entry["os"] = entry.get("os") or r["os"]

        # Open-detection counts per IP
        det_counts: Dict[str, int] = {}
        if det_fetched:
            for r in self.db.conn.execute(
                """SELECT ip_address, COUNT(*) AS cnt
                   FROM vm_detections
                   WHERE fetched_at = ? AND is_disabled = 0
                     AND status IN ('New','Active','Re-Opened')
                   GROUP BY ip_address""",
                (det_fetched,),
            ).fetchall():
                det_counts[r["ip_address"]] = r["cnt"]

        # Filter to hosts with NO matched owner
        orphans = []
        for ip, info in ips_by_source.items():
            resolved = self.db.get_asset_owner(ip)
            if resolved and resolved.get("owner"):
                continue  # has an owner — skip
            info["open_vulns"] = det_counts.get(ip, 0)
            orphans.append(info)

        # Sort: most open-vulns first, then highest TruRisk
        orphans.sort(key=lambda h: (h["open_vulns"],
                                     h.get("trurisk_score") or 0), reverse=True)

        return {
            "total": len(orphans),
            "total_hosts": len(ips_by_source),
            "orphans": orphans,
        }

    # ── Operational KPIs ─────────────────────────────────────────

    def kpi_badges(self, coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Compact KPI badges for the main dashboard.

        `coverage` lets the caller (dashboard_summary) reuse a single
        `asset_coverage()` computation across the whole page render instead
        of running the (set-union-heavy) coverage query twice.
        """
        if coverage is None:
            coverage = self.asset_coverage()
        return {
            "patchable_pct": self.patchable_percentage().get("patchable_pct", 0),
            "avg_mttr": self.detection_age().get("mean_days_to_remediate", 0),
            "sla_compliance_pct": self._overall_sla_compliance(),
            "scan_coverage_pct": coverage.get("scan_coverage_30d_pct", 0),
            "reopen_rate": self.reopen_rate().get("rate_pct", 0),
        }

    def patchable_percentage(self) -> Dict[str, Any]:
        """% of open vulns that are Confirmed (patchable) vs Potential."""
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {"patchable": 0, "non_patchable": 0, "patchable_pct": 0}
        rows = self.db.conn.execute(
            """SELECT detection_type, COUNT(*) as cnt
               FROM vm_detections
               WHERE fetched_at = ? AND status IN ('New','Active') AND is_disabled = 0
               GROUP BY detection_type""",
            (fetched,),
        ).fetchall()
        type_counts = {r["detection_type"]: r["cnt"] for r in rows}
        confirmed = type_counts.get("Confirmed", 0)
        total = sum(type_counts.values()) or 1
        return {
            "patchable": confirmed,
            "non_patchable": total - confirmed,
            "patchable_pct": round(confirmed / total * 100, 1),
            "by_type": type_counts,
        }

    def mttr_by_severity(self) -> Dict[int, float]:
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {}
        rows = self.db.conn.execute(
            """SELECT severity,
                      AVG(julianday(last_fixed) - julianday(first_found)) as avg_days
               FROM vm_detections
               WHERE fetched_at = ? AND status = 'Fixed'
               AND last_fixed != '' AND first_found != ''
               GROUP BY severity""",
            (fetched,),
        ).fetchall()
        return {r["severity"]: round(r["avg_days"], 1) if r["avg_days"] else 0 for r in rows}

    def sla_compliance(self) -> Dict[str, Any]:
        """SLA compliance breakdown per severity.

        Previously 10 queries (2 per severity × 5 severities). Now a single
        GROUP BY severity with a per-severity CASE that compares first_found
        to that severity's SLA cutoff. The cutoff per severity is pre-computed
        in Python and passed in as a bound param so SQLite can evaluate the
        CASE branch-free.
        """
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {"by_severity": {}, "overall_pct": 0}
        sla_targets = self.db.get_sla_targets()

        # Per-severity SLA cutoff timestamps (detections first_found at or
        # before this stamp have exceeded their SLA window).
        cutoffs = {}
        sla_days_map = {}
        for sev in range(1, 6):
            sla_days = sla_targets.get(sev, self.config.get_sla_days(sev))
            sla_days_map[sev] = sla_days
            cutoffs[sev] = (datetime.utcnow() - timedelta(days=sla_days)).isoformat()

        rows = self.db.conn.execute(
            """SELECT severity,
                      COUNT(*) AS open_count,
                      SUM(CASE
                          WHEN severity = 5 AND first_found <= ? THEN 1
                          WHEN severity = 4 AND first_found <= ? THEN 1
                          WHEN severity = 3 AND first_found <= ? THEN 1
                          WHEN severity = 2 AND first_found <= ? THEN 1
                          WHEN severity = 1 AND first_found <= ? THEN 1
                          ELSE 0 END) AS breach_count
               FROM vm_detections
               WHERE fetched_at = ?
                 AND status IN ('New','Active')
                 AND is_disabled = 0
               GROUP BY severity""",
            (cutoffs[5], cutoffs[4], cutoffs[3], cutoffs[2], cutoffs[1], fetched),
        ).fetchall()

        by_sev_rows = {r["severity"]: r for r in rows}
        results: Dict[int, Dict[str, Any]] = {}
        total_compliant = 0
        total_open = 0
        for sev in range(1, 6):
            r = by_sev_rows.get(sev)
            open_count = r["open_count"] if r else 0
            breach_count = r["breach_count"] if r else 0
            compliant = open_count - breach_count
            total_compliant += compliant
            total_open += open_count
            results[sev] = {
                "total": open_count,
                "compliant": compliant,
                "breaching": breach_count,
                "sla_days": sla_days_map[sev],
                "compliance_pct": round(compliant / max(open_count, 1) * 100, 1),
            }

        overall_pct = round(total_compliant / max(total_open, 1) * 100, 1)
        return {"by_severity": results, "overall_pct": overall_pct}

    def _overall_sla_compliance(self) -> float:
        # sla_compliance is now a single query — no need for a cheaper
        # shortcut variant.
        return self.sla_compliance().get("overall_pct", 0)

    def scan_coverage(self) -> Dict[str, Any]:
        return self.asset_coverage()

    def detection_fix_rate(self, days: int = 7) -> Dict[str, Any]:
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        new_count = self.db.conn.execute(
            "SELECT COUNT(*) FROM detection_changes WHERE change_type = 'new' AND detected_at >= ?",
            (cutoff,),
        ).fetchone()[0]
        fixed_count = self.db.conn.execute(
            "SELECT COUNT(*) FROM detection_changes WHERE change_type = 'fixed' AND detected_at >= ?",
            (cutoff,),
        ).fetchone()[0]
        return {
            "period_days": days,
            "new_vulns": new_count,
            "fixed_vulns": fixed_count,
            "net_change": new_count - fixed_count,
            "fix_ratio": round(fixed_count / max(new_count, 1) * 100, 1),
        }

    def reopen_rate(self) -> Dict[str, Any]:
        fetched = self._fetched_at("vm_detections")
        if not fetched:
            return {"reopened": 0, "total_fixed": 0, "rate_pct": 0}
        row = self.db.conn.execute(
            """SELECT
                 SUM(CASE WHEN status = 'Re-Opened' THEN 1 ELSE 0 END) as reopened,
                 SUM(CASE WHEN status IN ('Fixed','Re-Opened') THEN 1 ELSE 0 END) as total
               FROM vm_detections
               WHERE fetched_at = ? AND is_disabled = 0""",
            (fetched,),
        ).fetchone()
        reopened = row["reopened"] or 0
        total = row["total"] or 1
        return {
            "reopened": reopened,
            "total_fixed": total,
            "rate_pct": round(reopened / total * 100, 1),
        }

    def all_kpis(self, include_disabled: bool = False) -> Dict[str, Any]:
        return {
            "patchable": self.patchable_percentage(),
            "mttr_by_severity": self.mttr_by_severity(),
            "sla_compliance": self.sla_compliance(),
            "scan_coverage": self.scan_coverage(),
            "detection_fix_rate": self.detection_fix_rate(),
            "reopen_rate": self.reopen_rate(),
            "detection_age": self.detection_age(),
            "vuln_overview": self.vuln_overview(include_disabled=include_disabled),
        }

    # ── Tag Analytics ────────────────────────────────────────────

    def tag_summary(self) -> List[Dict]:
        return self.db.get_tag_summary()

    def tag_detail(self, tag_name: str) -> Dict[str, Any]:
        hosts = self.db.get_hosts_by_tag(tag_name, limit=500)
        det_fetched = self._fetched_at("vm_detections")
        vuln_summary = {"total": 0, "by_severity": {}, "by_status": {}}

        if det_fetched and hosts:
            host_ids = [h["host_id"] for h in hosts if h.get("host_id")]
            if host_ids:
                placeholders = ",".join("?" * len(host_ids))
                rows = self.db.conn.execute(
                    f"""SELECT severity, status, COUNT(*) as cnt
                        FROM vm_detections
                        WHERE fetched_at = ? AND host_id IN ({placeholders})
                        AND is_disabled = 0
                        GROUP BY severity, status""",
                    [det_fetched] + host_ids,
                ).fetchall()
                for r in rows:
                    vuln_summary["total"] += r["cnt"]
                    vuln_summary["by_severity"][r["severity"]] = (
                        vuln_summary["by_severity"].get(r["severity"], 0) + r["cnt"]
                    )
                    vuln_summary["by_status"][r["status"]] = (
                        vuln_summary["by_status"].get(r["status"], 0) + r["cnt"]
                    )

        return {"tag_name": tag_name, "hosts": hosts, "vuln_summary": vuln_summary}

    def tag_comparison(self, tag_names: List[str]) -> List[Dict]:
        results = []
        for name in tag_names:
            detail = self.tag_detail(name)
            results.append({
                "tag_name": name,
                "host_count": len(detail["hosts"]),
                "vuln_summary": detail["vuln_summary"],
            })
        return results

    def monitored_tag_dashboard(self) -> List[Dict]:
        if not self.config.monitored_tags:
            return []
        return self.tag_comparison(self.config.monitored_tags)

    # ── Ownership & Cyber 6-Pack ─────────────────────────────────

    def ownership_summary(self) -> List[Dict]:
        """Per-owner metrics from current detection data."""
        det_fetched = self._fetched_at("vm_detections")
        if not det_fetched:
            return []

        owners = self.db.get_owners()
        if not owners:
            return []

        # Build owner → IPs mapping
        owner_ips: Dict[str, Dict] = {}
        for rule in owners:
            key = rule["owner"]
            if key not in owner_ips:
                owner_ips[key] = {"owner": key, "business_unit": rule.get("business_unit", ""), "ips": set()}
            if rule["match_type"] == "ip":
                owner_ips[key]["ips"].add(rule["match_value"])

        results = []
        for owner_name, info in owner_ips.items():
            if not info["ips"]:
                continue
            ips = list(info["ips"])
            placeholders = ",".join("?" * len(ips))
            row = self.db.conn.execute(
                f"""SELECT
                      COUNT(*) as total_vulns,
                      SUM(CASE WHEN severity >= 4 THEN 1 ELSE 0 END) as critical,
                      AVG(severity) as avg_severity
                    FROM vm_detections
                    WHERE fetched_at = ? AND ip_address IN ({placeholders})
                    AND status IN ('New','Active') AND is_disabled = 0""",
                [det_fetched] + ips,
            ).fetchone()
            results.append({
                "owner": owner_name,
                "business_unit": info["business_unit"],
                "host_count": len(ips),
                "total_vulns": row["total_vulns"] or 0,
                "critical": row["critical"] or 0,
                "avg_severity": round(row["avg_severity"] or 0, 1),
            })
        results.sort(key=lambda x: x["total_vulns"], reverse=True)
        return results

    def cyber_six_pack(self, group_by: str = "owner") -> Dict[str, Any]:
        """Cyber 6-Pack view: weighted avg age + SLA breaches per group."""
        det_fetched = self._fetched_at("vm_detections")
        if not det_fetched:
            return {"groups": [], "enterprise": {}}

        sla_targets = self.db.get_sla_targets()

        if group_by == "tag":
            groups = self._six_pack_by_tag(det_fetched, sla_targets)
        elif group_by == "os":
            groups = self._six_pack_by_os(det_fetched, sla_targets)
        else:
            groups = self._six_pack_by_owner(det_fetched, sla_targets)

        # Enterprise summary
        total_weighted_age = sum(g["weighted_avg_age"] * g["total_vulns"] for g in groups)
        total_vulns = sum(g["total_vulns"] for g in groups)
        total_breaching = sum(g["sla_breaching"] for g in groups)
        enterprise = {
            "weighted_avg_age": round(total_weighted_age / max(total_vulns, 1), 1),
            "total_vulns": total_vulns,
            "sla_breaching": total_breaching,
            "sla_compliance_pct": round((total_vulns - total_breaching) / max(total_vulns, 1) * 100, 1),
        }

        return {"groups": groups, "enterprise": enterprise}

    def cyber_six_pack_trend(self, group_by: str = "owner", months_back: int = 12) -> Dict[str, Any]:
        """Month-over-month Cyber 6-Pack trend.

        Returns {months: ['YYYY-MM', ...], groups: [{name, avg_age:[...], sla_breaches:[...]}, ...]}

        Approach: take the current detection snapshot, bucket each open detection by the
        month of its `first_found` date, then for each group compute per-bucket:
          - avg_age (mean days from first_found to now, across detections in that bucket)
          - sla_breaches (detections in that bucket whose age exceeds the per-severity SLA window)
        This yields a directional view of how each group's aging cohort has grown.
        """
        det_fetched = self._fetched_at("vm_detections")
        if not det_fetched:
            return {"months": [], "groups": []}

        sla = self.db.get_sla_targets()

        # Build month labels (oldest → newest), aligned to the 1st of each month
        now = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        months: List[str] = []
        for m in range(months_back - 1, -1, -1):
            # Walk back m whole months
            y, mo = now.year, now.month - m
            while mo <= 0:
                mo += 12
                y -= 1
            months.append(f"{y:04d}-{mo:02d}")

        # Determine group → list of IPs (reuse the same grouping as cyber_six_pack)
        if group_by == "tag":
            group_rows = self._six_pack_by_tag(det_fetched, sla)
            group_ips = {g["name"]: self._ips_for_tag(g["name"]) for g in group_rows[:8]}
        elif group_by == "os":
            group_rows = self._six_pack_by_os(det_fetched, sla)
            group_ips = {g["name"]: self._ips_for_os(g["name"]) for g in group_rows[:8]}
        else:
            # owner — batch-resolve to avoid a per-IP DB trip per host (the
            # trend view used to scale O(n_hosts) × months).
            host_fetched = self._fetched_at("vm_hosts")
            group_ips = {}
            if host_fetched:
                all_ips = [
                    r["ip_address"] for r in self.db.conn.execute(
                        "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
                        (host_fetched,),
                    ).fetchall()
                ]
                resolved_groups = self._group_ips_by_owner(all_ips)
                group_ips = {name: info["ips"] for name, info in resolved_groups.items()}
            # Keep top 8 groups by IP count so charts stay readable
            group_ips = dict(sorted(group_ips.items(), key=lambda kv: len(kv[1]), reverse=True)[:8])

        # For each group, compute per-month metrics by first_found bucket.
        # We push bucketing + aggregation into SQL so we stream O(months)
        # rows out per group instead of O(n_detections) across the wire and
        # re-summing them in Python. At production scale each group can have
        # 100k+ detections; the old path pulled every row back, the new one
        # pulls ≤ months_back rows.
        groups_out: List[Dict] = []
        # SLA window per severity — used inline in the CASE below.
        sla5, sla4, sla3, sla2, sla1 = (sla.get(s, 365) for s in (5, 4, 3, 2, 1))
        for name, ips in group_ips.items():
            if not ips:
                continue
            ph = ",".join("?" * len(ips))
            rows = self.db.conn.execute(
                f"""SELECT substr(first_found, 1, 7) AS ym,
                           AVG(julianday('now') - julianday(first_found)) AS avg_age,
                           COUNT(*) AS cnt,
                           SUM(CASE
                               WHEN severity = 5
                                    AND (julianday('now') - julianday(first_found)) > ? THEN 1
                               WHEN severity = 4
                                    AND (julianday('now') - julianday(first_found)) > ? THEN 1
                               WHEN severity = 3
                                    AND (julianday('now') - julianday(first_found)) > ? THEN 1
                               WHEN severity = 2
                                    AND (julianday('now') - julianday(first_found)) > ? THEN 1
                               WHEN severity = 1
                                    AND (julianday('now') - julianday(first_found)) > ? THEN 1
                               ELSE 0 END) AS breach_count
                    FROM vm_detections
                    WHERE fetched_at = ? AND ip_address IN ({ph})
                      AND status IN ('New','Active') AND is_disabled = 0
                      AND first_found != ''
                    GROUP BY ym""",
                [sla5, sla4, sla3, sla2, sla1, det_fetched] + ips,
            ).fetchall()

            # Key by month; fill missing months with zero so the chart x-axis
            # aligns across groups.
            by_month = {r["ym"]: r for r in rows}
            avg_age_series = [
                round(by_month[m]["avg_age"], 1)
                if m in by_month and by_month[m]["avg_age"] is not None else 0
                for m in months
            ]
            sla_series = [
                by_month[m]["breach_count"] if m in by_month else 0
                for m in months
            ]
            total_series = [
                by_month[m]["cnt"] if m in by_month else 0
                for m in months
            ]
            groups_out.append({
                "name": name,
                "avg_age": avg_age_series,
                "sla_breaches": sla_series,
                "total_vulns": total_series,
            })

        return {"months": months, "groups": groups_out}

    def _ips_for_tag(self, tag_name: str) -> List[str]:
        hosts = self.db.get_hosts_by_tag(tag_name, limit=500)
        return [h["ip_address"] for h in hosts if h.get("ip_address")]

    def _ips_for_os(self, os_name: str) -> List[str]:
        fetched = self._fetched_at("vm_hosts")
        if not fetched:
            return []
        rows = self.db.conn.execute(
            "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ? AND os = ?",
            (fetched, os_name),
        ).fetchall()
        return [r["ip_address"] for r in rows]

    def _batch_resolve_owners(self, ips: List[str]) -> Dict[str, Dict[str, str]]:
        """Resolve owner + business_unit for a list of IPs in O(N) DB trips.

        Mirrors `db.get_asset_owner`'s precedence — direct IP → IP range →
        host tag → OS pattern — but fetches every rule table once and every
        host-scoped fact (tags, OS) once, then does the matching in Python.
        At production scale (104k VM hosts) this collapses ~104k sequential
        queries into ~5, which was the single biggest hit on the 6-Pack page.

        Unmatched IPs are omitted from the result; callers should treat a
        missing key as "Unassigned".
        """
        import ipaddress as ipm

        # One fetch per match_type. Keeps query count O(1) regardless of |ips|.
        rule_rows = self.db.conn.execute(
            "SELECT match_type, match_value, owner, business_unit FROM asset_owners"
        ).fetchall()
        ip_rules: Dict[str, Dict[str, str]] = {}
        range_rules: List[Dict[str, Any]] = []
        tag_rules: Dict[str, Dict[str, str]] = {}
        os_rules: List[Dict[str, Any]] = []
        for r in rule_rows:
            entry = {"owner": r["owner"], "business_unit": r["business_unit"] or ""}
            mt = r["match_type"]
            if mt == "ip":
                ip_rules[r["match_value"]] = entry
            elif mt == "ip_range":
                try:
                    range_rules.append({
                        "network": ipm.ip_network(r["match_value"], strict=False),
                        **entry,
                    })
                except ValueError:
                    continue
            elif mt == "tag":
                tag_rules[r["match_value"]] = entry
            elif mt == "os_pattern":
                os_rules.append({
                    "pattern": r["match_value"].replace("%", "").lower(),
                    **entry,
                })

        # Lazy-load tag / OS facts only if any rule type might need them.
        ip_tags: Dict[str, set] = {}
        if tag_rules:
            tag_fetched = self._fetched_at("host_tags")
            if tag_fetched:
                for r in self.db.conn.execute(
                    "SELECT ip_address, tag_name FROM host_tags WHERE fetched_at = ?",
                    (tag_fetched,),
                ).fetchall():
                    ip_tags.setdefault(r["ip_address"], set()).add(r["tag_name"])

        ip_os: Dict[str, str] = {}
        if os_rules:
            host_fetched = self._fetched_at("vm_hosts")
            if host_fetched:
                for r in self.db.conn.execute(
                    "SELECT ip_address, os FROM vm_hosts WHERE fetched_at = ? AND os != ''",
                    (host_fetched,),
                ).fetchall():
                    ip_os[r["ip_address"]] = r["os"]

        resolved: Dict[str, Dict[str, str]] = {}
        for ip in ips:
            # 1. direct IP
            if ip in ip_rules:
                resolved[ip] = ip_rules[ip]
                continue
            # 2. IP range
            addr = None
            if range_rules:
                try:
                    addr = ipm.ip_address(ip)
                except ValueError:
                    addr = None
                if addr is not None:
                    hit = next((r for r in range_rules if addr in r["network"]), None)
                    if hit:
                        resolved[ip] = {"owner": hit["owner"], "business_unit": hit["business_unit"]}
                        continue
            # 3. tag-based
            if tag_rules:
                tags = ip_tags.get(ip, set())
                hit_name = next((t for t in tags if t in tag_rules), None)
                if hit_name:
                    resolved[ip] = tag_rules[hit_name]
                    continue
            # 4. OS pattern
            if os_rules:
                host_os = ip_os.get(ip, "").lower()
                if host_os:
                    hit = next((r for r in os_rules if r["pattern"] in host_os), None)
                    if hit:
                        resolved[ip] = {"owner": hit["owner"], "business_unit": hit["business_unit"]}
                        continue
        return resolved

    def _group_ips_by_owner(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """Batch-group a list of IPs by resolved owner (Unassigned for misses).

        Returns `{owner_name: {"ips": [...], "business_unit": "..."}}`.
        """
        resolved = self._batch_resolve_owners(ips)
        groups: Dict[str, Dict[str, Any]] = {}
        for ip in ips:
            entry = resolved.get(ip)
            name = entry["owner"] if entry else "Unassigned"
            bu = entry["business_unit"] if entry else ""
            g = groups.setdefault(name, {"ips": [], "business_unit": bu})
            g["ips"].append(ip)
        return groups

    def _six_pack_by_owner(self, fetched: str, sla: Dict) -> List[Dict]:
        # Get all VM host IPs, resolve each to an owner, group by owner
        host_fetched = self._fetched_at("vm_hosts")
        if not host_fetched:
            return []
        rows = self.db.conn.execute(
            "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ?",
            (host_fetched,),
        ).fetchall()
        all_ips = [r["ip_address"] for r in rows]

        # Batch-resolve owners in one pass (vs. the old per-IP query loop).
        owner_groups = self._group_ips_by_owner(all_ips)

        groups = []
        for owner_name, info in owner_groups.items():
            ips = info["ips"]
            metrics = self._six_pack_metrics_for_ips(fetched, ips, sla)
            metrics["name"] = owner_name
            metrics["business_unit"] = info["business_unit"]
            metrics["host_count"] = len(ips)
            groups.append(metrics)
        return sorted(groups, key=lambda x: x["total_vulns"], reverse=True)

    def _six_pack_by_tag(self, fetched: str, sla: Dict) -> List[Dict]:
        tag_fetched = self._fetched_at("host_tags")
        if not tag_fetched:
            return []
        tags = self.db.get_all_tags()
        groups = []
        for tag_name in tags[:20]:  # Top 20 tags
            hosts = self.db.get_hosts_by_tag(tag_name, limit=500)
            ips = [h["ip_address"] for h in hosts if h.get("ip_address")]
            if not ips:
                continue
            metrics = self._six_pack_metrics_for_ips(fetched, ips, sla)
            metrics["name"] = tag_name
            metrics["host_count"] = len(ips)
            groups.append(metrics)
        return sorted(groups, key=lambda x: x["total_vulns"], reverse=True)

    def _six_pack_by_os(self, fetched: str, sla: Dict) -> List[Dict]:
        host_fetched = self._fetched_at("vm_hosts")
        if not host_fetched:
            return []
        rows = self.db.conn.execute(
            "SELECT DISTINCT os FROM vm_hosts WHERE fetched_at = ? AND os != '' LIMIT 20",
            (host_fetched,),
        ).fetchall()
        groups = []
        for r in rows:
            os_name = r["os"]
            ip_rows = self.db.conn.execute(
                "SELECT DISTINCT ip_address FROM vm_hosts WHERE fetched_at = ? AND os = ?",
                (host_fetched, os_name),
            ).fetchall()
            ips = [row["ip_address"] for row in ip_rows]
            if not ips:
                continue
            metrics = self._six_pack_metrics_for_ips(fetched, ips, sla)
            metrics["name"] = os_name
            metrics["host_count"] = len(ips)
            groups.append(metrics)
        return sorted(groups, key=lambda x: x["total_vulns"], reverse=True)

    def _six_pack_metrics_for_ips(self, fetched: str, ips: List[str], sla: Dict) -> Dict:
        placeholders = ",".join("?" * len(ips))

        # Precompute per-severity SLA cutoff timestamps so the breach check
        # can be folded into the same aggregation query as total + weighted age.
        # Was: 6 queries (1 age + 5 severity). Now: 1 query.
        cutoffs = {
            sev: (datetime.utcnow() - timedelta(days=sla.get(sev, 365))).isoformat()
            for sev in range(1, 6)
        }
        row = self.db.conn.execute(
            f"""SELECT
                  SUM(julianday('now') - julianday(first_found)) AS total_age,
                  COUNT(*) AS cnt,
                  SUM(CASE
                      WHEN severity = 5 AND first_found <= ? THEN 1
                      WHEN severity = 4 AND first_found <= ? THEN 1
                      WHEN severity = 3 AND first_found <= ? THEN 1
                      WHEN severity = 2 AND first_found <= ? THEN 1
                      WHEN severity = 1 AND first_found <= ? THEN 1
                      ELSE 0 END) AS breach_count
                FROM vm_detections
                WHERE fetched_at = ? AND ip_address IN ({placeholders})
                  AND status IN ('New','Active') AND is_disabled = 0
                  AND first_found != ''""",
            [cutoffs[5], cutoffs[4], cutoffs[3], cutoffs[2], cutoffs[1], fetched] + ips,
        ).fetchone()
        total_vulns = row["cnt"] or 0
        weighted_age = round((row["total_age"] or 0) / max(total_vulns, 1), 1)
        breach_count = row["breach_count"] or 0

        # Average TruRisk score for hosts in the group
        host_fetched = self._fetched_at("vm_hosts")
        avg_trurisk = None
        if host_fetched:
            tr_row = self.db.conn.execute(
                f"""SELECT AVG(trurisk_score) AS avg_tr
                    FROM vm_hosts
                    WHERE fetched_at = ? AND trurisk_score > 0
                      AND ip_address IN ({placeholders})""",
                [host_fetched] + ips,
            ).fetchone()
            if tr_row and tr_row["avg_tr"] is not None:
                avg_trurisk = round(tr_row["avg_tr"], 0)

        return {
            "total_vulns": total_vulns,
            "weighted_avg_age": weighted_age,
            "sla_breaching": breach_count,
            "sla_compliance_pct": round((total_vulns - breach_count) / max(total_vulns, 1) * 100, 1),
            "avg_trurisk": avg_trurisk,
        }

    # ── Trend Analytics ──────────────────────────────────────────

    def weekly_trends(self, weeks_back: int = 12) -> List[Dict]:
        return self.db.get_weekly_rollups(weeks_back)

    def monthly_trends(self, months_back: int = 12) -> List[Dict]:
        return self.db.get_monthly_rollups(months_back)

    def recent_changes(self, days_back: int = 7) -> Dict[str, Any]:
        cutoff = (datetime.utcnow() - timedelta(days=days_back)).isoformat()
        rows = self.db.conn.execute(
            """SELECT change_type, COUNT(*) as cnt
               FROM detection_changes WHERE detected_at >= ?
               GROUP BY change_type""",
            (cutoff,),
        ).fetchall()
        by_type = {r["change_type"]: r["cnt"] for r in rows}
        return {
            "period_days": days_back,
            "new": by_type.get("new", 0),
            "fixed": by_type.get("fixed", 0),
            "reopened": by_type.get("reopened", 0),
            "severity_change": by_type.get("severity_change", 0),
        }

    def week_over_week(self) -> Dict[str, Any]:
        rollups = self.db.get_weekly_rollups(2)
        if len(rollups) < 2:
            return {"current": rollups[0] if rollups else {}, "previous": {}, "deltas": {}}
        current = rollups[-1]
        previous = rollups[-2]
        deltas = {}
        for key in ("total_vulns", "sev5_count", "sev4_count", "status_new",
                     "status_active", "status_fixed", "avg_trurisk", "total_hosts"):
            c = current.get(key, 0) or 0
            p = previous.get(key, 0) or 0
            deltas[key] = c - p
        return {"current": current, "previous": previous, "deltas": deltas}

    # ── GFS Rollup Computation ───────────────────────────────────

    def compute_weekly_rollup(self) -> Dict:
        """Compute and store current week's rollup from live data."""
        now = datetime.utcnow()
        # Monday of current week
        monday = now - timedelta(days=now.weekday())
        week_start = monday.strftime("%Y-%m-%d")

        overview = self.vuln_overview()
        coverage = self.asset_coverage()
        age = self.detection_age()

        # New/fixed this week from change log
        week_cutoff = monday.isoformat()
        new_this_week = self.db.conn.execute(
            "SELECT COUNT(*) FROM detection_changes WHERE change_type = 'new' AND detected_at >= ?",
            (week_cutoff,),
        ).fetchone()[0]
        fixed_this_week = self.db.conn.execute(
            "SELECT COUNT(*) FROM detection_changes WHERE change_type = 'fixed' AND detected_at >= ?",
            (week_cutoff,),
        ).fetchone()[0]

        # TruRisk stats
        fetched_hosts = self._fetched_at("vm_hosts")
        avg_trurisk = 0
        max_trurisk = 0
        if fetched_hosts:
            row = self.db.conn.execute(
                "SELECT AVG(trurisk_score) as avg_tr, MAX(trurisk_score) as max_tr FROM vm_hosts WHERE fetched_at = ?",
                (fetched_hosts,),
            ).fetchone()
            avg_trurisk = round(row["avg_tr"] or 0, 1)
            max_trurisk = row["max_tr"] or 0

        # QDS average
        fetched_det = self._fetched_at("vm_detections")
        avg_qds = 0
        if fetched_det:
            row = self.db.conn.execute(
                "SELECT AVG(qds) FROM vm_detections WHERE fetched_at = ? AND is_disabled = 0 AND qds > 0",
                (fetched_det,),
            ).fetchone()
            avg_qds = round(row[0] or 0, 1)

        # Tag metrics for monitored tags
        tag_metrics = {}
        if self.config.monitored_tags:
            for tag_name in self.config.monitored_tags:
                detail = self.tag_detail(tag_name)
                tag_metrics[tag_name] = {
                    "host_count": len(detail["hosts"]),
                    "vuln_count": detail["vuln_summary"]["total"],
                    "by_severity": detail["vuln_summary"]["by_severity"],
                }

        data = {
            "week_start": week_start,
            "total_vulns": overview["total"],
            "sev5_count": overview["by_severity"].get(5, 0),
            "sev4_count": overview["by_severity"].get(4, 0),
            "sev3_count": overview["by_severity"].get(3, 0),
            "sev2_count": overview["by_severity"].get(2, 0),
            "sev1_count": overview["by_severity"].get(1, 0),
            "status_new": overview["by_status"].get("New", 0),
            "status_active": overview["by_status"].get("Active", 0),
            "status_fixed": overview["by_status"].get("Fixed", 0),
            "status_reopened": overview["by_status"].get("Re-Opened", 0),
            "new_this_week": new_this_week,
            "fixed_this_week": fixed_this_week,
            "avg_trurisk": avg_trurisk,
            "max_trurisk": max_trurisk,
            "avg_qds": avg_qds,
            "total_hosts": coverage["total_unique_ips"],
            "csam_hosts": coverage["csam_only"] + coverage["both"],
            "vm_hosts": coverage["vm_only"] + coverage["both"],
            "both_hosts": coverage["both"],
            "coverage_pct": coverage["coverage_pct"],
            "aging_30d": age.get("aging_30d", 0),
            "aging_60d": age.get("aging_60d", 0),
            "aging_90d": age.get("aging_90d", 0),
            "tag_metrics": tag_metrics,
        }
        self.db.save_weekly_rollup(data)
        logger.info(f"Computed weekly rollup for {week_start}")
        return data

    def compute_monthly_rollup(self) -> Optional[Dict]:
        """Compute monthly rollup from the latest weekly data."""
        now = datetime.utcnow()
        month_start = now.strftime("%Y-%m-01")

        # Check if we already have one for this month
        existing = self.db.conn.execute(
            "SELECT id FROM monthly_rollups WHERE month_start = ?", (month_start,)
        ).fetchone()

        # Get latest weekly rollup data (use it as the monthly snapshot)
        weekly = self.db.get_weekly_rollups(1)
        if not weekly:
            return None

        latest = weekly[-1]
        data = {**latest, "month_start": month_start}
        # Rename week-specific fields
        data.pop("week_start", None)
        data.pop("id", None)
        data.pop("computed_at", None)
        data["new_this_month"] = data.pop("new_this_week", 0)
        data["fixed_this_month"] = data.pop("fixed_this_week", 0)

        self.db.save_monthly_rollup(data)
        logger.info(f"Computed monthly rollup for {month_start}")
        return data

    # ── Change Detection ─────────────────────────────────────────

    def detect_changes(self, old_detections: Dict[str, Dict],
                       new_detections: List[Dict], detected_at: str) -> List[Dict]:
        """Diff old vs new detections and return change records."""
        changes = []
        new_keys = set()

        for det in new_detections:
            key = f"{det.get('host_id', 0)}:{det.get('qid', det.get('QID', 0))}"
            new_keys.add(key)

            if key not in old_detections:
                changes.append({
                    "host_id": det.get("host_id", 0),
                    "ip_address": det.get("ip", ""),
                    "qid": det.get("qid", det.get("QID", 0)),
                    "change_type": "new",
                    "old_value": None,
                    "new_value": det.get("status", det.get("STATUS", "")),
                    "severity": det.get("severity", det.get("SEVERITY", 0)),
                    "detected_at": detected_at,
                })
            else:
                old = old_detections[key]
                new_status = det.get("status", det.get("STATUS", ""))
                old_status = old.get("status", "")

                if old_status == "Fixed" and new_status in ("Active", "New", "Re-Opened"):
                    changes.append({
                        "host_id": det.get("host_id", 0),
                        "ip_address": det.get("ip", ""),
                        "qid": det.get("qid", det.get("QID", 0)),
                        "change_type": "reopened",
                        "old_value": old_status,
                        "new_value": new_status,
                        "severity": det.get("severity", det.get("SEVERITY", 0)),
                        "detected_at": detected_at,
                    })
                elif old_status != new_status:
                    change_type = "fixed" if new_status == "Fixed" else "status_change"
                    changes.append({
                        "host_id": det.get("host_id", 0),
                        "ip_address": det.get("ip", ""),
                        "qid": det.get("qid", det.get("QID", 0)),
                        "change_type": change_type,
                        "old_value": old_status,
                        "new_value": new_status,
                        "severity": det.get("severity", det.get("SEVERITY", 0)),
                        "detected_at": detected_at,
                    })

        # Detections that disappeared (possibly fixed)
        for key, old in old_detections.items():
            if key not in new_keys and old.get("status") != "Fixed":
                parts = key.split(":")
                changes.append({
                    "host_id": int(parts[0]) if parts[0].isdigit() else 0,
                    "ip_address": "",
                    "qid": int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                    "change_type": "fixed",
                    "old_value": old.get("status", ""),
                    "new_value": "Fixed",
                    "severity": old.get("severity", 0),
                    "detected_at": detected_at,
                })

        return changes

    # ── Purge ────────────────────────────────────────────────────

    def purge_snapshots(self) -> Dict[str, Any]:
        """Enforce GFS retention policy."""
        daily = self.db.purge_daily_snapshots(self.config.daily_retention_days)
        weekly = self.db.purge_weekly_rollups(self.config.weekly_retention_weeks)
        return {"daily_purged": daily, "weekly_rollups_purged": weekly}
