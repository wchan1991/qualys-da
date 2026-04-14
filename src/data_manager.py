"""
Data Manager

Coordinator singleton that orchestrates:
- Data refresh (fetch from APIs → diff changes → save → compute rollups → purge)
- Query delegation
- CSV export
"""

import csv
import io
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any, List, Optional

from .config_loader import QualysDAConfig
from .database import QualysDADatabase
from .api_client import QualysClient, QualysError, AuthError
from .analytics import AnalyticsEngine

logger = logging.getLogger(__name__)


class DataManager:
    """
    High-level coordinator for data operations.

    Used as a lazy singleton in app.py via get_manager().
    """

    def __init__(self, config: QualysDAConfig):
        self.config = config
        self.db = QualysDADatabase(config.db_path)
        self.analytics = AnalyticsEngine(self.db, config)
        self._client: Optional[QualysClient] = None

    @property
    def client(self) -> QualysClient:
        if self._client is None:
            self._client = QualysClient(self.config)
        return self._client

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── Refresh ──────────────────────────────────────────────────

    def refresh_all(self) -> Dict[str, Any]:
        """Full refresh with three upgrades over the old sequential path:

        1. **Preflight auth** — verifies VM + CSAM credentials before any DB
           writes, so bad creds / firewall blocks fail in ~1–2 seconds
           instead of deep inside a partial pull.
        2. **Expected counts** — queries Qualys count endpoints upfront so
           the log shows "N assets expected" before pagination starts. The
           operator can tell instantly whether the refresh is small or huge.
        3. **Parallel pull** — CSAM on one thread, VM (hosts→detections) on
           another. Wall-clock roughly halves on typical tenants. Gated by
           `config.parallel_refresh` (set false to revert to sequential).
           The rate-limiter is now thread-safe (see api_client.RateLimiter).
        """
        refresh_id = self.db.log_refresh("all")
        now = datetime.utcnow().isoformat()
        counts = {"csam": 0, "vm_hosts": 0, "vm_detections": 0, "changes": 0}

        try:
            logger.info("=" * 60)
            logger.info("Starting full refresh")
            logger.info("=" * 60)

            # ── 1. Preflight auth: fail fast on bad creds ────────────
            try:
                self.client.ensure_authenticated()
            except AuthError as e:
                logger.error(f"Refresh aborted — auth failed: {e}")
                self.db.complete_refresh(
                    refresh_id, status="failed", error=f"auth: {e}"
                )
                raise

            # ── 2. Preflight counts (non-fatal if endpoint unavailable) ──
            csam_expected = self.client.count_csam_assets()
            vm_host_expected = self.client.count_vm_hosts()
            vm_det_expected = self.client.count_vm_detections()

            def _fmt(n):
                return f"{n:,}" if n is not None else "unknown"

            logger.info(
                f"Expected volumes — CSAM assets: {_fmt(csam_expected)} · "
                f"VM hosts: {_fmt(vm_host_expected)} · "
                f"VM detections: {_fmt(vm_det_expected)}"
            )

            # Snapshot previous detection state for diffing (before new data lands)
            old_detections = self.db.get_previous_detections()

            # ── 3. Fetch: parallel (default) or sequential (config opt-out) ──
            if self.config.parallel_refresh:
                logger.info("Fetching CSAM and VM in parallel...")

                def _csam_thread():
                    return self.client.fetch_csam_assets(expected=csam_expected)

                def _vm_thread():
                    # Hosts + detections share the VM session's auth cookie and
                    # the VM rate-limit bucket, so keep them sequential *inside*
                    # this thread — parallelizing them offers little speedup
                    # and risks tripping the VM rate limit.
                    hosts = self.client.fetch_vm_hosts(expected=vm_host_expected)
                    dets = self.client.fetch_vm_detections(expected=vm_det_expected)
                    return hosts, dets

                with ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="refresh"
                ) as pool:
                    csam_future = pool.submit(_csam_thread)
                    vm_future = pool.submit(_vm_thread)
                    csam_assets = csam_future.result()
                    vm_hosts, vm_detections = vm_future.result()
            else:
                logger.info("Fetching sequentially (parallel_refresh=false)...")
                csam_assets = self.client.fetch_csam_assets(expected=csam_expected)
                vm_hosts = self.client.fetch_vm_hosts(expected=vm_host_expected)
                vm_detections = self.client.fetch_vm_detections(expected=vm_det_expected)

            # ── 4. DB writes (single-threaded) ───────────────────────
            counts["csam"] = self.db.save_csam_assets(csam_assets, now)
            counts["vm_hosts"] = self.db.save_vm_hosts(vm_hosts, now)
            counts["vm_detections"] = self.db.save_vm_detections(vm_detections, now)

            # Extract and save tags
            csam_tags = QualysClient.extract_tags_from_csam(csam_assets)
            vm_host_tags = QualysClient.extract_tags_from_vm_hosts(vm_hosts)
            vm_det_tags = QualysClient.extract_tags_from_detections(vm_detections)
            all_tags = csam_tags + vm_host_tags + vm_det_tags
            self.db.save_host_tags(all_tags, now)

            # Detect and save changes
            changes = self.analytics.detect_changes(old_detections, vm_detections, now)
            counts["changes"] = self.db.save_detection_changes(changes)

            # Compute rollups
            self.analytics.compute_weekly_rollup()
            # Monthly rollup on first day of month or first refresh of month
            today = datetime.utcnow()
            if today.day <= 7:
                self.analytics.compute_monthly_rollup()

            # GFS retention
            self.analytics.purge_snapshots()

            self.db.complete_refresh(
                refresh_id,
                csam_expected=csam_expected,
                vm_host_expected=vm_host_expected,
                vm_detection_expected=vm_det_expected,
                **counts,
            )
            logger.info(f"Refresh complete: {counts}")

        except AuthError:
            # Already logged + marked failed above; don't double-log.
            raise
        except Exception as e:
            logger.exception(f"Refresh failed: {e}")
            self.db.complete_refresh(refresh_id, status="failed", error=str(e))
            raise

        return counts

    def refresh_csam(self) -> int:
        refresh_id = self.db.log_refresh("csam")
        now = datetime.utcnow().isoformat()
        try:
            assets = self.client.fetch_csam_assets()
            count = self.db.save_csam_assets(assets, now)
            tags = QualysClient.extract_tags_from_csam(assets)
            self.db.save_host_tags(tags, now)
            self.db.complete_refresh(refresh_id, csam=count)
            return count
        except Exception as e:
            self.db.complete_refresh(refresh_id, status="failed", error=str(e))
            raise

    def refresh_vm_hosts(self) -> int:
        refresh_id = self.db.log_refresh("vm-hosts")
        now = datetime.utcnow().isoformat()
        try:
            hosts = self.client.fetch_vm_hosts()
            count = self.db.save_vm_hosts(hosts, now)
            tags = QualysClient.extract_tags_from_vm_hosts(hosts)
            self.db.save_host_tags(tags, now)
            self.db.complete_refresh(refresh_id, vm_hosts=count)
            return count
        except Exception as e:
            self.db.complete_refresh(refresh_id, status="failed", error=str(e))
            raise

    def refresh_vm_detections(self) -> int:
        refresh_id = self.db.log_refresh("vm-detections")
        now = datetime.utcnow().isoformat()
        try:
            old_detections = self.db.get_previous_detections()
            detections = self.client.fetch_vm_detections()
            count = self.db.save_vm_detections(detections, now)
            tags = QualysClient.extract_tags_from_detections(detections)
            self.db.save_host_tags(tags, now)
            changes = self.analytics.detect_changes(old_detections, detections, now)
            self.db.save_detection_changes(changes)
            self.analytics.compute_weekly_rollup()
            self.db.complete_refresh(refresh_id, vm_detections=count, changes=len(changes))
            return count
        except Exception as e:
            self.db.complete_refresh(refresh_id, status="failed", error=str(e))
            raise

    # ── Query Delegation ─────────────────────────────────────────

    def get_dashboard(self) -> Dict[str, Any]:
        return self.analytics.dashboard_summary()

    def query_detections(self, **filters) -> List[Dict]:
        return self.db.get_latest_detections(**filters)

    def get_host_detail(self, ip: str) -> Dict[str, Any]:
        return self.db.get_joined_host_data(ip)

    def health_check(self) -> Dict[str, Any]:
        return self.client.health_check()

    # ── CSV Export ────────────────────────────────────────────────

    def export_csv(self, export_type: str = "detections", **filters) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        if export_type == "detections":
            writer.writerow([
                "Host ID", "IP", "DNS", "OS", "QID", "Type", "Severity",
                "Status", "QDS", "First Found", "Last Found", "Times Found",
            ])
            rows = self.db.get_latest_detections(limit=100000, **filters)
            for r in rows:
                writer.writerow([
                    r.get("host_id"), r.get("ip_address"), r.get("dns", ""),
                    r.get("os", ""), r.get("qid"), r.get("detection_type"),
                    r.get("severity"), r.get("status"), r.get("qds"),
                    r.get("first_found"), r.get("last_found"), r.get("times_found"),
                ])

        elif export_type == "hosts":
            writer.writerow([
                "Host ID", "IP", "DNS", "NetBIOS", "OS", "TruRisk",
                "Last Scan", "Last Activity", "Tracking Method",
            ])
            rows = self.db.get_latest_vm_hosts(limit=100000, **filters)
            for r in rows:
                writer.writerow([
                    r.get("host_id"), r.get("ip_address"), r.get("dns"),
                    r.get("netbios"), r.get("os"), r.get("trurisk_score"),
                    r.get("last_scan_date"), r.get("last_activity_date"),
                    r.get("tracking_method"),
                ])

        elif export_type == "assets":
            writer.writerow([
                "Asset ID", "Name", "IP", "OS", "Last Seen",
            ])
            rows = self.db.get_latest_csam_assets(limit=100000, **filters)
            for r in rows:
                writer.writerow([
                    r.get("asset_id"), r.get("name"), r.get("ip_address"),
                    r.get("os"), r.get("last_seen"),
                ])

        elif export_type == "kpis":
            kpis = self.analytics.all_kpis()
            writer.writerow(["KPI", "Value"])
            writer.writerow(["Patchable %", kpis["patchable"]["patchable_pct"]])
            writer.writerow(["SLA Compliance %", kpis["sla_compliance"]["overall_pct"]])
            writer.writerow(["Reopen Rate %", kpis["reopen_rate"]["rate_pct"]])
            writer.writerow(["Mean Time to Remediate (days)", kpis["detection_age"]["mean_days_to_remediate"]])
            for sev, days in kpis["mttr_by_severity"].items():
                writer.writerow([f"MTTR Severity {sev}", days])

        return output.getvalue()
