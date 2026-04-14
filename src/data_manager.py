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
from datetime import datetime
from typing import Dict, Any, List, Optional

from .config_loader import QualysDAConfig
from .database import QualysDADatabase
from .api_client import QualysClient, QualysError
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
        """Full refresh: fetch all 3 APIs, diff, save, compute rollups, purge."""
        refresh_id = self.db.log_refresh("all")
        now = datetime.utcnow().isoformat()
        counts = {"csam": 0, "vm_hosts": 0, "vm_detections": 0, "changes": 0}

        try:
            # Get previous detection state for diffing
            old_detections = self.db.get_previous_detections()

            # Fetch from all APIs
            csam_assets = self.client.fetch_csam_assets()
            vm_hosts = self.client.fetch_vm_hosts()
            vm_detections = self.client.fetch_vm_detections()

            # Save data
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

            self.db.complete_refresh(refresh_id, **counts)
            logger.info(f"Refresh complete: {counts}")

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
