"""
Database Module

SQLite database for Qualys Data Analytics:
- CSAM asset storage
- VM host and detection storage
- Normalized tag storage
- Asset ownership mapping
- GFS rollup tables (weekly + monthly)
- Detection change log
- Custom saved queries

Thread-safe: Creates new connections per-thread for Flask compatibility.
"""

import sqlite3
import json
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class QualysDADatabase:
    """
    Thread-safe SQLite database for Qualys data analytics.

    Creates a new connection for each thread to avoid SQLite threading issues.
    Uses WAL mode and tuned cache for performance at scale.
    """

    def __init__(self, db_path: str = "data/qualys_da.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._local = threading.local()
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path), check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
            # Performance tuning
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA cache_size=-64000")  # 64MB
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            logger.debug(
                f"Created new DB connection for thread {threading.current_thread().name}"
            )
        return self._local.conn

    @property
    def conn(self) -> sqlite3.Connection:
        return self._get_connection()

    def _init_schema(self) -> None:
        cursor = self.conn.cursor()

        # ── CSAM Assets ──────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS csam_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id TEXT NOT NULL,
                name TEXT,
                ip_address TEXT,
                os TEXT,
                hardware TEXT,
                software TEXT,
                tags TEXT,
                ports TEXT,
                network_interfaces TEXT,
                last_seen TEXT,
                created TEXT,
                raw_data TEXT,
                fetched_at TEXT NOT NULL,
                UNIQUE(asset_id, fetched_at)
            )
        """)

        # ── VM Hosts ─────────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vm_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                ip_address TEXT,
                dns TEXT,
                netbios TEXT,
                os TEXT,
                trurisk_score INTEGER,
                last_scan_date TEXT,
                last_vm_scanned_date TEXT,
                last_activity_date TEXT,
                tracking_method TEXT,
                raw_data TEXT,
                fetched_at TEXT NOT NULL,
                UNIQUE(host_id, fetched_at)
            )
        """)

        # ── VM Detections ────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vm_detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                ip_address TEXT,
                qid INTEGER NOT NULL,
                detection_type TEXT,
                severity INTEGER,
                status TEXT,
                is_disabled INTEGER DEFAULT 0,
                qds INTEGER,
                cve_id TEXT,
                cvss_base REAL,
                cvss_temporal REAL,
                cvss_vector TEXT,
                patchable INTEGER DEFAULT 0,
                vendor TEXT,
                product TEXT,
                package_name TEXT,
                package_version TEXT,
                fix_version TEXT,
                title TEXT,
                first_found TEXT,
                last_found TEXT,
                last_fixed TEXT,
                last_test TEXT,
                times_found INTEGER,
                results TEXT,
                raw_data TEXT,
                fetched_at TEXT NOT NULL,
                UNIQUE(host_id, qid, fetched_at)
            )
        """)

        # Idempotent ALTER TABLEs for existing databases (migration)
        for coldef in [
            "cve_id TEXT",
            "cvss_base REAL",
            "cvss_temporal REAL",
            "cvss_vector TEXT",
            "patchable INTEGER DEFAULT 0",
            "vendor TEXT",
            "product TEXT",
            "package_name TEXT",
            "package_version TEXT",
            "fix_version TEXT",
            "title TEXT",
        ]:
            col = coldef.split()[0]
            try:
                cursor.execute(f"ALTER TABLE vm_detections ADD COLUMN {coldef}")
                logger.info(f"Migrated vm_detections: added {col}")
            except sqlite3.OperationalError:
                pass  # column already exists

        # ── Normalized Host Tags ─────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS host_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER,
                ip_address TEXT,
                tag_id INTEGER NOT NULL,
                tag_name TEXT NOT NULL,
                criticality_score INTEGER,
                source TEXT NOT NULL,
                fetched_at TEXT NOT NULL,
                UNIQUE(host_id, tag_id, source, fetched_at)
            )
        """)

        # ── Asset Ownership Mapping ──────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS asset_owners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                match_type TEXT NOT NULL,
                match_value TEXT NOT NULL,
                owner TEXT NOT NULL,
                business_unit TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(match_type, match_value)
            )
        """)

        # ── Saved Queries ────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS saved_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                sql_text TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_run_at TEXT
            )
        """)

        # ── SLA Targets ──────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sla_targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                severity INTEGER NOT NULL UNIQUE,
                days INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)

        # ── Detection Change Log ─────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS detection_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host_id INTEGER NOT NULL,
                ip_address TEXT,
                qid INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                severity INTEGER,
                detected_at TEXT NOT NULL
            )
        """)

        # ── Weekly Rollups ───────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS weekly_rollups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                week_start TEXT NOT NULL,
                total_vulns INTEGER,
                sev5_count INTEGER,
                sev4_count INTEGER,
                sev3_count INTEGER,
                sev2_count INTEGER,
                sev1_count INTEGER,
                status_new INTEGER,
                status_active INTEGER,
                status_fixed INTEGER,
                status_reopened INTEGER,
                new_this_week INTEGER,
                fixed_this_week INTEGER,
                avg_trurisk REAL,
                max_trurisk INTEGER,
                avg_qds REAL,
                total_hosts INTEGER,
                csam_hosts INTEGER,
                vm_hosts INTEGER,
                both_hosts INTEGER,
                coverage_pct REAL,
                aging_30d INTEGER,
                aging_60d INTEGER,
                aging_90d INTEGER,
                tag_metrics TEXT,
                computed_at TEXT NOT NULL,
                UNIQUE(week_start)
            )
        """)

        # ── Monthly Rollups ──────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS monthly_rollups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                month_start TEXT NOT NULL,
                total_vulns INTEGER,
                sev5_count INTEGER,
                sev4_count INTEGER,
                sev3_count INTEGER,
                sev2_count INTEGER,
                sev1_count INTEGER,
                status_new INTEGER,
                status_active INTEGER,
                status_fixed INTEGER,
                status_reopened INTEGER,
                new_this_month INTEGER,
                fixed_this_month INTEGER,
                avg_trurisk REAL,
                max_trurisk INTEGER,
                avg_qds REAL,
                total_hosts INTEGER,
                csam_hosts INTEGER,
                vm_hosts INTEGER,
                both_hosts INTEGER,
                coverage_pct REAL,
                aging_30d INTEGER,
                aging_60d INTEGER,
                aging_90d INTEGER,
                tag_metrics TEXT,
                computed_at TEXT NOT NULL,
                UNIQUE(month_start)
            )
        """)

        # ── Refresh Log ──────────────────────────────────────────
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS refresh_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                source TEXT NOT NULL,
                csam_count INTEGER,
                vm_host_count INTEGER,
                vm_detection_count INTEGER,
                csam_expected INTEGER,
                vm_host_expected INTEGER,
                vm_detection_expected INTEGER,
                changes_detected INTEGER,
                status TEXT NOT NULL,
                error TEXT
            )
        """)
        # Idempotent migration for existing databases
        for coldef in [
            "csam_expected INTEGER",
            "vm_host_expected INTEGER",
            "vm_detection_expected INTEGER",
        ]:
            col = coldef.split()[0]
            try:
                cursor.execute(f"ALTER TABLE refresh_log ADD COLUMN {coldef}")
                logger.info(f"Migrated refresh_log: added {col}")
            except sqlite3.OperationalError:
                pass  # column already exists

        # ── CSAM Pull Checkpoint (single-row resume state) ────────
        # One row max (enforced by CHECK id = 1). On each page of a CSAM pull
        # we upsert last_asset_id; when the pull finishes cleanly we flip
        # completed=1. A fresh pull that finds completed=0 resumes from
        # last_asset_id (passed as startFromId to the Qualys API).
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS csam_checkpoint (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_asset_id TEXT,
                assets_pulled INTEGER DEFAULT 0,
                started_at TEXT,
                updated_at TEXT,
                completed INTEGER DEFAULT 0,
                lookback_days INTEGER,
                note TEXT
            )
        """)

        # ── Indexes ──────────────────────────────────────────────
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_csam_ip ON csam_assets(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_csam_fetched ON csam_assets(fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_csam_fetched_ip ON csam_assets(fetched_at, ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_vmhosts_ip ON vm_hosts(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_vmhosts_hostid ON vm_hosts(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_vmhosts_fetched ON vm_hosts(fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_vmhosts_fetched_ip ON vm_hosts(fetched_at, ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_detect_hostid ON vm_detections(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_detect_ip ON vm_detections(ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_detect_qid ON vm_detections(qid)",
            "CREATE INDEX IF NOT EXISTS idx_detect_severity ON vm_detections(severity)",
            "CREATE INDEX IF NOT EXISTS idx_detect_status ON vm_detections(status)",
            "CREATE INDEX IF NOT EXISTS idx_detect_fetched ON vm_detections(fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_detect_fetched_sev ON vm_detections(fetched_at, severity, status)",
            "CREATE INDEX IF NOT EXISTS idx_detect_fetched_ip ON vm_detections(fetched_at, ip_address)",
            "CREATE INDEX IF NOT EXISTS idx_detect_first_found ON vm_detections(first_found)",
            "CREATE INDEX IF NOT EXISTS idx_detect_cve ON vm_detections(cve_id, fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_detect_cvss ON vm_detections(cvss_base, fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_detect_patchable ON vm_detections(patchable, fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_tags_name ON host_tags(tag_name, fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_tags_ip ON host_tags(ip_address, fetched_at)",
            "CREATE INDEX IF NOT EXISTS idx_tags_hostid ON host_tags(host_id)",
            "CREATE INDEX IF NOT EXISTS idx_changes_detected ON detection_changes(detected_at)",
            "CREATE INDEX IF NOT EXISTS idx_changes_type ON detection_changes(change_type, detected_at)",
            "CREATE INDEX IF NOT EXISTS idx_changes_host ON detection_changes(host_id, qid)",
            "CREATE INDEX IF NOT EXISTS idx_weekly_start ON weekly_rollups(week_start)",
            "CREATE INDEX IF NOT EXISTS idx_monthly_start ON monthly_rollups(month_start)",
            "CREATE INDEX IF NOT EXISTS idx_owners_type ON asset_owners(match_type, match_value)",
        ]
        for idx in indexes:
            cursor.execute(idx)

        # ── SQL Views ────────────────────────────────────────────
        cursor.execute("DROP VIEW IF EXISTS v_detections")
        cursor.execute("""
            CREATE VIEW v_detections AS
            SELECT
                d.host_id, d.ip_address, d.qid, d.detection_type,
                d.severity, d.status, d.is_disabled, d.qds,
                d.cve_id, d.cvss_base, d.cvss_temporal, d.cvss_vector,
                d.patchable, d.vendor, d.product,
                d.package_name, d.package_version, d.fix_version,
                d.title,
                d.first_found, d.last_found, d.last_fixed, d.times_found,
                d.fetched_at,
                h.dns, h.netbios, h.os, h.trurisk_score,
                o.owner, o.business_unit
            FROM vm_detections d
            LEFT JOIN vm_hosts h ON d.host_id = h.host_id
                AND h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
            LEFT JOIN asset_owners o ON (
                (o.match_type = 'ip' AND o.match_value = d.ip_address)
            )
            WHERE d.fetched_at = (SELECT MAX(fetched_at) FROM vm_detections)
        """)

        cursor.execute("DROP VIEW IF EXISTS v_hosts")
        cursor.execute("""
            CREATE VIEW v_hosts AS
            SELECT
                h.host_id, h.ip_address, h.dns, h.netbios, h.os,
                h.trurisk_score, h.last_scan_date, h.last_vm_scanned_date,
                h.last_activity_date, h.tracking_method, h.fetched_at,
                o.owner, o.business_unit
            FROM vm_hosts h
            LEFT JOIN asset_owners o ON (
                (o.match_type = 'ip' AND o.match_value = h.ip_address)
            )
            WHERE h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
        """)

        cursor.execute("DROP VIEW IF EXISTS v_assets")
        cursor.execute("""
            CREATE VIEW v_assets AS
            SELECT
                a.asset_id, a.name, a.ip_address, a.os,
                a.hardware, a.software, a.tags, a.ports,
                a.last_seen, a.fetched_at,
                o.owner, o.business_unit
            FROM csam_assets a
            LEFT JOIN asset_owners o ON (
                (o.match_type = 'ip' AND o.match_value = a.ip_address)
            )
            WHERE a.fetched_at = (SELECT MAX(fetched_at) FROM csam_assets)
        """)

        cursor.execute("DROP VIEW IF EXISTS v_changes")
        cursor.execute("""
            CREATE VIEW v_changes AS
            SELECT
                c.id, c.host_id, c.ip_address, c.qid,
                c.change_type, c.old_value, c.new_value,
                c.severity, c.detected_at,
                h.dns, h.os
            FROM detection_changes c
            LEFT JOIN vm_hosts h ON c.host_id = h.host_id
                AND h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
        """)

        # Insert default SLA targets if empty
        cursor.execute("SELECT COUNT(*) FROM sla_targets")
        if cursor.fetchone()[0] == 0:
            now = datetime.utcnow().isoformat()
            cursor.executemany(
                "INSERT INTO sla_targets (severity, days, updated_at) VALUES (?, ?, ?)",
                [(5, 7, now), (4, 30, now), (3, 90, now), (2, 180, now), (1, 365, now)],
            )

        self.conn.commit()
        logger.info(f"Database initialized: {self.db_path}")

    # ── Save Methods ─────────────────────────────────────────────

    def save_csam_assets(self, assets: List[Dict], fetched_at: str) -> int:
        cursor = self.conn.cursor()
        count = 0
        for batch_start in range(0, len(assets), 1000):
            batch = assets[batch_start : batch_start + 1000]
            cursor.executemany(
                """INSERT OR REPLACE INTO csam_assets
                   (asset_id, name, ip_address, os, hardware, software, tags,
                    ports, network_interfaces, last_seen, created, raw_data, fetched_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        a.get("assetId", a.get("id", "")),
                        a.get("name", ""),
                        a.get("address", a.get("ipAddress", "")),
                        a.get("os", ""),
                        json.dumps(a.get("hardware", {})),
                        json.dumps(a.get("software", [])),
                        json.dumps(a.get("tagList", a.get("tags", []))),
                        json.dumps(a.get("openPort", a.get("ports", []))),
                        json.dumps(a.get("networkInterface", [])),
                        a.get("lastSeen", ""),
                        a.get("created", ""),
                        json.dumps(a),
                        fetched_at,
                    )
                    for a in batch
                ],
            )
            count += len(batch)
        self.conn.commit()
        logger.info(f"Saved {count} CSAM assets")
        return count

    def save_vm_hosts(self, hosts: List[Dict], fetched_at: str) -> int:
        cursor = self.conn.cursor()
        count = 0
        for batch_start in range(0, len(hosts), 1000):
            batch = hosts[batch_start : batch_start + 1000]
            cursor.executemany(
                """INSERT OR REPLACE INTO vm_hosts
                   (host_id, ip_address, dns, netbios, os, trurisk_score,
                    last_scan_date, last_vm_scanned_date, last_activity_date,
                    tracking_method, raw_data, fetched_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        h.get("host_id", h.get("ID", 0)),
                        h.get("ip", h.get("IP", "")),
                        h.get("dns", h.get("DNS", "")),
                        h.get("netbios", h.get("NETBIOS", "")),
                        h.get("os", h.get("OS", "")),
                        h.get("trurisk_score", h.get("TRURISK_SCORE", 0)),
                        h.get("last_scan_date", h.get("LAST_SCAN_DATETIME", "")),
                        h.get("last_vm_scanned_date", h.get("LAST_VM_SCANNED_DATE", "")),
                        h.get("last_activity_date", h.get("LAST_ACTIVITY", "")),
                        h.get("tracking_method", h.get("TRACKING_METHOD", "")),
                        json.dumps(h),
                        fetched_at,
                    )
                    for h in batch
                ],
            )
            count += len(batch)
        self.conn.commit()
        logger.info(f"Saved {count} VM hosts")
        return count

    def save_vm_detections(self, detections: List[Dict], fetched_at: str) -> int:
        cursor = self.conn.cursor()
        count = 0
        for batch_start in range(0, len(detections), 1000):
            batch = detections[batch_start : batch_start + 1000]
            cursor.executemany(
                """INSERT OR REPLACE INTO vm_detections
                   (host_id, ip_address, qid, detection_type, severity, status,
                    is_disabled, qds,
                    cve_id, cvss_base, cvss_temporal, cvss_vector, patchable,
                    vendor, product, package_name, package_version, fix_version,
                    title,
                    first_found, last_found, last_fixed,
                    last_test, times_found, results, raw_data, fetched_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        d.get("host_id", 0),
                        d.get("ip", ""),
                        d.get("qid", d.get("QID", 0)),
                        d.get("type", d.get("TYPE", "")),
                        d.get("severity", d.get("SEVERITY", 0)),
                        d.get("status", d.get("STATUS", "")),
                        1 if d.get("is_disabled", d.get("IS_DISABLED", False)) else 0,
                        d.get("qds", d.get("QDS", 0)),
                        d.get("cve_id", d.get("CVE_ID")),
                        d.get("cvss_base", d.get("CVSS_BASE")),
                        d.get("cvss_temporal", d.get("CVSS_TEMPORAL")),
                        d.get("cvss_vector", d.get("CVSS_VECTOR")),
                        1 if d.get("patchable", d.get("PATCHABLE", False)) else 0,
                        d.get("vendor", d.get("VENDOR")),
                        d.get("product", d.get("PRODUCT")),
                        d.get("package_name", d.get("PACKAGE_NAME")),
                        d.get("package_version", d.get("PACKAGE_VERSION")),
                        d.get("fix_version", d.get("FIX_VERSION")),
                        d.get("title", d.get("TITLE")),
                        d.get("first_found", d.get("FIRST_FOUND_DATETIME", "")),
                        d.get("last_found", d.get("LAST_FOUND_DATETIME", "")),
                        d.get("last_fixed", d.get("LAST_FIXED_DATETIME", "")),
                        d.get("last_test", d.get("LAST_TEST_DATETIME", "")),
                        d.get("times_found", d.get("TIMES_FOUND", 0)),
                        d.get("results", d.get("RESULTS", "")),
                        json.dumps(d),
                        fetched_at,
                    )
                    for d in batch
                ],
            )
            count += len(batch)
        self.conn.commit()
        logger.info(f"Saved {count} VM detections")
        return count

    def save_host_tags(self, tags: List[Dict], fetched_at: str) -> int:
        cursor = self.conn.cursor()
        count = 0
        for batch_start in range(0, len(tags), 1000):
            batch = tags[batch_start : batch_start + 1000]
            cursor.executemany(
                """INSERT OR REPLACE INTO host_tags
                   (host_id, ip_address, tag_id, tag_name, criticality_score,
                    source, fetched_at)
                   VALUES (?,?,?,?,?,?,?)""",
                [
                    (
                        t.get("host_id"),
                        t.get("ip_address", ""),
                        t.get("tag_id", 0),
                        t.get("tag_name", ""),
                        t.get("criticality_score"),
                        t.get("source", ""),
                        fetched_at,
                    )
                    for t in batch
                ],
            )
            count += len(batch)
        self.conn.commit()
        logger.info(f"Saved {count} host tags")
        return count

    def save_detection_changes(self, changes: List[Dict]) -> int:
        if not changes:
            return 0
        cursor = self.conn.cursor()
        cursor.executemany(
            """INSERT INTO detection_changes
               (host_id, ip_address, qid, change_type, old_value,
                new_value, severity, detected_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            [
                (
                    c["host_id"], c.get("ip_address", ""), c["qid"],
                    c["change_type"], c.get("old_value"),
                    c.get("new_value"), c.get("severity", 0), c["detected_at"],
                )
                for c in changes
            ],
        )
        self.conn.commit()
        logger.info(f"Saved {len(changes)} detection changes")
        return len(changes)

    def log_refresh(self, source: str) -> int:
        cursor = self.conn.cursor()
        cursor.execute(
            """INSERT INTO refresh_log (started_at, source, status)
               VALUES (?, ?, 'running')""",
            (datetime.utcnow().isoformat(), source),
        )
        self.conn.commit()
        return cursor.lastrowid

    def complete_refresh(self, refresh_id: int, csam: int = 0, vm_hosts: int = 0,
                         vm_detections: int = 0, changes: int = 0,
                         status: str = "success", error: str = None,
                         csam_expected: Optional[int] = None,
                         vm_host_expected: Optional[int] = None,
                         vm_detection_expected: Optional[int] = None):
        self.conn.execute(
            """UPDATE refresh_log
               SET completed_at=?, csam_count=?, vm_host_count=?,
                   vm_detection_count=?, changes_detected=?, status=?, error=?,
                   csam_expected=?, vm_host_expected=?, vm_detection_expected=?
               WHERE id=?""",
            (datetime.utcnow().isoformat(), csam, vm_hosts, vm_detections,
             changes, status, error,
             csam_expected, vm_host_expected, vm_detection_expected,
             refresh_id),
        )
        self.conn.commit()

    # ── CSAM Resume Checkpoint ──────────────────────────────────
    # Tiny single-row table that remembers the last asset ID of the most
    # recent CSAM pull. Lets us resume after a rate-limit / crash instead
    # of re-fetching the first N pages on the next run.

    def get_csam_checkpoint(self) -> Optional[Dict]:
        """Return the current CSAM checkpoint row, or None if no pull has run."""
        row = self.conn.execute(
            "SELECT last_asset_id, assets_pulled, started_at, updated_at, "
            "completed, lookback_days, note FROM csam_checkpoint WHERE id = 1"
        ).fetchone()
        if not row:
            return None
        return {
            "last_asset_id": row[0],
            "assets_pulled": row[1] or 0,
            "started_at": row[2],
            "updated_at": row[3],
            "completed": bool(row[4]),
            "lookback_days": row[5],
            "note": row[6],
        }

    def update_csam_checkpoint(self, last_asset_id: Optional[str],
                               assets_pulled: int,
                               completed: bool,
                               lookback_days: Optional[int] = None,
                               started_at: Optional[str] = None,
                               note: Optional[str] = None) -> None:
        """Upsert the single checkpoint row. `started_at` is preserved across
        updates when None — we only set it on the very first page of a run."""
        now = datetime.utcnow().isoformat()
        existing = self.get_csam_checkpoint()
        if existing is None:
            self.conn.execute(
                """INSERT INTO csam_checkpoint
                   (id, last_asset_id, assets_pulled, started_at, updated_at,
                    completed, lookback_days, note)
                   VALUES (1, ?, ?, ?, ?, ?, ?, ?)""",
                (last_asset_id, assets_pulled, started_at or now, now,
                 1 if completed else 0, lookback_days, note),
            )
        else:
            # Keep the original started_at unless the caller is explicitly
            # starting a new pull (completed=True on the prior row means the
            # next update is a fresh start; we detect that on the caller side
            # by passing started_at explicitly).
            preserved_start = started_at or existing["started_at"] or now
            self.conn.execute(
                """UPDATE csam_checkpoint
                   SET last_asset_id=?, assets_pulled=?, started_at=?,
                       updated_at=?, completed=?, lookback_days=?, note=?
                   WHERE id=1""",
                (last_asset_id, assets_pulled, preserved_start, now,
                 1 if completed else 0, lookback_days, note),
            )
        self.conn.commit()

    def clear_csam_checkpoint(self) -> None:
        """Wipe the checkpoint — forces next pull to start from the beginning."""
        self.conn.execute("DELETE FROM csam_checkpoint WHERE id = 1")
        self.conn.commit()

    # ── Query Methods ────────────────────────────────────────────

    def get_latest_fetched_at(self, table: str) -> Optional[str]:
        allowed = {"csam_assets", "vm_hosts", "vm_detections", "host_tags"}
        if table not in allowed:
            return None
        row = self.conn.execute(
            f"SELECT MAX(fetched_at) FROM {table}"
        ).fetchone()
        return row[0] if row and row[0] else None

    def get_latest_csam_assets(self, limit: int = 100, offset: int = 0,
                                ip: str = None) -> List[Dict]:
        fetched = self.get_latest_fetched_at("csam_assets")
        if not fetched:
            return []
        query = "SELECT * FROM csam_assets WHERE fetched_at = ?"
        params: list = [fetched]
        if ip:
            query += " AND ip_address LIKE ?"
            params.append(f"%{ip}%")
        query += " ORDER BY ip_address LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in self.conn.execute(query, params).fetchall()]

    def get_latest_vm_hosts(self, limit: int = 100, offset: int = 0,
                             ip: str = None, os_filter: str = None) -> List[Dict]:
        fetched = self.get_latest_fetched_at("vm_hosts")
        if not fetched:
            return []
        query = "SELECT * FROM vm_hosts WHERE fetched_at = ?"
        params: list = [fetched]
        if ip:
            query += " AND ip_address LIKE ?"
            params.append(f"%{ip}%")
        if os_filter:
            query += " AND os LIKE ?"
            params.append(f"%{os_filter}%")
        query += " ORDER BY ip_address LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in self.conn.execute(query, params).fetchall()]

    def get_latest_detections(self, limit: int = 100, offset: int = 0,
                               ip: str = None, severity_min: int = None,
                               status: List[str] = None, qid: int = None,
                               date_from: str = None, date_to: str = None,
                               tag: str = None,
                               include_disabled: bool = False) -> List[Dict]:
        fetched = self.get_latest_fetched_at("vm_detections")
        if not fetched:
            return []

        if tag:
            query = """
                SELECT d.* FROM vm_detections d
                JOIN host_tags t ON d.host_id = t.host_id
                WHERE d.fetched_at = ? AND t.tag_name = ?
            """
            params: list = [fetched, tag]
            tag_fetched = self.get_latest_fetched_at("host_tags")
            if tag_fetched:
                query += " AND t.fetched_at = ?"
                params.append(tag_fetched)
        else:
            query = "SELECT * FROM vm_detections WHERE fetched_at = ?"
            params = [fetched]

        if not include_disabled:
            query += " AND d.is_disabled = 0" if tag else " AND is_disabled = 0"
        if ip:
            col = "d.ip_address" if tag else "ip_address"
            query += f" AND {col} LIKE ?"
            params.append(f"%{ip}%")
        if severity_min is not None:
            col = "d.severity" if tag else "severity"
            query += f" AND {col} >= ?"
            params.append(severity_min)
        if status:
            col = "d.status" if tag else "status"
            placeholders = ",".join("?" * len(status))
            query += f" AND {col} IN ({placeholders})"
            params.extend(status)
        if qid:
            col = "d.qid" if tag else "qid"
            query += f" AND {col} = ?"
            params.append(qid)
        if date_from:
            col = "d.first_found" if tag else "first_found"
            query += f" AND {col} >= ?"
            params.append(date_from)
        if date_to:
            col = "d.last_found" if tag else "last_found"
            query += f" AND {col} <= ?"
            params.append(date_to)

        query += " ORDER BY severity DESC, first_found ASC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [dict(r) for r in self.conn.execute(query, params).fetchall()]

    def get_detection_count(self, include_disabled: bool = False) -> int:
        fetched = self.get_latest_fetched_at("vm_detections")
        if not fetched:
            return 0
        query = "SELECT COUNT(*) FROM vm_detections WHERE fetched_at = ?"
        params: list = [fetched]
        if not include_disabled:
            query += " AND is_disabled = 0"
        return self.conn.execute(query, params).fetchone()[0]

    def get_joined_host_data(self, ip: str) -> Dict[str, Any]:
        """Get combined CSAM + VM host + detection summary for an IP."""
        result: Dict[str, Any] = {"ip": ip, "csam": None, "vm_host": None,
                                   "detections": [], "tags": []}

        csam_fetched = self.get_latest_fetched_at("csam_assets")
        if csam_fetched:
            row = self.conn.execute(
                "SELECT * FROM csam_assets WHERE fetched_at = ? AND ip_address = ?",
                (csam_fetched, ip),
            ).fetchone()
            if row:
                result["csam"] = dict(row)

        vm_fetched = self.get_latest_fetched_at("vm_hosts")
        if vm_fetched:
            row = self.conn.execute(
                "SELECT * FROM vm_hosts WHERE fetched_at = ? AND ip_address = ?",
                (vm_fetched, ip),
            ).fetchone()
            if row:
                result["vm_host"] = dict(row)

        det_fetched = self.get_latest_fetched_at("vm_detections")
        if det_fetched:
            rows = self.conn.execute(
                "SELECT * FROM vm_detections WHERE fetched_at = ? AND ip_address = ? ORDER BY severity DESC",
                (det_fetched, ip),
            ).fetchall()
            result["detections"] = [dict(r) for r in rows]

        tag_fetched = self.get_latest_fetched_at("host_tags")
        if tag_fetched:
            rows = self.conn.execute(
                "SELECT * FROM host_tags WHERE fetched_at = ? AND ip_address = ?",
                (tag_fetched, ip),
            ).fetchall()
            result["tags"] = [dict(r) for r in rows]

        # Ownership — use full resolution (IP → range → tag → OS pattern)
        result["owner"] = self.get_asset_owner(ip)

        return result

    def get_hosts_by_tag(self, tag_name: str, limit: int = 100, offset: int = 0) -> List[Dict]:
        tag_fetched = self.get_latest_fetched_at("host_tags")
        if not tag_fetched:
            return []
        rows = self.conn.execute(
            """SELECT DISTINCT t.ip_address, t.host_id, h.dns, h.os, h.trurisk_score
               FROM host_tags t
               LEFT JOIN vm_hosts h ON t.host_id = h.host_id
                   AND h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
               WHERE t.tag_name = ? AND t.fetched_at = ?
               ORDER BY t.ip_address
               LIMIT ? OFFSET ?""",
            (tag_name, tag_fetched, limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_tag_summary(self) -> List[Dict]:
        tag_fetched = self.get_latest_fetched_at("host_tags")
        det_fetched = self.get_latest_fetched_at("vm_detections")
        if not tag_fetched:
            return []
        rows = self.conn.execute(
            """SELECT t.tag_name,
                      COUNT(DISTINCT t.ip_address) as host_count,
                      COALESCE(SUM(CASE WHEN d.status IN ('New','Active') AND d.is_disabled = 0 THEN 1 ELSE 0 END), 0) as vuln_count,
                      COALESCE(AVG(CASE WHEN d.status IN ('New','Active') AND d.is_disabled = 0 THEN d.severity END), 0) as avg_severity,
                      COALESCE(AVG(h.trurisk_score), 0) as avg_trurisk
               FROM host_tags t
               LEFT JOIN vm_detections d ON t.host_id = d.host_id AND d.fetched_at = ?
               LEFT JOIN vm_hosts h ON t.host_id = h.host_id
                   AND h.fetched_at = (SELECT MAX(fetched_at) FROM vm_hosts)
               WHERE t.fetched_at = ?
               GROUP BY t.tag_name
               ORDER BY vuln_count DESC""",
            (det_fetched, tag_fetched),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_all_tags(self) -> List[str]:
        tag_fetched = self.get_latest_fetched_at("host_tags")
        if not tag_fetched:
            return []
        rows = self.conn.execute(
            "SELECT DISTINCT tag_name FROM host_tags WHERE fetched_at = ? ORDER BY tag_name",
            (tag_fetched,),
        ).fetchall()
        return [r[0] for r in rows]

    # ── Previous Detections (for change detection) ───────────────

    def get_previous_detections(self) -> Dict[str, Dict]:
        """Get the latest detection state keyed by (host_id, qid) for diffing."""
        fetched = self.get_latest_fetched_at("vm_detections")
        if not fetched:
            return {}
        rows = self.conn.execute(
            "SELECT host_id, qid, status, severity, is_disabled FROM vm_detections WHERE fetched_at = ?",
            (fetched,),
        ).fetchall()
        return {
            f"{r['host_id']}:{r['qid']}": {
                "status": r["status"],
                "severity": r["severity"],
                "is_disabled": r["is_disabled"],
            }
            for r in rows
        }

    # ── Rollup Methods ───────────────────────────────────────────

    def save_weekly_rollup(self, data: Dict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO weekly_rollups
               (week_start, total_vulns, sev5_count, sev4_count, sev3_count,
                sev2_count, sev1_count, status_new, status_active, status_fixed,
                status_reopened, new_this_week, fixed_this_week, avg_trurisk,
                max_trurisk, avg_qds, total_hosts, csam_hosts, vm_hosts,
                both_hosts, coverage_pct, aging_30d, aging_60d, aging_90d,
                tag_metrics, computed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["week_start"], data.get("total_vulns", 0),
                data.get("sev5_count", 0), data.get("sev4_count", 0),
                data.get("sev3_count", 0), data.get("sev2_count", 0),
                data.get("sev1_count", 0), data.get("status_new", 0),
                data.get("status_active", 0), data.get("status_fixed", 0),
                data.get("status_reopened", 0), data.get("new_this_week", 0),
                data.get("fixed_this_week", 0), data.get("avg_trurisk", 0),
                data.get("max_trurisk", 0), data.get("avg_qds", 0),
                data.get("total_hosts", 0), data.get("csam_hosts", 0),
                data.get("vm_hosts", 0), data.get("both_hosts", 0),
                data.get("coverage_pct", 0), data.get("aging_30d", 0),
                data.get("aging_60d", 0), data.get("aging_90d", 0),
                json.dumps(data.get("tag_metrics", {})),
                datetime.utcnow().isoformat(),
            ),
        )
        self.conn.commit()

    def save_monthly_rollup(self, data: Dict) -> None:
        self.conn.execute(
            """INSERT OR REPLACE INTO monthly_rollups
               (month_start, total_vulns, sev5_count, sev4_count, sev3_count,
                sev2_count, sev1_count, status_new, status_active, status_fixed,
                status_reopened, new_this_month, fixed_this_month, avg_trurisk,
                max_trurisk, avg_qds, total_hosts, csam_hosts, vm_hosts,
                both_hosts, coverage_pct, aging_30d, aging_60d, aging_90d,
                tag_metrics, computed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data["month_start"], data.get("total_vulns", 0),
                data.get("sev5_count", 0), data.get("sev4_count", 0),
                data.get("sev3_count", 0), data.get("sev2_count", 0),
                data.get("sev1_count", 0), data.get("status_new", 0),
                data.get("status_active", 0), data.get("status_fixed", 0),
                data.get("status_reopened", 0), data.get("new_this_month", 0),
                data.get("fixed_this_month", 0), data.get("avg_trurisk", 0),
                data.get("max_trurisk", 0), data.get("avg_qds", 0),
                data.get("total_hosts", 0), data.get("csam_hosts", 0),
                data.get("vm_hosts", 0), data.get("both_hosts", 0),
                data.get("coverage_pct", 0), data.get("aging_30d", 0),
                data.get("aging_60d", 0), data.get("aging_90d", 0),
                json.dumps(data.get("tag_metrics", {})),
                datetime.utcnow().isoformat(),
            ),
        )
        self.conn.commit()

    def get_weekly_rollups(self, weeks_back: int = 12) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM weekly_rollups ORDER BY week_start DESC LIMIT ?",
            (weeks_back,),
        ).fetchall()
        result = [dict(r) for r in rows]
        result.reverse()
        return result

    def get_monthly_rollups(self, months_back: int = 12) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM monthly_rollups ORDER BY month_start DESC LIMIT ?",
            (months_back,),
        ).fetchall()
        result = [dict(r) for r in rows]
        result.reverse()
        return result

    # ── Ownership Methods ────────────────────────────────────────

    def get_owners(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM asset_owners ORDER BY owner, match_type"
        ).fetchall()
        return [dict(r) for r in rows]

    def add_owner(self, match_type: str, match_value: str, owner: str,
                  business_unit: str = "", notes: str = "") -> int:
        now = datetime.utcnow().isoformat()
        cursor = self.conn.execute(
            """INSERT OR REPLACE INTO asset_owners
               (match_type, match_value, owner, business_unit, notes, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?)""",
            (match_type, match_value, owner, business_unit, notes, now, now),
        )
        self.conn.commit()
        return cursor.lastrowid

    def delete_owner(self, owner_id: int) -> bool:
        cursor = self.conn.execute("DELETE FROM asset_owners WHERE id = ?", (owner_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def update_owner(self, owner_id: int, **kwargs) -> bool:
        sets = []
        params = []
        for key in ("match_type", "match_value", "owner", "business_unit", "notes"):
            if key in kwargs:
                sets.append(f"{key} = ?")
                params.append(kwargs[key])
        if not sets:
            return False
        sets.append("updated_at = ?")
        params.append(datetime.utcnow().isoformat())
        params.append(owner_id)
        cursor = self.conn.execute(
            f"UPDATE asset_owners SET {', '.join(sets)} WHERE id = ?", params
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def get_asset_owner(self, ip: str) -> Optional[Dict]:
        """Resolve owner for an IP address."""
        row = self.conn.execute(
            "SELECT owner, business_unit FROM asset_owners WHERE match_type = 'ip' AND match_value = ?",
            (ip,),
        ).fetchone()
        if row:
            return dict(row)
        # Check IP range matches
        rows = self.conn.execute(
            "SELECT match_value, owner, business_unit FROM asset_owners WHERE match_type = 'ip_range'"
        ).fetchall()
        import ipaddress as ipm
        try:
            addr = ipm.ip_address(ip)
            for r in rows:
                try:
                    if addr in ipm.ip_network(r["match_value"], strict=False):
                        return {"owner": r["owner"], "business_unit": r["business_unit"]}
                except ValueError:
                    continue
        except ValueError:
            pass
        # Check tag-based ownership
        tag_fetched = self.get_latest_fetched_at("host_tags")
        if tag_fetched:
            host_tags = self.conn.execute(
                "SELECT tag_name FROM host_tags WHERE ip_address = ? AND fetched_at = ?",
                (ip, tag_fetched),
            ).fetchall()
            tag_names = {r["tag_name"] for r in host_tags}
            tag_owners = self.conn.execute(
                "SELECT match_value, owner, business_unit FROM asset_owners WHERE match_type = 'tag'"
            ).fetchall()
            for r in tag_owners:
                if r["match_value"] in tag_names:
                    return {"owner": r["owner"], "business_unit": r["business_unit"]}

        # Check OS pattern-based ownership
        host_fetched = self.get_latest_fetched_at("vm_hosts")
        if host_fetched:
            host_row = self.conn.execute(
                "SELECT os FROM vm_hosts WHERE ip_address = ? AND fetched_at = ?",
                (ip, host_fetched),
            ).fetchone()
            if host_row and host_row["os"]:
                os_owners = self.conn.execute(
                    "SELECT match_value, owner, business_unit FROM asset_owners WHERE match_type = 'os_pattern'"
                ).fetchall()
                for r in os_owners:
                    pattern = r["match_value"].replace("%", "")
                    if pattern.lower() in host_row["os"].lower():
                        return {"owner": r["owner"], "business_unit": r["business_unit"]}

        return None

    # ── SLA Methods ──────────────────────────────────────────────

    def get_sla_targets(self) -> Dict[int, int]:
        rows = self.conn.execute("SELECT severity, days FROM sla_targets").fetchall()
        return {r["severity"]: r["days"] for r in rows}

    def update_sla_targets(self, targets: Dict[int, int]) -> None:
        now = datetime.utcnow().isoformat()
        for severity, days in targets.items():
            self.conn.execute(
                "INSERT OR REPLACE INTO sla_targets (severity, days, updated_at) VALUES (?,?,?)",
                (severity, days, now),
            )
        self.conn.commit()

    # ── Saved Query Methods ──────────────────────────────────────

    def get_saved_queries(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM saved_queries ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    def save_query(self, name: str, sql_text: str, description: str = "") -> int:
        cursor = self.conn.execute(
            "INSERT INTO saved_queries (name, description, sql_text, created_at) VALUES (?,?,?,?)",
            (name, description, sql_text, datetime.utcnow().isoformat()),
        )
        self.conn.commit()
        return cursor.lastrowid

    def delete_saved_query(self, query_id: int) -> bool:
        cursor = self.conn.execute("DELETE FROM saved_queries WHERE id = ?", (query_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def execute_readonly(self, sql: str) -> Dict[str, Any]:
        """Execute a read-only SQL query. Only SELECT statements allowed.

        Returns {"columns": [...], "rows": [{...}, ...]} on success,
        or {"error": "..."} on validation failure.
        """
        stripped = sql.strip().upper()
        if not stripped.startswith("SELECT"):
            return {"error": "Only SELECT queries are allowed"}
        for keyword in ("INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
                        "ATTACH", "DETACH", "PRAGMA"):
            if keyword in stripped:
                return {"error": f"Query contains disallowed keyword: {keyword}"}
        try:
            cursor = self.conn.execute(sql)
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            rows = [dict(r) for r in cursor.fetchall()]
            return {"columns": columns, "rows": rows}
        except Exception as e:
            return {"error": str(e)}

    # ── Retention / Purge ────────────────────────────────────────

    def purge_daily_snapshots(self, days: int = 30) -> Dict[str, int]:
        """Delete snapshot rows older than N days, keeping weekly/monthly preserved ones."""
        from datetime import timedelta
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        counts = {}
        for table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags"):
            cursor = self.conn.execute(
                f"DELETE FROM {table} WHERE fetched_at < ?", (cutoff,)
            )
            counts[table] = cursor.rowcount
        self.conn.commit()
        logger.info(f"Purged daily snapshots older than {days}d: {counts}")
        return counts

    def purge_weekly_rollups(self, weeks: int = 52) -> int:
        from datetime import timedelta
        cutoff = (datetime.utcnow() - timedelta(weeks=weeks)).strftime("%Y-%m-%d")
        cursor = self.conn.execute(
            "DELETE FROM weekly_rollups WHERE week_start < ?", (cutoff,)
        )
        self.conn.commit()
        logger.info(f"Purged {cursor.rowcount} weekly rollups older than {weeks}w")
        return cursor.rowcount

    def get_refresh_log(self, limit: int = 20) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM refresh_log ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_db_stats(self) -> Dict[str, Any]:
        stats = {}
        for table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags",
                       "detection_changes", "weekly_rollups", "monthly_rollups",
                       "asset_owners", "saved_queries", "refresh_log"):
            row = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            stats[table] = row[0]
        stats["latest_csam"] = self.get_latest_fetched_at("csam_assets")
        stats["latest_vm_hosts"] = self.get_latest_fetched_at("vm_hosts")
        stats["latest_vm_detections"] = self.get_latest_fetched_at("vm_detections")
        # DB file size
        if self.db_path.exists():
            stats["db_size_mb"] = round(self.db_path.stat().st_size / (1024 * 1024), 2)
        return stats
