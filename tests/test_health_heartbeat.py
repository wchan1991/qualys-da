#!/usr/bin/env python3
"""
Qualys DA — Health Heartbeat + Ingestion Visibility Tests

Locks the invariants behind the "look under the hood" surface:

* `health_log` table accepts inserts via `log_health_check`, returns the
  most-recent row via `get_latest_health_check`, paginates via
  `get_health_log`, and gets pruned by `purge_daily_snapshots`.
* `scheduled_health_check()` reuses `manager.health_check()` and writes
  one row per call — never raises, never crashes the scheduler.
* `/api/health-status` reads the latest heartbeat row, derives an `age_seconds`
  + `stale` flag using the configured interval, and returns nulls when no
  heartbeats have run yet.
* `/api/health-log` returns the most-recent N rows in DESC order.
* `/api/ingestion-stats` aggregates current snapshot counts, refresh-log
  history, heartbeat summary, and computes `success_rate_pct` correctly.
* `get_ingestion_stats` returns expected shape and arithmetic on a
  populated DB (lifetime aggregates, last-success timestamp).
* `_log_startup_banner` runs both the empty-DB branch and the populated
  branch without raising.

Run:  python -m unittest tests.test_health_heartbeat -v
"""

import io
import json
import logging
import os
import sys
import tempfile
import time
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

# sys.path prelude matches the rest of the suite
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.database import QualysDADatabase


def _make_db(db_path):
    """QualysDADatabase takes a path str, not the config object."""
    return QualysDADatabase(db_path)


# ── DB helpers ──────────────────────────────────────────────

class HealthLogTableTest(unittest.TestCase):
    """Schema, helpers, and retention for the new `health_log` table."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="hb_")
        os.close(fd)
        self.db = _make_db(self.db_path)

    def tearDown(self):
        try:
            self.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_log_and_fetch_latest(self):
        rid = self.db.log_health_check(
            vm_available=True, csam_available=False,
            vm_error=None, csam_error="AuthError 401",
            duration_ms=842,
        )
        self.assertIsInstance(rid, int)
        latest = self.db.get_latest_health_check()
        self.assertIsNotNone(latest)
        self.assertEqual(latest["vm_available"], 1)
        self.assertEqual(latest["csam_available"], 0)
        self.assertEqual(latest["csam_error"], "AuthError 401")
        self.assertEqual(latest["duration_ms"], 842)
        self.assertIn("checked_at", latest)

    def test_get_health_log_orders_desc(self):
        # Insert with explicit timestamp ordering
        for i, secs_ago in enumerate([300, 200, 100]):
            ts = (datetime.utcnow() - timedelta(seconds=secs_ago)).isoformat()
            self.db.conn.execute(
                "INSERT INTO health_log (checked_at, vm_available, csam_available) "
                "VALUES (?, 1, 1)",
                (ts,),
            )
        self.db.conn.commit()
        rows = self.db.get_health_log(limit=5)
        self.assertEqual(len(rows), 3)
        # Most recent first
        self.assertGreater(rows[0]["checked_at"], rows[1]["checked_at"])
        self.assertGreater(rows[1]["checked_at"], rows[2]["checked_at"])

    def test_purge_daily_snapshots_prunes_health_log(self):
        # Old row (40 days ago) + recent row
        old_ts = (datetime.utcnow() - timedelta(days=40)).isoformat()
        self.db.conn.execute(
            "INSERT INTO health_log (checked_at, vm_available, csam_available) "
            "VALUES (?, 1, 1)", (old_ts,),
        )
        self.db.log_health_check(True, True, duration_ms=100)
        self.db.conn.commit()
        before = self.db.conn.execute("SELECT COUNT(*) FROM health_log").fetchone()[0]
        self.assertEqual(before, 2)

        counts = self.db.purge_daily_snapshots(days=30)
        self.assertEqual(counts.get("health_log"), 1)
        after = self.db.conn.execute("SELECT COUNT(*) FROM health_log").fetchone()[0]
        self.assertEqual(after, 1, "Recent heartbeat should survive 30d retention")

    def test_get_latest_returns_none_when_empty(self):
        self.assertIsNone(self.db.get_latest_health_check())


# ── get_ingestion_stats ─────────────────────────────────────

class IngestionStatsTest(unittest.TestCase):
    """Aggregate rollup powering the startup banner, navbar chip, and
    Settings KPI grid. Tests both the empty-DB shape and a populated
    case with refresh history."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="ig_")
        os.close(fd)
        self.db = _make_db(self.db_path)

    def tearDown(self):
        try:
            self.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_empty_db_shape(self):
        s = self.db.get_ingestion_stats()
        self.assertEqual(s["csam_assets_count"], 0)
        self.assertEqual(s["vm_hosts_count"], 0)
        self.assertEqual(s["vm_detections_count"], 0)
        self.assertIsNone(s["csam_assets_latest"])
        self.assertEqual(s["refresh_history"]["total"], 0)
        self.assertIsNone(s["last_success"])
        self.assertEqual(s["heartbeats"]["total"], 0)
        self.assertGreaterEqual(s["db_size_mb"], 0.0)

    def test_populated_aggregates(self):
        # Seed two successful refreshes + one failed
        now = datetime.utcnow()
        for status, started_offset, completed_offset in [
            ("success", 7200, 7000),  # 200s duration
            ("success", 3600, 3300),  # 300s duration
            ("failed", 1800, 1700),
        ]:
            started = (now - timedelta(seconds=started_offset)).isoformat()
            completed = (now - timedelta(seconds=completed_offset)).isoformat()
            self.db.conn.execute(
                """INSERT INTO refresh_log
                   (started_at, completed_at, source, status)
                   VALUES (?, ?, 'all', ?)""",
                (started, completed, status),
            )
        # Seed snapshot data — 5 csam assets under one fetched_at
        for i in range(5):
            self.db.conn.execute(
                """INSERT INTO csam_assets (asset_id, ip_address, fetched_at)
                   VALUES (?, ?, ?)""",
                (f"a{i}", f"10.0.0.{i}", now.isoformat()),
            )
        self.db.conn.commit()

        s = self.db.get_ingestion_stats()
        self.assertEqual(s["csam_assets_count"], 5)
        self.assertEqual(s["refresh_history"]["total"], 3)
        self.assertEqual(s["refresh_history"]["success"], 2)
        self.assertEqual(s["refresh_history"]["failed"], 1)
        self.assertIsNotNone(s["last_success"])
        # Avg duration: (200 + 300) / 2 = 250s = ~4.17 min
        self.assertAlmostEqual(s["avg_duration_minutes"], 4.2, delta=0.5)


# ── App routes (Flask test client) ──────────────────────────

class HeartbeatRouteTest(unittest.TestCase):
    """End-to-end via Flask test client. Covers /api/health-status,
    /api/health-log, /api/ingestion-stats, and the startup banner helper.

    We swap out `app.py`'s singleton `_manager` with one pointing at a
    temp DB so the routes hit isolated state."""

    @classmethod
    def setUpClass(cls):
        # Imported here so the test_qa baseline isn't disturbed by an
        # extra module-load at import time.
        import app as app_module
        cls.app_module = app_module

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="route_")
        os.close(fd)
        # Build an isolated DataManager + swap it in as the singleton.
        from src.data_manager import DataManager
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t",
                             health_check_interval_hours=4)
        self._mgr = DataManager(cfg)
        self._mgr._client = MagicMock()
        self.app_module._manager = self._mgr
        self.app_module._config = cfg
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        try:
            self._mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        # Clear the singleton so the next test's setUp re-injects cleanly.
        self.app_module._manager = None
        self.app_module._config = None

    def test_health_status_empty(self):
        resp = self.client.get("/api/health-status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIsNone(data["vm"])
        self.assertIsNone(data["csam"])
        self.assertIsNone(data["checked_at"])
        self.assertTrue(data["stale"])

    def test_health_status_recent_not_stale(self):
        self._mgr.db.log_health_check(True, True, duration_ms=100)
        resp = self.client.get("/api/health-status")
        data = resp.get_json()
        self.assertTrue(data["vm"])
        self.assertTrue(data["csam"])
        self.assertFalse(data["stale"])
        self.assertLess(data["age_seconds"], 5)

    def test_health_status_old_is_stale(self):
        # Insert a row aged past 1.25× interval (4h × 1.25 = 5h)
        old = (datetime.utcnow() - timedelta(hours=6)).isoformat()
        self._mgr.db.conn.execute(
            "INSERT INTO health_log (checked_at, vm_available, csam_available) "
            "VALUES (?, 1, 1)", (old,),
        )
        self._mgr.db.conn.commit()
        resp = self.client.get("/api/health-status")
        data = resp.get_json()
        self.assertTrue(data["stale"], f"6h-old heartbeat should be stale, got {data}")

    def test_health_log_route_limit(self):
        # Insert 5 rows
        for i in range(5):
            self._mgr.db.log_health_check(True, True, duration_ms=100 + i)
        resp = self.client.get("/api/health-log?limit=3")
        rows = resp.get_json()
        self.assertEqual(len(rows), 3)

    def test_ingestion_stats_route_shape(self):
        # Seed some refreshes for a non-trivial success_rate_pct
        now = datetime.utcnow().isoformat()
        for status in ["success", "success", "failed"]:
            self._mgr.db.conn.execute(
                """INSERT INTO refresh_log
                   (started_at, completed_at, source, status)
                   VALUES (?, ?, 'all', ?)""",
                (now, now, status),
            )
        self._mgr.db.conn.commit()
        resp = self.client.get("/api/ingestion-stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("csam_assets_count", data)
        self.assertIn("refresh_history", data)
        self.assertEqual(data["refresh_history"]["total"], 3)
        # 2 success of 3 terminal = 66.7%
        self.assertAlmostEqual(
            data["refresh_history"]["success_rate_pct"], 66.7, delta=0.1,
        )


# ── scheduled_health_check ──────────────────────────────────

class ScheduledHealthCheckTest(unittest.TestCase):
    """The heartbeat job must call manager.health_check(), insert one
    row, and never raise — even if health_check itself blows up."""

    def setUp(self):
        import app as app_module
        self.app_module = app_module
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="sched_")
        os.close(fd)
        from src.data_manager import DataManager
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self._mgr = DataManager(cfg)
        self.app_module._manager = self._mgr
        self.app_module._config = cfg

    def tearDown(self):
        try:
            self._mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_writes_one_row_per_call(self):
        self._mgr.health_check = MagicMock(return_value={
            "vm": True, "csam": False,
            "vm_error": None, "csam_error": "AuthError 401",
        })
        self.app_module.scheduled_health_check()
        rows = self._mgr.db.get_health_log(limit=10)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vm_available"], 1)
        self.assertEqual(rows[0]["csam_available"], 0)
        self.assertEqual(rows[0]["csam_error"], "AuthError 401")

    def test_never_raises_when_health_check_throws(self):
        self._mgr.health_check = MagicMock(side_effect=RuntimeError("nope"))
        # Must not propagate — otherwise the scheduler would die
        try:
            self.app_module.scheduled_health_check()
        except Exception as e:
            self.fail(f"scheduled_health_check should swallow exceptions; raised {e}")
        # And: nothing got written, since health_check failed before log_health_check
        self.assertEqual(len(self._mgr.db.get_health_log(limit=10)), 0)


# ── Startup banner ──────────────────────────────────────────

class StartupBannerTest(unittest.TestCase):
    """Banner helper covers both the empty-DB and populated branches
    without raising. Captures log output to confirm the right branch fires."""

    def setUp(self):
        import app as app_module
        self.app_module = app_module
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="banner_")
        os.close(fd)
        from src.data_manager import DataManager
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self._mgr = DataManager(cfg)
        self.app_module._manager = self._mgr
        self.app_module._config = cfg

    def tearDown(self):
        try:
            self._mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_empty_db_banner_branch(self):
        with self.assertLogs("app", level="INFO") as cm:
            self.app_module._log_startup_banner()
        joined = "\n".join(cm.output)
        self.assertIn("Database is empty", joined)

    def test_populated_db_banner_branch(self):
        # One CSAM asset + one refresh_log entry → triggers the
        # populated branch.
        now = datetime.utcnow().isoformat()
        self._mgr.db.conn.execute(
            "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) VALUES (?, ?, ?)",
            ("a1", "10.0.0.1", now),
        )
        self._mgr.db.conn.execute(
            "INSERT INTO refresh_log (started_at, completed_at, source, status) "
            "VALUES (?, ?, 'all', 'success')",
            (now, now),
        )
        self._mgr.db.conn.commit()
        with self.assertLogs("app", level="INFO") as cm:
            self.app_module._log_startup_banner()
        joined = "\n".join(cm.output)
        self.assertIn("CSAM assets:", joined)
        self.assertIn("Refresh history:", joined)
        self.assertNotIn("Database is empty", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
