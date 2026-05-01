#!/usr/bin/env python3
"""
Qualys DA — Full-Wipe Purge Tests

Pins the invariants for `db.purge_all_data()` and the
`manager.purge_all()` orchestrator + the `/api/purge/all` route guard.

Specifically:

* `purge_all_data()` deletes from every snapshot + derived + operational
  table, and (when `include_config=True`) also from the config tables.
  Schema is preserved (no DROP TABLE) so the next refresh works
  immediately.
* The default keeps `asset_owners`, `sla_targets`, `saved_queries` so
  operators don't lose their setup when they reset the data.
* `manager.purge_all()` cancels any in-flight refresh BEFORE wiping —
  if cancel doesn't take effect within the wait window, it still
  proceeds and reports `cancel_completed: false`.
* `POST /api/purge/all` rejects requests without `?confirm=YES`.
* The route accepts `?include_config=true` to opt into wiping config.

Run:  python -m unittest tests.test_purge_all -v
"""

import os
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.database import QualysDADatabase
from src.data_manager import DataManager


def _seed_all_tables(db):
    """Seed at least one row in every table the purge touches.

    Returns a dict mapping table → expected pre-purge count, so tests
    can assert on the deltas.
    """
    now = datetime.utcnow().isoformat()
    seeds = {}

    # Snapshot tables
    db.conn.execute(
        "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) VALUES (?, ?, ?)",
        ("a1", "10.0.0.1", now),
    )
    seeds["csam_assets"] = 1

    db.conn.execute(
        "INSERT INTO vm_hosts (host_id, ip_address, fetched_at) VALUES (?, ?, ?)",
        (1, "10.0.0.1", now),
    )
    seeds["vm_hosts"] = 1

    db.conn.execute(
        "INSERT INTO vm_detections (host_id, qid, fetched_at) VALUES (?, ?, ?)",
        (1, 1001, now),
    )
    seeds["vm_detections"] = 1

    db.conn.execute(
        "INSERT INTO host_tags (host_id, tag_id, tag_name, source, fetched_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (1, 100, "Production", "vm", now),
    )
    seeds["host_tags"] = 1

    # Derived history
    db.conn.execute(
        "INSERT INTO detection_changes (host_id, qid, change_type, detected_at) "
        "VALUES (?, ?, ?, ?)",
        (1, 1001, "new", now),
    )
    seeds["detection_changes"] = 1

    db.conn.execute(
        "INSERT INTO weekly_rollups (week_start, total_vulns, computed_at) "
        "VALUES (?, ?, ?)",
        ("2026-04-28", 100, now),
    )
    seeds["weekly_rollups"] = 1

    db.conn.execute(
        "INSERT INTO monthly_rollups (month_start, total_vulns, computed_at) "
        "VALUES (?, ?, ?)",
        ("2026-04-01", 100, now),
    )
    seeds["monthly_rollups"] = 1

    # Operational state
    # Complete the refresh_log row so it's in terminal state — most
    # tests want "data exists but no refresh is running right now".
    # The orchestration test seeds its own running row separately.
    rid = db.log_refresh("all")
    db.complete_refresh(rid, status="success")
    seeds["refresh_log"] = 1

    db.log_health_check(True, True, duration_ms=100)
    seeds["health_log"] = 1

    db.update_csam_checkpoint(
        last_asset_id="a1", assets_pulled=1, completed=False,
        lookback_days=0, snapshot_fetched_at=now,
    )
    seeds["csam_checkpoint"] = 1

    # Config tables (kept by default, wiped only with include_config=True)
    db.conn.execute(
        "INSERT INTO asset_owners (match_type, match_value, owner, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("ip", "10.0.0.1", "alice", now, now),
    )
    seeds["asset_owners"] = 1

    # sla_targets is auto-seeded with 5 default rows by _init_schema
    seeds["sla_targets"] = db.conn.execute(
        "SELECT COUNT(*) FROM sla_targets"
    ).fetchone()[0]

    db.conn.execute(
        "INSERT INTO saved_queries (name, sql_text, created_at) VALUES (?, ?, ?)",
        ("My Query", "SELECT 1", now),
    )
    seeds["saved_queries"] = 1

    db.conn.commit()
    return seeds


class PurgeAllDataTest(unittest.TestCase):
    """Direct DB-level test of `purge_all_data` — covers every table
    the purge touches and verifies what survives in each mode."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="purge_")
        os.close(fd)
        self.db = QualysDADatabase(self.db_path)

    def tearDown(self):
        try:
            self.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def _row_count(self, table: str) -> int:
        return self.db.conn.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]

    def test_default_wipes_data_keeps_config(self):
        """include_config=False (default) wipes all snapshot + ops tables
        but preserves asset_owners, sla_targets, saved_queries."""
        seeds = _seed_all_tables(self.db)
        # Sanity: every seeded table has rows
        for table, n in seeds.items():
            self.assertGreater(self._row_count(table), 0,
                               f"Setup error: {table} should have rows")

        counts = self.db.purge_all_data(include_config=False)

        # Wiped
        for table in ("csam_assets", "vm_hosts", "vm_detections",
                      "host_tags", "detection_changes",
                      "weekly_rollups", "monthly_rollups",
                      "refresh_log", "health_log", "csam_checkpoint"):
            self.assertEqual(self._row_count(table), 0,
                             f"{table} should be empty after purge")
            self.assertEqual(counts.get(table), seeds[table],
                             f"counts[{table}] should match deleted row count")

        # Preserved
        self.assertEqual(self._row_count("asset_owners"), 1)
        self.assertEqual(self._row_count("sla_targets"), seeds["sla_targets"])
        self.assertEqual(self._row_count("saved_queries"), 1)
        # And those tables are NOT in the counts dict
        self.assertNotIn("asset_owners", counts)
        self.assertNotIn("sla_targets", counts)
        self.assertNotIn("saved_queries", counts)

    def test_include_config_wipes_everything(self):
        """include_config=True also wipes asset_owners, sla_targets,
        saved_queries — full factory reset."""
        _seed_all_tables(self.db)
        counts = self.db.purge_all_data(include_config=True)
        for table in ("asset_owners", "sla_targets", "saved_queries"):
            self.assertEqual(self._row_count(table), 0,
                             f"{table} should be empty after include_config purge")
            self.assertIn(table, counts)

    def test_schema_preserved_after_purge(self):
        """The purge uses DELETE not DROP — so the next refresh can
        write to the same tables without re-running _init_schema."""
        _seed_all_tables(self.db)
        self.db.purge_all_data()
        # Insert a row to prove the table still exists with the right shape
        now = datetime.utcnow().isoformat()
        self.db.conn.execute(
            "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) VALUES (?, ?, ?)",
            ("post_purge", "10.1.1.1", now),
        )
        self.db.conn.commit()
        self.assertEqual(self._row_count("csam_assets"), 1)


class PurgeAllOrchestratorTest(unittest.TestCase):
    """`manager.purge_all()` cancels in-flight refresh before wiping."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="purge_orch_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_no_refresh_running_just_wipes(self):
        """When nothing is running, no cancel is needed — straight to wipe."""
        _seed_all_tables(self.mgr.db)
        result = self.mgr.purge_all()
        self.assertFalse(result["cancel_was_needed"])
        self.assertTrue(result["cancel_completed"])
        self.assertGreater(sum(result["purged_counts"].values()), 0)

    def test_cancels_running_refresh_first(self):
        """If a row in refresh_log has status='running', purge_all
        sets the cancel event before wiping."""
        # Seed a 'running' row directly so we don't need to actually
        # spin up a fetch
        rid = self.mgr.db.log_refresh("all")
        self.assertEqual(
            self.mgr.db.get_refresh_log(limit=1)[0]["status"], "running"
        )
        self.assertFalse(self.mgr.is_cancel_requested())

        # Spin off a thread that flips the running row to "cancelled"
        # mid-wait, simulating a real fetcher that picks up the cancel
        # signal at its next page boundary. Without this, purge_all
        # would wait the full 30s timeout.
        def _simulate_fetcher_responds_to_cancel():
            for _ in range(20):  # poll up to 1s
                if self.mgr.is_cancel_requested():
                    self.mgr.db.complete_refresh(rid, status="cancelled")
                    return
                time.sleep(0.05)
        t = threading.Thread(target=_simulate_fetcher_responds_to_cancel,
                             daemon=True)
        t.start()

        result = self.mgr.purge_all(cancel_wait_seconds=5.0)
        t.join(timeout=2.0)

        self.assertTrue(result["cancel_was_needed"])
        self.assertTrue(result["cancel_completed"],
            "Mock fetcher should have flipped status to 'cancelled' in time")
        self.assertTrue(self.mgr.is_cancel_requested())

    def test_proceeds_even_if_cancel_times_out(self):
        """Last-resort: if the in-flight refresh refuses to stop,
        purge_all still wipes — the refresh's next DB write will fail,
        which is fine because we're wiping anyway."""
        _seed_all_tables(self.mgr.db)
        # Seed a stuck 'running' row that nothing will ever flip
        self.mgr.db.log_refresh("all")
        result = self.mgr.purge_all(cancel_wait_seconds=0.5)
        self.assertTrue(result["cancel_was_needed"])
        self.assertFalse(result["cancel_completed"],
            "Should report cancel_completed=False when stuck")
        # And the wipe still happened — refresh_log row got deleted too
        self.assertEqual(
            self.mgr.db.conn.execute(
                "SELECT COUNT(*) FROM refresh_log"
            ).fetchone()[0], 0,
        )


class PurgeRouteTest(unittest.TestCase):
    """POST /api/purge/all — confirm=YES guard + include_config flag."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="purge_route_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)
        self.mgr._client = MagicMock()
        self.app_module._manager = self.mgr
        self.app_module._config = cfg
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_route_rejects_without_confirm(self):
        """No ?confirm=YES → 200 with an error message and NO data wiped."""
        _seed_all_tables(self.mgr.db)
        resp = self.client.post("/api/purge/all")
        data = resp.get_json()
        self.assertIn("error", data)
        # Data is still there — wipe did not happen
        n = self.mgr.db.conn.execute(
            "SELECT COUNT(*) FROM csam_assets"
        ).fetchone()[0]
        self.assertEqual(n, 1, "Without confirm, the wipe must not run")

    def test_route_with_confirm_wipes_data(self):
        _seed_all_tables(self.mgr.db)
        resp = self.client.post("/api/purge/all?confirm=YES")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("purged_counts", data)
        # Data is gone
        self.assertEqual(
            self.mgr.db.conn.execute(
                "SELECT COUNT(*) FROM csam_assets"
            ).fetchone()[0], 0,
        )
        # Config is preserved by default
        self.assertEqual(
            self.mgr.db.conn.execute(
                "SELECT COUNT(*) FROM asset_owners"
            ).fetchone()[0], 1,
        )

    def test_route_include_config_wipes_config_too(self):
        _seed_all_tables(self.mgr.db)
        resp = self.client.post(
            "/api/purge/all?confirm=YES&include_config=true"
        )
        self.assertEqual(resp.status_code, 200)
        # Config is also gone now
        self.assertEqual(
            self.mgr.db.conn.execute(
                "SELECT COUNT(*) FROM asset_owners"
            ).fetchone()[0], 0,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
