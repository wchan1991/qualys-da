#!/usr/bin/env python3
"""
Qualys DA — CSAM Resume Correctness Tests

Covers the data-loss gap that used to exist in the CSAM resume path.
Pre-fix: the checkpoint tracked *which page was last seen*, not *which
assets were persisted*. A mid-pull rate-limit meant successfully fetched
pages were dropped from memory and a successful resume would overwrite
MAX(fetched_at) with only the tail half of the fleet — silently halving
the dashboard.

These tests pin the new invariant: every page is written to `csam_assets`
inside the `on_page` callback under a single `snapshot_fetched_at`, so a
resumed pull extends the same snapshot rather than creating a new one.

Run:  python -m unittest tests.test_csam_resume -v
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# sys.path prelude matches test_qa.py
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.database import QualysDADatabase
from src.data_manager import DataManager
from src.api_client import RateLimitError


def _make_manager(db_path, lookback_days=0):
    """Build a DataManager backed by a temp DB and a fake Qualys client.

    The fake client's `fetch_csam_assets` is controlled per-test to
    drive the `on_page` callback deterministically and inject failures.
    """
    config = QualysDAConfig(
        db_path=db_path,
        username="test",
        password="test",
        csam_resume_enabled=True,
        csam_lookback_days=lookback_days,
        parallel_refresh=False,
    )
    mgr = DataManager(config)
    # Replace the lazy client with a MagicMock so we never hit the network.
    mgr._client = MagicMock()
    return mgr


def _asset(asset_id, ip):
    """Minimal asset dict shaped like Qualys's CSAM response."""
    return {
        "assetId": asset_id, "name": f"host-{asset_id}", "address": ip,
        "os": "Linux", "hardware": {}, "software": [],
        "tagList": [], "openPort": [], "networkInterface": [],
        "lastSeen": "", "created": "",
    }


class CsamResumeTest(unittest.TestCase):

    def setUp(self):
        # Use a unique tempfile per test so they don't interfere.
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="csam_resume_")
        os.close(fd)

    def tearDown(self):
        # Explicit close so Windows releases the file handle before unlink.
        try:
            self.mgr.close()  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()  # type: ignore[attr-defined]
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    # ── Schema / migration ───────────────────────────────────────

    def test_migration_adds_snapshot_fetched_at_column(self):
        """The checkpoint table must carry snapshot_fetched_at after init."""
        self.mgr = _make_manager(self.db_path)
        cols = [
            r[1] for r in
            self.mgr.db.conn.execute("PRAGMA table_info(csam_checkpoint)").fetchall()
        ]
        self.assertIn("snapshot_fetched_at", cols)

    # ── Clean pull ───────────────────────────────────────────────

    def test_clean_pull_writes_all_pages_under_one_snapshot(self):
        """Every page the API returns must land under the same fetched_at."""
        self.mgr = _make_manager(self.db_path)

        # Stage the fake client: 3 pages, call on_page for each, return list.
        def fake_fetch(*, expected, lookback_days, resume_from_id,
                       on_page, on_filter_fallback):
            pages = [
                [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")],
                [_asset("a3", "10.0.0.3"), _asset("a4", "10.0.0.4")],
                [_asset("a5", "10.0.0.5")],
            ]
            all_assets = []
            for i, p in enumerate(pages, start=1):
                all_assets.extend(p)
                last_id = p[-1]["assetId"]
                has_more = i < len(pages)
                on_page(i, len(all_assets), last_id, has_more, p)
            return all_assets

        self.mgr.client.fetch_csam_assets.side_effect = fake_fetch

        assets, snapshot = self.mgr._fetch_csam_with_checkpoint()

        self.assertEqual(len(assets), 5)
        self.assertIsNotNone(snapshot)

        # All 5 rows must share one fetched_at equal to the returned snapshot.
        rows = self.mgr.db.conn.execute(
            "SELECT DISTINCT fetched_at FROM csam_assets"
        ).fetchall()
        self.assertEqual(len(rows), 1,
                         f"Expected 1 distinct fetched_at, got {rows}")
        self.assertEqual(rows[0][0], snapshot)

        # Checkpoint must be marked complete and its snapshot cleared.
        cp = self.mgr.db.get_csam_checkpoint()
        self.assertTrue(cp["completed"])
        self.assertIsNone(cp["snapshot_fetched_at"])

    # ── Mid-pull exception ───────────────────────────────────────

    def test_mid_pull_exception_preserves_partial_rows_and_checkpoint(self):
        """A RateLimitError on page 3 must leave pages 1-2 on disk AND a
        resumable checkpoint pointing at the same snapshot_fetched_at."""
        self.mgr = _make_manager(self.db_path)

        def fake_fetch(*, expected, lookback_days, resume_from_id,
                       on_page, on_filter_fallback):
            # Deliver 2 pages cleanly, then raise on page 3.
            p1 = [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")]
            p2 = [_asset("a3", "10.0.0.3"), _asset("a4", "10.0.0.4")]
            on_page(1, 2, "a2", True, p1)
            on_page(2, 4, "a4", True, p2)
            raise RateLimitError("simulated 429")

        self.mgr.client.fetch_csam_assets.side_effect = fake_fetch

        with self.assertRaises(RateLimitError):
            self.mgr._fetch_csam_with_checkpoint()

        # Partial rows must be on disk under one fetched_at.
        distinct_ts = self.mgr.db.conn.execute(
            "SELECT DISTINCT fetched_at FROM csam_assets"
        ).fetchall()
        self.assertEqual(len(distinct_ts), 1,
                         "Expected all partial rows under one fetched_at")
        saved_fetched_at = distinct_ts[0][0]

        count = self.mgr.db.conn.execute(
            "SELECT COUNT(*) FROM csam_assets"
        ).fetchone()[0]
        self.assertEqual(count, 4, "Pages 1-2 should be saved (4 rows)")

        # Checkpoint must be resumable and point at the same snapshot.
        cp = self.mgr.db.get_csam_checkpoint()
        self.assertFalse(cp["completed"])
        self.assertEqual(cp["last_asset_id"], "a4")
        self.assertEqual(cp["snapshot_fetched_at"], saved_fetched_at)
        self.assertIn("interrupted", cp["note"])

    # ── Resume extends the same snapshot ─────────────────────────

    def test_resume_extends_same_snapshot(self):
        """After a mid-pull failure, a second call must land ALL rows under
        the same fetched_at as the first partial run."""
        self.mgr = _make_manager(self.db_path)

        # Phase 1: fail mid-pull (same as above).
        def phase1(*, expected, lookback_days, resume_from_id,
                   on_page, on_filter_fallback):
            p1 = [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")]
            p2 = [_asset("a3", "10.0.0.3"), _asset("a4", "10.0.0.4")]
            on_page(1, 2, "a2", True, p1)
            on_page(2, 4, "a4", True, p2)
            raise RateLimitError("simulated 429")

        self.mgr.client.fetch_csam_assets.side_effect = phase1
        with self.assertRaises(RateLimitError):
            self.mgr._fetch_csam_with_checkpoint()

        snapshot_before = self.mgr.db.get_csam_checkpoint()["snapshot_fetched_at"]
        self.assertIsNotNone(snapshot_before)

        # Phase 2: resume — must be called with resume_from_id="a4" and the
        # returned assets must be appended under the SAME fetched_at.
        phase2_captured = {}

        def phase2(*, expected, lookback_days, resume_from_id,
                   on_page, on_filter_fallback):
            phase2_captured["resume_from_id"] = resume_from_id
            p3 = [_asset("a5", "10.0.0.5"), _asset("a6", "10.0.0.6")]
            on_page(1, 2, "a6", False, p3)
            return p3

        self.mgr.client.fetch_csam_assets.side_effect = phase2
        assets, snapshot_after = self.mgr._fetch_csam_with_checkpoint()

        # Resume was correctly wired from the checkpoint's last_asset_id.
        self.assertEqual(phase2_captured["resume_from_id"], "a4")

        # Same snapshot timestamp is reused across the two runs.
        self.assertEqual(snapshot_after, snapshot_before)

        # All 6 rows end up under that single fetched_at.
        distinct_ts = self.mgr.db.conn.execute(
            "SELECT DISTINCT fetched_at FROM csam_assets"
        ).fetchall()
        self.assertEqual(len(distinct_ts), 1)
        self.assertEqual(distinct_ts[0][0], snapshot_before)
        total = self.mgr.db.conn.execute(
            "SELECT COUNT(*) FROM csam_assets"
        ).fetchone()[0]
        self.assertEqual(total, 6)

        # Dashboard would now query MAX(fetched_at) → this snapshot; row
        # count matches the full fleet. Regression lock against the old
        # tail-only-snapshot bug.
        latest = self.mgr.db.get_latest_fetched_at("csam_assets")
        self.assertEqual(latest, snapshot_before)

        # Checkpoint is cleared (completed + snapshot nulled).
        cp = self.mgr.db.get_csam_checkpoint()
        self.assertTrue(cp["completed"])
        self.assertIsNone(cp["snapshot_fetched_at"])

    # ── Lookback drift forces a fresh start ──────────────────────

    def test_lookback_drift_resets_checkpoint(self):
        """If config.csam_lookback_days changes between runs, the resume
        must bail out and start a fresh snapshot — we can't mix differently
        filtered populations under one fetched_at."""
        self.mgr = _make_manager(self.db_path, lookback_days=90)

        def phase1(*, expected, lookback_days, resume_from_id,
                   on_page, on_filter_fallback):
            p1 = [_asset("a1", "10.0.0.1")]
            on_page(1, 1, "a1", True, p1)
            raise RateLimitError("simulated 429")

        self.mgr.client.fetch_csam_assets.side_effect = phase1
        with self.assertRaises(RateLimitError):
            self.mgr._fetch_csam_with_checkpoint()
        snapshot_phase1 = self.mgr.db.get_csam_checkpoint()["snapshot_fetched_at"]

        # Operator changes the lookback window before the next refresh.
        self.mgr.config.csam_lookback_days = 30

        captured = {}

        def phase2(*, expected, lookback_days, resume_from_id,
                   on_page, on_filter_fallback):
            captured["resume_from_id"] = resume_from_id
            captured["lookback_days"] = lookback_days
            p = [_asset("b1", "10.0.0.9")]
            on_page(1, 1, "b1", False, p)
            return p

        self.mgr.client.fetch_csam_assets.side_effect = phase2
        _, snapshot_phase2 = self.mgr._fetch_csam_with_checkpoint()

        # Resume pointer was NOT honoured (drift → fresh start).
        self.assertIsNone(captured["resume_from_id"])
        self.assertEqual(captured["lookback_days"], 30)

        # A fresh snapshot was allocated rather than extending the old one.
        self.assertNotEqual(snapshot_phase2, snapshot_phase1)

    # ── Filter fallback clears lookback on the checkpoint ────────

    def test_filter_fallback_clears_checkpoint_lookback(self):
        """When Qualys rejects the QQL filter and we retry without it, the
        checkpoint's lookback_days must be cleared so a later resume doesn't
        re-apply the rejected filter."""
        self.mgr = _make_manager(self.db_path, lookback_days=90)

        def fake_fetch(*, expected, lookback_days, resume_from_id,
                       on_page, on_filter_fallback):
            # Simulate Qualys rejecting the filter on page 1.
            on_filter_fallback()
            p = [_asset("a1", "10.0.0.1")]
            on_page(1, 1, "a1", False, p)
            return p

        self.mgr.client.fetch_csam_assets.side_effect = fake_fetch

        self.mgr._fetch_csam_with_checkpoint()

        cp = self.mgr.db.get_csam_checkpoint()
        # Clean completion overwrites lookback_days with the config's value
        # (90) — the fallback-clearing write in _on_filter_fallback happens
        # mid-pull. The important assertion is that, had the pull been
        # interrupted at the fallback moment, the checkpoint would show a
        # NULL lookback. Reach into the journaled history via note instead:
        self.assertTrue(cp["completed"])
        # And verify the _on_filter_fallback path was hit: checkpoint went
        # through a state with a filter-fallback note. We can only check
        # the final state here; see direct update assertion below.

    def test_filter_fallback_writes_null_lookback_immediately(self):
        """Direct pin: when on_filter_fallback fires, the checkpoint's
        lookback_days transitions to NULL before the next page lands."""
        self.mgr = _make_manager(self.db_path, lookback_days=90)

        observed_lookbacks = []

        def fake_fetch(*, expected, lookback_days, resume_from_id,
                       on_page, on_filter_fallback):
            on_filter_fallback()
            # Capture the checkpoint state immediately after fallback.
            cp = self.mgr.db.get_csam_checkpoint()
            observed_lookbacks.append(cp["lookback_days"])
            # Then raise, so the clean-completion path doesn't overwrite it.
            raise RateLimitError("test halt after fallback")

        self.mgr.client.fetch_csam_assets.side_effect = fake_fetch

        with self.assertRaises(RateLimitError):
            self.mgr._fetch_csam_with_checkpoint()

        self.assertEqual(observed_lookbacks, [None],
                         "Filter fallback should null out lookback_days "
                         "so a later resume doesn't re-apply the bad filter.")


if __name__ == "__main__":
    unittest.main(verbosity=2)
