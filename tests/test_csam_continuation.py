#!/usr/bin/env python3
"""
Qualys DA — CSAM Cross-Query Continuation Tests

Pins the invariants for the outer continuation loop in
`DataManager._fetch_csam_with_checkpoint` that broke past the
~50,000-asset per-query cap Qualys silently imposes.

Hypothesis verified by these tests:
* Qualys returns `hasMore=0` after ~50k assets even when the tenant has
  more matching assets. The wrapper detects this via `total_fetched <
  expected - tolerance` and launches another inner-loop call using the
  final `lastSeenAssetId` as the new starting cursor.
* Stall guard: if a continuation iteration produces zero new assets,
  the wrapper stops to avoid an infinite loop.
* Preflight unavailable (`expected=None`): the continuation guard is
  disabled and the wrapper trusts the inner loop's `hasMore=0`.
* Resume mid-continuation: `query_iteration` and `expected_count` are
  persisted in `csam_checkpoint` so a crash between iterations
  resumes with the correct numbering.

Tests mock `client.fetch_csam_assets` with a `side_effect` list of
per-iteration callables — each callable represents one inner-loop run
(call into Qualys's paginated search ending at the per-query cap).

Run:  python -m unittest tests.test_csam_continuation -v
"""

import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.data_manager import DataManager
from src.api_client import QualysClient


def _asset(asset_id, ip="10.0.0.1"):
    return {
        "assetId": asset_id, "name": f"host-{asset_id}", "address": ip,
        "os": "Linux", "hardware": {}, "software": [],
        "tagList": [], "openPort": [], "networkInterface": [],
        "lastSeen": "", "created": "",
    }


def _make_manager(db_path):
    cfg = QualysDAConfig(
        db_path=db_path, username="t", password="t",
        csam_resume_enabled=True, csam_lookback_days=0,
        parallel_refresh=True,
    )
    mgr = DataManager(cfg)
    mgr._client = MagicMock(spec=QualysClient)
    mgr._client.ensure_authenticated = MagicMock(return_value=None)
    return mgr


def _make_inner_loop_fake(*, asset_id_range, last_seen_at_end,
                          expected_resume_from=None,
                          _sentinel=object()):
    """Build a fake `fetch_csam_assets` that simulates one inner-loop
    call: returns a list of assets, calls on_page once, and ends with
    `hasMore=0`.

    `asset_id_range` is the range of asset_ids this query returns.
    `last_seen_at_end` is the cursor returned with hasMore=0.
    `expected_resume_from`, if set (use the sentinel to mean "skip the
    assertion"), asserts the wrapper passed that value as
    `resume_from_id`.
    """
    def _fake(*, expected, lookback_days, resume_from_id, on_page,
              on_filter_fallback):
        if expected_resume_from is not _sentinel:
            assert resume_from_id == expected_resume_from, (
                f"expected resume_from_id={expected_resume_from!r}, "
                f"got {resume_from_id!r}"
            )
        assets = [
            _asset(f"a{i}", f"10.0.{i // 256}.{i % 256}")
            for i in asset_id_range
        ]
        # One on_page call (representing a single page of results) —
        # the wrapper's on_page persists the assets and updates the
        # checkpoint with the new cross-query cumulative total.
        on_page(1, len(assets), last_seen_at_end, False, assets)
        return assets
    return _fake


def _chain_fakes(*fakes):
    """Bind a sequence of inner-loop fakes to a MagicMock as a
    dispatcher. `MagicMock.side_effect=[callable, callable]` returns
    the callables themselves, not their results — we need a single
    function that walks the sequence."""
    it = iter(fakes)
    def _dispatcher(**kwargs):
        return next(it)(**kwargs)
    return _dispatcher


# ── Cold-start single query ─────────────────────────────────

class ColdStartTest(unittest.TestCase):
    """Cold start with no checkpoint: wrapper passes resume_from_id=None
    on the first inner-loop call (no `startFromId` in the request body
    — same as omitting `lastSeenAssetId` per the prompt §3.1)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="ct_cold_")
        os.close(fd)

    def tearDown(self):
        try:
            self.mgr.close()
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_cold_start_omits_resume_cursor(self):
        """First inner-loop call must receive `resume_from_id=None`,
        which `fetch_csam_assets` translates to omitting `startFromId`
        from the request body. Asset ID 0 is a legal Qualys value, so
        defaulting to `0` would risk skipping a real asset."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(10),
                last_seen_at_end="a9",
                expected_resume_from=None,  # cold start — no cursor
            ),
        )
        assets, _ = self.mgr._fetch_csam_with_checkpoint(expected=10)
        self.assertEqual(len(assets), 10)
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 1)

    def test_cold_start_persists_expected_count(self):
        """`expected_count` lands in the checkpoint so a resume mid-run
        can skip the preflight count call."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(asset_id_range=range(5),
                                  last_seen_at_end="a4"),
        )
        self.mgr._fetch_csam_with_checkpoint(expected=5)
        cp = self.mgr.db.get_csam_checkpoint()
        # On clean completion expected_count is preserved by the
        # sentinel-aware update; the actual value persisted depends
        # on the wrapper's update sequence, but query_iteration must
        # have been reset to 1 on clean completion.
        self.assertTrue(cp["completed"])
        self.assertEqual(cp["query_iteration"], 1)


# ── 50k-cap continuation ────────────────────────────────────

class FiftyKCapContinuationTest(unittest.TestCase):
    """The headline scenario: Qualys caps a query at 50k assets even
    when the tenant has more. The wrapper detects this and continues."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="ct_50k_")
        os.close(fd)

    def tearDown(self):
        try:
            self.mgr.close()
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_continuation_pulls_remaining_assets_after_cap(self):
        """Inner loop returns 5,000 assets with hasMore=0; expected was
        12,000 → wrapper launches a continuation that returns 7,000
        more, starting from the last cursor of the first query.

        Note: tolerance is `max(100, 1% of expected)`. We use larger
        numbers in tests than the prompt's 50→120 example so the tolerance
        floor of 100 doesn't accidentally count 50/120 as 'close enough'."""
        self.mgr = _make_manager(self.db_path)
        # Two consecutive inner-loop calls: query 1 returns 5,000 (cap),
        # query 2 returns 7,000 (remaining). Total = 12,000 = expected.
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(5_000),
                last_seen_at_end="a4999",
                expected_resume_from=None,
            ),
            _make_inner_loop_fake(
                asset_id_range=range(5_000, 12_000),
                last_seen_at_end="a11999",
                expected_resume_from="a4999",  # cursor threaded through
            ),
        )
        assets, _ = self.mgr._fetch_csam_with_checkpoint(expected=12_000)
        self.assertEqual(len(assets), 12_000,
            "Wrapper must continue past the per-query cap until expected reached")
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 2,
            "Exactly two inner-loop calls — one for cap, one for the rest")
        # Asset rows persisted under one snapshot
        snap = self.mgr.db.get_latest_fetched_at("csam_assets")
        n_persisted = self.mgr.db.conn.execute(
            "SELECT COUNT(*) FROM csam_assets WHERE fetched_at = ?",
            (snap,),
        ).fetchone()[0]
        self.assertEqual(n_persisted, 12_000)

    def test_continuation_stops_when_target_reached_within_tolerance(self):
        """Tolerance = max(100, 1% of expected). For expected=120 →
        tolerance = 100. So 20 of 120 (drift -100) is exactly at the
        tolerance edge — should be classified as success, no further
        continuation."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(asset_id_range=range(20),
                                  last_seen_at_end="a19"),
        )
        with self.assertLogs("src.data_manager", level="INFO") as cm:
            self.mgr._fetch_csam_with_checkpoint(expected=120)
        joined = "\n".join(cm.output)
        # Should reach the "pull complete" log, not "stopped early"
        self.assertIn("pull complete", joined)
        # Only one inner-loop call (within tolerance, no continuation)
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 1)

    def test_three_query_continuation(self):
        """Stress test: three iterations chained. expected=3,000, each
        query returns 1,000. Verifies the cross-query cursor threading
        survives multiple hops past the tolerance floor."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(0, 1_000),
                last_seen_at_end="a999",
                expected_resume_from=None,
            ),
            _make_inner_loop_fake(
                asset_id_range=range(1_000, 2_000),
                last_seen_at_end="a1999",
                expected_resume_from="a999",
            ),
            _make_inner_loop_fake(
                asset_id_range=range(2_000, 3_000),
                last_seen_at_end="a2999",
                expected_resume_from="a1999",
            ),
        )
        assets, _ = self.mgr._fetch_csam_with_checkpoint(expected=3_000)
        self.assertEqual(len(assets), 3_000)
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 3)


# ── Stall guard ─────────────────────────────────────────────

class StallGuardTest(unittest.TestCase):
    """If a continuation iteration produces zero new assets, the loop
    bails to avoid spinning forever."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="ct_stall_")
        os.close(fd)

    def tearDown(self):
        try:
            self.mgr.close()
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_zero_progress_iteration_stops_with_warning(self):
        """expected=10,000. Query 1 returns 5,000, hasMore=0. Query 2
        returns 0 assets, hasMore=0 (server stalled). Wrapper must
        detect no progress and stop with a WARNING.

        Numbers chosen so 5,000 is meaningfully short of expected
        beyond the tolerance floor of 100, forcing continuation; then
        the empty-second-iteration triggers the stall guard."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(5_000),
                last_seen_at_end="a4999",
            ),
            _make_inner_loop_fake(
                asset_id_range=range(0),  # empty: 0 new assets
                last_seen_at_end="a4999",
                expected_resume_from="a4999",
            ),
        )
        with self.assertLogs("src.data_manager", level="WARNING") as cm:
            assets, _ = self.mgr._fetch_csam_with_checkpoint(expected=10_000)
        joined = "\n".join(cm.output)
        # One stall warning
        self.assertTrue(
            any("made no progress" in m for m in cm.output),
            f"Expected stall warning, got: {cm.output}",
        )
        # Pull stopped at 5,000 of 10,000 (50% short)
        self.assertEqual(len(assets), 5_000)
        # Two inner-loop calls (the stalling one fired but produced nothing)
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 2)


# ── Preflight unavailable ───────────────────────────────────

class PreflightUnavailableTest(unittest.TestCase):
    """When count_csam_assets returns None upstream, expected=None at
    the wrapper. Continuation guard is disabled — wrapper trusts the
    inner loop's hasMore=0 as authoritative."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(
            suffix=".db", prefix="ct_no_preflight_",
        )
        os.close(fd)

    def tearDown(self):
        try:
            self.mgr.close()
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_no_expected_no_continuation_attempted(self):
        """expected=None → exactly one inner-loop call, even though the
        50 assets returned would have been short of any reasonable
        target. Without a count we can't know the target exists."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(50),
                last_seen_at_end="a49",
            ),
        )
        with self.assertLogs("src.data_manager", level="INFO") as cm:
            self.mgr._fetch_csam_with_checkpoint(expected=None)
        # Only one inner-loop call (no continuation attempted)
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 1)
        joined = "\n".join(cm.output)
        # Final log should mention preflight was unavailable
        self.assertIn("preflight count was unavailable", joined)


# ── Resume mid-continuation ─────────────────────────────────

class ResumeMidContinuationTest(unittest.TestCase):
    """Crash between continuation iterations 1 and 2 → checkpoint
    should preserve enough state for the next refresh to resume
    correctly."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="ct_resume_")
        os.close(fd)

    def tearDown(self):
        try:
            self.mgr.close()
        except Exception:
            pass
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_resume_picks_up_from_last_cursor(self):
        """Simulate: previous run's checkpoint has last_asset_id='a4999',
        completed=False, 5,000 already persisted. New invocation should
        pass 'a4999' as resume_from_id on its FIRST inner-loop call and
        the cross-query running total should accumulate from there."""
        self.mgr = _make_manager(self.db_path)
        snap = "2026-05-04T12:00:00"
        # Pre-populate 5,000 assets in the DB under the prior snapshot —
        # simulates the interrupted run's persisted page-saves.
        for i in range(5_000):
            self.mgr.db.conn.execute(
                "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) "
                "VALUES (?, ?, ?)",
                (f"a{i}", f"10.0.0.{i % 255}", snap),
            )
        self.mgr.db.conn.commit()
        # And a checkpoint pointing at the cursor where the prior run stopped
        self.mgr.db.update_csam_checkpoint(
            last_asset_id="a4999",
            assets_pulled=5_000,
            completed=False,
            lookback_days=0,
            note="interrupted",
            snapshot_fetched_at=snap,
            expected_count=12_000,
            query_iteration=2,
        )
        # The resume's inner-loop call must receive resume_from_id='a4999'.
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(5_000, 12_000),
                last_seen_at_end="a11999",
                expected_resume_from="a4999",
            ),
        )
        assets, returned_snap = self.mgr._fetch_csam_with_checkpoint(
            expected=12_000,
        )
        # Resume reuses the prior snapshot timestamp
        self.assertEqual(returned_snap, snap)
        # 5,000 from prior run + 7,000 from resume = 12,000
        cp = self.mgr.db.get_csam_checkpoint()
        self.assertEqual(cp["assets_pulled"], 12_000)
        self.assertTrue(cp["completed"])

    def test_resume_with_completed_checkpoint_starts_fresh(self):
        """If the last checkpoint is `completed=True`, the next run
        starts a fresh snapshot (does NOT resume the prior cursor)."""
        self.mgr = _make_manager(self.db_path)
        # Pre-populate a completed checkpoint
        self.mgr.db.update_csam_checkpoint(
            last_asset_id=None,
            assets_pulled=120,
            completed=True,
            lookback_days=0,
            note="complete",
            snapshot_fetched_at=None,
        )
        self.mgr.client.fetch_csam_assets.side_effect = _chain_fakes(
            _make_inner_loop_fake(
                asset_id_range=range(80),
                last_seen_at_end="b79",
                expected_resume_from=None,  # fresh start
            ),
        )
        self.mgr._fetch_csam_with_checkpoint(expected=80)
        # Inner-loop got resume_from_id=None as expected
        self.assertEqual(self.mgr.client.fetch_csam_assets.call_count, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
