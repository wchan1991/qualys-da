#!/usr/bin/env python3
"""
Qualys DA — Drift Detection Tests

Pins the invariants for the count-endpoint vs actual-fetch drift
classification in `data_manager._classify_drift`. The user wanted a
way to know when CSAM (or VM hosts / detections) ended up short of the
total Qualys reported during preflight — so a clean pull that landed
95k of 100k expected assets shows up as `partial`, not green-flag
`success`.

Specifically:

* Pure helper: actual < expected → `partial` with a drift message
* Pure helper: actual == expected → `success`
* Pure helper: actual > expected → `success` (positive drift, count was
  stale by the time pagination finished — benign)
* Pure helper: expected is None → `success` (count endpoint failed; no
  reference value to compare against)
* Pure helper: tolerance window absorbs small drift
* End-to-end through `refresh_all`: mocked CSAM fetcher returns short
  vs the seeded `count_csam_assets` mock → `csam_status='partial'`
* End-to-end: mocked VM hosts fetcher returns short vs
  `count_vm_hosts` mock → `vm_host_status='partial'`
* Resume safety: if `_fetch_csam_with_checkpoint` returns only this
  run's pages but the DB total matches expected, status stays success

Run:  python -m unittest tests.test_csam_drift -v
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
from src.data_manager import DataManager, _classify_drift
from src.api_client import QualysClient


def _asset(asset_id, ip):
    return {
        "assetId": asset_id, "name": f"host-{asset_id}", "address": ip,
        "os": "Linux", "hardware": {}, "software": [],
        "tagList": [], "openPort": [], "networkInterface": [],
        "lastSeen": "", "created": "",
    }


def _vm_host(host_id, ip):
    return {
        "host_id": host_id, "ip": ip, "dns": f"h{host_id}.example",
        "netbios": "", "os": "Linux", "trurisk_score": 0,
        "last_scan_date": "", "last_vm_scanned_date": "",
        "last_scap_scanned_date": "", "last_scanned_date": "",
        "tracking_method": "IP", "network_id": 0,
        "tags": [],
    }


def _vm_detection(host_id, ip, qid):
    return {
        "host_id": host_id, "ip": ip, "dns": "", "os": "Linux",
        "qid": qid, "severity": 3, "type": "Confirmed", "status": "Active",
        "first_found": "2024-01-01T00:00:00Z", "last_found": "",
        "last_processed": "", "times_found": 1, "port": 0,
        "protocol": "tcp", "ssl": 0, "qds": 0, "results": "",
        "tags": [], "is_ignored": 0, "is_disabled": 0,
    }


def _make_manager(db_path):
    """Same fixture pattern as test_parallel_refresh, but caller is
    expected to override the count_* mocks per-test to exercise drift."""
    cfg = QualysDAConfig(
        db_path=db_path, username="t", password="t",
        csam_resume_enabled=True, csam_lookback_days=0,
        parallel_refresh=True,
    )
    mgr = DataManager(cfg)
    mgr._client = MagicMock(spec=QualysClient)
    mgr._client.ensure_authenticated = MagicMock(return_value=None)
    # Default to None — tests must override to exercise drift.
    mgr._client.count_csam_assets = MagicMock(return_value=None)
    mgr._client.count_vm_hosts = MagicMock(return_value=None)
    mgr._client.count_vm_detections = MagicMock(return_value=None)
    return mgr


# ── Pure helper tests (no DB / no Flask) ────────────────────

class ClassifyDriftPureTest(unittest.TestCase):
    """`_classify_drift` is a pure function — these tests just exercise
    the classification matrix without touching any I/O."""

    def test_short_pull_marks_partial(self):
        status, err = _classify_drift(95_000, 100_000, "CSAM")
        self.assertEqual(status, "partial")
        self.assertIsNotNone(err)
        self.assertIn("95,000", err)
        self.assertIn("100,000", err)
        self.assertIn("-5,000", err)

    def test_exact_match_marks_success(self):
        status, err = _classify_drift(100_000, 100_000, "CSAM")
        self.assertEqual(status, "success")
        self.assertIsNone(err)

    def test_positive_drift_still_success(self):
        """Count endpoint stale by the time we finished paginating —
        we got everything plus a few extras Qualys added during the
        pull. Benign; classify as success."""
        status, err = _classify_drift(100_005, 100_000, "CSAM")
        self.assertEqual(status, "success")
        self.assertIsNone(err)

    def test_no_expected_is_success(self):
        """count_csam_assets() can return None (preflight call failed,
        non-fatal). With nothing to compare against, classify as
        success — we can't infer drift without a reference."""
        status, err = _classify_drift(100_000, None, "CSAM")
        self.assertEqual(status, "success")
        self.assertIsNone(err)

    def test_tolerance_absorbs_small_drift(self):
        """Operators with high-churn fleets may want a tolerance window
        so single-asset noise doesn't constantly mark partial."""
        status, _ = _classify_drift(99_998, 100_000, "CSAM", tolerance=5)
        self.assertEqual(status, "success")
        # Beyond tolerance, still partial
        status, _ = _classify_drift(99_990, 100_000, "CSAM", tolerance=5)
        self.assertEqual(status, "partial")


# ── End-to-end through refresh_all ──────────────────────────

class CsamDriftEndToEndTest(unittest.TestCase):
    """Drive the full refresh_all path with mocked fetchers that return
    fewer rows than the seeded count endpoints — assert the row gets
    `csam_status='partial'` and surfaces a useful drift error."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="drift_")
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

    def test_csam_short_pull_marks_status_partial(self):
        """Count endpoint says 5 assets, fetcher returns 3 → CSAM
        status flips from `success` to `partial` with a drift error."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.count_csam_assets = MagicMock(return_value=5)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            # Pull only 3 of the 5 expected. on_page persists each
            # batch to the DB so the drift comparison sees the
            # snapshot's actual row count.
            assets = [
                _asset("a1", "10.0.0.1"),
                _asset("a2", "10.0.0.2"),
                _asset("a3", "10.0.0.3"),
            ]
            on_page(1, 3, "a3", False, assets)
            return assets

        def fake_hosts(*, expected=None, on_page=None):
            return []

        def fake_dets(*, expected=None, on_page=None):
            return []

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        self.mgr.refresh_all()

        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(
            row["csam_status"], "partial",
            "CSAM should be 'partial' when actual count is short of "
            "count_csam_assets() expected"
        )
        self.assertIn("3", row["error"] or "")
        self.assertIn("5", row["error"] or "")

    def test_csam_exact_match_keeps_success(self):
        """Count endpoint says 3, fetcher returns 3 → still success."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.count_csam_assets = MagicMock(return_value=3)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            assets = [_asset(f"a{i}", f"10.0.0.{i}") for i in range(1, 4)]
            on_page(1, 3, "a3", False, assets)
            return assets

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = lambda **kw: []
        self.mgr.client.fetch_vm_detections.side_effect = lambda **kw: []

        self.mgr.refresh_all()
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["csam_status"], "success")

    def test_vm_hosts_short_pull_marks_partial(self):
        """Same drift logic applies to VM hosts."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.count_vm_hosts = MagicMock(return_value=10)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            return []

        def fake_hosts(*, expected=None, on_page=None):
            # Only 7 of the 10 expected — drift = -3
            hosts = [_vm_host(i, f"10.0.0.{i}") for i in range(1, 8)]
            if on_page:
                on_page(1, len(hosts), False, hosts)
            return hosts

        def fake_dets(*, expected=None, on_page=None):
            return []

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        self.mgr.refresh_all()
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["vm_host_status"], "partial")
        self.assertIn("7", row["error"] or "")
        self.assertIn("10", row["error"] or "")

    def test_vm_detections_short_pull_marks_partial(self):
        """Same drift logic applies to VM detections."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.count_vm_detections = MagicMock(return_value=4)

        def fake_dets(*, expected=None, on_page=None):
            dets = [_vm_detection(i, f"10.0.0.{i}", 1000 + i)
                    for i in range(1, 3)]  # only 2 of 4 expected
            if on_page:
                on_page(1, len(dets), False, dets)
            return dets

        self.mgr.client.fetch_csam_assets.side_effect = lambda **kw: []
        self.mgr.client.fetch_vm_hosts.side_effect = lambda **kw: []
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        self.mgr.refresh_all()
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["vm_detection_status"], "partial")

    def test_csam_drift_uses_db_count_not_len_assets(self):
        """Resume safety: on a resumed run, fetch_csam_assets returns
        only this run's NEW pages, but the DB has every page across
        all resumed runs under the same snapshot_fetched_at. Drift
        check must compare DB count to expected, not len(assets) — or
        every resumed pull would falsely show as 'partial'."""
        self.mgr = _make_manager(self.db_path)
        self.mgr.client.count_csam_assets = MagicMock(return_value=5)

        # Simulate a previous run's already-saved assets by inserting
        # 3 assets directly into the DB. The fake fetch_csam_assets
        # below will return only 2 NEW assets (simulating the resumed
        # tail), but the snapshot's total in the DB is 5 — matching
        # the expected, so status should be `success`.

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            # Pretend a previous run already saved 3 assets under
            # this snapshot. We seed them via a "page 0" save with
            # the snapshot timestamp the wrapper allocates.
            # Easier: use the on_page callback to save the pre-existing
            # 3 assets first, then save the new 2.
            old = [_asset(f"a{i}", f"10.0.0.{i}") for i in range(1, 4)]
            on_page(1, 3, "a3", True, old)
            new = [_asset("a4", "10.0.0.4"), _asset("a5", "10.0.0.5")]
            on_page(2, 5, "a5", False, new)
            # Return ONLY the new ones — simulating the in-memory
            # state on a resumed run.
            return new

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = lambda **kw: []
        self.mgr.client.fetch_vm_detections.side_effect = lambda **kw: []

        self.mgr.refresh_all()
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(
            row["csam_status"], "success",
            "Drift comparison must use DB count (5) not len(assets) "
            "(2), otherwise every resumed pull falsely shows partial"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
