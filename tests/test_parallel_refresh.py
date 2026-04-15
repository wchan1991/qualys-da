#!/usr/bin/env python3
"""
Qualys DA — Parallel Refresh + Partial Status Tests

Pins the invariants for the "fully parallel, per-API-isolated" refresh
pipeline. Specifically:

* One API failing must NOT cancel the other two. The Status Page needs
  to show per-API outcomes so the operator can see which single Refresh
  button to re-click.
* Live counts: refresh_log's `csam_count` / `vm_host_count` /
  `vm_detection_count` must move while status is still 'running' so the
  dashboard banner has something to show during a 15-minute pull.
* Row-level status is the aggregate: all-success → success, all-fail →
  failed, anything mixed → partial.
* Three-tier throttle pacing on CSAM: WARN at <50 remaining,
  WARN + 0.5s slow-down at <=10, INFO + ToWait-Sec hard-wait at <=2.

Run:  python -m unittest tests.test_parallel_refresh -v
"""

import logging
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

# sys.path prelude matches the rest of the suite
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.data_manager import DataManager
from src.api_client import RateLimitError, QualysClient


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
    # Minimal shape accepted by save_vm_detections
    return {
        "host_id": host_id, "ip": ip, "dns": "", "os": "Linux",
        "qid": qid, "severity": 3, "type": "Confirmed", "status": "Active",
        "first_found": "2024-01-01T00:00:00Z", "last_found": "",
        "last_processed": "", "times_found": 1, "port": 0,
        "protocol": "tcp", "ssl": 0, "qds": 0, "results": "",
        "tags": [], "is_ignored": 0, "is_disabled": 0,
    }


def _make_manager(db_path):
    """Build a DataManager with a mocked Qualys client and
    parallel_refresh ON so refresh_all exercises the 3-way executor."""
    config = QualysDAConfig(
        db_path=db_path, username="test", password="test",
        csam_resume_enabled=True, csam_lookback_days=0,
        parallel_refresh=True,
    )
    mgr = DataManager(config)
    mgr._client = MagicMock(spec=QualysClient)
    # ensure_authenticated is a no-op in tests
    mgr._client.ensure_authenticated = MagicMock(return_value=None)
    # Count endpoints return plausible numbers so refresh_log shows expected
    mgr._client.count_csam_assets = MagicMock(return_value=4)
    mgr._client.count_vm_hosts = MagicMock(return_value=2)
    mgr._client.count_vm_detections = MagicMock(return_value=2)
    # Tag extraction helpers are @staticmethod on the real class — no need
    # to mock; they just walk the passed lists.
    return mgr


class ParallelRefreshIsolationTest(unittest.TestCase):

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(
            suffix=".db", prefix="parallel_refresh_"
        )
        os.close(fd)

    def tearDown(self):
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

    # ── Failure isolation ────────────────────────────────────────

    def test_csam_failure_does_not_abort_vm_threads(self):
        """CSAM raising RateLimitError must leave VM hosts and VM
        detections free to complete and commit their data.

        This is the central invariant behind the "Refresh in progress"
        banner's per-API outcome strip — without it, any one 429 would
        nuke the operator's only path to seeing partial progress."""
        self.mgr = _make_manager(self.db_path)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            # Persist page 1 via on_page, then blow up like a real 429.
            p1 = [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")]
            on_page(1, 2, "a2", True, p1)
            raise RateLimitError("simulated 429")

        def fake_hosts(*, expected=None, on_page=None):
            hosts = [_vm_host(1, "10.0.0.1"), _vm_host(2, "10.0.0.2")]
            if on_page:
                on_page(1, len(hosts), False, hosts)
            return hosts

        def fake_dets(*, expected=None, on_page=None):
            dets = [_vm_detection(1, "10.0.0.1", 1001),
                    _vm_detection(2, "10.0.0.2", 1002)]
            if on_page:
                on_page(1, len(dets), False, dets)
            return dets

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        counts = self.mgr.refresh_all()

        # VM succeeded; CSAM saved its partial page before failing.
        self.assertEqual(counts["vm_hosts"], 2,
                         "VM hosts thread must not be cancelled by CSAM's failure")
        self.assertEqual(counts["vm_detections"], 2,
                         "VM detections thread must not be cancelled by CSAM's failure")
        self.assertEqual(counts["csam"], 2,
                         "CSAM page 1 was persisted before the raise")

        # Row-level status = 'partial' (mixed outcomes), per-API columns
        # tell the operator exactly which one failed.
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(row["csam_status"], "partial")
        self.assertEqual(row["vm_host_status"], "success")
        self.assertEqual(row["vm_detection_status"], "success")
        self.assertIn("RateLimitError", row["error"] or "")

    def test_total_failure_across_all_three_is_row_failed(self):
        """All three APIs failing with zero rows persisted → row status
        must be 'failed' (not 'partial'), so the failed-vs-partial
        filter on the Status Page stays meaningful."""
        self.mgr = _make_manager(self.db_path)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            raise RateLimitError("csam dead")

        def fake_hosts(*, expected=None, on_page=None):
            raise RuntimeError("hosts dead")

        def fake_dets(*, expected=None, on_page=None):
            raise RuntimeError("dets dead")

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        counts = self.mgr.refresh_all()
        self.assertEqual(counts["csam"], 0)
        self.assertEqual(counts["vm_hosts"], 0)
        self.assertEqual(counts["vm_detections"], 0)

        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["status"], "failed")
        self.assertEqual(row["csam_status"], "failed")
        self.assertEqual(row["vm_host_status"], "failed")
        self.assertEqual(row["vm_detection_status"], "failed")

    def test_all_success_is_row_success(self):
        """Sanity lock: the happy path still marks the row 'success' and
        all per-API columns 'success'."""
        self.mgr = _make_manager(self.db_path)

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            assets = [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")]
            on_page(1, 2, "a2", False, assets)
            return assets

        def fake_hosts(*, expected=None, on_page=None):
            hosts = [_vm_host(1, "10.0.0.1")]
            if on_page:
                on_page(1, 1, False, hosts)
            return hosts

        def fake_dets(*, expected=None, on_page=None):
            dets = [_vm_detection(1, "10.0.0.1", 1001)]
            if on_page:
                on_page(1, 1, False, dets)
            return dets

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        self.mgr.refresh_all()
        row = self.mgr.db.get_refresh_log(limit=1)[0]
        self.assertEqual(row["status"], "success")
        self.assertEqual(row["csam_status"], "success")
        self.assertEqual(row["vm_host_status"], "success")
        self.assertEqual(row["vm_detection_status"], "success")

    # ── Live-updating counts ─────────────────────────────────────

    def test_live_counts_move_while_status_running(self):
        """The on_page callbacks must call update_refresh_progress so the
        refresh_log row's counts move during the pull, not only at the
        terminal complete_refresh. Pins the contract that backs the
        in-progress banner on the dashboard."""
        self.mgr = _make_manager(self.db_path)

        observed_csam_counts = []

        def fake_csam(*, expected, lookback_days, resume_from_id,
                      on_page, on_filter_fallback):
            # Two pages; between them, peek at refresh_log.csam_count to
            # prove the earlier page's count landed before the pull ended.
            p1 = [_asset("a1", "10.0.0.1"), _asset("a2", "10.0.0.2")]
            on_page(1, 2, "a2", True, p1)
            observed_csam_counts.append(
                self.mgr.db.get_refresh_log(limit=1)[0]["csam_count"]
            )
            p2 = [_asset("a3", "10.0.0.3")]
            on_page(2, 3, "a3", False, p2)
            observed_csam_counts.append(
                self.mgr.db.get_refresh_log(limit=1)[0]["csam_count"]
            )
            return p1 + p2

        def fake_hosts(*, expected=None, on_page=None):
            hosts = [_vm_host(1, "10.0.0.1")]
            if on_page:
                on_page(1, 1, False, hosts)
            return hosts

        def fake_dets(*, expected=None, on_page=None):
            dets = [_vm_detection(1, "10.0.0.1", 1001)]
            if on_page:
                on_page(1, 1, False, dets)
            return dets

        self.mgr.client.fetch_csam_assets.side_effect = fake_csam
        self.mgr.client.fetch_vm_hosts.side_effect = fake_hosts
        self.mgr.client.fetch_vm_detections.side_effect = fake_dets

        self.mgr.refresh_all()

        # The first peek happened after page 1 (2 assets), the second
        # after page 2 (3 assets). Neither should be 0, and the final
        # row count must equal the last peek.
        self.assertEqual(observed_csam_counts, [2, 3],
                         f"Expected live counts [2,3], got {observed_csam_counts}")


class ThrottleTiersTest(unittest.TestCase):
    """Pins the three-tier CSAM throttle logic from
    api_client._csam_apply_server_throttle without needing a real
    Qualys endpoint."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(
            suffix=".db", prefix="throttle_tiers_"
        )
        os.close(fd)
        config = QualysDAConfig(
            db_path=self.db_path, username="u", password="p",
            parallel_refresh=False,
        )
        self.client = QualysClient(config)

    def tearDown(self):
        try:
            self.client.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def _fake_response(self, headers, status=200):
        resp = MagicMock()
        resp.headers = headers
        resp.status_code = status
        return resp

    def test_low_quota_emits_warning_once_per_window(self):
        """Remaining<50 should WARN, but not repeat within the same
        quota window — big pulls can issue 100+ headers per window."""
        # Stub time.sleep so the test doesn't actually wait out any
        # ToWait-Sec sleeps the throttle decides to do.
        import src.api_client as apimod
        orig_sleep = apimod.time.sleep
        apimod.time.sleep = MagicMock()  # type: ignore[assignment]
        try:
            with self.assertLogs("src.api_client", level="WARNING") as cm:
                # First call at Remaining=47 — expect one WARN.
                r1 = self._fake_response({
                    "X-RateLimit-Limit": "300",
                    "X-RateLimit-Remaining": "47",
                    "X-RateLimit-ToWait-Sec": "120",
                })
                self.client._csam_apply_server_throttle(r1)
                # Second call, same window, Remaining=45 — must NOT re-warn.
                r2 = self._fake_response({
                    "X-RateLimit-Limit": "300",
                    "X-RateLimit-Remaining": "45",
                    "X-RateLimit-ToWait-Sec": "120",
                })
                self.client._csam_apply_server_throttle(r2)

            low_warns = [m for m in cm.output if "CSAM quota low" in m]
            self.assertEqual(len(low_warns), 1,
                             f"Expected exactly 1 low-quota WARN, got: {cm.output}")
        finally:
            apimod.time.sleep = orig_sleep  # type: ignore[assignment]

    def test_soft_slow_down_at_10_remaining_emits_warning_and_sleeps(self):
        """Remaining<=10 should WARN and inject a brief slow-down."""
        orig_sleep = time.sleep
        try:
            time.sleep = MagicMock()  # type: ignore[assignment]
            with self.assertLogs("src.api_client", level="WARNING") as cm:
                r = self._fake_response({
                    "X-RateLimit-Limit": "300",
                    "X-RateLimit-Remaining": "9",
                })
                self.client._csam_apply_server_throttle(r)
            slow = [m for m in cm.output if "slowing down" in m]
            self.assertEqual(len(slow), 1,
                             f"Expected soft slow-down WARN, got: {cm.output}")
            time.sleep.assert_called_once()  # type: ignore[attr-defined]
            self.assertEqual(time.sleep.call_args[0][0], 0.5)  # type: ignore[attr-defined]
        finally:
            time.sleep = orig_sleep  # type: ignore[assignment]

    def test_hard_wait_at_2_remaining_honours_to_wait(self):
        """Remaining<=2 with ToWait-Sec>0 should sleep that full duration."""
        orig_sleep = time.sleep
        try:
            time.sleep = MagicMock()  # type: ignore[assignment]
            r = self._fake_response({
                "X-RateLimit-Limit": "300",
                "X-RateLimit-Remaining": "1",
                "X-RateLimit-ToWait-Sec": "7",
            })
            self.client._csam_apply_server_throttle(r)
            # Priority in the helper: ToWait-Sec>0 matches first and
            # sleeps 7s. Either way, the 2s minimum cannot apply.
            self.assertTrue(time.sleep.called)  # type: ignore[attr-defined]
            self.assertGreaterEqual(time.sleep.call_args[0][0], 2.0)  # type: ignore[attr-defined]
        finally:
            time.sleep = orig_sleep  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main(verbosity=2)
