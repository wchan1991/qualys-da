#!/usr/bin/env python3
"""
Qualys DA — CSAM Lookback Bucketing Tests

Pins the invariants for the lookback-bucketing strategy added on
2026-05-05 to work around tenants where Qualys's pagination cursor
stalls or caps a single query at fewer assets than match the filter.

When `csam_lookback_buckets > 1` AND `csam_lookback_days > 0`, the
wrapper:
  * Splits the lookback window into N equal buckets
  * Runs ONE paginated `fetch_csam_assets` call per bucket
  * Each bucket has its own cursor lifecycle and a narrower filter
  * Accumulates results across buckets under one snapshot

This sidesteps both:
  - Cursor stalls within a single query (each bucket starts fresh)
  - Per-query asset caps (each bucket returns fewer matching assets)

Default (`csam_lookback_buckets=1`) preserves the existing single-query
+ continuation-loop behaviour. The new tests in this module cover:

  * 3 buckets across 90-day lookback → exactly 3 fetch_csam_assets
    calls, each with the correct date-range QQL filter
  * Each bucket gets fresh cursor (no resume_from_id) and the
    bucket-specific filter_qql_override
  * Accumulated assets across buckets land in the DB
  * Bucket #0 (newest) has no upper bound to catch just-checked-in assets
  * `buckets=1` path is unaffected (existing tests cover that)
  * `buckets > 1` with `lookback=0` falls through to single-query
    (no filter to bucket)

Run:  python -m unittest tests.test_csam_bucketing -v
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


def _make_manager(db_path, *, lookback_days=90, lookback_buckets=1):
    cfg = QualysDAConfig(
        db_path=db_path, username="t", password="t",
        csam_resume_enabled=True,
        csam_lookback_days=lookback_days,
        csam_lookback_buckets=lookback_buckets,
        parallel_refresh=True,
    )
    mgr = DataManager(cfg)
    mgr._client = MagicMock(spec=QualysClient)
    mgr._client.ensure_authenticated = MagicMock(return_value=None)
    return mgr


class BucketingDispatchTest(unittest.TestCase):
    """When `csam_lookback_buckets > 1`, the wrapper makes N independent
    calls to `fetch_csam_assets`, each with a per-bucket date filter."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="bucket_")
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

    def test_three_buckets_across_90_day_lookback(self):
        """3 buckets × 30 days = 90 days. Each bucket gets one
        fetch_csam_assets call with a different filter_qql_override.
        Bucket #0 (most recent) has only a lower bound; later buckets
        have both lower and upper bounds."""
        self.mgr = _make_manager(self.db_path, lookback_days=90,
                                  lookback_buckets=3)

        # Track every call to fetch_csam_assets so we can assert on the
        # filter_qql_override values passed in.
        captured_calls = []

        def _fake_csam(*, expected, filter_qql_override=None,
                       lookback_days=None, resume_from_id=None,
                       on_page=None, on_filter_fallback=None):
            captured_calls.append({
                "filter_qql_override": filter_qql_override,
                "resume_from_id": resume_from_id,
                "expected": expected,
            })
            # Return distinct assets per bucket so we can verify
            # accumulation
            bucket_idx = len(captured_calls) - 1
            assets = [
                _asset(f"b{bucket_idx}_a{i}", f"10.{bucket_idx}.0.{i}")
                for i in range(10)
            ]
            on_page(1, len(assets), f"b{bucket_idx}_a9", False, assets)
            return assets

        self.mgr.client.fetch_csam_assets.side_effect = _fake_csam

        assets, _ = self.mgr._fetch_csam_with_checkpoint(expected=30)

        self.assertEqual(len(captured_calls), 3,
            "3 buckets => exactly 3 fetch_csam_assets calls")
        self.assertEqual(len(assets), 30,
            "10 assets per bucket × 3 buckets = 30 total accumulated")

        # Each bucket should pass a non-None filter_qql_override
        for i, call in enumerate(captured_calls):
            self.assertIsNotNone(call["filter_qql_override"],
                f"Bucket {i} must pass a filter override, not None")
            self.assertIn("lastCheckedIn", call["filter_qql_override"])
            # Each bucket starts with a fresh cursor
            self.assertIsNone(call["resume_from_id"],
                f"Bucket {i} must start with no cursor (fresh start)")

        # Bucket #0 (most recent) — no upper bound (catches assets that
        # just checked in)
        self.assertNotIn("AND", captured_calls[0]["filter_qql_override"],
            "Most-recent bucket must have only a lower bound, not a range")
        # Later buckets have both lower and upper bounds
        for i in (1, 2):
            f = captured_calls[i]["filter_qql_override"]
            self.assertIn("AND", f,
                f"Bucket {i} must have both lower and upper bounds")
            self.assertIn(">=", f)
            self.assertIn("<", f)

    def test_persisted_to_db_across_buckets(self):
        """Bucketed pull writes assets to the same csam_assets snapshot."""
        self.mgr = _make_manager(self.db_path, lookback_days=60,
                                  lookback_buckets=2)

        def _fake_csam(*, expected, filter_qql_override=None,
                       lookback_days=None, resume_from_id=None,
                       on_page=None, on_filter_fallback=None):
            bucket_idx = self.mgr.client.fetch_csam_assets.call_count - 1
            assets = [
                _asset(f"b{bucket_idx}_a{i}", f"10.{bucket_idx}.0.{i}")
                for i in range(5)
            ]
            on_page(1, len(assets), f"b{bucket_idx}_a4", False, assets)
            return assets

        self.mgr.client.fetch_csam_assets.side_effect = _fake_csam
        self.mgr._fetch_csam_with_checkpoint(expected=10)

        # 5 assets × 2 buckets = 10 in the DB under one snapshot
        snap = self.mgr.db.get_latest_fetched_at("csam_assets")
        n_persisted = self.mgr.db.conn.execute(
            "SELECT COUNT(*) FROM csam_assets WHERE fetched_at = ?",
            (snap,),
        ).fetchone()[0]
        self.assertEqual(n_persisted, 10,
            "Both buckets' assets must persist under the same snapshot")

    def test_buckets_one_falls_back_to_single_query(self):
        """`csam_lookback_buckets=1` (default) => single-query path,
        same as before — wrapper does NOT use filter_qql_override."""
        self.mgr = _make_manager(self.db_path, lookback_days=90,
                                  lookback_buckets=1)

        captured = []

        def _fake_csam(*, expected, filter_qql_override=None,
                       lookback_days=None, resume_from_id=None,
                       on_page=None, on_filter_fallback=None):
            captured.append({
                "filter_qql_override": filter_qql_override,
                "lookback_days": lookback_days,
            })
            assets = [_asset(f"a{i}") for i in range(5)]
            on_page(1, 5, "a4", False, assets)
            return assets

        self.mgr.client.fetch_csam_assets.side_effect = _fake_csam
        self.mgr._fetch_csam_with_checkpoint(expected=5)

        # Single call — buckets=1 collapses to the existing path
        self.assertEqual(len(captured), 1)
        # That call has NO filter_qql_override — uses default lookback
        self.assertIsNone(captured[0]["filter_qql_override"],
            "buckets=1 path should not pass filter_qql_override")
        # And lookback_days flows through normally
        self.assertEqual(captured[0]["lookback_days"], 90)

    def test_buckets_with_no_lookback_falls_through(self):
        """Bucketing only applies when lookback_days > 0. With
        lookback_days=0, there's no time window to bucket — fall through
        to single-query no-filter behaviour."""
        self.mgr = _make_manager(self.db_path, lookback_days=0,
                                  lookback_buckets=4)

        captured = []

        def _fake_csam(*, expected, filter_qql_override=None,
                       lookback_days=None, resume_from_id=None,
                       on_page=None, on_filter_fallback=None):
            captured.append({"filter_qql_override": filter_qql_override})
            assets = [_asset(f"a{i}") for i in range(3)]
            on_page(1, 3, "a2", False, assets)
            return assets

        self.mgr.client.fetch_csam_assets.side_effect = _fake_csam
        self.mgr._fetch_csam_with_checkpoint(expected=3)

        # lookback=0 disables bucketing — exactly one call, no filter
        self.assertEqual(len(captured), 1)
        self.assertIsNone(captured[0]["filter_qql_override"])


class FilterQqlOverridePropagationTest(unittest.TestCase):
    """Pure unit test of `fetch_csam_assets` with `filter_qql_override` —
    the override must take priority over `lookback_days` when both are
    set, and the request body must include the override as the QQL
    filter."""

    def test_override_supersedes_lookback_days(self):
        cfg = QualysDAConfig(username="t", password="t",
                             csam_resume_enabled=True,
                             csam_lookback_days=90,
                             rate_limit_enabled=False)
        client = QualysClient(cfg)
        client._csam_authenticate = MagicMock(return_value=None)

        # Mock the underlying _csam_request so we can inspect the body
        captured_body = {}

        def _fake_request(method, endpoint, *, json_body=None, **kw):
            captured_body.update(json_body)
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "ServiceResponse": {
                    "responseCode": "SUCCESS",
                    "data": {"asset": [{"assetId": "a1"}]},
                    "hasMoreRecords": 0,
                    "lastSeenAssetId": "a1",
                }
            }
            return resp

        client._csam_request = MagicMock(side_effect=_fake_request)
        client.fetch_csam_assets(
            filter_qql_override="lastCheckedIn >= '2026-04-01' AND lastCheckedIn < '2026-04-15'",
            lookback_days=90,  # would otherwise build its own filter
        )
        # The body should carry our override, NOT the lookback-derived QQL
        self.assertIn("filter", captured_body["ServiceRequest"])
        sent_filter = captured_body["ServiceRequest"]["filter"]
        self.assertEqual(
            sent_filter,
            "lastCheckedIn >= '2026-04-01' AND lastCheckedIn < '2026-04-15'",
            "filter_qql_override must take priority over lookback_days"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
