#!/usr/bin/env python3
"""
Qualys DA — CSAM Cursor-Driven Pagination Tests

Pins the invariants from the engineering prompt that fixed the
50,000-asset hard cap:

* Pagination terminates ONLY on `hasMoreRecords == 0`. The old
  `max_pages=500` ceiling combined with Qualys silently clamping
  `limitResults` to ~100 produced the cap; new default is 10,000 pages.
* Cursor-stall detection: if `lastSeenAssetId` repeats across two
  consecutive pages with `hasMore=1`, abort to avoid an infinite loop.
* `lastSeenAssetId == null` with `hasMore=1` aborts (invalid cursor).
* `hasMoreRecords` field missing entirely → defensive WARNING + treat
  as completion.
* Empty `asset[]` with `hasMore=1` continues paginating (trust the API).
* `on_page` callback fires once per page so checkpoint persistence
  keeps pace with pagination.
* Pagination can pull >50,000 assets (i.e. past the former cap).

Tests work by directly mocking `QualysClient._csam_request` to return
a synthetic response sequence — much closer to the API than mocking
`fetch_csam_assets` itself, which is what the existing test suite did.

Run:  python -m unittest tests.test_csam_pagination -v
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.api_client import QualysClient


def _fake_response(*, assets=None, has_more=1, last_seen_id=None,
                    status_code=200, missing_has_more=False):
    """Build a MagicMock that mimics a `requests.Response` enough
    for `fetch_csam_assets` to consume.

    `missing_has_more=True` returns a payload with the `hasMoreRecords`
    field absent entirely (the §6.4 defensive case)."""
    resp = MagicMock()
    resp.status_code = status_code
    payload = {
        "ServiceResponse": {
            "responseCode": "SUCCESS",
            "data": {"asset": assets or []},
            "lastSeenAssetId": last_seen_id,
        }
    }
    if not missing_has_more:
        payload["ServiceResponse"]["hasMoreRecords"] = has_more
    resp.json.return_value = payload
    return resp


def _make_client():
    cfg = QualysDAConfig(username="t", password="t",
                         csam_resume_enabled=True, csam_lookback_days=0,
                         rate_limit_enabled=False)  # skip rate limiter
    client = QualysClient(cfg)
    # Skip the auth handshake — we're not exercising HTTP, only the
    # pagination loop above _csam_request.
    client._csam_authenticate = MagicMock(return_value=None)
    return client


class CursorTerminationTest(unittest.TestCase):
    """The loop exits ONLY on `hasMoreRecords == 0` in the happy path."""

    def test_single_page_terminates_after_one_call(self):
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1", "address": "10.0.0.1"}],
                has_more=0, last_seen_id="a1",
            ),
        ])
        assets = client.fetch_csam_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(client._csam_request.call_count, 1)

    def test_three_pages_terminates_on_last_hasMore_zero(self):
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1"}], has_more=1, last_seen_id="a1",
            ),
            _fake_response(
                assets=[{"assetId": "a2"}], has_more=1, last_seen_id="a2",
            ),
            _fake_response(
                assets=[{"assetId": "a3"}], has_more=0, last_seen_id="a3",
            ),
        ])
        assets = client.fetch_csam_assets()
        self.assertEqual(len(assets), 3)
        self.assertEqual(client._csam_request.call_count, 3)
        # Cursor was passed through correctly: page 2 should have had
        # startFromId=a1, page 3 should have had startFromId=a2.
        bodies = [c.kwargs.get("json_body") or c.args[2]
                  for c in client._csam_request.call_args_list]
        self.assertNotIn("startFromId",
                         bodies[0]["ServiceRequest"]["preferences"],
                         "First call has no cursor")
        self.assertEqual(
            bodies[1]["ServiceRequest"]["preferences"]["startFromId"], "a1"
        )
        self.assertEqual(
            bodies[2]["ServiceRequest"]["preferences"]["startFromId"], "a2"
        )

    def test_more_than_500_pages_no_longer_capped(self):
        """The old `max_pages=500` ceiling combined with Qualys silently
        clamping page size produced a 50,000-asset cap. With the new
        default of 10,000 pages, pulls past page 500 should now succeed.

        We simulate 600 pages of 1 asset each — well past the former
        ceiling — and verify all 600 land."""
        client = _make_client()
        responses = []
        for i in range(600):
            is_last = (i == 599)
            responses.append(_fake_response(
                assets=[{"assetId": f"a{i}"}],
                has_more=0 if is_last else 1,
                last_seen_id=f"a{i}",
            ))
        client._csam_request = MagicMock(side_effect=responses)
        assets = client.fetch_csam_assets()
        self.assertEqual(len(assets), 600,
            "Pagination must pull past the former 500-page ceiling")
        self.assertEqual(client._csam_request.call_count, 600)

    def test_max_pages_safety_cap_logs_warning(self):
        """If a buggy server kept returning hasMore=1 forever, the
        safety cap should kick in — but log a WARNING with the reason
        so operators see it, not a silent green-flag completion."""
        client = _make_client()
        # Always return hasMore=1 and a fresh cursor — the cursor-stall
        # check won't fire because each response advances the ID.
        responses = [
            _fake_response(
                assets=[{"assetId": f"a{i}"}],
                has_more=1, last_seen_id=f"a{i}",
            )
            for i in range(10)  # enough to trip a max_pages=5 cap
        ]
        client._csam_request = MagicMock(side_effect=responses)
        with self.assertLogs("src.api_client", level="WARNING") as cm:
            assets = client.fetch_csam_assets(max_pages=5)
        # Exactly 5 pages consumed, then bailed
        self.assertEqual(client._csam_request.call_count, 5)
        self.assertEqual(len(assets), 5)
        joined = "\n".join(cm.output)
        self.assertIn("safety cap", joined)


class CursorStallTest(unittest.TestCase):
    """If the server returns the same `lastSeenAssetId` two pages in
    a row with `hasMore=1`, abort to avoid spinning forever."""

    def test_cursor_stall_aborts_with_warning(self):
        client = _make_client()
        # Page 1: cursor=a5, hasMore=1.  Page 2: same cursor, hasMore=1.
        # Loop should abort after page 2 with a warning.
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a5"}], has_more=1, last_seen_id="a5",
            ),
            _fake_response(
                assets=[{"assetId": "a6"}], has_more=1, last_seen_id="a5",
            ),
            _fake_response(  # would-be page 3 — should not be reached
                assets=[{"assetId": "a7"}], has_more=0, last_seen_id="a7",
            ),
        ])
        with self.assertLogs("src.api_client", level="WARNING") as cm:
            assets = client.fetch_csam_assets()
        # Pages 1 and 2 consumed; loop aborted before page 3.
        self.assertEqual(client._csam_request.call_count, 2)
        self.assertEqual(len(assets), 2)
        joined = "\n".join(cm.output)
        self.assertIn("cursor stalled", joined.lower())


class DefensiveResponseTest(unittest.TestCase):
    """Edge-case handling for malformed / unexpected API responses."""

    def test_missing_has_more_treated_as_completion(self):
        """§6.4 — if the field is absent entirely, defensively assume
        the pull is done and emit a WARNING."""
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1"}],
                last_seen_id="a1",
                missing_has_more=True,
            ),
        ])
        with self.assertLogs("src.api_client", level="WARNING") as cm:
            assets = client.fetch_csam_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(client._csam_request.call_count, 1)
        joined = "\n".join(cm.output)
        self.assertIn("hasmorerecords", joined.lower())
        self.assertIn("missing", joined.lower())

    def test_null_lastSeenAssetId_with_hasMore_one_aborts(self):
        """§6.1 — invalid response: server says more pages exist but
        gives no cursor. Abort to avoid an infinite loop."""
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1"}],
                has_more=1, last_seen_id=None,
            ),
        ])
        with self.assertLogs("src.api_client", level="WARNING") as cm:
            assets = client.fetch_csam_assets()
        self.assertEqual(len(assets), 1)
        self.assertEqual(client._csam_request.call_count, 1)
        joined = "\n".join(cm.output)
        self.assertIn("null", joined.lower())

    def test_empty_asset_array_with_hasMore_continues(self):
        """§6.3 — empty asset[] but hasMore=1 should continue paginating
        (trust the API). The old loop did the right thing here; this
        test pins the behaviour so a future refactor doesn't regress."""
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[],  # empty page
                has_more=1, last_seen_id="cursor1",
            ),
            _fake_response(
                assets=[{"assetId": "real1"}],
                has_more=0, last_seen_id="real1",
            ),
        ])
        assets = client.fetch_csam_assets()
        self.assertEqual(client._csam_request.call_count, 2,
            "Empty asset[] with hasMore=1 must NOT abort the loop")
        self.assertEqual(len(assets), 1)


class OnPageCallbackTest(unittest.TestCase):
    """Checkpoint persistence rides on the `on_page` callback. Verify
    it fires once per page, with the right cursor."""

    def test_on_page_fires_once_per_page_with_cursor(self):
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1"}], has_more=1, last_seen_id="a1",
            ),
            _fake_response(
                assets=[{"assetId": "a2"}], has_more=1, last_seen_id="a2",
            ),
            _fake_response(
                assets=[{"assetId": "a3"}], has_more=0, last_seen_id="a3",
            ),
        ])
        callback_calls = []
        def on_page(page, total, last_seen, has_more, page_assets):
            callback_calls.append({
                "page": page, "total": total, "last_seen": last_seen,
                "has_more": has_more,
            })
        client.fetch_csam_assets(on_page=on_page)
        self.assertEqual(len(callback_calls), 3)
        # Cursors threaded through correctly
        self.assertEqual(callback_calls[0]["last_seen"], "a1")
        self.assertEqual(callback_calls[1]["last_seen"], "a2")
        self.assertEqual(callback_calls[2]["last_seen"], "a3")
        # Final page reports has_more=False
        self.assertFalse(callback_calls[2]["has_more"])
        self.assertTrue(callback_calls[0]["has_more"])


class CompletionLoggingTest(unittest.TestCase):
    """Acceptance §5.6 — final log line includes hasMore=0 on clean
    completion; exit-other-reason gets a WARNING."""

    def test_clean_completion_log_format(self):
        client = _make_client()
        client._csam_request = MagicMock(side_effect=[
            _fake_response(
                assets=[{"assetId": "a1"}], has_more=0, last_seen_id="a1",
            ),
        ])
        with self.assertLogs("src.api_client", level="INFO") as cm:
            client.fetch_csam_assets()
        joined = "\n".join(cm.output)
        # Must indicate clean completion via hasMore=0
        self.assertIn("hasMore=0", joined)
        self.assertIn("CSAM pull complete", joined)


if __name__ == "__main__":
    unittest.main(verbosity=2)
