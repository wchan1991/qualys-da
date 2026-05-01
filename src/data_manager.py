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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Iterator

from .config_loader import QualysDAConfig
from .database import QualysDADatabase
from .api_client import (
    QualysClient, QualysError, AuthError, CancelledError,
)
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
        # Cooperative cancellation flag for in-flight refreshes.
        # Set via `request_cancel()` (POST /api/refresh/cancel); cleared
        # via `reset_cancel()` at the start of every refresh_all. The
        # CSAM page loop, VM page loops, and the 429 window-hop sleep
        # all check this flag at safe points and raise `CancelledError`
        # so the refresh terminates cleanly with status='cancelled'.
        self._cancel_event = threading.Event()

    @property
    def client(self) -> QualysClient:
        if self._client is None:
            self._client = QualysClient(self.config)
            # Share the cancel event with the client so `_csam_request`'s
            # multi-window sleep can be interrupted without waiting out
            # a 47-minute ToWait-Sec.
            self._client._cancel_event = self._cancel_event
        return self._client

    # ── Cancellation API ─────────────────────────────────────────
    #
    # Called by the Flask route POST /api/refresh/cancel. Cooperative —
    # the in-flight refresh checks the event at its next safe point
    # (between pages, or when waking from a window-hop sleep) and exits
    # with status='cancelled'. Already-persisted rows are kept; the CSAM
    # checkpoint is preserved so the next refresh can resume.

    def request_cancel(self) -> None:
        """Signal any in-flight refresh to abort at its next checkpoint."""
        logger.info("Cancellation requested for in-flight refresh")
        self._cancel_event.set()

    def reset_cancel(self) -> None:
        """Clear the cancel flag — called at the start of every refresh_all."""
        self._cancel_event.clear()

    def is_cancel_requested(self) -> bool:
        return self._cancel_event.is_set()

    # ── Full Wipe Orchestrator ───────────────────────────────────
    #
    # Cancels any in-flight refresh first (using the cancel-event we
    # ship for refresh cancellation), waits up to N seconds for the
    # refresh to actually terminate, then wipes the DB. Without this
    # cancel-first step, purging while CSAM is mid-pull would yank
    # tables out from under the writer and leave the checkpoint
    # pointing at a snapshot_fetched_at that no longer exists.

    def purge_all(self, *,
                  include_config: bool = False,
                  cancel_wait_seconds: float = 30.0) -> Dict[str, Any]:
        """Cancel any running refresh, then wipe all ingested data.

        Returns a dict with:
          - cancel_was_needed: bool — did we have to interrupt a refresh?
          - cancel_completed: bool — did it stop within the wait window?
          - purged_counts: dict of table → rows-deleted
          - include_config: bool — whether config tables were also wiped

        See `db.purge_all_data` for the table list. Schema is preserved
        (delete + VACUUM, not DROP TABLE) so the next refresh can begin
        immediately.
        """
        result: Dict[str, Any] = {
            "cancel_was_needed": False,
            "cancel_completed": True,
            "include_config": include_config,
        }
        # Step 1: if a refresh is running, signal cancel and wait for it
        # to actually stop. The cancel_event interrupts a 47-min CSAM
        # window-hop sleep instantly; per-page cancel checks pick up the
        # signal between pages for VM and CSAM workers.
        rows = self.db.get_refresh_log(limit=1)
        if rows and rows[0].get("status") == "running":
            result["cancel_was_needed"] = True
            logger.warning(
                "Purge requested with refresh in flight — cancelling first"
            )
            self.request_cancel()
            deadline = time.monotonic() + cancel_wait_seconds
            while time.monotonic() < deadline:
                rows = self.db.get_refresh_log(limit=1)
                if not rows or rows[0].get("status") != "running":
                    break
                time.sleep(0.5)
            else:
                result["cancel_completed"] = False
                logger.warning(
                    f"Refresh still 'running' after {cancel_wait_seconds}s "
                    f"wait. Proceeding with purge — the in-flight worker "
                    f"will fail on its next DB write, which is acceptable "
                    f"since we're wiping anyway."
                )
        # Step 2: wipe.
        result["purged_counts"] = self.db.purge_all_data(
            include_config=include_config,
        )
        # Step 3: drop the analytics cache so the next page render
        # doesn't show stale numbers from the deleted snapshot.
        self.analytics.invalidate_cache()
        return result

    def close(self):
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── CSAM fetch with resume checkpoint ────────────────────────
    #
    # Wraps `client.fetch_csam_assets()` with three guarantees the naive
    # "pull everything then save" path couldn't offer:
    #
    #   1. **Resumable.** A per-page callback writes `last_asset_id` to
    #      `csam_checkpoint`. A rate-limit / crash / kill-9 leaves the next
    #      run able to pass it as `startFromId` and continue.
    #   2. **Durable mid-pull.** The same callback ALSO writes the freshly
    #      fetched page into `csam_assets` under a stable `snapshot_fetched_at`
    #      that is chosen when the pull begins (or re-used from the
    #      checkpoint on resume). So the rows we already have are on disk
    #      even if the pull dies before completing — the resumed run extends
    #      the same snapshot rather than orphaning the head-half.
    #   3. **Config drift detection.** If `csam_lookback_days` changed
    #      between the interrupted pull and the resume, we can't safely
    #      extend the same snapshot (different filters → different
    #      populations). We reset the checkpoint and start a clean pull.
    def _fetch_csam_with_checkpoint(
        self, *, expected: Optional[int] = None,
        refresh_id: Optional[int] = None,
    ) -> Tuple[List[Dict], str]:
        """Return (assets, snapshot_fetched_at).

        `snapshot_fetched_at` is the timestamp under which every page was
        saved to `csam_assets` — callers should use it when stamping any
        derived artefacts (e.g. host_tags rows derived from these assets)
        that need to be queryable via the same `MAX(fetched_at)`.

        `refresh_id`, when provided, causes each page to live-update
        `refresh_log.csam_count` via `update_refresh_progress` so the
        Status Page banner can show progress while the pull is in flight.
        """
        checkpoint = None
        resume_from: Optional[str] = None
        snapshot_fetched_at: Optional[str] = None

        if self.config.csam_resume_enabled:
            checkpoint = self.db.get_csam_checkpoint()
            if checkpoint and not checkpoint["completed"]:
                # (Fix 2) Lookback drift: if config changed between the
                # interrupted run and now, the head-half on disk and the
                # tail we're about to pull were filtered differently. Reset
                # rather than silently stitching mismatched populations.
                prior_lookback = checkpoint.get("lookback_days")
                current_lookback = self.config.csam_lookback_days
                if prior_lookback != current_lookback:
                    logger.warning(
                        f"CSAM checkpoint lookback drift: previous pull used "
                        f"lookback_days={prior_lookback}, current config is "
                        f"{current_lookback}. Resetting checkpoint and starting fresh."
                    )
                    # Fall through as if no checkpoint existed.
                    checkpoint = None
                else:
                    resume_from = checkpoint["last_asset_id"]
                    snapshot_fetched_at = checkpoint.get("snapshot_fetched_at")
                    if resume_from and snapshot_fetched_at:
                        logger.info(
                            f"CSAM resume: previous pull stopped at asset "
                            f"{resume_from} after {checkpoint['assets_pulled']:,} "
                            f"assets (snapshot {snapshot_fetched_at}) — "
                            f"continuing and extending the same snapshot."
                        )
                    elif resume_from:
                        # Checkpoint pre-dates the snapshot_fetched_at column
                        # (older DB migrated in-place). Treat as a clean start
                        # so we don't mix two snapshots under one fetched_at.
                        logger.warning(
                            "CSAM checkpoint has no snapshot_fetched_at "
                            "(pre-migration row). Starting fresh to avoid "
                            "mixing snapshots."
                        )
                        resume_from = None

        # Fresh start path: allocate a new snapshot timestamp and write it
        # into the checkpoint BEFORE the first page, so a crash between
        # allocation and first-page-save still leaves the checkpoint valid.
        started_now = datetime.utcnow().isoformat()
        if resume_from is None:
            snapshot_fetched_at = started_now
            self.db.update_csam_checkpoint(
                last_asset_id=None,
                assets_pulled=0,
                completed=False,
                lookback_days=self.config.csam_lookback_days,
                started_at=started_now,
                note="running",
                snapshot_fetched_at=snapshot_fetched_at,
            )

        # Must be non-None by now — we either resumed an existing snapshot
        # or allocated a new one.
        assert snapshot_fetched_at is not None

        def _on_page(page, total, last_id, has_more, page_assets):
            # (Fix 1) Persist this page's assets under the stable snapshot
            # timestamp FIRST. save_csam_assets uses INSERT OR REPLACE on
            # (asset_id, fetched_at), so re-running the same page (e.g.
            # because startFromId boundary is inclusive on some tenants)
            # is idempotent.
            if page_assets:
                try:
                    self.db.save_csam_assets(page_assets, snapshot_fetched_at)
                except Exception as save_err:
                    # A save failure mid-pull is more serious than a
                    # checkpoint failure — log loudly and re-raise so the
                    # pull aborts. The next run will see the partial rows
                    # already on disk under the same snapshot_fetched_at and
                    # resume cleanly.
                    logger.error(
                        f"CSAM save_csam_assets failed on page {page}: {save_err}"
                    )
                    raise
            # Then update the checkpoint so the resume pointer can't
            # outrun the persisted rows.
            self.db.update_csam_checkpoint(
                last_asset_id=last_id,
                assets_pulled=total,
                completed=(not has_more),
                lookback_days=self.config.csam_lookback_days,
                note=f"page {page}",
                snapshot_fetched_at=snapshot_fetched_at,
            )
            # Live-update the refresh_log row so the Status Page banner
            # shows progress without waiting for the pull to terminate.
            # Callback failures here are non-fatal — we do not want a
            # flaky DB write on the *log* row to abort a successful pull.
            if refresh_id is not None:
                try:
                    self.db.update_refresh_progress(
                        refresh_id, csam_count=total
                    )
                except Exception as prog_err:
                    logger.debug(
                        f"update_refresh_progress (csam) failed: {prog_err}"
                    )

        def _on_filter_fallback():
            # (Fix 2 cont.) Qualys rejected our QQL filter and fetch_csam_assets
            # will retry without it. Clear the stored lookback so a later
            # resume doesn't re-apply the rejected filter.
            logger.info(
                "CSAM filter fallback engaged — clearing checkpoint lookback."
            )
            self.db.update_csam_checkpoint(
                last_asset_id=None,
                assets_pulled=0,
                completed=False,
                lookback_days=None,
                note="filter fallback — lookback cleared",
                snapshot_fetched_at=snapshot_fetched_at,
            )

        try:
            assets = self.client.fetch_csam_assets(
                expected=expected,
                lookback_days=self.config.csam_lookback_days,
                resume_from_id=resume_from,
                on_page=_on_page,
                on_filter_fallback=_on_filter_fallback,
            )
            # Clean completion — mark done AND clear snapshot_fetched_at so
            # the next refresh starts fresh (won't accidentally try to
            # extend a stale snapshot).
            self.db.update_csam_checkpoint(
                last_asset_id=None,
                assets_pulled=len(assets),
                completed=True,
                lookback_days=self.config.csam_lookback_days,
                note="complete",
                snapshot_fetched_at=None,
            )
            return assets, snapshot_fetched_at
        except Exception as e:
            # on_page has already persisted rows + checkpoint up to the last
            # successful page; just annotate why the pull stopped. We
            # DELIBERATELY leave snapshot_fetched_at in place so the next
            # run can extend the same snapshot (that's the whole point).
            latest = self.db.get_csam_checkpoint() or {}
            self.db.update_csam_checkpoint(
                last_asset_id=latest.get("last_asset_id"),
                assets_pulled=latest.get("assets_pulled", 0),
                completed=False,
                lookback_days=self.config.csam_lookback_days,
                note=f"interrupted: {type(e).__name__}: {e}"[:200],
            )
            raise

    # ── Refresh ──────────────────────────────────────────────────

    def refresh_all(self) -> Dict[str, Any]:
        """Full refresh with per-API failure isolation.

        All three Qualys APIs (CSAM assets, VM hosts, VM detections) are
        pulled in parallel. A failure in one API no longer cancels the
        others — each thread's exception is caught and recorded, the
        surviving threads still commit their data, and the Status Page
        shows per-API outcomes so the operator knows which single Refresh
        button to press to retry the part that failed.

        Preflights (auth, count endpoints) still fail fast because they
        precede the parallel fan-out: a bad credential or an unreachable
        Qualys tenant will short-circuit before any thread is spawned.
        """
        # Clear any leftover cancel signal from a prior run so this
        # refresh starts cleanly. Must happen BEFORE log_refresh so a
        # stale cancel from before the new refresh-id was created
        # can't accidentally short-circuit it.
        self.reset_cancel()
        refresh_id = self.db.log_refresh("all")
        now = datetime.utcnow().isoformat()
        counts = {"csam": 0, "vm_hosts": 0, "vm_detections": 0, "changes": 0}

        # Per-API outcome tracking. Starts as "skipped"; each thread
        # flips its own slot to success/partial/failed/cancelled as the
        # result comes back. If the whole function short-circuits on auth
        # failure these stay as "skipped", which is correct.
        outcomes = {"csam": "skipped", "vm_hosts": "skipped",
                    "vm_detections": "skipped"}
        errors: Dict[str, str] = {}

        # ── "Look under the hood" delta logging ──────────────────
        # Snapshot the DB state before the pull so we can log the
        # actual row-count deltas at the end. This is a separate
        # signal from the API-fetch counts in `refresh_log` — those
        # tell you what came down the wire; these tell you what
        # actually landed in the DB after dedup / replace logic.
        # `refresh_num` is the human-friendly sequence number visible
        # in `tail -f logs/app.log | grep "Refresh #"`.
        try:
            before_stats = self.db.get_ingestion_stats()
            refresh_num = before_stats["refresh_history"]["total"]  # this run included
        except Exception as e:
            logger.debug(f"Could not snapshot pre-refresh stats: {e}")
            before_stats = None
            refresh_num = None

        try:
            logger.info("=" * 60)
            if refresh_num is not None and before_stats is not None:
                logger.info(
                    f"Refresh #{refresh_num} starting (before: "
                    f"CSAM {before_stats['csam_assets_count']:,} · "
                    f"Hosts {before_stats['vm_hosts_count']:,} · "
                    f"Detections {before_stats['vm_detections_count']:,})"
                )
            else:
                logger.info("Starting full refresh")
            logger.info("=" * 60)

            # ── 1. Preflight auth: fail fast on bad creds ────────────
            try:
                self.client.ensure_authenticated()
            except AuthError as e:
                logger.error(f"Refresh aborted — auth failed: {e}")
                self.db.complete_refresh(
                    refresh_id, status="failed", error=f"auth: {e}",
                    csam_status="skipped", vm_host_status="skipped",
                    vm_detection_status="skipped",
                )
                raise

            # ── 2. Preflight counts (non-fatal if endpoint unavailable) ──
            csam_expected = self.client.count_csam_assets()
            vm_host_expected = self.client.count_vm_hosts()
            vm_det_expected = self.client.count_vm_detections()

            def _fmt(n):
                return f"{n:,}" if n is not None else "unknown"

            logger.info(
                f"Expected volumes — CSAM assets: {_fmt(csam_expected)} · "
                f"VM hosts: {_fmt(vm_host_expected)} · "
                f"VM detections: {_fmt(vm_det_expected)}"
            )
            # Seed the refresh_log row with expected volumes up front so
            # the Status Page banner can render "0 of N" from the very
            # first poll rather than waiting for the first page.
            self.db.update_refresh_progress(
                refresh_id,
                csam_expected=csam_expected,
                vm_host_expected=vm_host_expected,
                vm_detection_expected=vm_det_expected,
            )

            # Snapshot previous detection state for diffing (before new data lands)
            old_detections = self.db.get_previous_detections()

            # Per-API workers — each catches its own exception so a crash
            # in one API doesn't abort the others. Return shape:
            # {"status": "success"|"partial"|"failed",
            #  "count": int, "data": Any, "error": str|None,
            #  "snapshot": str|None   # CSAM only
            # }
            def _run_csam():
                try:
                    assets, snapshot = self._fetch_csam_with_checkpoint(
                        expected=csam_expected, refresh_id=refresh_id,
                    )
                    return {"status": "success", "count": len(assets),
                            "data": assets, "snapshot": snapshot,
                            "error": None}
                except CancelledError as e:
                    # Operator-requested stop — distinct from failure.
                    # CSAM saves per-page so already-fetched rows are
                    # durable; the checkpoint preserves resume state.
                    saved = 0
                    try:
                        cp = self.db.get_csam_checkpoint() or {}
                        saved = int(cp.get("assets_pulled") or 0)
                    except Exception:
                        pass
                    logger.info(
                        f"CSAM refresh cancelled: {e} "
                        f"(saved {saved} assets, checkpoint preserved)"
                    )
                    return {"status": "cancelled", "count": saved,
                            "data": None, "snapshot": None,
                            "error": f"CancelledError: {e}"}
                except Exception as e:
                    # CSAM saves inside on_page, so the checkpoint knows
                    # how many made it to disk. Use that to distinguish
                    # "saved some → partial" from "nothing → failed".
                    saved = 0
                    try:
                        cp = self.db.get_csam_checkpoint() or {}
                        saved = int(cp.get("assets_pulled") or 0)
                    except Exception:
                        pass
                    status = "partial" if saved > 0 else "failed"
                    logger.warning(
                        f"CSAM refresh {status}: {type(e).__name__}: {e} "
                        f"(saved {saved} assets before failing)"
                    )
                    return {"status": status, "count": saved, "data": None,
                            "snapshot": None,
                            "error": f"{type(e).__name__}: {e}"}

            def _run_vm_hosts():
                try:
                    def _hosts_on_page(page, total, has_more, page_hosts):
                        try:
                            self.db.update_refresh_progress(
                                refresh_id, vm_host_count=total
                            )
                        except Exception as prog_err:
                            logger.debug(
                                f"update_refresh_progress (vm_hosts) failed: "
                                f"{prog_err}"
                            )
                    hosts = self.client.fetch_vm_hosts(
                        expected=vm_host_expected, on_page=_hosts_on_page,
                    )
                    return {"status": "success", "count": len(hosts),
                            "data": hosts, "error": None}
                except CancelledError as e:
                    logger.info(f"VM hosts refresh cancelled: {e}")
                    return {"status": "cancelled", "count": 0, "data": None,
                            "error": f"CancelledError: {e}"}
                except Exception as e:
                    logger.warning(
                        f"VM hosts refresh failed: {type(e).__name__}: {e}"
                    )
                    # fetch_vm_hosts buffers internally; if it raised
                    # before returning, we have no partial list. Treat as
                    # failed rather than partial.
                    return {"status": "failed", "count": 0, "data": None,
                            "error": f"{type(e).__name__}: {e}"}

            def _run_vm_detections():
                try:
                    def _dets_on_page(page, total, has_more, page_dets):
                        try:
                            self.db.update_refresh_progress(
                                refresh_id, vm_detection_count=total
                            )
                        except Exception as prog_err:
                            logger.debug(
                                f"update_refresh_progress (vm_detections) "
                                f"failed: {prog_err}"
                            )
                    dets = self.client.fetch_vm_detections(
                        expected=vm_det_expected, on_page=_dets_on_page,
                    )
                    return {"status": "success", "count": len(dets),
                            "data": dets, "error": None}
                except CancelledError as e:
                    logger.info(f"VM detections refresh cancelled: {e}")
                    return {"status": "cancelled", "count": 0, "data": None,
                            "error": f"CancelledError: {e}"}
                except Exception as e:
                    logger.warning(
                        f"VM detections refresh failed: {type(e).__name__}: {e}"
                    )
                    return {"status": "failed", "count": 0, "data": None,
                            "error": f"{type(e).__name__}: {e}"}

            # ── 3. Fetch: parallel (default) or sequential (config opt-out) ──
            if self.config.parallel_refresh:
                logger.info(
                    "Fetching CSAM, VM hosts, VM detections in parallel..."
                )
                with ThreadPoolExecutor(
                    max_workers=3, thread_name_prefix="refresh"
                ) as pool:
                    csam_future = pool.submit(_run_csam)
                    hosts_future = pool.submit(_run_vm_hosts)
                    dets_future = pool.submit(_run_vm_detections)
                    csam_res = csam_future.result()
                    hosts_res = hosts_future.result()
                    dets_res = dets_future.result()
            else:
                logger.info("Fetching sequentially (parallel_refresh=false)...")
                # Each step still isolated so a VM-hosts failure doesn't
                # skip VM-detections.
                csam_res = _run_csam()
                hosts_res = _run_vm_hosts()
                dets_res = _run_vm_detections()

            csam_assets = csam_res["data"] or []
            vm_hosts = hosts_res["data"] or []
            vm_detections = dets_res["data"] or []
            outcomes["csam"] = csam_res["status"]
            outcomes["vm_hosts"] = hosts_res["status"]
            outcomes["vm_detections"] = dets_res["status"]
            if csam_res["error"]:
                errors["csam"] = csam_res["error"]
            if hosts_res["error"]:
                errors["vm_hosts"] = hosts_res["error"]
            if dets_res["error"]:
                errors["vm_detections"] = dets_res["error"]

            # ── 4. DB writes (single-threaded) ───────────────────────
            # CSAM assets are already on disk — the on_page callback in
            # _fetch_csam_with_checkpoint wrote every page under its stable
            # snapshot_fetched_at. So here we only record the count, not
            # re-save. VM tables still use `now` since VM has no checkpoint
            # (yet).
            #
            # If a VM fetch failed wholesale (status=="failed", data is
            # None), we skip the corresponding save — overwriting a good
            # table with an empty one would silently nuke the dashboard.
            counts["csam"] = csam_res["count"]
            # Skip the save when the VM fetch failed OR was cancelled —
            # both leave us with no data buffer to write, and overwriting
            # a good prior snapshot with an empty one would silently nuke
            # the dashboard.
            no_save = ("failed", "cancelled")
            if hosts_res["status"] not in no_save:
                counts["vm_hosts"] = self.db.save_vm_hosts(vm_hosts, now)
            else:
                logger.warning(
                    f"VM hosts save skipped: fetch {hosts_res['status']}, "
                    f"preserving prior snapshot."
                )
            if dets_res["status"] not in no_save:
                counts["vm_detections"] = self.db.save_vm_detections(
                    vm_detections, now
                )
            else:
                logger.warning(
                    f"VM detections save skipped: fetch {dets_res['status']}, "
                    f"preserving prior snapshot."
                )

            # Extract and save tags (only from sources we actually got data for).
            csam_tags = QualysClient.extract_tags_from_csam(csam_assets)
            vm_host_tags = QualysClient.extract_tags_from_vm_hosts(vm_hosts)
            vm_det_tags = QualysClient.extract_tags_from_detections(vm_detections)
            all_tags = csam_tags + vm_host_tags + vm_det_tags
            if all_tags:
                self.db.save_host_tags(all_tags, now)

            # Detect and save changes — only meaningful when detections
            # actually succeeded. Diffing against an empty list would
            # generate a false "everything disappeared" change wave.
            if dets_res["status"] != "failed" and vm_detections:
                changes = self.analytics.detect_changes(
                    old_detections, vm_detections, now
                )
                counts["changes"] = self.db.save_detection_changes(changes)

            # Compute rollups (harmless even on partial data; they run off
            # whatever snapshot is latest in the DB).
            self.analytics.compute_weekly_rollup()
            # Monthly rollup on first day of month or first refresh of month
            today = datetime.utcnow()
            if today.day <= 7:
                self.analytics.compute_monthly_rollup()

            # GFS retention
            self.analytics.purge_snapshots()

            # ── 5. Classify row-level status and write terminal state ──
            #
            # Precedence order:
            #   1. Any 'cancelled' AND no 'success' → row 'cancelled'
            #      (operator stopped the pull; preserve the intent in the
            #      log so the partial-vs-cancelled distinction survives)
            #   2. All 'success'                    → row 'success'
            #   3. Only failed/skipped, no success  → row 'failed'
            #   4. Anything mixed                   → row 'partial'
            statuses = set(outcomes.values())
            if "cancelled" in statuses and "success" not in statuses:
                row_status = "cancelled"
                error_summary = "; ".join(
                    f"{api}={outcomes[api]}"
                    + (f"({errors[api]})" if api in errors else "")
                    for api in ("csam", "vm_hosts", "vm_detections")
                )
            elif statuses == {"success"}:
                row_status = "success"
                error_summary = None
            elif statuses <= {"failed", "skipped"} and "success" not in statuses:
                row_status = "failed"
                error_summary = "; ".join(
                    f"{k}={v}" for k, v in errors.items()
                ) or "all APIs failed"
            else:
                row_status = "partial"
                error_summary = "; ".join(
                    f"{api}={outcomes[api]}"
                    + (f"({errors[api]})" if api in errors else "")
                    for api in ("csam", "vm_hosts", "vm_detections")
                )

            self.db.complete_refresh(
                refresh_id,
                csam_expected=csam_expected,
                vm_host_expected=vm_host_expected,
                vm_detection_expected=vm_det_expected,
                csam_status=outcomes["csam"],
                vm_host_status=outcomes["vm_hosts"],
                vm_detection_status=outcomes["vm_detections"],
                status=row_status,
                error=error_summary,
                **counts,
            )
            # Drop the dashboard cache so the next page load sees new data.
            self.analytics.invalidate_cache()
            logger.info(
                f"Refresh complete: status={row_status} outcomes={outcomes} "
                f"counts={counts}"
            )
            # ── "Look under the hood" delta log ──────────────────
            # Counts are read after invalidate_cache so they reflect
            # post-pull DB state. Signed deltas tell the operator what
            # actually changed (new assets, retired hosts, dedup-replaced
            # detections). Counts here are DB row counts, not API
            # fetch counts — the latter live in refresh_log.
            if before_stats is not None and refresh_num is not None:
                try:
                    after = self.db.get_ingestion_stats()
                    csam_d = after['csam_assets_count'] - before_stats['csam_assets_count']
                    host_d = after['vm_hosts_count'] - before_stats['vm_hosts_count']
                    det_d = after['vm_detections_count'] - before_stats['vm_detections_count']
                    logger.info(
                        f"Refresh #{refresh_num} complete (after: "
                        f"CSAM {after['csam_assets_count']:,} · "
                        f"Hosts {after['vm_hosts_count']:,} · "
                        f"Detections {after['vm_detections_count']:,} "
                        f"— Δ {csam_d:+,} / {host_d:+,} / {det_d:+,})"
                    )
                except Exception as e:
                    logger.debug(f"Post-refresh stats snapshot failed: {e}")

        except AuthError:
            # Already logged + marked failed above; don't double-log.
            raise
        except Exception as e:
            logger.exception(f"Refresh failed: {e}")
            self.db.complete_refresh(
                refresh_id, status="failed", error=str(e),
                csam_status=outcomes.get("csam", "skipped"),
                vm_host_status=outcomes.get("vm_hosts", "skipped"),
                vm_detection_status=outcomes.get("vm_detections", "skipped"),
            )
            raise

        return counts

    def refresh_csam(self) -> int:
        refresh_id = self.db.log_refresh("csam")
        now = datetime.utcnow().isoformat()
        try:
            # Assets are saved incrementally inside the checkpoint wrapper;
            # `assets` is just the in-memory aggregate used for tag extraction.
            assets, _csam_snapshot = self._fetch_csam_with_checkpoint(
                refresh_id=refresh_id
            )
            count = len(assets)
            tags = QualysClient.extract_tags_from_csam(assets)
            self.db.save_host_tags(tags, now)
            self.db.complete_refresh(
                refresh_id, csam=count, csam_status="success"
            )
            self.analytics.invalidate_cache()
            return count
        except Exception as e:
            # Pull checkpoint to see whether any pages made it to disk
            # before the failure — distinguishes partial from total loss.
            saved = 0
            try:
                cp = self.db.get_csam_checkpoint() or {}
                saved = int(cp.get("assets_pulled") or 0)
            except Exception:
                pass
            per_api = "partial" if saved > 0 else "failed"
            row_status = "partial" if saved > 0 else "failed"
            self.db.complete_refresh(
                refresh_id, csam=saved, status=row_status, error=str(e),
                csam_status=per_api,
            )
            raise

    def refresh_vm_hosts(self) -> int:
        refresh_id = self.db.log_refresh("vm-hosts")
        now = datetime.utcnow().isoformat()
        try:
            def _on_page(page, total, has_more, page_hosts):
                try:
                    self.db.update_refresh_progress(
                        refresh_id, vm_host_count=total
                    )
                except Exception as prog_err:
                    logger.debug(
                        f"update_refresh_progress (vm_hosts) failed: {prog_err}"
                    )
            hosts = self.client.fetch_vm_hosts(on_page=_on_page)
            count = self.db.save_vm_hosts(hosts, now)
            tags = QualysClient.extract_tags_from_vm_hosts(hosts)
            self.db.save_host_tags(tags, now)
            self.db.complete_refresh(
                refresh_id, vm_hosts=count, vm_host_status="success"
            )
            self.analytics.invalidate_cache()
            return count
        except Exception as e:
            self.db.complete_refresh(
                refresh_id, status="failed", error=str(e),
                vm_host_status="failed",
            )
            raise

    def refresh_vm_detections(self) -> int:
        refresh_id = self.db.log_refresh("vm-detections")
        now = datetime.utcnow().isoformat()
        try:
            def _on_page(page, total, has_more, page_dets):
                try:
                    self.db.update_refresh_progress(
                        refresh_id, vm_detection_count=total
                    )
                except Exception as prog_err:
                    logger.debug(
                        f"update_refresh_progress (vm_detections) failed: "
                        f"{prog_err}"
                    )
            old_detections = self.db.get_previous_detections()
            detections = self.client.fetch_vm_detections(on_page=_on_page)
            count = self.db.save_vm_detections(detections, now)
            tags = QualysClient.extract_tags_from_detections(detections)
            self.db.save_host_tags(tags, now)
            changes = self.analytics.detect_changes(old_detections, detections, now)
            self.db.save_detection_changes(changes)
            self.analytics.compute_weekly_rollup()
            self.db.complete_refresh(
                refresh_id, vm_detections=count, changes=len(changes),
                vm_detection_status="success",
            )
            self.analytics.invalidate_cache()
            return count
        except Exception as e:
            self.db.complete_refresh(
                refresh_id, status="failed", error=str(e),
                vm_detection_status="failed",
            )
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

    # ── CSV Export ───────────────────────────────────────────────
    #
    # The streaming variant `export_csv_stream` is the canonical export
    # path. It yields CSV-formatted strings (header first, then row
    # batches) and has NO row cap — a 1M-row export uses ~5MB of memory
    # regardless of fleet size.
    #
    # The legacy `export_csv` method is kept as a thin wrapper that
    # joins the stream so external callers don't have to change. Both
    # honour the same filter dict shape, including `date_from`/`date_to`
    # which the legacy /api/export/csv route used to silently drop.

    def export_csv_stream(self, export_type: str = "detections",
                          *, batch_size: int = 1000,
                          **filters) -> "Iterator[str]":
        """Yield CSV chunks (header line + row batches) for a given type.

        Use this directly with Flask's `stream_with_context` for the
        web export route, or iterate it into a file for the CLI.
        Memory stays at ~`batch_size` rows regardless of total volume.
        """

        def _chunk(rows_callable, header: list, row_to_columns):
            """Pump rows from the DB iterator through csv.writer in batches.

            `rows_callable` returns an iterator of dicts; `header` is the
            CSV header row; `row_to_columns(dict) -> list` shapes each
            row. We re-use a single StringIO buffer per batch — write a
            chunk's worth of rows, yield, truncate, repeat.
            """
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(header)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            count = 0
            for r in rows_callable():
                writer.writerow(row_to_columns(r))
                count += 1
                if count >= batch_size:
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate(0)
                    count = 0
            if count > 0:
                yield buf.getvalue()

        if export_type == "detections":
            yield from _chunk(
                rows_callable=lambda: self.db.iter_latest_detections(
                    batch_size=batch_size, **filters,
                ),
                header=[
                    "Host ID", "IP", "DNS", "OS", "QID", "Type", "Severity",
                    "Status", "QDS", "First Found", "Last Found", "Times Found",
                ],
                row_to_columns=lambda r: [
                    r.get("host_id"), r.get("ip_address"), r.get("dns", ""),
                    r.get("os", ""), r.get("qid"), r.get("detection_type"),
                    r.get("severity"), r.get("status"), r.get("qds"),
                    r.get("first_found"), r.get("last_found"),
                    r.get("times_found"),
                ],
            )
        elif export_type == "hosts":
            yield from _chunk(
                rows_callable=lambda: self.db.iter_latest_vm_hosts(
                    batch_size=batch_size, **filters,
                ),
                header=[
                    "Host ID", "IP", "DNS", "NetBIOS", "OS", "TruRisk",
                    "Last Scan", "Last Activity", "Tracking Method",
                ],
                row_to_columns=lambda r: [
                    r.get("host_id"), r.get("ip_address"), r.get("dns"),
                    r.get("netbios"), r.get("os"), r.get("trurisk_score"),
                    r.get("last_scan_date"), r.get("last_activity_date"),
                    r.get("tracking_method"),
                ],
            )
        elif export_type == "assets":
            yield from _chunk(
                rows_callable=lambda: self.db.iter_latest_csam_assets(
                    batch_size=batch_size, **filters,
                ),
                header=[
                    "Asset ID", "Name", "IP", "OS", "Last Seen",
                ],
                row_to_columns=lambda r: [
                    r.get("asset_id"), r.get("name"), r.get("ip_address"),
                    r.get("os"), r.get("last_seen"),
                ],
            )
        elif export_type == "kpis":
            # KPIs are a tiny static rollup — streaming is overkill but
            # we expose the same generator shape for caller uniformity.
            buf = io.StringIO()
            writer = csv.writer(buf)
            kpis = self.analytics.all_kpis()
            writer.writerow(["KPI", "Value"])
            writer.writerow(["Patchable %", kpis["patchable"]["patchable_pct"]])
            writer.writerow(
                ["SLA Compliance %", kpis["sla_compliance"]["overall_pct"]]
            )
            writer.writerow(["Reopen Rate %", kpis["reopen_rate"]["rate_pct"]])
            writer.writerow([
                "Mean Time to Remediate (days)",
                kpis["detection_age"]["mean_days_to_remediate"],
            ])
            for sev, days in kpis["mttr_by_severity"].items():
                writer.writerow([f"MTTR Severity {sev}", days])
            yield buf.getvalue()
        else:
            # Unknown type → empty CSV with just an error header so the
            # downloaded file isn't silently empty.
            yield f"error,unknown export type: {export_type}\n"

    def export_csv(self, export_type: str = "detections", **filters) -> str:
        """In-memory wrapper around `export_csv_stream` for callers that
        want the full string. Don't use on big fleets — prefer the
        stream directly. Kept for backwards compat."""
        return "".join(
            self.export_csv_stream(export_type=export_type, **filters)
        )
