#!/usr/bin/env python3
"""
Standalone CSAM 90-day pull test.

Reads credentials from config/.config (same loader the app uses).
Runs ONE fetch_csam_assets pull with lookback_days=90 — no DB writes,
no checkpoint, no scheduler. Prints per-page progress + a final
summary so you can verify pagination behaviour against your tenant
without touching the running app's database.

Usage (from project root):
    python scripts/test_csam_90day.py
    python scripts/test_csam_90day.py --buckets 6           # bucketed mode
    python scripts/test_csam_90day.py --no-filter           # full fleet, no lookback
    python scripts/test_csam_90day.py --dump out.csv        # also dump asset IDs

Exit codes:
    0  pull completed (hasMoreRecords=0 reached or all buckets done)
    1  auth / config / network error
    2  pull stopped early (cap, cursor stall, etc)
"""

import argparse
import csv
import logging
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# Project imports — script lives in scripts/, code in src/
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.config_loader import load_config  # noqa: E402
from src.api_client import QualysClient, QualysError, RateLimitError, AuthError  # noqa: E402


# ── Logging ──────────────────────────────────────────────────
#
# Console: only this script's own messages (csam_test). Quiet —
# per-page chatter from api_client is suppressed so the operator
# sees just the totals.
# File:    full DEBUG from everything (api_client per-page detail
# preserved in logs/csam_90day_test.log for post-mortem).

(ROOT / "logs").mkdir(exist_ok=True)

# Console handler — only `csam_test` logger
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter(
    "%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
))
console.addFilter(lambda r: r.name == "csam_test")

# File handler — everything at DEBUG
fh = logging.FileHandler(ROOT / "logs" / "csam_90day_test.log", mode="w")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(
    "%(asctime)s  %(levelname)-7s  %(name)s  %(message)s"
))

root = logging.getLogger()
root.setLevel(logging.DEBUG)
root.addHandler(console)
root.addHandler(fh)

log = logging.getLogger("csam_test")


def parse_args():
    p = argparse.ArgumentParser(description="CSAM 90-day pull test")
    p.add_argument("--lookback", type=int, default=90,
                   help="Lookback window in days (default 90, 0 = no filter)")
    p.add_argument("--buckets", type=int, default=1,
                   help="Split lookback into N date buckets (default 1 = single query)")
    p.add_argument("--no-filter", action="store_true",
                   help="Pull entire fleet — overrides --lookback")
    p.add_argument("--dump", type=str, default=None,
                   help="Path to write asset IDs as CSV (optional)")
    p.add_argument("--max-pages", type=int, default=10000,
                   help="Defensive page cap (default 10000)")
    return p.parse_args()


def build_buckets(lookback_days: int, n_buckets: int):
    """Returns list of (qql_filter, label) tuples — same logic the wrapper uses."""
    if n_buckets <= 1 or lookback_days <= 0:
        return []
    bucket_size = lookback_days / n_buckets
    now = datetime.utcnow()
    out = []
    for i in range(n_buckets):
        days_min = i * bucket_size
        days_max = (i + 1) * bucket_size
        cutoff_high = now - timedelta(days=days_min)
        cutoff_low = now - timedelta(days=days_max)
        low_iso = cutoff_low.strftime("%Y-%m-%dT%H:%M:%SZ")
        high_iso = cutoff_high.strftime("%Y-%m-%dT%H:%M:%SZ")
        if i == 0:
            qql = f"lastCheckedIn >= '{low_iso}'"
        else:
            qql = f"lastCheckedIn >= '{low_iso}' AND lastCheckedIn < '{high_iso}'"
        out.append((qql, f"bucket {i+1}/{n_buckets} ({days_min:.0f}-{days_max:.0f}d ago)"))
    return out


def make_on_page_callback(state):
    """Accumulate per-page state silently. Per-page detail still goes
    to the DEBUG file log via api_client; console stays quiet so only
    totals show up there."""
    def _on_page(page, total, last_id, has_more, page_assets):
        n = len(page_assets) if page_assets else 0
        state["pages"] += 1
        state["assets_this_query"] += n
        for a in page_assets or []:
            aid = a.get("assetId")
            if aid is not None:
                state["unique_ids"].add(str(aid))
    return _on_page


def main():
    args = parse_args()
    (ROOT / "logs").mkdir(exist_ok=True)

    log.info("=" * 70)
    log.info("CSAM 90-day pull test — standalone, no DB writes")
    log.info("=" * 70)

    # ── Step 1: load config ──────────────────────────────────────
    try:
        config = load_config()
    except Exception as e:
        log.error(f"Config load failed: {e}")
        return 1

    if not config.username or not config.password:
        log.error("Missing credentials. Fill [credentials] in config/.config.")
        return 1

    log.info(f"VM URL:   {config.vm_base_url}")
    log.info(f"CSAM URL: {config.csam_base_url}")
    log.info(f"Username: {config.username}")
    log.info(f"Page size: {config.csam_page_size}")
    log.info(f"Parallel refresh: {config.parallel_refresh}")
    log.info("")

    # ── Step 2: build client + auth probe ────────────────────────
    client = QualysClient(config)
    try:
        client._csam_authenticate()
        log.info("CSAM auth: OK")
    except AuthError as e:
        log.error(f"CSAM auth FAILED: {e}")
        return 1
    except Exception as e:
        log.error(f"CSAM auth error: {type(e).__name__}: {e}")
        return 1

    # ── Step 3: preflight count (no filter — total fleet) ────────
    log.info("Running CSAM count preflight (full fleet, no filter)...")
    t0 = time.time()
    expected = client.count_csam_assets()
    log.info(f"  count: {expected if expected is not None else 'UNAVAILABLE'} "
             f"({(time.time() - t0)*1000:.0f}ms)")
    log.info("")

    # ── Step 4: pull ─────────────────────────────────────────────
    lookback = 0 if args.no_filter else args.lookback
    buckets = build_buckets(lookback, args.buckets) if not args.no_filter else []

    state = {
        "pages": 0,
        "assets_this_query": 0,
        "unique_ids": set(),
        "buckets_run": 0,
    }
    all_assets = []

    pull_start = time.time()
    try:
        if buckets:
            log.info(f"Bucketed pull: {len(buckets)} buckets across "
                     f"{lookback}-day lookback")
            for idx, (qql, label) in enumerate(buckets, 1):
                state["assets_this_query"] = 0  # reset per-bucket
                bucket_t0 = time.time()
                bucket_assets = client.fetch_csam_assets(
                    max_pages=args.max_pages,
                    expected=None,
                    filter_qql_override=qql,
                    on_page=make_on_page_callback(state),
                )
                state["buckets_run"] += 1
                all_assets.extend(bucket_assets)
                log.info(f"{label}: returned {len(bucket_assets):,} assets "
                         f"({time.time() - bucket_t0:.1f}s)")
        else:
            mode = "no filter (full fleet)" if lookback == 0 else f"{lookback}-day lookback"
            log.info(f"Single-query pull: {mode}")
            all_assets = client.fetch_csam_assets(
                max_pages=args.max_pages,
                expected=expected,
                lookback_days=lookback,
                on_page=make_on_page_callback(state),
            )
    except RateLimitError as e:
        log.error(f"Pull stopped — rate limit exhausted: {e}")
        return 2
    except QualysError as e:
        log.error(f"Pull stopped — Qualys API error: {e}")
        return 2
    except KeyboardInterrupt:
        log.warning("Pull cancelled by user (Ctrl+C)")
        return 2

    elapsed = time.time() - pull_start

    # ── Step 5: summary ──────────────────────────────────────────
    log.info("")
    log.info("=" * 70)
    log.info("SUMMARY")
    log.info("=" * 70)
    log.info(f"Wall time:           {elapsed:.1f}s")
    log.info(f"Total assets pulled: {len(all_assets):,}")
    log.info(f"Unique asset IDs:    {len(state['unique_ids']):,}")
    log.info(f"Pages fetched:       {state['pages']:,}")
    if buckets:
        log.info(f"Buckets completed:   {state['buckets_run']}/{len(buckets)}")
    if expected is not None:
        diff = len(state["unique_ids"]) - expected
        pct = (diff / expected * 100) if expected else 0
        log.info(f"Preflight expected:  {expected:,}  (drift: {diff:+,} = {pct:+.1f}%)")
    if all_assets:
        avg_per_page = len(all_assets) / max(1, state["pages"])
        log.info(f"Avg assets/page:     {avg_per_page:.1f}")
        log.info(f"Pull rate:           {len(all_assets) / elapsed:.0f} assets/sec")

    # ── Optional: dump asset IDs to CSV ──────────────────────────
    if args.dump:
        dump_path = Path(args.dump)
        with open(dump_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["assetId", "name", "address", "lastCheckedIn"])
            for a in all_assets:
                w.writerow([
                    a.get("assetId", ""),
                    a.get("name", ""),
                    a.get("address", ""),
                    a.get("lastCheckedIn", a.get("lastSeen", "")),
                ])
        log.info(f"Dumped {len(all_assets):,} rows to {dump_path}")

    log.info("")
    log.info(f"Full DEBUG log: logs/csam_90day_test.log")
    return 0


if __name__ == "__main__":
    sys.exit(main())
