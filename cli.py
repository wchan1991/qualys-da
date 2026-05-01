#!/usr/bin/env python3
"""
Qualys Data Analytics - CLI

Command-line interface for manual operations.

Usage:
    python cli.py health          - Test API connectivity
    python cli.py refresh         - Full data refresh (all sources)
    python cli.py refresh --source csam|vm-hosts|vm-detections
    python cli.py export --type detections|hosts|assets|kpis [--output ./exports/]
    python cli.py purge [--dry-run]
    python cli.py status          - Show DB stats and last refresh
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config_loader import load_config
from src.data_manager import DataManager

# Configure logging
Path("logs").mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def cmd_health(args, manager):
    """Test API connectivity."""
    print("Testing API connections...")
    try:
        result = manager.health_check()
        vm_ok = result.get("vm", {}).get("status") == "ok"
        csam_ok = result.get("csam", {}).get("status") == "ok"
        print(f"  VM API:   {'OK' if vm_ok else 'FAILED'}")
        print(f"  CSAM API: {'OK' if csam_ok else 'FAILED'}")
        if vm_ok and csam_ok:
            print("All connections healthy.")
            return 0
        else:
            print("Some connections failed. Check credentials and URLs.")
            return 1
    except Exception as e:
        print(f"Health check failed: {e}")
        return 1


def cmd_refresh(args, manager):
    """Refresh data from Qualys APIs."""
    source = getattr(args, "source", None)
    if source:
        print(f"Refreshing {source}...")
        if source == "csam":
            result = manager.refresh_csam()
        elif source == "vm-hosts":
            result = manager.refresh_vm_hosts()
        elif source == "vm-detections":
            result = manager.refresh_vm_detections()
        else:
            print(f"Unknown source: {source}")
            return 1
    else:
        print("Starting full refresh (all sources)...")
        result = manager.refresh_all()

    print(f"Refresh complete: {result}")
    return 0


def cmd_export(args, manager):
    """Export data to CSV — streams chunks to disk so memory stays
    bounded regardless of fleet size. No row cap (the legacy
    `export_csv` capped at 100k and silently truncated big fleets)."""
    export_type = args.type
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = output_dir / f"qualys_{export_type}_{timestamp}.csv"

    print(f"Exporting {export_type} to {filename}...")
    rows_written = 0
    with open(filename, "w", newline="", encoding="utf-8") as f:
        for chunk in manager.export_csv_stream(export_type):
            f.write(chunk)
            # Each chunk is one batch worth of CSV lines; the row count
            # progress is approximate (header + line breaks count toward
            # the chunk) but useful for long-running exports.
            rows_written += chunk.count("\n")

    # Subtract 1 for the header row we wrote first.
    estimated_rows = max(0, rows_written - 1)
    size_mb = filename.stat().st_size / (1024 * 1024)
    print(
        f"Exported to {filename} "
        f"(~{estimated_rows:,} rows, {size_mb:.1f} MB)"
    )
    return 0


def cmd_purge(args, manager):
    """Purge data — either GFS retention (default) or full wipe (--all)."""
    dry_run = args.dry_run

    # ── Full-wipe path ───────────────────────────────────────────
    # Requires --all and a confirmation prompt unless --yes is passed.
    # Cancels in-flight refreshes first via the orchestrator; see
    # DataManager.purge_all() docstring.
    if getattr(args, "all", False):
        include_config = getattr(args, "include_config", False)
        if dry_run:
            print("DRY RUN — would wipe all ingested data" +
                  (" + config tables (asset_owners, sla_targets, "
                   "saved_queries)" if include_config else ""))
            stats = manager.db.get_db_stats()
            print(f"  Current DB size: {stats.get('db_size_mb', 0)} MB")
            return 0
        if not getattr(args, "yes", False):
            print("WARNING: This will delete ALL ingested data" +
                  (" AND config tables (ownership rules, SLA, saved queries)"
                   if include_config else "") + ".")
            print("Type DELETE to confirm: ", end="", flush=True)
            try:
                resp = input().strip()
            except EOFError:
                resp = ""
            if resp != "DELETE":
                print("Aborted.")
                return 1
        print("Cancelling any in-flight refresh and wiping...")
        result = manager.purge_all(include_config=include_config)
        if result["cancel_was_needed"]:
            print(f"  Refresh cancellation: "
                  f"{'completed' if result['cancel_completed'] else 'TIMED OUT'}")
        total = sum(result["purged_counts"].values())
        print(f"Purged {total:,} rows across "
              f"{len(result['purged_counts'])} tables:")
        for table, count in result["purged_counts"].items():
            print(f"  {table}: {count:,} rows deleted")
        return 0

    # ── Retention purge (default) ────────────────────────────────
    if dry_run:
        print("DRY RUN — showing what would be purged:")

    config = manager.config
    print(f"  Daily retention:  {config.daily_retention_days} days")
    print(f"  Weekly retention: {config.weekly_retention_weeks} weeks")

    db = manager.db
    stats_before = db.get_db_stats()

    if not dry_run:
        manager.analytics.purge_snapshots()
        stats_after = db.get_db_stats()
        print("Purge complete.")
        for table, count in stats_after.get("tables", {}).items():
            before = stats_before.get("tables", {}).get(table, count)
            diff = before - count
            if diff > 0:
                print(f"  {table}: removed {diff} rows ({before} → {count})")
    else:
        print("  (No changes made — use without --dry-run to execute)")
    return 0


def cmd_status(args, manager):
    """Show database stats and last refresh info."""
    stats = manager.db.get_db_stats()
    print("Database Statistics:")
    print(f"  Path: {manager.config.db_path}")
    for table, count in stats.get("tables", {}).items():
        print(f"  {table}: {count:,} rows")

    refresh_log = manager.db.get_refresh_log(5)
    if refresh_log:
        print("\nRecent Refreshes:")

        def _fmt_pair(actual, expected):
            """Render 'actual/expected' with a * marker if there's drift."""
            actual = actual or 0
            if expected is None:
                return f"{actual:,}"
            mark = "" if actual == expected else "*"
            return f"{actual:,}/{expected:,}{mark}"

        for entry in refresh_log:
            print(
                f"  {entry.get('started_at', '?')} | "
                f"{entry.get('source', '?')} | "
                f"{entry.get('status', '?')} | "
                f"CSAM:{_fmt_pair(entry.get('csam_count'), entry.get('csam_expected'))} "
                f"VM-H:{_fmt_pair(entry.get('vm_host_count'), entry.get('vm_host_expected'))} "
                f"VM-D:{_fmt_pair(entry.get('vm_detection_count'), entry.get('vm_detection_expected'))}"
            )
        print("  (* = fetched count differs from Qualys count-endpoint preflight)")
    else:
        print("\nNo refresh history yet.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Qualys Data Analytics CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # health
    subparsers.add_parser("health", help="Test API connectivity")

    # refresh
    refresh_parser = subparsers.add_parser("refresh", help="Refresh data from APIs")
    refresh_parser.add_argument("--source", choices=["csam", "vm-hosts", "vm-detections"],
                                help="Refresh a specific source only")

    # export
    export_parser = subparsers.add_parser("export", help="Export data to CSV")
    export_parser.add_argument("--type", choices=["detections", "hosts", "assets", "kpis"],
                               default="detections", help="Data type to export")
    export_parser.add_argument("--output", default="./exports/", help="Output directory")

    # purge
    purge_parser = subparsers.add_parser(
        "purge",
        help="Purge data — old (GFS retention, default) or all (--all)",
    )
    purge_parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be purged without executing",
    )
    purge_parser.add_argument(
        "--all", action="store_true",
        help=("DESTRUCTIVE: wipe ALL ingested data (snapshot tables, rollups, "
              "change log, refresh log, heartbeats, CSAM checkpoint). "
              "Cancels any in-flight refresh first. Requires interactive "
              "DELETE confirmation unless --yes is also passed."),
    )
    purge_parser.add_argument(
        "--include-config", action="store_true",
        help=("With --all, also wipe configuration tables (asset_owners, "
              "sla_targets, saved_queries). Use for a full factory reset."),
    )
    purge_parser.add_argument(
        "--yes", action="store_true",
        help="Skip the interactive DELETE prompt (use with --all in scripts).",
    )

    # status
    subparsers.add_parser("status", help="Show DB stats and refresh history")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Initialize
    try:
        config = load_config()
        manager = DataManager(config)
    except Exception as e:
        print(f"Initialization failed: {e}")
        return 1

    commands = {
        "health": cmd_health,
        "refresh": cmd_refresh,
        "export": cmd_export,
        "purge": cmd_purge,
        "status": cmd_status,
    }

    handler = commands.get(args.command)
    if handler:
        try:
            return handler(args, manager)
        except Exception as e:
            logger.error(f"Command '{args.command}' failed: {e}", exc_info=True)
            print(f"Error: {e}")
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
