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
    """Export data to CSV."""
    export_type = args.type
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = output_dir / f"qualys_{export_type}_{timestamp}.csv"

    print(f"Exporting {export_type} to {filename}...")
    csv_content = manager.export_csv(export_type)

    with open(filename, "w", newline="", encoding="utf-8") as f:
        f.write(csv_content)

    print(f"Exported to {filename}")
    return 0


def cmd_purge(args, manager):
    """Purge old data per GFS retention policy."""
    dry_run = args.dry_run
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
        for entry in refresh_log:
            print(f"  {entry.get('started_at', '?')} | {entry.get('source', '?')} | {entry.get('status', '?')} | "
                  f"CSAM:{entry.get('csam_count', 0)} VM-H:{entry.get('vm_host_count', 0)} VM-D:{entry.get('vm_detection_count', 0)}")
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
    purge_parser = subparsers.add_parser("purge", help="Purge old data (GFS retention)")
    purge_parser.add_argument("--dry-run", action="store_true", help="Show what would be purged without executing")

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
