#!/usr/bin/env python3
"""
Qualys Data Analytics - Web Application

Browser-based dashboard for Qualys vulnerability data.
Run: python app.py
Open: http://localhost:5000

Thread-safety: QualysDADatabase uses thread-local storage for SQLite
connections, making it safe with Flask's threaded mode.
"""

import io
import csv
import sys
import time
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, jsonify, request, send_file, Response
)

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.config_loader import load_config
from src.data_manager import DataManager
from src.api_client import QualysError

# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)
app.secret_key = "qualys-da-dev-key"

# Ensure directories exist
Path("logs").mkdir(exist_ok=True)
Path("data").mkdir(exist_ok=True)
Path("exports").mkdir(exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global singletons
_manager = None
_config = None


def get_config():
    """Get or load configuration."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def get_manager() -> DataManager:
    """Get or create the data manager (lazy singleton)."""
    global _manager
    if _manager is None:
        _manager = DataManager(get_config())
    return _manager


# ============================================================
# API RESPONSE DECORATOR
# ============================================================

def api_response(f):
    """Wrap API route handlers with JSON error handling."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            if isinstance(result, Response):
                return result
            return jsonify(result)
        except QualysError as e:
            logger.error(f"Qualys API error in {f.__name__}: {e}")
            return jsonify({"error": str(e)}), 502
        except Exception as e:
            logger.error(f"Error in {f.__name__}: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    return decorated


# ============================================================
# SCHEDULER (APScheduler)
# ============================================================

_scheduler = None


def init_scheduler():
    """Initialize APScheduler for weekly refresh."""
    global _scheduler
    config = get_config()
    if not config.scheduler_enabled:
        logger.info("Scheduler disabled in config")
        return

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        _scheduler = BackgroundScheduler()

        day_map = {
            'monday': 'mon', 'tuesday': 'tue', 'wednesday': 'wed',
            'thursday': 'thu', 'friday': 'fri', 'saturday': 'sat', 'sunday': 'sun'
        }
        day = day_map.get(config.refresh_day.lower(), 'mon')

        _scheduler.add_job(
            scheduled_refresh,
            'cron',
            day_of_week=day,
            hour=config.refresh_hour,
            id='weekly_refresh',
            name='Weekly data refresh'
        )
        # Register the API availability heartbeat (default: every 4h).
        # Reuses the same scheduler instance so start/stop lifecycle is
        # shared. First run fires 30s after startup so the connection-dot
        # has data to read on the very first page load (rather than
        # waiting up to 4h for a heartbeat).
        if config.health_check_enabled:
            interval_h = max(1, int(config.health_check_interval_hours))
            _scheduler.add_job(
                scheduled_health_check,
                'interval',
                hours=interval_h,
                id='health_heartbeat',
                name='Qualys API availability heartbeat',
                next_run_time=datetime.now() + timedelta(seconds=30),
            )
            logger.info(
                f"Scheduler: registered health_heartbeat "
                f"(interval: {interval_h}h, first run in 30s)"
            )
        _scheduler.start()
        logger.info(f"Scheduler started: refresh every {config.refresh_day} at {config.refresh_hour:02d}:00")
    except ImportError:
        logger.warning("apscheduler not installed — scheduler disabled")
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")


def scheduled_refresh():
    """Run by the scheduler."""
    logger.info("Scheduled refresh starting...")
    try:
        manager = get_manager()
        result = manager.refresh_all()
        logger.info(f"Scheduled refresh complete: {result}")
    except Exception as e:
        logger.error(f"Scheduled refresh failed: {e}", exc_info=True)


def scheduled_health_check():
    """Periodic API availability heartbeat — default cadence: every 4 hours.

    Calls `manager.health_check()` (which itself just runs the cached-token
    auth probes for VM and CSAM) and records the outcome in `health_log`.
    The connection-dot in the nav bar reads from `health_log` so operators
    see availability problems within minutes rather than waiting until the
    next weekly refresh.

    Designed to be cheap: each run makes at most 2 auth calls (one VM,
    one CSAM), and only when the cached tokens have expired (~4h cycles).
    """
    logger.debug("Heartbeat firing...")
    try:
        manager = get_manager()
        start = time.monotonic()
        result = manager.health_check()
        duration_ms = int((time.monotonic() - start) * 1000)
        manager.db.log_health_check(
            vm_available=bool(result.get("vm")),
            csam_available=bool(result.get("csam")),
            vm_error=result.get("vm_error"),
            csam_error=result.get("csam_error"),
            duration_ms=duration_ms,
        )
        if not result.get("vm") or not result.get("csam"):
            logger.warning(
                f"Heartbeat: VM={result.get('vm')} CSAM={result.get('csam')} "
                f"(vm_err={result.get('vm_error')}, "
                f"csam_err={result.get('csam_error')})"
            )
        else:
            logger.info(f"Heartbeat OK ({duration_ms}ms)")
    except Exception as e:
        # Heartbeat failures must NEVER crash the scheduler — log loudly
        # and let the next interval try again.
        logger.error(f"Health heartbeat raised: {e}", exc_info=True)


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/six-pack")
def six_pack_page():
    return render_template("six_pack.html")


@app.route("/cve-dashboard")
def cve_dashboard_page():
    return render_template("cve_dashboard.html")


@app.route("/patchable-dashboard")
def patchable_dashboard_page():
    return render_template("patchable_dashboard.html")


@app.route("/orphaned")
def orphaned_page():
    return render_template("orphaned.html")


@app.route("/kpis")
def kpis_page():
    return render_template("kpis.html")


@app.route("/query")
def query_page():
    return render_template("query.html")


@app.route("/tags")
def tags_page():
    return render_template("tags.html")


@app.route("/trends")
def trends_page():
    return render_template("trends.html")


@app.route("/hosts")
def hosts_page():
    return render_template("hosts.html")


@app.route("/ownership")
def ownership_page():
    return render_template("ownership.html")


@app.route("/sql")
def custom_query_page():
    return render_template("custom_query.html")


@app.route("/settings")
def settings_page():
    return render_template("settings.html")


# ============================================================
# API: Health & Refresh
# ============================================================

@app.route("/api/health")
@api_response
def api_health():
    manager = get_manager()
    return manager.health_check()


@app.route("/api/refresh", methods=["POST"])
@api_response
def api_refresh():
    manager = get_manager()
    thread = threading.Thread(target=manager.refresh_all, daemon=True)
    thread.start()
    return {"status": "refresh_started", "message": "Full refresh started in background"}


@app.route("/api/refresh/<source>", methods=["POST"])
@api_response
def api_refresh_source(source):
    manager = get_manager()
    if source == "csam":
        fn = manager.refresh_csam
    elif source == "vm-hosts":
        fn = manager.refresh_vm_hosts
    elif source == "vm-detections":
        fn = manager.refresh_vm_detections
    else:
        return {"error": f"Unknown source: {source}"}
    thread = threading.Thread(target=fn, daemon=True)
    thread.start()
    return {"status": "refresh_started", "source": source}


@app.route("/api/refresh/cancel", methods=["POST"])
@api_response
def api_refresh_cancel():
    """Signal any in-flight refresh to abort cooperatively.

    Returns immediately — cancellation is checked at the next safe point
    by each per-API worker (between pages, or when waking from a 429
    window-hop sleep). The refresh row's `status` flips to `'cancelled'`
    and per-API columns reflect which workers reached a cancel checkpoint
    in time. Already-persisted rows (CSAM saves per-page) are kept; the
    CSAM checkpoint preserves resume state so the next refresh can pick
    up from the exact page where the cancel landed.
    """
    manager = get_manager()
    db = manager.db
    # Sanity check: only act if there's actually a running refresh.
    rows = db.get_refresh_log(limit=1)
    if not rows or rows[0].get("status") != "running":
        return {
            "status": "no_active_refresh",
            "message": "No refresh is currently running.",
        }
    manager.request_cancel()
    return {
        "status": "cancel_requested",
        "refresh_id": rows[0].get("id"),
        "message": (
            "Cancel signal sent. The refresh will abort at its next "
            "page/checkpoint boundary; an in-flight 429 wait is "
            "interrupted immediately. Saved rows are preserved."
        ),
    }


# ============================================================
# API: Dashboard
# ============================================================

@app.route("/api/dashboard")
@api_response
def api_dashboard():
    manager = get_manager()
    return manager.get_dashboard()


# ============================================================
# API: Metrics
# ============================================================

@app.route("/api/metrics/vuln-overview")
@api_response
def api_vuln_overview():
    include_disabled = request.args.get("include_disabled", "false").lower() == "true"
    return get_manager().analytics.vuln_overview(include_disabled)


@app.route("/api/metrics/risk-distribution")
@api_response
def api_risk_distribution():
    return get_manager().analytics.risk_distribution()


@app.route("/api/metrics/asset-coverage")
@api_response
def api_asset_coverage():
    return get_manager().analytics.asset_coverage()


@app.route("/api/metrics/detection-age")
@api_response
def api_detection_age():
    return get_manager().analytics.detection_age()


@app.route("/api/metrics/os-distribution")
@api_response
def api_os_distribution():
    return get_manager().analytics.os_distribution()


@app.route("/api/metrics/app-distribution")
@api_response
def api_app_distribution():
    return get_manager().analytics.app_distribution()


@app.route("/api/metrics/top-qids")
@api_response
def api_top_qids():
    n = int(request.args.get("n", 20))
    return get_manager().analytics.top_qids(n)


@app.route("/api/cve-dashboard")
@api_response
def api_cve_dashboard():
    months = int(request.args.get("months", 12))
    return get_manager().analytics.cve_dashboard(months)


@app.route("/api/metrics/week-over-week")
@api_response
def api_week_over_week():
    return get_manager().analytics.week_over_week()


@app.route("/api/metrics/changes")
@api_response
def api_changes():
    days = int(request.args.get("days", 7))
    return get_manager().analytics.recent_changes(days)


# ============================================================
# API: Trends
# ============================================================

@app.route("/api/metrics/trends/weekly")
@api_response
def api_weekly_trends():
    weeks = int(request.args.get("weeks", 12))
    return get_manager().analytics.weekly_trends(weeks)


@app.route("/api/metrics/trends/monthly")
@api_response
def api_monthly_trends():
    months = int(request.args.get("months", 12))
    return get_manager().analytics.monthly_trends(months)


# ============================================================
# API: Detections
# ============================================================

@app.route("/api/detections")
@api_response
def api_detections():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    filters = {
        "ip": request.args.get("ip"),
        "severity_min": request.args.get("severity_min", type=int),
        "status": request.args.getlist("status") or None,
        "qid": request.args.get("qid", type=int),
        "date_from": request.args.get("date_from"),
        "date_to": request.args.get("date_to"),
        "tag": request.args.get("tag"),
        "include_disabled": request.args.get("include_disabled", "false").lower() == "true",
        "limit": per_page,
        "offset": (page - 1) * per_page,
    }
    # Remove None values
    filters = {k: v for k, v in filters.items() if v is not None}
    return get_manager().query_detections(**filters)


# ============================================================
# API: Hosts
# ============================================================

@app.route("/api/hosts")
@api_response
def api_hosts():
    ip = request.args.get("ip")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    manager = get_manager()
    return manager.db.get_latest_vm_hosts(
        ip=ip, limit=per_page, offset=(page - 1) * per_page
    )


@app.route("/api/host/<path:ip>")
@api_response
def api_host_detail(ip):
    return get_manager().get_host_detail(ip)


@app.route("/api/assets")
@api_response
def api_assets():
    ip = request.args.get("ip")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 100, type=int)
    manager = get_manager()
    return manager.db.get_latest_csam_assets(ip=ip, page=page, per_page=per_page)


# ============================================================
# API: Tags
# ============================================================

@app.route("/api/tags")
@api_response
def api_tags():
    return get_manager().analytics.tag_summary()


@app.route("/api/tags/monitored")
@api_response
def api_tags_monitored():
    return get_manager().analytics.monitored_tag_dashboard()


@app.route("/api/tags/<path:tag_name>")
@api_response
def api_tag_detail(tag_name):
    return get_manager().analytics.tag_detail(tag_name)


@app.route("/api/metrics/tag-comparison")
@api_response
def api_tag_comparison():
    tags_param = request.args.get("tags", "")
    tag_names = [t.strip() for t in tags_param.split(",") if t.strip()]
    return get_manager().analytics.tag_comparison(tag_names)


# ============================================================
# API: Cyber 6-Pack
# ============================================================

@app.route("/api/six-pack")
@api_response
def api_six_pack():
    group_by = request.args.get("group_by", "owner")
    return get_manager().analytics.cyber_six_pack(group_by)


@app.route("/api/six-pack/trend")
@api_response
def api_six_pack_trend():
    group_by = request.args.get("group_by", "owner")
    months = request.args.get("months", 12, type=int)
    return get_manager().analytics.cyber_six_pack_trend(group_by, months)


@app.route("/api/six-pack/cve")
@api_response
def api_six_pack_cve():
    group_by = request.args.get("group_by", "owner")
    return get_manager().analytics.cve_by_ownership(group_by)


@app.route("/api/six-pack/waterfall")
@api_response
def api_six_pack_waterfall():
    group_by = request.args.get("group_by", "owner")
    owner = request.args.get("owner") or None
    months = request.args.get("months", 12, type=int)
    return get_manager().analytics.waterfall_by_ownership(group_by, owner, months)


@app.route("/api/six-pack/os")
@api_response
def api_six_pack_os():
    group_by = request.args.get("group_by", "owner")
    return get_manager().analytics.os_by_ownership(group_by)


@app.route("/api/patchable-dashboard")
@api_response
def api_patchable_dashboard():
    return get_manager().analytics.patchable_by_severity()


@app.route("/api/orphaned")
@api_response
def api_orphaned():
    return get_manager().analytics.orphaned_assets()


# ============================================================
# API: KPIs
# ============================================================

@app.route("/api/kpis")
@api_response
def api_kpis():
    include_disabled = request.args.get("include_disabled", "false").lower() == "true"
    return get_manager().analytics.all_kpis(include_disabled)


@app.route("/api/kpis/sla-compliance")
@api_response
def api_sla_compliance():
    return get_manager().analytics.sla_compliance()


@app.route("/api/kpis/mttr")
@api_response
def api_mttr():
    return get_manager().analytics.mttr_by_severity()


@app.route("/api/kpis/patchable")
@api_response
def api_patchable():
    return get_manager().analytics.patchable_percentage()


# ============================================================
# API: SLA Targets
# ============================================================

@app.route("/api/sla-targets")
@api_response
def api_sla_targets():
    return get_manager().db.get_sla_targets()


@app.route("/api/sla-targets", methods=["PUT"])
@api_response
def api_update_sla_targets():
    targets = request.get_json()
    get_manager().db.update_sla_targets(targets)
    return {"status": "ok"}


# ============================================================
# API: Ownership
# ============================================================

@app.route("/api/owners")
@api_response
def api_owners():
    return get_manager().db.get_owners()


@app.route("/api/owners", methods=["POST"])
@api_response
def api_add_owner():
    data = request.get_json()
    get_manager().db.add_owner(
        match_type=data["match_type"],
        match_value=data["match_value"],
        owner=data["owner"],
        business_unit=data.get("business_unit", ""),
        notes=data.get("notes", "")
    )
    return {"status": "ok"}


@app.route("/api/owners/<int:owner_id>", methods=["PUT"])
@api_response
def api_update_owner(owner_id):
    data = request.get_json()
    get_manager().db.update_owner(owner_id, data)
    return {"status": "ok"}


@app.route("/api/owners/<int:owner_id>", methods=["DELETE"])
@api_response
def api_delete_owner(owner_id):
    get_manager().db.delete_owner(owner_id)
    return {"status": "ok"}


@app.route("/api/owners/import", methods=["POST"])
@api_response
def api_import_owners():
    if "file" not in request.files:
        return {"error": "No file provided"}
    file = request.files["file"]
    content = file.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    imported = 0
    db = get_manager().db
    for row in reader:
        try:
            db.add_owner(
                match_type=row.get("match_type", "").strip(),
                match_value=row.get("match_value", "").strip(),
                owner=row.get("owner", "").strip(),
                business_unit=row.get("business_unit", "").strip(),
                notes=row.get("notes", "").strip()
            )
            imported += 1
        except Exception as e:
            logger.warning(f"Failed to import row: {row} — {e}")
    return {"imported": imported}


@app.route("/api/owners/unassigned")
@api_response
def api_unassigned():
    mgr = get_manager()
    # Batch-resolve owners in one pass instead of per-IP queries
    hosts = mgr.db.get_latest_vm_hosts(page=1, per_page=5000)
    all_ips = [h.get("ip_address", "") for h in hosts]
    resolved_map = mgr.analytics._batch_resolve_owners(all_ips)
    unassigned = []
    for h in hosts:
        ip = h.get("ip_address", "")
        if not resolved_map.get(ip):
            unassigned.append(h)
    return unassigned[:500]


@app.route("/api/owners/preview")
@api_response
def api_preview_owner():
    match_type = request.args.get("match_type", "ip")
    match_value = request.args.get("match_value", "")
    db = get_manager().db
    hosts = db.get_latest_vm_hosts(page=1, per_page=5000)

    matched = []
    for h in hosts:
        ip = h.get("ip_address", "")
        if match_type == "ip" and ip == match_value:
            matched.append(h)
        elif match_type == "ip_range":
            try:
                import ipaddress
                if ipaddress.ip_address(ip) in ipaddress.ip_network(match_value, strict=False):
                    matched.append(h)
            except (ValueError, TypeError):
                pass
        elif match_type == "os_pattern":
            os_val = h.get("os", "") or ""
            if match_value.replace("%", "").lower() in os_val.lower():
                matched.append(h)
        elif match_type == "tag":
            tags = db.get_all_tags()
            tag_ips = set()
            for t in tags:
                if t.get("tag_name") == match_value:
                    tag_hosts = db.get_hosts_by_tag(match_value)
                    tag_ips = {th.get("ip_address") for th in tag_hosts}
                    break
            if ip in tag_ips:
                matched.append(h)

    return matched[:500]


# ============================================================
# API: Custom Queries
# ============================================================

@app.route("/api/query", methods=["POST"])
@api_response
def api_execute_query():
    data = request.get_json()
    sql = data.get("sql", "").strip()
    if not sql:
        return {"error": "No SQL provided"}
    db = get_manager().db
    result = db.execute_readonly(sql)
    return result


@app.route("/api/query/saved")
@api_response
def api_saved_queries():
    return get_manager().db.get_saved_queries()


@app.route("/api/query/save", methods=["POST"])
@api_response
def api_save_query():
    data = request.get_json()
    get_manager().db.save_query(
        name=data["name"],
        sql_text=data["sql"],
        description=data.get("description", "")
    )
    return {"status": "ok"}


@app.route("/api/query/saved/<int:query_id>", methods=["DELETE"])
@api_response
def api_delete_query(query_id):
    get_manager().db.delete_saved_query(query_id)
    return {"status": "ok"}


# ============================================================
# API: pandas post-processing (real, server-side)
# pandas is lazy-imported here so dashboard pages never pay the cost.
# ============================================================

@app.route("/api/query/postprocess", methods=["POST"])
@api_response
def api_query_postprocess():
    """Apply a pandas operation to a query result payload.

    Request JSON: {operation, columns, rows, ...op-specific args}
    Response JSON: {columns: [...], rows: [...]}
    """
    import pandas as pd  # lazy import
    body = request.get_json() or {}
    op = body.get("operation")
    columns = body.get("columns") or []
    rows = body.get("rows") or []
    if not rows:
        return {"error": "No data to process"}
    df = pd.DataFrame(rows, columns=columns) if columns else pd.DataFrame(rows)

    try:
        if op == "describe":
            out = df.describe(include="all").reset_index().rename(columns={"index": "stat"})
        elif op == "group":
            group_col = body["group_by"]
            agg_func = body.get("agg_func", "count")
            value_col = body.get("value_col")
            if agg_func == "count" or not value_col:
                out = df.groupby(group_col).size().reset_index(name="count")
            else:
                out = df.groupby(group_col)[value_col].agg(agg_func).reset_index()
        elif op == "pivot":
            out = df.pivot_table(
                index=body["index"],
                columns=body["columns"],
                values=body["values"],
                aggfunc=body.get("agg_func", "sum"),
                fill_value=0,
            ).reset_index()
            out.columns = [str(c) for c in out.columns]
        elif op == "rolling":
            window = int(body.get("window", 4))
            col = body["value_col"]
            order_by = body.get("order_by") or columns[0]
            df = df.sort_values(order_by)
            df[f"{col}_rolling{window}"] = df[col].rolling(window, min_periods=1).mean()
            out = df
        elif op == "percentiles":
            col = body["value_col"]
            qs = [0.5, 0.9, 0.95, 0.99]
            out = pd.DataFrame({
                "percentile": ["p50", "p90", "p95", "p99"],
                col: df[col].quantile(qs).values,
            })
        elif op == "correlation":
            out = df.corr(numeric_only=True).reset_index().rename(columns={"index": "column"})
        else:
            return {"error": f"Unknown operation: {op}"}
    except KeyError as e:
        return {"error": f"Missing column: {e}"}
    except Exception as e:
        logger.error(f"pandas postprocess error: {e}", exc_info=True)
        return {"error": str(e)}

    return {
        "columns": [str(c) for c in out.columns],
        "rows": out.where(pd.notnull(out), None).to_dict(orient="records"),
    }


@app.route("/api/query/export/xlsx", methods=["POST"])
def api_query_export_xlsx():
    """Export a query result payload as an Excel (.xlsx) file."""
    try:
        import pandas as pd
    except ImportError:
        return jsonify({"error": "pandas is not installed — run: pip install -r requirements.txt"}), 500
    body = request.get_json() or {}
    columns = body.get("columns") or []
    rows = body.get("rows") or []
    if not rows:
        return jsonify({"error": "No rows to export"}), 400
    df = pd.DataFrame(rows, columns=columns) if columns else pd.DataFrame(rows)
    buf = io.BytesIO()
    try:
        with pd.ExcelWriter(buf, engine="openpyxl") as w:
            df.to_excel(w, sheet_name="Query", index=False)
    except ImportError:
        return jsonify({"error": "openpyxl is not installed — run: pip install -r requirements.txt"}), 500
    buf.seek(0)
    return send_file(
        buf,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="query_results.xlsx",
    )


# ============================================================
# API: Export
# ============================================================

@app.route("/api/export/csv")
def api_export_csv():
    export_type = request.args.get("type", "detections")
    manager = get_manager()

    filters = {
        "ip": request.args.get("ip"),
        "severity_min": request.args.get("severity_min", type=int),
        "status": request.args.getlist("status") or None,
        "qid": request.args.get("qid", type=int),
        "tag": request.args.get("tag"),
        "include_disabled": request.args.get("include_disabled", "false").lower() == "true",
    }
    filters = {k: v for k, v in filters.items() if v is not None}

    csv_content = manager.export_csv(export_type, **filters)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"qualys_{export_type}_{timestamp}.csv"

    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================
# API: DB Stats / Refresh Log
# ============================================================

@app.route("/api/stats")
@api_response
def api_stats():
    return get_manager().db.get_db_stats()


@app.route("/api/refresh-log")
@api_response
def api_refresh_log():
    limit = request.args.get("limit", 10, type=int)
    return get_manager().db.get_refresh_log(limit)


@app.route("/api/refresh-status")
@api_response
def api_refresh_status():
    """Powers the dashboard's in-progress banner.

    Returns the most recent refresh_log row with status='running' (plus
    live counts + expected volumes so the poller can render a progress
    line), or the most recent terminal row within the last 10 seconds
    so the banner can flash a final state before dismissing. Returns
    ``None`` when there's no interesting state to show.
    """
    db = get_manager().db
    rows = db.get_refresh_log(limit=1)
    if not rows:
        return None
    row = rows[0]
    # Only surface running rows or rows that just completed. Past that
    # the dashboard should look idle.
    if row.get("status") != "running":
        completed_at = row.get("completed_at")
        if not completed_at:
            return None
        try:
            delta = (
                datetime.utcnow() - datetime.fromisoformat(completed_at)
            ).total_seconds()
        except (ValueError, TypeError):
            return None
        # 10s grace window — long enough for the banner to show the
        # final state, short enough to auto-idle on reload.
        if delta > 10:
            return None

    # Include the last successful snapshot timestamp so the banner can
    # say "showing last snapshot from <time>" while the new pull runs.
    row["last_success_fetched_at"] = db.get_latest_fetched_at("csam_assets")
    return row


# ============================================================
# API: Health Heartbeat + Ingestion Visibility
# ============================================================
#
# These three endpoints power the always-visible operator surface:
#   /api/health-status   — connection-dot reads this (cached, fast)
#   /api/health-log      — Settings page "Recent Heartbeats" card
#   /api/ingestion-stats — navbar asset-count chip + Settings KPI card
#
# /api/health (live probe) is preserved unchanged for the Settings page's
# manual "Test connection" button, so operators retain the on-demand
# debugging path when the cached data isn't enough.

@app.route("/api/health-status")
@api_response
def api_health_status():
    """Most recent heartbeat result — drives the connection dot.

    Cheap (single indexed DB read), unlike /api/health which probes Qualys
    live on every page nav. Returns:
      vm/csam: bool or None (None means "no heartbeat yet")
      vm_error/csam_error: str or None (last error if API was down)
      checked_at: ISO timestamp of the heartbeat row
      age_seconds: how old the latest heartbeat is
      stale: True if older than 1.25 × interval — signals scheduler-died
             vs. just-haven't-checked-yet
    """
    manager = get_manager()
    row = manager.db.get_latest_health_check()
    if not row:
        return {"vm": None, "csam": None, "checked_at": None,
                "age_seconds": None, "stale": True,
                "vm_error": None, "csam_error": None}
    try:
        checked = datetime.fromisoformat(row["checked_at"])
        age = int((datetime.utcnow() - checked).total_seconds())
    except (ValueError, TypeError):
        age = None
    interval_s = max(1, int(manager.config.health_check_interval_hours)) * 3600
    return {
        "vm": bool(row["vm_available"]),
        "csam": bool(row["csam_available"]),
        "vm_error": row["vm_error"],
        "csam_error": row["csam_error"],
        "checked_at": row["checked_at"],
        "age_seconds": age,
        # 1.25x buffer: a heartbeat at minute 239 of a 240-minute interval
        # shouldn't be flagged stale just because the next one hasn't fired.
        "stale": age is not None and age > int(interval_s * 1.25),
    }


@app.route("/api/health-log")
@api_response
def api_health_log():
    """Heartbeat history — Settings page "Recent Heartbeats" card."""
    limit = max(1, min(500, request.args.get("limit", 20, type=int)))
    return get_manager().db.get_health_log(limit)


@app.route("/api/ingestion-stats")
@api_response
def api_ingestion_stats():
    """Aggregate stats for the ingestion-visibility surface.

    Drives:
      - The navbar asset-counter chip (compact CSAM/Hosts/Detections counts)
      - The Settings page Ingestion Statistics card
      - The startup log banner (via the same db helper, called from __main__)
    """
    db = get_manager().db
    stats = db.get_ingestion_stats()
    # Add success-rate derivation here (rather than in the DB helper) so the
    # core helper stays a pure rollup the startup banner can also consume.
    h = stats["refresh_history"]
    terminal = h["success"] + h["partial"] + h["failed"]
    stats["refresh_history"]["success_rate_pct"] = (
        round(100.0 * h["success"] / terminal, 1) if terminal > 0 else None
    )
    return stats


# ============================================================
# DATA EXPLORER
# ============================================================

@app.route("/data-explorer")
def data_explorer_page():
    return render_template("data_explorer.html")


@app.route("/api/data-explorer/summary")
@api_response
def api_data_explorer_summary():
    """Summary stats for the data explorer cards."""
    db = get_manager().db
    stats = db.get_db_stats()
    # Add latest fetched_at for host_tags
    stats["latest_host_tags"] = db.get_latest_fetched_at("host_tags")
    # Count distinct snapshots across all snapshot tables
    snapshot_count = 0
    for table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags"):
        row = db.conn.execute(
            f"SELECT COUNT(DISTINCT fetched_at) FROM {table}"
        ).fetchone()
        snapshot_count += row[0] if row else 0
    stats["snapshot_count"] = snapshot_count
    return stats


@app.route("/api/data-explorer/snapshots")
@api_response
def api_data_explorer_snapshots():
    """List all snapshot timestamps across the four raw tables, with row counts."""
    db = get_manager().db
    snapshots = []
    for table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags"):
        rows = db.conn.execute(
            f"""SELECT '{table}' AS table_name, fetched_at, COUNT(*) AS row_count
                FROM {table} GROUP BY fetched_at ORDER BY fetched_at DESC"""
        ).fetchall()
        snapshots.extend([dict(r) for r in rows])
    # Sort by fetched_at descending
    snapshots.sort(key=lambda s: s.get("fetched_at", ""), reverse=True)
    return snapshots


EXPLORER_TABLES = {
    "csam_assets", "vm_hosts", "vm_detections", "host_tags",
    "detection_changes", "health_log",
}

EXPLORER_SEARCH_COLS = {
    "csam_assets": ["ip_address", "name", "asset_id", "os"],
    "vm_hosts": ["ip_address", "dns", "os", "netbios"],
    "vm_detections": ["ip_address", "qid", "cve_id", "title", "status"],
    "host_tags": ["ip_address", "tag_name", "source"],
    "detection_changes": ["ip_address", "qid", "change_type"],
    # health_log doesn't have an IP/host search axis; the only useful
    # filter is the error-string substring (e.g. find every "AuthError"
    # heartbeat over the last month).
    "health_log": ["vm_error", "csam_error"],
}


@app.route("/api/data-explorer/browse")
@api_response
def api_data_explorer_browse():
    """Paginated browse of a raw table (latest snapshot for snapshot tables)."""
    table = request.args.get("table", "csam_assets")
    if table not in EXPLORER_TABLES:
        return {"error": f"Unknown table: {table}"}, 400
    page = max(1, request.args.get("page", 1, type=int))
    per_page = min(500, max(1, request.args.get("per_page", 50, type=int)))
    search = request.args.get("search", "").strip()
    db = get_manager().db

    # Snapshot-scoped tables filter to latest fetched_at
    where_parts = []
    params = []
    if table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags"):
        fetched = db.get_latest_fetched_at(table)
        if fetched:
            where_parts.append("fetched_at = ?")
            params.append(fetched)

    # Search filter
    if search:
        search_cols = EXPLORER_SEARCH_COLS.get(table, [])
        if search_cols:
            or_clauses = []
            for col in search_cols:
                or_clauses.append(f"{col} LIKE ?")
                params.append(f"%{search}%")
            where_parts.append(f"({' OR '.join(or_clauses)})")

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    # Count
    count_row = db.conn.execute(
        f"SELECT COUNT(*) FROM {table}{where_sql}", params
    ).fetchone()
    total = count_row[0] if count_row else 0

    # Column names
    col_info = db.conn.execute(f"PRAGMA table_info({table})").fetchall()
    columns = [c["name"] for c in col_info]

    # Data (skip heavy columns from the query to keep it fast)
    skip = {"raw_data", "hardware", "software", "ports", "network_interfaces", "results"}
    select_cols = [c for c in columns if c not in skip]

    offset = (page - 1) * per_page
    rows = db.conn.execute(
        f"SELECT {','.join(select_cols)} FROM {table}{where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    return {
        "table": table,
        "columns": select_cols,
        "rows": [dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@app.route("/api/data-explorer/export-csv")
def api_data_explorer_export_csv():
    """Export the full latest snapshot of a table as CSV."""
    table = request.args.get("table", "csam_assets")
    if table not in EXPLORER_TABLES:
        return jsonify({"error": f"Unknown table: {table}"}), 400
    search = request.args.get("search", "").strip()
    db = get_manager().db

    where_parts = []
    params = []
    if table in ("csam_assets", "vm_hosts", "vm_detections", "host_tags"):
        fetched = db.get_latest_fetched_at(table)
        if fetched:
            where_parts.append("fetched_at = ?")
            params.append(fetched)
    if search:
        search_cols = EXPLORER_SEARCH_COLS.get(table, [])
        if search_cols:
            or_clauses = [f"{col} LIKE ?" for col in search_cols]
            params.extend(f"%{search}%" for _ in search_cols)
            where_parts.append(f"({' OR '.join(or_clauses)})")

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    # Exclude raw_data to keep export manageable
    col_info = db.conn.execute(f"PRAGMA table_info({table})").fetchall()
    columns = [c["name"] for c in col_info if c["name"] != "raw_data"]

    rows = db.conn.execute(
        f"SELECT {','.join(columns)} FROM {table}{where_sql} ORDER BY id DESC",
        params,
    ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row[c] for c in columns])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={table}_export.csv"},
    )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("error.html",
                           error_code=404,
                           error_title="Page Not Found",
                           error_message="The page you're looking for doesn't exist."), 404


@app.errorhandler(500)
def internal_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Internal server error"}), 500
    return render_template("error.html",
                           error_code=500,
                           error_title="Server Error",
                           error_message="An unexpected error occurred."), 500


# ============================================================
# MAIN
# ============================================================

def _lan_ip() -> str:
    """Best-effort primary LAN IP. Falls back to 127.0.0.1 if offline."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is actually sent — UDP connect() just picks the outbound
        # interface the OS would use, which is the LAN IP we want to print.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _friendly_age(iso_ts: str) -> str:
    """Format an ISO timestamp as 'N units ago' for human-readable banners.

    Used by the startup banner and (mirrored in JS) by the navbar tooltip
    so an operator can read freshness at a glance without parsing dates.
    """
    if not iso_ts:
        return "never"
    try:
        ts = datetime.fromisoformat(iso_ts)
    except (ValueError, TypeError):
        return "unknown"
    delta = datetime.utcnow() - ts
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def _log_startup_banner():
    """Emit a multi-line snapshot of the current DB state at startup.

    Powers the "look under the hood" operator UX — see plan section 7a.
    Mirrors what the navbar asset-counter chip shows, but in a richer
    log-friendly format for terminal-watchers and `tail -f logs/app.log`.
    """
    try:
        stats = get_manager().db.get_ingestion_stats()
    except Exception as e:
        logger.warning(f"Startup banner failed to read DB stats: {e}")
        return

    history = stats["refresh_history"]
    is_empty = (
        stats["csam_assets_count"] == 0
        and stats["vm_hosts_count"] == 0
        and stats["vm_detections_count"] == 0
        and history["total"] == 0
    )

    logger.info("=" * 60)
    logger.info("Database state at startup")
    if is_empty:
        logger.info(
            "  Database is empty. Run 'python cli.py refresh' "
            "or click Refresh All to ingest from Qualys."
        )
    else:
        def fmt_snap(table_label, count_key, latest_key):
            count = stats.get(count_key, 0)
            latest = stats.get(latest_key)
            age = f", {_friendly_age(latest)}" if latest else ""
            return (
                f"  {table_label:<18} {count:>9,}"
                + (f"  (latest snapshot: {latest}{age})" if latest else "")
            )

        logger.info(fmt_snap("CSAM assets:", "csam_assets_count", "csam_assets_latest"))
        logger.info(fmt_snap("VM hosts:", "vm_hosts_count", "vm_hosts_latest"))
        logger.info(fmt_snap("VM detections:", "vm_detections_count", "vm_detections_latest"))
        logger.info(fmt_snap("Host tags:", "host_tags_count", "host_tags_latest"))
        logger.info(
            f"  {'Detection changes:':<18} "
            f"{stats.get('detection_changes_30d', 0):>9,}  (cumulative, last 30d)"
        )
        logger.info(
            f"  {'Refresh history:':<18} "
            f"{history['total']:>9,} runs · "
            f"{history['success']} success · "
            f"{history['partial']} partial · "
            f"{history['failed']} failed"
        )
        last_ok = stats.get("last_success")
        if last_ok:
            logger.info(
                f"  {'Last successful:':<18} {last_ok}  ({_friendly_age(last_ok)})"
            )
        else:
            logger.info(f"  {'Last successful:':<18} never")
        hb = stats.get("heartbeats", {})
        hb_latest = hb.get("latest") or {}
        if hb_latest:
            hb_status = "OK" if (
                hb_latest.get("vm_available") and hb_latest.get("csam_available")
            ) else "DEGRADED"
            logger.info(
                f"  {'Heartbeats:':<18} {hb.get('total', 0):>9,} rows · "
                f"last check: {_friendly_age(hb_latest.get('checked_at'))} ({hb_status})"
            )
        else:
            logger.info(f"  {'Heartbeats:':<18}         0 rows · awaiting first check")
        logger.info(f"  {'DB file size:':<18} {stats.get('db_size_mb', 0):>9.1f} MB")
    logger.info("=" * 60)


def _parse_cli_args(argv):
    """Parse server host/port flags. Returns (host_override, port_override, public)."""
    import argparse
    p = argparse.ArgumentParser(
        description="Qualys Data Analytics web server.",
        epilog="Default: binds to localhost only. Use --public to expose on LAN.",
    )
    p.add_argument(
        "--host",
        help="Bind address (e.g. 127.0.0.1, 0.0.0.0, 10.0.0.5). "
             "Overrides [server] host in config.",
    )
    p.add_argument(
        "--port",
        type=int,
        help="Listen port. Overrides [server] port in config.",
    )
    p.add_argument(
        "--public",
        action="store_true",
        help="Shortcut for --host 0.0.0.0 (bind to all interfaces; reachable "
             "from LAN by your machine's IP).",
    )
    return p.parse_args(argv)


if __name__ == "__main__":
    logger.info("Starting Qualys Data Analytics...")
    config = get_config()
    logger.info(f"Config loaded: {config}")

    args = _parse_cli_args(sys.argv[1:])

    # Resolve bind host: --public > --host > config > default
    if args.public:
        host = "0.0.0.0"
    elif args.host:
        host = args.host
    else:
        host = config.server_host
    port = args.port or config.server_port

    # Initialize scheduler
    init_scheduler()

    # Pre-initialize manager to create tables
    get_manager()
    logger.info("Database initialized")

    # ── "Look under the hood" startup banner ─────────────────────
    # Surfaces what's already in the DB the moment the app boots so the
    # operator can immediately see asset counts, refresh history, and
    # heartbeat status without navigating to /data-explorer or running
    # a SQL query. Mirrored by the navbar asset-count chip in the UI.
    _log_startup_banner()

    # Print reachable URL(s) so the user knows exactly where to point a browser.
    if host in ("0.0.0.0", "::"):
        lan = _lan_ip()
        logger.info("=" * 60)
        logger.info(f"Serving on ALL interfaces (port {port}):")
        logger.info(f"  Local:   http://localhost:{port}")
        logger.info(f"  LAN:     http://{lan}:{port}")
        logger.info("=" * 60)
    else:
        display = "localhost" if host in ("127.0.0.1", "localhost") else host
        logger.info("=" * 60)
        logger.info(f"Serving on http://{display}:{port}  (bound to {host})")
        logger.info("  Use --public to expose on LAN.")
        logger.info("=" * 60)

    app.run(
        host=host,
        port=port,
        debug=True,
        use_reloader=False  # Avoid double scheduler init
    )
