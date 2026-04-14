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
import logging
import threading
from datetime import datetime
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
    db = get_manager().db
    # Get all hosts, then filter out ones with an owner
    hosts = db.get_latest_vm_hosts(page=1, per_page=5000)
    unassigned = []
    for h in hosts:
        owner = db.get_asset_owner(h.get("ip_address", ""))
        if not owner:
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

if __name__ == "__main__":
    logger.info("Starting Qualys Data Analytics...")
    config = get_config()
    logger.info(f"Config loaded: {config}")

    # Initialize scheduler
    init_scheduler()

    # Pre-initialize manager to create tables
    get_manager()
    logger.info("Database initialized")

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True,
        use_reloader=False  # Avoid double scheduler init
    )
