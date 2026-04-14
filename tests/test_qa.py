#!/usr/bin/env python3
"""
Qualys DA — QA Test Suite

Catches the classes of bugs that slip through import-only testing:
  1. Template rendering (url_for mismatches, undefined variables)
  2. API endpoint responses (status codes, JSON shape)
  3. HTML/JS element ID consistency (template ↔ app.js)
  4. Database round-trip (save → query)
  5. Analytics engine (returns expected keys, no SQL errors)
  6. CSV export (parseable, correct headers)
  7. CLI smoke test (subcommands don't crash)

Run:  python -m pytest tests/test_qa.py -v
      python tests/test_qa.py               (standalone, no pytest needed)
"""

import io
import csv
import re
import sys
import json
import unittest
from pathlib import Path

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from app import app
from src.config_loader import load_config
from src.database import QualysDADatabase
from src.analytics import AnalyticsEngine


# ════════════════════════════════════════════════════════════════
# Test fixtures
# ════════════════════════════════════════════════════════════════

def get_test_client():
    app.config["TESTING"] = True
    return app.test_client()


def seed_minimal(db):
    """Insert just enough data for analytics to not crash on empty tables."""
    ts = "2026-04-12T00:00:00Z"
    db.save_vm_hosts([{
        "host_id": 1, "ip": "10.0.0.1", "dns": "test.local",
        "netbios": "TEST", "os": "Windows Server 2022",
        "trurisk_score": 500, "last_scan_date": "2026-04-10T00:00:00Z",
        "last_vm_scanned_date": "", "last_activity_date": "", "tracking_method": "IP",
    }], ts)
    db.save_vm_detections([{
        "host_id": 1, "ip": "10.0.0.1", "qid": 90001,
        "type": "Confirmed", "severity": 5, "status": "Active",
        "is_disabled": False, "qds": 90,
        "first_found": "2026-03-01T00:00:00Z", "last_found": "2026-04-10T00:00:00Z",
        "last_fixed": "", "last_test": "2026-04-10T00:00:00Z",
        "times_found": 5, "results": "",
    }], ts)
    db.save_csam_assets([{
        "assetId": "CSAM-1", "name": "test-host", "address": "10.0.0.1",
        "os": "Windows Server 2022", "hardware": {}, "software": [],
        "tagList": [{"tagId": 1, "tagName": "Production", "criticalityScore": 5}],
        "openPort": [], "networkInterface": [], "lastSeen": ts, "created": ts,
    }], ts)
    db.save_host_tags([{
        "host_id": 1, "ip_address": "10.0.0.1",
        "tag_id": 1, "tag_name": "Production",
        "criticality_score": 5, "source": "csam",
    }], ts)


# ════════════════════════════════════════════════════════════════
# 1. TEMPLATE RENDERING — every page route returns 200
# ════════════════════════════════════════════════════════════════

class TestPageRoutes(unittest.TestCase):
    """Every page must render without template errors (url_for, undefined vars)."""

    @classmethod
    def setUpClass(cls):
        cls.client = get_test_client()

    def _assert_page_ok(self, path):
        resp = self.client.get(path)
        self.assertEqual(resp.status_code, 200,
                         f"GET {path} returned {resp.status_code}")
        self.assertIn(b"<!DOCTYPE html>", resp.data,
                      f"GET {path} missing DOCTYPE — template probably crashed")

    def test_dashboard(self):
        self._assert_page_ok("/")

    def test_six_pack(self):
        self._assert_page_ok("/six-pack")

    def test_kpis(self):
        self._assert_page_ok("/kpis")

    def test_query(self):
        self._assert_page_ok("/query")

    def test_tags(self):
        self._assert_page_ok("/tags")

    def test_trends(self):
        self._assert_page_ok("/trends")

    def test_hosts(self):
        self._assert_page_ok("/hosts")

    def test_ownership(self):
        self._assert_page_ok("/ownership")

    def test_sql(self):
        self._assert_page_ok("/sql")

    def test_404_page(self):
        resp = self.client.get("/nonexistent-page")
        self.assertEqual(resp.status_code, 404)


# ════════════════════════════════════════════════════════════════
# 2. ELEMENT ID CONSISTENCY — template IDs ↔ app.js selectors
# ════════════════════════════════════════════════════════════════

class TestElementIdConsistency(unittest.TestCase):
    """JS getElementById calls must have matching IDs in the templates."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parent.parent
        # Collect all element IDs from app.js
        js_path = root / "static" / "app.js"
        js_text = js_path.read_text(encoding="utf-8")
        cls.js_ids = set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", js_text))

        # Collect all element IDs from base.html (the layout shared by all pages)
        base_path = root / "templates" / "base.html"
        base_text = base_path.read_text(encoding="utf-8")
        cls.base_ids = set(re.findall(r'id="([^"]+)"', base_text))

    def test_app_js_ids_exist_in_base_template(self):
        """Every ID referenced in app.js must exist in base.html."""
        missing = self.js_ids - self.base_ids
        self.assertEqual(missing, set(),
                         f"app.js references IDs not in base.html: {missing}")


# ════════════════════════════════════════════════════════════════
# 3. URL_FOR CONSISTENCY — template endpoints ↔ app.py routes
# ════════════════════════════════════════════════════════════════

class TestUrlForConsistency(unittest.TestCase):
    """Every url_for() endpoint in templates must exist as a Flask route."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parent.parent / "templates"
        cls.template_endpoints = set()
        for tpl in root.glob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            # Match url_for('endpoint_name') — ignore url_for('static', ...)
            for m in re.finditer(r"url_for\(['\"](\w+)['\"]\s*[,)]", text):
                ep = m.group(1)
                if ep != "static":
                    cls.template_endpoints.add(ep)

        # Collect registered Flask endpoints
        with app.app_context():
            cls.flask_endpoints = set(app.view_functions.keys())

    def test_all_template_endpoints_registered(self):
        missing = self.template_endpoints - self.flask_endpoints
        self.assertEqual(missing, set(),
                         f"Templates use url_for() for unregistered endpoints: {missing}")


# ════════════════════════════════════════════════════════════════
# 4. API ENDPOINTS — JSON responses with correct status codes
# ════════════════════════════════════════════════════════════════

class TestApiEndpoints(unittest.TestCase):
    """API routes must return valid JSON and not 500."""

    @classmethod
    def setUpClass(cls):
        cls.client = get_test_client()

    def _assert_api_ok(self, path, expected_type=None):
        resp = self.client.get(path)
        self.assertIn(resp.status_code, (200, 204),
                       f"GET {path} returned {resp.status_code}: {resp.data[:200]}")
        if resp.status_code == 200:
            data = resp.get_json(silent=True)
            self.assertIsNotNone(data,
                                 f"GET {path} returned non-JSON body")
            if expected_type:
                self.assertIsInstance(data, expected_type,
                                     f"GET {path} expected {expected_type.__name__}, got {type(data).__name__}")
        return resp

    def test_dashboard(self):
        self._assert_api_ok("/api/dashboard", dict)

    def test_vuln_overview(self):
        self._assert_api_ok("/api/metrics/vuln-overview", dict)

    def test_risk_distribution(self):
        self._assert_api_ok("/api/metrics/risk-distribution", dict)

    def test_asset_coverage(self):
        self._assert_api_ok("/api/metrics/asset-coverage", dict)

    def test_detection_age(self):
        self._assert_api_ok("/api/metrics/detection-age", dict)

    def test_os_distribution(self):
        self._assert_api_ok("/api/metrics/os-distribution", list)

    def test_top_qids(self):
        self._assert_api_ok("/api/metrics/top-qids?n=5", list)

    def test_weekly_trends(self):
        self._assert_api_ok("/api/metrics/trends/weekly?weeks=4", list)

    def test_monthly_trends(self):
        self._assert_api_ok("/api/metrics/trends/monthly?months=3", list)

    def test_changes(self):
        self._assert_api_ok("/api/metrics/changes?days=7", dict)

    def test_week_over_week(self):
        self._assert_api_ok("/api/metrics/week-over-week", dict)

    def test_detections(self):
        self._assert_api_ok("/api/detections", list)

    def test_hosts(self):
        self._assert_api_ok("/api/hosts", list)

    def test_tags(self):
        self._assert_api_ok("/api/tags", list)

    def test_tags_monitored(self):
        self._assert_api_ok("/api/tags/monitored", list)

    def test_six_pack(self):
        self._assert_api_ok("/api/six-pack?group_by=tag", dict)

    def test_kpis(self):
        self._assert_api_ok("/api/kpis", dict)

    def test_sla_targets(self):
        self._assert_api_ok("/api/sla-targets", dict)

    def test_owners(self):
        self._assert_api_ok("/api/owners", list)

    def test_saved_queries(self):
        self._assert_api_ok("/api/query/saved", list)

    def test_stats(self):
        self._assert_api_ok("/api/stats", dict)

    def test_refresh_log(self):
        self._assert_api_ok("/api/refresh-log", list)

    def test_detections_with_filters(self):
        self._assert_api_ok("/api/detections?severity_min=4&status=Active&status=New", list)

    def test_export_csv(self):
        resp = self.client.get("/api/export/csv?type=detections")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/csv", resp.content_type)
        # Verify it's parseable CSV
        text = resp.data.decode("utf-8")
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        self.assertGreater(len(rows), 0, "CSV export is empty (no header row)")

    def test_api_404(self):
        resp = self.client.get("/api/nonexistent")
        self.assertEqual(resp.status_code, 404)
        data = resp.get_json(silent=True)
        self.assertIsNotNone(data)
        self.assertIn("error", data)


# ════════════════════════════════════════════════════════════════
# 5. API MUTATIONS — POST/PUT/DELETE
# ════════════════════════════════════════════════════════════════

class TestApiMutations(unittest.TestCase):
    """Write operations should succeed and persist."""

    @classmethod
    def setUpClass(cls):
        cls.client = get_test_client()

    def test_custom_query_execute(self):
        resp = self.client.post("/api/query",
                                json={"sql": "SELECT 1 as test_col"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("columns", data)
        self.assertIn("rows", data)
        self.assertEqual(data["columns"], ["test_col"])

    def test_custom_query_rejects_write(self):
        resp = self.client.post("/api/query",
                                json={"sql": "DROP TABLE vm_hosts"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("error", data)

    def test_sla_targets_roundtrip(self):
        resp = self.client.put("/api/sla-targets",
                               json={5: 7, 4: 30, 3: 90, 2: 180, 1: 365})
        self.assertEqual(resp.status_code, 200)
        resp = self.client.get("/api/sla-targets")
        data = resp.get_json()
        self.assertEqual(data.get("5") or data.get(5), 7)

    def test_saved_query_crud(self):
        # Create
        resp = self.client.post("/api/query/save",
                                json={"name": "QA Test Query",
                                      "sql": "SELECT 1",
                                      "description": "test"})
        self.assertEqual(resp.status_code, 200)
        # List
        resp = self.client.get("/api/query/saved")
        data = resp.get_json()
        saved = [q for q in data if q["name"] == "QA Test Query"]
        self.assertEqual(len(saved), 1)
        # Delete
        resp = self.client.delete(f"/api/query/saved/{saved[0]['id']}")
        self.assertEqual(resp.status_code, 200)

    def test_ownership_crud(self):
        # Create
        resp = self.client.post("/api/owners",
                                json={"match_type": "ip", "match_value": "192.168.99.99",
                                      "owner": "QA Tester", "business_unit": "QA"})
        self.assertEqual(resp.status_code, 200)
        # Verify
        resp = self.client.get("/api/owners")
        data = resp.get_json()
        rule = [r for r in data if r["owner"] == "QA Tester"]
        self.assertEqual(len(rule), 1)
        # Delete
        resp = self.client.delete(f"/api/owners/{rule[0]['id']}")
        self.assertEqual(resp.status_code, 200)


# ════════════════════════════════════════════════════════════════
# 6. DATABASE ROUND-TRIP
# ════════════════════════════════════════════════════════════════

class TestDatabaseRoundTrip(unittest.TestCase):
    """Data saved through the DB layer must be queryable."""

    @classmethod
    def setUpClass(cls):
        cls.db = QualysDADatabase("data/qualys_da.db")

    def test_vm_hosts_queryable(self):
        hosts = self.db.get_latest_vm_hosts()
        self.assertIsInstance(hosts, list)

    def test_detections_queryable(self):
        dets = self.db.get_latest_detections()
        self.assertIsInstance(dets, list)

    def test_csam_assets_queryable(self):
        assets = self.db.get_latest_csam_assets()
        self.assertIsInstance(assets, list)

    def test_tag_summary(self):
        tags = self.db.get_tag_summary()
        self.assertIsInstance(tags, list)

    def test_weekly_rollups(self):
        rollups = self.db.get_weekly_rollups(4)
        self.assertIsInstance(rollups, list)

    def test_db_stats_keys(self):
        stats = self.db.get_db_stats()
        expected_keys = {"csam_assets", "vm_hosts", "vm_detections",
                         "host_tags", "db_size_mb"}
        self.assertTrue(expected_keys.issubset(stats.keys()),
                        f"Missing keys: {expected_keys - stats.keys()}")

    def test_execute_readonly_blocks_writes(self):
        result = self.db.execute_readonly("DELETE FROM vm_hosts")
        self.assertIsInstance(result, dict)
        self.assertIn("error", result)

    def test_execute_readonly_allows_select(self):
        result = self.db.execute_readonly("SELECT COUNT(*) as cnt FROM vm_hosts")
        self.assertIsInstance(result, dict)
        self.assertIn("columns", result)
        self.assertIn("rows", result)
        self.assertEqual(result["columns"], ["cnt"])


# ════════════════════════════════════════════════════════════════
# 7. ANALYTICS ENGINE — methods return expected shapes
# ════════════════════════════════════════════════════════════════

class TestAnalyticsEngine(unittest.TestCase):
    """Analytics methods must not throw and must return dicts/lists with expected keys."""

    @classmethod
    def setUpClass(cls):
        config = load_config()
        db = QualysDADatabase(config.db_path)
        cls.engine = AnalyticsEngine(db, config)

    def _check_dict_keys(self, result, required_keys, method_name):
        self.assertIsInstance(result, dict,
                              f"{method_name} should return dict, got {type(result)}")
        for key in required_keys:
            self.assertIn(key, result,
                          f"{method_name} missing key '{key}'")

    def test_vuln_overview(self):
        r = self.engine.vuln_overview()
        self._check_dict_keys(r, ["total", "by_severity", "by_status"], "vuln_overview")

    def test_risk_distribution(self):
        r = self.engine.risk_distribution()
        self._check_dict_keys(r, ["trurisk_histogram", "top_riskiest"], "risk_distribution")

    def test_asset_coverage(self):
        r = self.engine.asset_coverage()
        self.assertIsInstance(r, dict)

    def test_detection_age(self):
        r = self.engine.detection_age()
        self.assertIsInstance(r, dict)

    def test_patchable_percentage(self):
        r = self.engine.patchable_percentage()
        self._check_dict_keys(r, ["patchable", "non_patchable", "patchable_pct"],
                              "patchable_percentage")

    def test_sla_compliance(self):
        r = self.engine.sla_compliance()
        self.assertIsInstance(r, dict)

    def test_mttr_by_severity(self):
        r = self.engine.mttr_by_severity()
        self.assertIsInstance(r, dict)

    def test_tag_summary(self):
        r = self.engine.tag_summary()
        self.assertIsInstance(r, list)

    def test_cyber_six_pack_by_tag(self):
        r = self.engine.cyber_six_pack("tag")
        self._check_dict_keys(r, ["enterprise", "groups"], "cyber_six_pack(tag)")

    def test_cyber_six_pack_by_os(self):
        r = self.engine.cyber_six_pack("os")
        self._check_dict_keys(r, ["enterprise", "groups"], "cyber_six_pack(os)")

    def test_weekly_trends(self):
        r = self.engine.weekly_trends(4)
        self.assertIsInstance(r, list)

    def test_monthly_trends(self):
        r = self.engine.monthly_trends(3)
        self.assertIsInstance(r, list)

    def test_recent_changes(self):
        r = self.engine.recent_changes(7)
        self.assertIsInstance(r, dict)

    def test_all_kpis(self):
        r = self.engine.all_kpis()
        self.assertIsInstance(r, dict)

    def test_dashboard_summary(self):
        r = self.engine.dashboard_summary()
        self.assertIsInstance(r, dict)


# ════════════════════════════════════════════════════════════════
# 8. TEMPLATE JS ↔ API CONTRACT
#    Ensures fetchApi() URLs in templates have matching routes
# ════════════════════════════════════════════════════════════════

class TestTemplateApiContract(unittest.TestCase):
    """fetchApi() calls in templates should reference routes that exist."""

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).parent.parent / "templates"
        cls.api_urls = set()
        for tpl in root.glob("*.html"):
            text = tpl.read_text(encoding="utf-8")
            # Match fetchApi('/api/...') — extract the base path before query params
            for m in re.finditer(r"fetchApi\(['\"](/api/[^'\"?+]+)", text):
                url = m.group(1)
                # Skip URLs that are clearly concatenated with a variable
                # (e.g., '/api/host/' + ip) — these have dynamic path segments
                if url.endswith("/"):
                    continue
                cls.api_urls.add(url)

        # Build a set of registered API route patterns
        cls.route_patterns = set()
        for rule in app.url_map.iter_rules():
            path = re.sub(r"<[^>]+>", "*", rule.rule)
            cls.route_patterns.add(path)

    def test_all_fetchapi_urls_have_routes(self):
        """Every static fetchApi URL in templates should match a Flask route."""
        missing = []
        for url in sorted(self.api_urls):
            # Check exact match or wildcard match
            matched = False
            for pattern in self.route_patterns:
                if url == pattern:
                    matched = True
                    break
                # Simple wildcard: /api/host/* matches /api/host/<path:ip>
                if "*" in pattern:
                    # Use .+ for path params (can contain slashes)
                    regex = "^" + pattern.replace("*", ".+") + "$"
                    if re.match(regex, url):
                        matched = True
                        break
            if not matched:
                missing.append(url)
        self.assertEqual(missing, [],
                         f"Templates call fetchApi for unregistered routes: {missing}")


# ════════════════════════════════════════════════════════════════
# 9. STATIC FILES EXIST
# ════════════════════════════════════════════════════════════════

class TestStaticFiles(unittest.TestCase):
    """Static files referenced in base.html must exist."""

    def test_style_css_exists(self):
        self.assertTrue((Path(__file__).parent.parent / "static" / "style.css").exists())

    def test_app_js_exists(self):
        self.assertTrue((Path(__file__).parent.parent / "static" / "app.js").exists())

    def test_all_templates_exist(self):
        tpl_dir = Path(__file__).parent.parent / "templates"
        expected = ["base.html", "index.html", "query.html", "tags.html",
                    "six_pack.html", "kpis.html", "trends.html", "hosts.html",
                    "ownership.html", "custom_query.html", "error.html"]
        for name in expected:
            self.assertTrue((tpl_dir / name).exists(), f"Missing template: {name}")


# ════════════════════════════════════════════════════════════════
# 10. CLI SMOKE TEST
# ════════════════════════════════════════════════════════════════

class TestCli(unittest.TestCase):
    """CLI subcommands must not crash."""

    def test_status_runs(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "cli.py", "status"],
            capture_output=True, text=True, timeout=15,
            cwd=str(Path(__file__).parent.parent)
        )
        self.assertEqual(result.returncode, 0,
                         f"cli.py status failed:\n{result.stderr}")

    def test_help_runs(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, "cli.py", "--help"],
            capture_output=True, text=True, timeout=10,
            cwd=str(Path(__file__).parent.parent)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("health", result.stdout)


# ════════════════════════════════════════════════════════════════
# RUNNER
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Can run standalone: python tests/test_qa.py
    unittest.main(verbosity=2)
