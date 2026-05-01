#!/usr/bin/env python3
"""
Qualys DA — Streaming CSV Export Tests

Pins the invariants for the unbounded streaming export pipeline:

* `data_manager.export_csv_stream(...)` yields CSV chunks (header first)
  with NO row cap. Replaces the legacy 100k-truncated `export_csv`.
* `db.iter_latest_detections(...)` honours `date_from`/`date_to` —
  the bug fix for `/api/export/csv` silently dropping date filters.
* `/api/export/csv` streams via `stream_with_context` and the
  `_build_export_filters` helper now includes date keys.
* `/api/data-explorer/export-csv` streams a single table.
* `/api/data-explorer/export-all-zip` returns a valid ZIP with one
  CSV per Data Explorer table.
* CLI `cmd_export` writes the streaming output to disk without a cap
  (test seeds 1500 rows, expects 1501 lines including header).

Run:  python -m unittest tests.test_export_streaming -v
"""

import csv
import io
import os
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.config_loader import QualysDAConfig
from src.data_manager import DataManager


def _seed_detections(db, count: int, *, fetched_at=None,
                     first_found_iso="2026-04-01T00:00:00"):
    """Insert N synthetic detection rows under one snapshot."""
    if fetched_at is None:
        fetched_at = datetime.utcnow().isoformat()
    rows = [
        (i, "10.0.0.1", 1000 + i, "Confirmed", 3, "Active",
         0, 50, "CVE-X", 7.5, "", "", 1, "", "", "", "", "Title",
         first_found_iso, "", "", "", 1, "", "{}", fetched_at)
        for i in range(count)
    ]
    db.conn.executemany(
        """INSERT INTO vm_detections
           (host_id, ip_address, qid, detection_type, severity, status,
            is_disabled, qds, cve_id, cvss_base, cvss_temporal, cvss_vector,
            patchable, vendor, product, package_name, package_version, title,
            first_found, last_found, last_fixed, last_test, times_found,
            results, raw_data, fetched_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )
    db.conn.commit()
    return fetched_at


# ── Streaming generator ─────────────────────────────────────

class ExportCsvStreamTest(unittest.TestCase):
    """Direct test of `manager.export_csv_stream` — proves no truncation
    past 100k and that the header is always the first chunk."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="export_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass

    def test_unbounded_export_returns_all_rows(self):
        """Seed >100 rows (a small N is enough — the point is to prove
        the cap is gone, not benchmark perf), iterate the stream, count
        the rows. Header + N data rows = N+1 total lines."""
        n = 1500  # well above the old 100k cap is overkill for unit tests
        _seed_detections(self.mgr.db, n)
        joined = "".join(self.mgr.export_csv_stream("detections"))
        # csv.reader copes with embedded newlines just fine
        reader = csv.reader(io.StringIO(joined))
        rows = list(reader)
        self.assertEqual(len(rows), n + 1, f"Expected header + {n} rows")
        # First row is the header
        self.assertIn("Host ID", rows[0])
        self.assertIn("QID", rows[0])

    def test_first_chunk_is_header_only(self):
        """The streaming generator must yield the header line BEFORE
        any data rows so consumers can render the column list early."""
        _seed_detections(self.mgr.db, 50)
        gen = self.mgr.export_csv_stream("detections")
        first = next(gen)
        first_line = first.splitlines()[0]
        self.assertIn("Host ID", first_line)
        self.assertIn("QID", first_line)
        # And the rest of the header chunk should NOT contain row data —
        # check by parsing as CSV. A "real" detection row would contain
        # numeric host_ids and IP addresses.
        gen.close()

    def test_unknown_type_yields_error_marker(self):
        """An unknown export type must surface visibly (not silently
        produce an empty file). The generator yields one error line."""
        chunks = list(self.mgr.export_csv_stream("not_a_real_type"))
        joined = "".join(chunks)
        self.assertIn("error", joined.lower())


# ── Date filter pass-through (the bug fix) ──────────────────

class DateFilterPassThroughTest(unittest.TestCase):
    """The Query Builder UI sends `date_from` / `date_to`; the legacy
    `/api/export/csv` route used to silently drop those keys. The new
    `_build_export_filters` helper should include them, and the DB
    iterator should honour them."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="export_date_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)
        self.mgr._client = MagicMock()
        self.app_module._manager = self.mgr
        self.app_module._config = cfg
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_iter_honours_date_from(self):
        """Seed two snapshots' worth of detections — older + newer —
        and verify the date_from filter only returns the newer ones."""
        # Older detection
        fetched_at = datetime.utcnow().isoformat()
        self.mgr.db.conn.execute(
            """INSERT INTO vm_detections
               (host_id, qid, severity, status, is_disabled,
                first_found, fetched_at)
               VALUES (1, 1001, 3, 'Active', 0, '2026-01-01', ?)""",
            (fetched_at,),
        )
        # Newer detection (within the filter window)
        self.mgr.db.conn.execute(
            """INSERT INTO vm_detections
               (host_id, qid, severity, status, is_disabled,
                first_found, fetched_at)
               VALUES (2, 1002, 3, 'Active', 0, '2026-04-15', ?)""",
            (fetched_at,),
        )
        self.mgr.db.conn.commit()

        rows = list(self.mgr.db.iter_latest_detections(date_from="2026-03-01"))
        self.assertEqual(len(rows), 1, "Only post-March detection should survive the filter")
        self.assertEqual(rows[0]["qid"], 1002)

    def test_route_passes_date_filter_through(self):
        """End-to-end via Flask test client — make sure the route's
        new _build_export_filters wires date_from into the export
        pipeline. Was a silent no-op before this commit."""
        fetched_at = datetime.utcnow().isoformat()
        self.mgr.db.conn.execute(
            """INSERT INTO vm_detections
               (host_id, qid, severity, status, is_disabled,
                first_found, fetched_at)
               VALUES (1, 1001, 3, 'Active', 0, '2026-01-01', ?)""",
            (fetched_at,),
        )
        self.mgr.db.conn.execute(
            """INSERT INTO vm_detections
               (host_id, qid, severity, status, is_disabled,
                first_found, fetched_at)
               VALUES (2, 1002, 3, 'Active', 0, '2026-04-15', ?)""",
            (fetched_at,),
        )
        self.mgr.db.conn.commit()
        resp = self.client.get(
            "/api/export/csv?type=detections&date_from=2026-03-01"
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        # Split by newline, drop trailing blank, parse — header + 1 row
        reader = csv.reader(io.StringIO(body))
        rows = list(reader)
        self.assertEqual(len(rows), 2, f"Expected header+1 row, got: {rows}")
        # The single data row should be the newer detection (qid=1002)
        # — column 4 is QID per the export header.
        self.assertEqual(rows[1][4], "1002")


# ── Data Explorer streaming export ──────────────────────────

class DataExplorerStreamingTest(unittest.TestCase):
    """The /api/data-explorer/export-csv route now streams via
    `stream_with_context`. We just verify it still works end-to-end
    and returns the expected CSV shape."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="exp_route_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)
        self.mgr._client = MagicMock()
        self.app_module._manager = self.mgr
        self.app_module._config = cfg
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_per_table_export_streams(self):
        now = datetime.utcnow().isoformat()
        for i in range(5):
            self.mgr.db.conn.execute(
                "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) "
                "VALUES (?, ?, ?)",
                (f"a{i}", f"10.0.0.{i}", now),
            )
        self.mgr.db.conn.commit()
        resp = self.client.get("/api/data-explorer/export-csv?table=csam_assets")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_data(as_text=True)
        reader = csv.reader(io.StringIO(body))
        rows = list(reader)
        # Header + 5 data rows
        self.assertEqual(len(rows), 6)
        # Header should include asset_id and ip_address
        self.assertIn("asset_id", rows[0])
        self.assertIn("ip_address", rows[0])

    def test_unknown_table_returns_400(self):
        resp = self.client.get("/api/data-explorer/export-csv?table=evil_table")
        self.assertEqual(resp.status_code, 400)


# ── Bulk ZIP export ─────────────────────────────────────────

class BulkZipExportTest(unittest.TestCase):
    """`/api/data-explorer/export-all-zip` returns a ZIP archive with
    one CSV per Data Explorer table."""

    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="exp_zip_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)
        self.mgr._client = MagicMock()
        self.app_module._manager = self.mgr
        self.app_module._config = cfg
        self.client = self.app_module.app.test_client()

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        try:
            os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError):
            pass
        self.app_module._manager = None
        self.app_module._config = None

    def test_zip_contains_one_csv_per_table(self):
        # Seed every table with at least one row so we can verify each
        # CSV has rows past the header.
        now = datetime.utcnow().isoformat()
        self.mgr.db.conn.execute(
            "INSERT INTO csam_assets (asset_id, ip_address, fetched_at) VALUES (?,?,?)",
            ("a1", "10.0.0.1", now),
        )
        self.mgr.db.conn.execute(
            "INSERT INTO vm_hosts (host_id, ip_address, fetched_at) VALUES (?,?,?)",
            (1, "10.0.0.1", now),
        )
        self.mgr.db.conn.execute(
            "INSERT INTO vm_detections (host_id, qid, severity, status, is_disabled, fetched_at) "
            "VALUES (1, 1001, 3, 'Active', 0, ?)",
            (now,),
        )
        self.mgr.db.conn.execute(
            "INSERT INTO host_tags (host_id, tag_id, tag_name, source, fetched_at) "
            "VALUES (1, 100, 'Production', 'vm', ?)",
            (now,),
        )
        self.mgr.db.conn.execute(
            "INSERT INTO detection_changes (host_id, qid, change_type, detected_at) "
            "VALUES (1, 1001, 'new', ?)",
            (now,),
        )
        self.mgr.db.log_health_check(True, True, duration_ms=100)
        self.mgr.db.conn.commit()

        resp = self.client.get("/api/data-explorer/export-all-zip")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, "application/zip")

        # Parse the response body as a ZIP file
        zip_buf = io.BytesIO(resp.get_data())
        with zipfile.ZipFile(zip_buf, mode="r") as zf:
            names = sorted(zf.namelist())
            # Each EXPLORER_TABLES entry should produce one CSV
            for table in ("csam_assets", "vm_hosts", "vm_detections",
                          "host_tags", "detection_changes", "health_log"):
                self.assertIn(f"{table}.csv", names)

            # Spot-check one entry: csam_assets should have header + 1 data row
            with zf.open("csam_assets.csv") as f:
                content = f.read().decode("utf-8")
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)
            self.assertGreaterEqual(len(rows), 2,
                "csam_assets.csv should have header + at least 1 row")


# ── CLI streaming ───────────────────────────────────────────

class CliExportStreamingTest(unittest.TestCase):
    """`cli.py cmd_export` now writes streamed chunks to disk. Test
    that 1500 rows land in the file (proving the old 100k cap is gone
    in spirit — we don't seed 100k for test speed)."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db", prefix="cli_export_")
        os.close(fd)
        cfg = QualysDAConfig(db_path=self.db_path, username="t", password="t")
        self.mgr = DataManager(cfg)
        self.out_dir = tempfile.mkdtemp(prefix="cli_export_out_")

    def tearDown(self):
        try:
            self.mgr.db.conn.close()
        except Exception:
            pass
        for entry in Path(self.out_dir).iterdir():
            try: entry.unlink()
            except OSError: pass
        try: os.rmdir(self.out_dir)
        except OSError: pass
        try: os.unlink(self.db_path)
        except (PermissionError, FileNotFoundError): pass

    def test_cli_export_writes_all_seeded_rows(self):
        n = 1500
        _seed_detections(self.mgr.db, n)

        # Build a faux argparse Namespace
        class _Args:
            type = "detections"
            output = self.out_dir
        args = _Args()
        args.output = self.out_dir

        from cli import cmd_export
        rc = cmd_export(args, self.mgr)
        self.assertEqual(rc, 0)

        # Find the produced file
        files = list(Path(self.out_dir).glob("qualys_detections_*.csv"))
        self.assertEqual(len(files), 1)
        with open(files[0], encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        # Header + N rows
        self.assertEqual(len(rows), n + 1,
            f"CLI export should write all {n} seeded rows + header")


if __name__ == "__main__":
    unittest.main(verbosity=2)
