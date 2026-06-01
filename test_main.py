import asyncio
import json
import sqlite3
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

import main
from lazy_dorking import shared
from lazy_dorking.bac import scanner as bac_scanner
from lazy_dorking.cred import scanner as cred_scanner


class BlhHunterTests(unittest.TestCase):
    def setUp(self):
        self._old_db_path = main.DB_PATH
        self._db_file = Path(__file__).resolve().parent / f".test_blh_hunter_{uuid.uuid4().hex}.db"
        main.DB_PATH = str(self._db_file)
        main._running_scans.clear()
        main._paused_scans.clear()
        main._deleted_scans.clear()
        main.init_db()

    def tearDown(self):
        main._running_scans.clear()
        main._paused_scans.clear()
        main._deleted_scans.clear()
        main.DB_PATH = self._old_db_path
        if self._db_file.exists():
            self._db_file.unlink()

    def insert_scan(self, scan_id="scan-1", status="pending", platforms=None):
        platforms = platforms or ["facebook"]
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO scans (id, domain, platforms, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, "example.com", json.dumps(platforms), status, "2026-05-05T00:00:00"),
        )
        con.commit()
        con.close()
        return scan_id

    def test_account_urls_accept_common_www_and_slug_forms(self):
        self.assertFalse(main.is_non_account_url("https://www.instagram.com/foo.bar/"))
        self.assertFalse(main.is_non_account_url("https://www.facebook.com/NASA.Page/"))
        self.assertFalse(main.is_non_account_url("https://github.com/foo-bar/"))

    def test_social_share_and_reserved_urls_are_rejected(self):
        self.assertTrue(main.is_non_account_url("https://twitter.com/home?status=https://www.nasa.gov/specials/apollo50th/index.h"))
        self.assertTrue(main.is_non_account_url("https://twitter.com/home"))
        self.assertTrue(main.is_non_account_url("https://facebook.com/sharer.php"))
        self.assertTrue(main.is_non_account_url("https://x.com/intent/tweet"))
        self.assertTrue(main.is_non_account_url("https://youtube.com/watch?v=abc123"))
        self.assertFalse(main.is_non_account_url("https://twitter.com/NASAAmes"))
        self.assertFalse(main.is_non_account_url("https://facebook.com/NASA.Page"))

    def test_cancelled_status_sets_finished_at(self):
        scan_id = self.insert_scan(status="running")

        main.update_scan_status(scan_id, "cancelled")

        con = sqlite3.connect(main.DB_PATH)
        row = con.execute("SELECT status, finished_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        con.close()
        self.assertEqual(row[0], "cancelled")
        self.assertIsNotNone(row[1])

    def test_stop_scan_cancels_stale_running_scan(self):
        scan_id = self.insert_scan(status="running")

        payload = asyncio.run(main.stop_scan(scan_id))

        self.assertEqual(payload["status"], "cancelled")
        con = sqlite3.connect(main.DB_PATH)
        row = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
        con.close()
        self.assertEqual(row[0], "cancelled")

    def test_facebook_error_page_is_broken_even_with_http_200(self):
        class Response:
            status_code = 200
            text = '"title":"Konten Ini Tidak Tersedia Saat Ini","canonicalRouteName":"comet.fbweb.CometErrorRoute"'

        self.assertTrue(main.is_facebook_account_not_found(Response(), "www.facebook.com"))

    def test_delete_scan_removes_scan_results_and_logs(self):
        scan_id = self.insert_scan(status="done")
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            """
            INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text,
                status, http_code, final_url, error_reason, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                "facebook",
                "https://old.example.com/contact",
                "https://www.facebook.com/NASA.Page/",
                "NASA",
                "alive",
                200,
                "https://www.facebook.com/NASA.Page/",
                "",
                "2026-05-05T00:00:01",
            ),
        )
        con.execute(
            "INSERT INTO scan_log (scan_id, message, created_at) VALUES (?, ?, ?)",
            (scan_id, "hello", "2026-05-05T00:00:02"),
        )
        con.commit()
        con.close()

        main._write_crawl_page(scan_id, "https://old.example.com/contact", "https://old.example.com/contact", "success")

        payload = asyncio.run(main.delete_scan(scan_id))

        self.assertEqual(payload["status"], "deleted")
        con = sqlite3.connect(main.DB_PATH)
        counts = (
            con.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan_id,)).fetchone()[0],
            con.execute("SELECT COUNT(*) FROM results WHERE scan_id=?", (scan_id,)).fetchone()[0],
            con.execute("SELECT COUNT(*) FROM scan_log WHERE scan_id=?", (scan_id,)).fetchone()[0],
            con.execute("SELECT COUNT(*) FROM crawl_pages WHERE scan_id=?", (scan_id,)).fetchone()[0],
        )
        con.close()
        self.assertEqual(counts, (0, 0, 0, 0))

    def test_delete_scan_removes_crawl_pages(self):
        scan_id = self.insert_scan(status="done")
        main._write_crawl_page(scan_id, "https://example.com/page1", "https://example.com/page1", "success")
        main._write_crawl_page(scan_id, "https://example.com/page2", "https://example.com/page2", "skipped")

        asyncio.run(main.delete_scan(scan_id))

        con = sqlite3.connect(main.DB_PATH)
        count = con.execute("SELECT COUNT(*) FROM crawl_pages WHERE scan_id=?", (scan_id,)).fetchone()[0]
        con.close()
        self.assertEqual(count, 0)

    def test_known_source_urls_reads_from_crawl_pages_for_same_platform(self):
        scan_id = self.insert_scan(status="done")
        main._write_crawl_page(scan_id, "https://example.com/contact", "https://example.com/contact", "success")
        main._write_crawl_page(scan_id, "https://example.com/about", "https://example.com/about", "skipped")

        known = main.get_known_source_urls("example.com", ["facebook"])
        self.assertIn(main.canonical_url("https://example.com/contact"), known)
        self.assertIn(main.canonical_url("https://example.com/about"), known)

    def test_known_source_urls_does_not_skip_source_seen_for_other_platform(self):
        scan_id = self.insert_scan("scan-instagram", status="done", platforms=["instagram"])
        main._write_crawl_page(scan_id, "https://example.com/contact", "https://example.com/contact", "success")

        known = main.get_known_source_urls("example.com", ["facebook"])

        self.assertNotIn(main.canonical_url("https://example.com/contact"), known)

    def test_known_source_urls_requires_all_selected_platforms_covered(self):
        facebook_scan = self.insert_scan("scan-facebook", status="done", platforms=["facebook"])
        main._write_crawl_page(facebook_scan, "https://example.com/contact", "https://example.com/contact", "success")

        known_for_facebook = main.get_known_source_urls("example.com", ["facebook"])
        known_for_facebook_and_instagram = main.get_known_source_urls("example.com", ["facebook", "instagram"])

        self.assertIn(main.canonical_url("https://example.com/contact"), known_for_facebook)
        self.assertNotIn(main.canonical_url("https://example.com/contact"), known_for_facebook_and_instagram)

    def test_crawl_pages_schema_migration_backfills_platforms_from_scan(self):
        con = sqlite3.connect(main.DB_PATH)
        con.execute("DROP TABLE crawl_pages")
        con.execute(
            """
            CREATE TABLE crawl_pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                domain TEXT,
                source_url TEXT NOT NULL,
                canonical_source_url TEXT,
                final_url TEXT,
                crawl_status TEXT NOT NULL,
                http_code INTEGER,
                error_reason TEXT,
                platform_hits INTEGER DEFAULT 0,
                account_hits INTEGER DEFAULT 0,
                crawled_at TEXT NOT NULL
            )
            """
        )
        con.execute(
            "INSERT INTO crawl_pages (scan_id, domain, source_url, canonical_source_url, final_url, crawl_status, crawled_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "scan-legacy",
                "example.com",
                "https://example.com/contact",
                main.canonical_url("https://example.com/contact"),
                "https://example.com/contact",
                "success",
                "2026-05-05T00:00:01",
            ),
        )
        con.execute(
            "INSERT INTO scans (id, domain, platforms, status, created_at) VALUES (?, ?, ?, ?, ?)",
            ("scan-legacy", "example.com", json.dumps(["facebook", "instagram"]), "done", "2026-05-05T00:00:00"),
        )
        con.commit()
        con.close()

        main.init_db()

        con = sqlite3.connect(main.DB_PATH)
        columns = {row[1] for row in con.execute("PRAGMA table_info(crawl_pages)").fetchall()}
        platforms_key = con.execute("SELECT platforms_key FROM crawl_pages WHERE scan_id=?", ("scan-legacy",)).fetchone()[0]
        con.close()
        self.assertIn("platforms_key", columns)
        self.assertEqual(platforms_key, "facebook,instagram")

    def test_seen_target_urls_prevents_recollection(self):
        scan_id = self.insert_scan(status="done")
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, "twitter", "https://example.com", "https://x.com/NASA", "NASA", "alive", 200, "https://x.com/NASA", "", "2026-05-05T00:00:01"),
        )
        con.commit()
        con.close()

        seen = main.get_seen_target_urls()
        self.assertIn(main.canonical_target_url("https://x.com/NASA"), seen)
        self.assertIn(main.canonical_target_url("https://www.x.com/NASA/"), seen)

    def test_blh_results_include_id_and_allow_manual_status_update(self):
        scan_id = self.insert_scan(status="done")
        con = sqlite3.connect(main.DB_PATH)
        cur = con.execute(
            "INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                "instagram",
                "https://example.com",
                "https://instagram.com/example",
                "Instagram",
                "alive",
                200,
                "https://instagram.com/example",
                "",
                "2026-05-05T00:00:01",
            ),
        )
        result_id = cur.lastrowid
        con.commit()
        con.close()
        client = TestClient(main.app)

        listed = client.get(f"/api/blh/scans/{scan_id}/results")
        updated = client.patch(f"/api/blh/results/{result_id}/status", json={"status": "broken"})
        listed_again = client.get(f"/api/blh/scans/{scan_id}/results")

        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.json()[0]["id"], result_id)
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "broken")
        self.assertEqual(listed_again.json()[0]["status"], "broken")

    def test_blh_can_pause_and_continue_active_scan(self):
        scan_id = self.insert_scan(status="running")
        main.blh_api._running_scans[scan_id] = asyncio.Event()
        main.blh_api._paused_scans[scan_id] = asyncio.Event()

        paused = asyncio.run(main.blh_api.pause_scan(scan_id))
        continued = asyncio.run(main.blh_api.continue_scan(scan_id))

        con = sqlite3.connect(main.DB_PATH)
        status = con.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()[0]
        con.close()
        self.assertEqual(paused["status"], "paused")
        self.assertEqual(continued["status"], "running")
        self.assertFalse(main.blh_api._paused_scans[scan_id].is_set())
        self.assertEqual(status, "running")

    def test_blh_pending_result_can_be_saved_and_updated_realtime(self):
        scan_id = self.insert_scan(status="running", platforms=["instagram"])
        link = {
            "source_url": "https://example.com/about",
            "target_url": "https://instagram.com/example",
            "anchor_text": "Instagram",
            "platform_domain": "instagram.com",
        }

        main.blh_scanner.save_pending_result(scan_id, link, ["instagram"])
        pending = TestClient(main.app).get(f"/api/blh/scans/{scan_id}/results").json()[0]
        main.blh_scanner.update_saved_result(
            scan_id,
            link,
            {
                "status": "alive",
                "http_code": 200,
                "final_url": "https://instagram.com/example",
                "error_reason": "",
            },
            ["instagram"],
        )
        updated = TestClient(main.app).get(f"/api/blh/scans/{scan_id}/results").json()[0]

        self.assertEqual(pending["status"], "pending")
        self.assertIsNone(pending["http_code"])
        self.assertEqual(updated["status"], "alive")
        self.assertEqual(updated["http_code"], 200)

    def test_manual_status_override_is_not_replaced_by_later_checker_result(self):
        scan_id = self.insert_scan(status="running", platforms=["instagram"])
        link = {
            "source_url": "https://example.com/about",
            "target_url": "https://instagram.com/example",
            "anchor_text": "Instagram",
            "platform_domain": "instagram.com",
        }
        result_id = main.blh_scanner.save_pending_result(scan_id, link, ["instagram"])
        client = TestClient(main.app)

        override = client.patch(f"/api/blh/results/{result_id}/status", json={"status": "broken"})
        main.blh_scanner.update_saved_result(
            scan_id,
            link,
            {
                "status": "alive",
                "http_code": 200,
                "final_url": "https://instagram.com/example",
                "error_reason": "",
            },
            ["instagram"],
        )
        listed = client.get(f"/api/blh/scans/{scan_id}/results").json()[0]

        self.assertEqual(override.status_code, 200)
        self.assertEqual(listed["status"], "broken")
        self.assertEqual(listed["http_code"], 200)

    def test_target_with_query_or_extra_path_rejected(self):
        self.assertTrue(main.is_non_account_url("https://x.com/NASA/status/123"))
        self.assertTrue(main.is_non_account_url("https://x.com/intent/tweet?url=abc"))
        self.assertTrue(main.is_non_account_url("https://youtube.com/watch?v=abc123"))
        self.assertTrue(main.is_non_account_url("https://facebook.com/sharer.php?u=abc"))
        self.assertFalse(main.is_non_account_url("https://x.com/NASA"))
        self.assertFalse(main.is_non_account_url("https://instagram.com/nasa"))

    def test_youtube_targets_require_at_handle(self):
        self.assertFalse(main.is_non_account_url("https://www.youtube.com/@NASA"))
        self.assertFalse(main.is_non_account_url("https://youtube.com/@NASA"))
        self.assertTrue(main.is_non_account_url("https://youtube.com/NASA"))
        self.assertTrue(main.is_non_account_url("https://youtube.com/channel/UC123"))
        self.assertTrue(main.is_non_account_url("https://youtu.be/Zpgw_BN9pCY"))

    def test_linkedin_targets_require_in_profile(self):
        self.assertFalse(main.is_non_account_url("https://www.linkedin.com/in/hmatt28/"))
        self.assertTrue(main.is_non_account_url("https://www.linkedin.com/company/nasa/"))
        self.assertTrue(main.is_non_account_url("https://www.linkedin.com/school/example/"))

    def test_bitly_and_flickr_targets_are_supported(self):
        self.assertIn("bitly", main.blh_scanner.PLATFORM_DOMAINS)
        self.assertIn("flickr", main.blh_scanner.PLATFORM_DOMAINS)
        self.assertFalse(main.is_non_account_url("https://bit.ly/nasa"))
        self.assertFalse(main.is_non_account_url("https://www.flickr.com/photos/nasa/"))
        self.assertTrue(main.is_non_account_url("https://www.flickr.com/photos/nasa/123456789"))

    def test_host_balanced_frontier_groups_by_hostname(self):
        seeds = [
            "https://www.nasa.gov/page1",
            "https://www.nasa.gov/page2",
            "https://science.nasa.gov/page1",
            "https://www.nasa.gov/page3",
            "https://science.nasa.gov/page2",
        ]
        host_queues = {}
        host_order = []
        for url in seeds:
            host = main.urlparse(url).hostname.lower()
            if host not in host_queues:
                host_queues[host] = []
                host_order.append(host)
            host_queues[host].append(url)

        self.assertEqual(len(host_order), 2)
        self.assertEqual(len(host_queues["www.nasa.gov"]), 3)
        self.assertEqual(len(host_queues["science.nasa.gov"]), 2)

    def test_deleted_scan_blocks_late_writes(self):
        scan_id = self.insert_scan(status="running")

        asyncio.run(main.delete_scan(scan_id))
        main.log_scan(scan_id, "late log")

        con = sqlite3.connect(main.DB_PATH)
        counts = (
            con.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan_id,)).fetchone()[0],
            con.execute("SELECT COUNT(*) FROM scan_log WHERE scan_id=?", (scan_id,)).fetchone()[0],
        )
        con.close()
        self.assertEqual(counts, (0, 0))

    def test_init_db_creates_lazy_dorking_feature_tables(self):
        con = sqlite3.connect(main.DB_PATH)
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        con.close()

        self.assertIn("bac_scans", tables)
        self.assertIn("bac_results", tables)
        self.assertIn("bac_scan_log", tables)
        self.assertIn("bac_crawl_pages", tables)
        self.assertIn("cred_scans", tables)
        self.assertIn("cred_results", tables)
        self.assertIn("cred_scan_log", tables)
        self.assertIn("cred_crawl_pages", tables)

    def test_feature_crawl_page_writer_uses_bac_services_column(self):
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO bac_scans (id, domain, services, status, created_at) VALUES (?, ?, ?, ?, ?)",
            ("bac-1", "example.com", json.dumps(["google_drive", "github"]), "running", "2026-05-05T00:00:00"),
        )
        con.commit()
        con.close()

        main.db._write_crawl_page(
            "bac-1",
            "https://example.com/resources",
            "https://example.com/resources",
            "success",
            crawl_table="bac_crawl_pages",
            scans_table="bac_scans",
            platforms_key_fn=bac_scanner.services_key,
            load_platforms_fn=bac_scanner.load_services_json,
        )

        con = sqlite3.connect(main.DB_PATH)
        row = con.execute(
            "SELECT domain, platforms_key FROM bac_crawl_pages WHERE scan_id=?",
            ("bac-1",),
        ).fetchone()
        con.close()
        self.assertEqual(row, ("example.com", "github,google_drive"))

    def test_feature_crawl_page_writer_uses_cred_categories_column(self):
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO cred_scans (id, domain, categories, status, created_at) VALUES (?, ?, ?, ?, ?)",
            ("cred-1", "example.com", json.dumps(["config", "logs"]), "running", "2026-05-05T00:00:00"),
        )
        con.commit()
        con.close()

        main.db._write_crawl_page(
            "cred-1",
            "https://example.com/about",
            "https://example.com/about",
            "success",
            crawl_table="cred_crawl_pages",
            scans_table="cred_scans",
            platforms_key_fn=cred_scanner.categories_key,
            load_platforms_fn=cred_scanner.load_categories_json,
        )

        con = sqlite3.connect(main.DB_PATH)
        row = con.execute(
            "SELECT domain, platforms_key FROM cred_crawl_pages WHERE scan_id=?",
            ("cred-1",),
        ).fetchone()
        con.close()
        self.assertEqual(row, ("example.com", "config,logs"))

    def test_bac_extract_targets_collects_selected_services(self):
        selected_domains = []
        for service in ("google_drive", "github"):
            selected_domains.extend(bac_scanner.BAC_SERVICES[service])

        links, stats = bac_scanner.bac_extract_targets(
            [
                ("https://drive.google.com/drive/folders/abc123", "Drive folder"),
                ("https://github.com/example/project", "Repo"),
                ("https://example.com/internal", "Internal"),
            ],
            "https://example.com/resources",
            selected_domains,
            set(),
            set(),
        )

        self.assertEqual(stats["platform_hits"], 2)
        self.assertEqual([link["anchor_text"] for link in links], ["Drive folder", "Repo"])

    def test_bac_google_drive_requires_drive_path_without_sharing(self):
        links, stats = bac_scanner.bac_extract_targets(
            [
                ("https://drive.google.com/drive/folders/abc123", "Drive folder"),
                ("https://drive.google.com/drive/u/0/folders/def456", "Drive workspace"),
                ("https://drive.google.com/file/d/abc123/view", "Shared file"),
                ("https://drive.google.com/drive/folders/abc123?sharing=1", "Sharing param"),
                ("https://drive.google.com/drive/sharing/abc123", "Sharing path"),
            ],
            "https://example.com/resources",
            bac_scanner.BAC_SERVICES["google_drive"],
            set(),
            set(),
        )

        self.assertEqual(stats["platform_hits"], 2)
        self.assertEqual([link["anchor_text"] for link in links], ["Drive folder", "Drive workspace"])

    def test_cred_sensitive_url_matching_stays_in_scope(self):
        match = cred_scanner.match_sensitive_url(
            "https://static.example.com/.env.production",
            "example.com",
            ["config"],
        )
        external = cred_scanner.match_sensitive_url(
            "https://evil.test/.env",
            "example.com",
            ["config"],
        )

        self.assertEqual(match["file_type"], "config")
        self.assertIsNone(external)

    def test_dashboard_stats_summarize_feature_usage_and_recent_scans(self):
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO scans (id, domain, platforms, status, created_at, finished_at, total_sources, total_links) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "blh-old",
                "example.com",
                json.dumps(["twitter", "github"]),
                "done",
                "2026-05-05T01:00:00",
                "2026-05-05T01:05:00",
                7,
                2,
            ),
        )
        con.execute(
            "INSERT INTO scans (id, domain, platforms, status, created_at, finished_at, total_sources, total_links) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "blh-new",
                "nasa.gov",
                json.dumps(["twitter"]),
                "error",
                "2026-05-06T02:00:00",
                "2026-05-06T02:05:00",
                3,
                0,
            ),
        )
        con.execute(
            "INSERT INTO bac_scans (id, domain, services, status, created_at, finished_at, total_sources, total_links) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "bac-usage",
                "example.com",
                json.dumps(["github"]),
                "done",
                "2026-05-07T03:00:00",
                "2026-05-07T03:05:00",
                4,
                1,
            ),
        )
        con.execute(
            "INSERT INTO cred_scans (id, domain, categories, status, created_at, finished_at, total_sources, total_links) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "cred-usage",
                "example.org",
                json.dumps(["config"]),
                "done",
                "2026-05-08T04:00:00",
                "2026-05-08T04:05:00",
                5,
                1,
            ),
        )
        con.executemany(
            "INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("blh-old", "twitter", "https://example.com", "https://x.com/example", "X", "alive", 200, "", "", "2026-05-05T01:01:00"),
                ("blh-old", "github", "https://example.com", "https://github.com/example", "GitHub", "alive", 200, "", "", "2026-05-05T01:02:00"),
            ],
        )
        con.execute(
            "INSERT INTO bac_results (scan_id, service, source_url, target_url, anchor_text, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("bac-usage", "github", "https://example.com", "https://github.com/example/repo", "Repo", "2026-05-07T03:01:00"),
        )
        con.execute(
            "INSERT INTO cred_results (scan_id, file_type, pattern_matched, source_url, target_url, anchor_text, extracted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("cred-usage", "config", ".env", "https://example.org", "https://example.org/.env", ".env", "2026-05-08T04:01:00"),
        )
        con.commit()
        con.close()

        stats = main.db.get_dashboard_stats()
        features = {feature["id"]: feature for feature in stats["features"]}

        self.assertEqual(stats["totals"]["scan_count"], 4)
        self.assertEqual(stats["totals"]["result_count"], 4)
        self.assertEqual(features["blh"]["scan_count"], 2)
        self.assertEqual(features["blh"]["result_count"], 2)
        self.assertEqual(features["blh"]["status_counts"], {"done": 1, "error": 1})
        self.assertEqual(features["blh"]["last_used_at"], "2026-05-06T02:00:00")
        self.assertEqual(features["blh"]["usage"][0], {"name": "twitter", "count": 2, "last_used_at": "2026-05-06T02:00:00"})
        self.assertEqual(features["bac"]["usage"][0]["name"], "github")
        self.assertEqual(features["cred"]["recent"][0]["used_for"], ["config"])

    def test_dashboard_feature_detail_is_light_and_domain_detail_is_filterable(self):
        con = sqlite3.connect(main.DB_PATH)
        con.execute(
            "INSERT INTO scans (id, domain, platforms, status, created_at, finished_at, total_sources, total_links) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "blh-detail",
                "example.com",
                json.dumps(["twitter"]),
                "done",
                "2026-05-05T01:00:00",
                "2026-05-05T01:05:00",
                2,
                1,
            ),
        )
        con.executemany(
            "INSERT INTO crawl_pages (scan_id, domain, platforms_key, source_url, canonical_source_url, final_url, crawl_status, http_code, error_reason, platform_hits, account_hits, crawled_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    "blh-detail",
                    "example.com",
                    "twitter",
                    "https://example.com/",
                    "https://example.com/",
                    "https://example.com/",
                    "success",
                    200,
                    "",
                    1,
                    1,
                    "2026-05-05T01:01:00",
                ),
                (
                    "blh-detail",
                    "example.com",
                    "twitter",
                    "https://example.com/about",
                    "https://example.com/about",
                    "https://example.com/about",
                    "success",
                    200,
                    "",
                    0,
                    0,
                    "2026-05-05T01:02:00",
                ),
            ],
        )
        con.execute(
            "INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text, status, http_code, final_url, error_reason, checked_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "blh-detail",
                "twitter",
                "https://example.com/",
                "https://x.com/example",
                "Twitter",
                "alive",
                200,
                "https://x.com/example",
                "",
                "2026-05-05T01:03:00",
            ),
        )
        con.commit()
        con.close()

        detail = main.db.get_dashboard_feature_detail("blh")
        domain_detail = main.db.get_dashboard_domain_detail("blh", "example.com", q="x.com")
        crawled_detail = main.db.get_dashboard_domain_detail("blh", "example.com", view="crawled")

        self.assertEqual(detail["feature"]["id"], "blh")
        self.assertEqual(detail["domains"][0]["domain"], "example.com")
        self.assertEqual(detail["domains"][0]["scan_count"], 1)
        self.assertEqual(detail["crawled_url_count"], 2)
        self.assertEqual(detail["target_link_count"], 1)
        self.assertNotIn("target_links", detail)
        self.assertNotIn("crawled_urls", detail)
        self.assertNotIn("crawled_urls", domain_detail)
        self.assertNotIn("target_links", crawled_detail)
        self.assertEqual([row["source_url"] for row in crawled_detail["crawled_urls"]], [
            "https://example.com/about",
            "https://example.com/",
        ])
        self.assertEqual(domain_detail["target_links"][0]["target_url"], "https://x.com/example")
        self.assertEqual(domain_detail["target_links"][0]["type"], "twitter")

    def test_dashboard_api_and_logo_assets_are_served(self):
        self.insert_scan("api-domain", status="done")
        client = TestClient(main.app)

        dashboard = client.get("/api/dashboard")
        detail = client.get("/api/dashboard/blh")
        domain_detail = client.get("/api/dashboard/blh/domains/example.com")
        crawled_detail = client.get("/api/dashboard/blh/domains/example.com?view=crawled")
        logo = client.get("/assets/BLH-logo.webp")

        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("features", dashboard.json())
        self.assertEqual(detail.status_code, 200)
        self.assertIn("crawled_url_count", detail.json())
        self.assertEqual(domain_detail.status_code, 200)
        self.assertIn("target_links", domain_detail.json())
        self.assertNotIn("crawled_urls", domain_detail.json())
        self.assertEqual(crawled_detail.status_code, 200)
        self.assertIn("crawled_urls", crawled_detail.json())
        self.assertEqual(logo.status_code, 200)
        self.assertEqual(logo.headers["content-type"], "image/webp")

    def test_cloudflare_blocked_source_is_logged_for_user(self):
        class Response:
            status_code = 403
            url = "https://example.com/"
            text = "<html><head><title>Just a moment...</title></head><body>Cloudflare</body></html>"
            headers = {"server": "cloudflare", "cf-ray": "abc"}

        self.assertEqual(shared.detect_access_challenge(Response()), "Cloudflare challenge")

    def test_crawler_logs_blocked_source_page(self):
        class Response:
            status_code = 403
            url = "https://example.com/"
            text = "<html><head><title>Just a moment...</title></head><body>Cloudflare</body></html>"
            headers = {"server": "cloudflare", "cf-ray": "abc"}

        class Client:
            async def get(self, *args, **kwargs):
                return Response()

        logs = []
        writes = []

        async def run():
            return await shared.discover_sources_by_crawling(
                Client(),
                "example.com",
                ["twitter.com"],
                ["https://example.com/"],
                "scan-1",
                log_fn=lambda _sid, msg: logs.append(msg),
                write_crawl_fn=lambda _sid, src, final, status, **kw: writes.append((src, final, status, kw)),
            )

        asyncio.run(run())

        self.assertTrue(any("Cloudflare challenge" in message for message in logs))
        self.assertEqual(writes[0][2], "skipped")
        self.assertEqual(writes[0][3]["error_reason"], "Cloudflare challenge")


if __name__ == "__main__":
    unittest.main()
