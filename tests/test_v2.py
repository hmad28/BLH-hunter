import asyncio
import tempfile
import unittest
import os
import uuid
from pathlib import Path

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import select, func, create_engine
from sqlalchemy.engine import make_url

from lazy_dorking.v2.api import get_store
from lazy_dorking.v2.app import app
from lazy_dorking.v2.models import ScanConfig
from lazy_dorking.v2.store import Store, jobs, pages, evidence, findings, urls
from lazy_dorking.v2.network import Page, fetch
from lazy_dorking.v2.analyzers import classify, extract, validate
from lazy_dorking.v2.worker import run_one


class DurablePipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.url = 'sqlite:///' + str(Path(self.tmp.name) / 'test.db')
        self.pg_admin = None
        if os.getenv('BLH_TEST_POSTGRES_URL'):
            # An opt-in PostgreSQL run gets its own schema, never production tables.
            base = make_url(os.environ['BLH_TEST_POSTGRES_URL'])
            if base.drivername == 'postgresql':
                base = base.set(drivername='postgresql+psycopg')
            self.pg_schema = 'blh_test_' + uuid.uuid4().hex
            self.pg_admin = create_engine(base)
            with self.pg_admin.begin() as con:
                con.exec_driver_sql(f'CREATE SCHEMA {self.pg_schema}')
            self.url = base.update_query_dict({'options': f'-csearch_path={self.pg_schema}'}).render_as_string(hide_password=False)
        self.store = Store(self.url)
        self.store.init()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.store.engine.dispose()
        if self.pg_admin:
            with self.pg_admin.begin() as con:
                con.exec_driver_sql(f'DROP SCHEMA {self.pg_schema} CASCADE')
            self.pg_admin.dispose()
        self.tmp.cleanup()

    def scan(self, **kwargs):
        return self.store.create(ScanConfig(domain='example.com', providers=[], prober='none', **kwargs))

    def seeded(self, **kwargs):
        sid = self.scan(**kwargs)
        j = self.store.claim()
        self.store.complete(j, {'urls': [{'url': 'https://a.example.com/', 'provider': 'roots'},
                                       {'url': 'https://b.example.com/', 'provider': 'roots'}]})
        return sid

    def test_restart_reclaims_unfinished_job_and_rejects_old_token(self):
        sid = self.seeded()
        old = self.store.claim(lease_seconds=-1)
        restarted = Store(self.url)
        try:
            new = restarted.claim()
            if new['id'] != old['id']:
                # Fairness may dispatch the next hostname before the recovered job.
                new = restarted.claim()
            self.assertEqual(old['id'], new['id'])
            self.assertFalse(self.store.complete(old, {'page': {'http_code': 200}}))
            self.assertTrue(restarted.complete(new, {'page': {'http_code': 200}}))
            self.assertEqual(restarted.get(sid)['pages'], 1)
        finally:
            restarted.engine.dispose()

    def test_hard_process_exit_preserves_queue_for_next_worker(self):
        import subprocess
        import sys
        sid = self.scan()
        script = ('import os,sys; from lazy_dorking.v2.store import Store; '
                  's=Store(sys.argv[1]); s.claim(lease_seconds=-1); os._exit(19)')
        process = subprocess.run([sys.executable, '-c', script, self.url], capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 19)
        recovered = self.store.claim()
        self.assertEqual(recovered['scan_id'], sid)
        self.assertEqual(recovered['attempts'], 2)

    def test_probe_does_not_remove_urls_after_failed_host_response(self):
        sid = self.store.create(ScanConfig(domain='example.com', providers=[], prober='native'))
        self.store.complete(self.store.claim(), {'urls': [{'url': 'https://example.com/old', 'provider': 'fixture'}]})
        probe = self.store.claim()
        self.assertEqual(probe['kind'], 'probe')
        self.store.complete(probe, {'probe': {'http_code': 403, 'engine': 'native'}})
        self.assertEqual(self.store.assets(sid)[0]['data']['http_code'], 403)
        self.assertEqual(self.store.claim()['kind'], 'crawl')

    def test_pause_resume_revokes_inflight_result(self):
        sid = self.seeded()
        job = self.store.claim()
        self.assertEqual(self.store.control(sid, 'pause'), 'PAUSED')
        self.assertIsNone(self.store.claim())
        self.assertFalse(self.store.complete(job, {'page': {'http_code': 200}}))
        self.store.control(sid, 'resume')
        self.assertIsNotNone(self.store.claim())

    def test_cancel_survives_restart(self):
        sid = self.seeded()
        self.store.claim()
        self.store.control(sid, 'cancel')
        other = Store(self.url)
        try:
            self.assertIsNone(other.claim())
            self.assertEqual(other.get(sid)['state'], 'CANCELLED')
        finally:
            other.engine.dispose()

    def test_round_robin_and_concurrent_host_exclusion(self):
        sid = self.seeded()
        first = self.store.claim()
        self.store.complete(first, {'page': {}, 'urls': [{'url': 'https://a.example.com/next', 'provider': 'html'}]})
        second = self.store.claim()
        self.assertEqual(second['host'], 'b.example.com')
        third = self.store.claim()
        self.assertEqual(third['host'], 'a.example.com')
        self.assertIsNone(self.store.claim())

    def test_budget_reserves_inflight_pages(self):
        sid = self.seeded(max_pages=1)
        first = self.store.claim()
        self.assertIsNone(self.store.claim())
        self.store.complete(first, {'page': {}})
        self.assertIsNone(self.store.claim())
        self.store.claim()
        self.assertEqual(self.store.get(sid)['pages'], 1)
        self.assertEqual(self.store.get(sid)['jobs'].get('skipped'), 1)

    def test_two_workers_cannot_claim_same_job(self):
        from concurrent.futures import ThreadPoolExecutor
        self.scan()
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda _: self.store.claim(), range(2)))
        self.assertEqual(sum(r is not None for r in results), 1)

    def test_atomic_evidence_idempotency_and_delete_cleanup(self):
        sid = self.seeded()
        job = self.store.claim()
        output = {'page': {}, 'findings': [{'finding': {'kind': 'blh', 'category': 'github', 'url': 'https://github.com/acme'},
                   'evidence': {'source_url': 'https://a.example.com/', 'discovered_by': 'native'}}]}
        self.store.complete(job, output)
        self.assertFalse(self.store.complete(job, output))
        self.assertEqual(self.store.get(sid)['new_findings'], 1)
        self.store.control(sid, 'delete')
        self.assertFalse(self.store.complete(job, output))
        with self.store.engine.connect() as con:
            for table in (jobs, pages, evidence, findings, urls):
                self.assertEqual(con.scalar(select(func.count()).select_from(table)), 0)
        # Deleted history must not suppress a new scan.
        sid2 = self.seeded()
        self.assertEqual(self.store.get(sid2)['urls'], 2)
        self.assertEqual(self.store.get(sid2)['jobs']['queued'], 2)

    def test_coverage_is_per_platform_and_retained_scan(self):
        sid = self.seeded(platforms=['github'])
        job = self.store.claim()
        self.store.complete(job, {'page': {}})
        self.store.control(sid, 'cancel')
        next_sid = self.scan(platforms=['instagram'])
        discovery = self.store.claim()
        self.store.complete(discovery, {'urls': [{'url': job['payload']['url'], 'provider': 'root'}]})
        self.assertEqual(self.store.get(next_sid)['jobs']['queued'], 1)

    def test_shared_finding_survives_only_while_referenced(self):
        first = self.scan()
        payload = {'findings': [{'finding': {'kind': 'blh', 'category': 'github', 'url': 'https://github.com/acme'},
                                 'evidence': {'source_url': 'https://example.com/'}}]}
        self.store.complete(self.store.claim(), payload)
        self.store.control(first, 'cancel')
        second = self.scan()
        self.store.complete(self.store.claim(), payload)
        self.assertFalse(self.store.results(second)[0]['is_new'])
        self.store.control(first, 'delete')
        self.assertEqual(len(self.store.results(second)), 1)
        self.store.control(second, 'delete')
        with self.store.engine.connect() as con:
            self.assertEqual(con.scalar(select(func.count()).select_from(findings)), 0)

    def test_migration_is_readonly_idempotent_and_never_dispatches(self):
        import sqlite3
        import hashlib
        from lazy_dorking import db
        from lazy_dorking.v2.migrate import import_legacy
        source = Path(self.tmp.name) / 'legacy.db'
        old = db.DB_PATH
        try:
            db.DB_PATH = str(source)
            db.init_db()
        finally:
            db.DB_PATH = old
        with sqlite3.connect(source) as con:
            con.execute("INSERT INTO bac_scans(id,domain,services,status) VALUES ('one','example.com','[\"github\"]','done')")
            con.execute("INSERT INTO bac_results(scan_id,service,source_url,target_url,anchor_text) VALUES ('one','github','https://example.com','https://github.com/acme/repo','Repo')")
        con.close()
        before = hashlib.sha256(source.read_bytes()).digest()
        preview = import_legacy(source, self.store)
        self.assertEqual(preview['scans'], 1)
        self.assertEqual(self.store.list(), [])
        result = import_legacy(source, self.store, apply=True)
        self.assertEqual(result['findings'], 1)
        self.assertIsNone(self.store.claim())
        self.assertEqual(import_legacy(source, self.store, apply=True)['already_imported'], 1)
        self.assertEqual(hashlib.sha256(source.read_bytes()).digest(), before)

    def test_failed_job_finishes_scan_as_failed(self):
        sid = self.scan()
        for _ in range(3):
            job = self.store.claim()
            self.store.fail(job, 'missing tool')
        self.store.claim()
        self.assertEqual(self.store.get(sid)['state'], 'FAILED')

    def test_out_of_scope_and_invalid_urls_not_enqueued(self):
        sid = self.scan()
        self.store.complete(self.store.claim(), {'urls': [
            {'url': 'https://example.com.evil.com/', 'provider': 'test'},
            {'url': 'https://user@example.com/', 'provider': 'test'},
            {'url': 'https://example.com:bad/', 'provider': 'test'}]})
        self.assertEqual(self.store.get(sid)['urls'], 0)

    def test_worker_end_to_end_without_external_requests(self):
        sid = self.scan()
        async def fixture(job, _):
            if job['kind'] == 'discover':
                return {'urls': [{'url': 'https://example.com/', 'provider': 'fixture'}]}
            if job['kind'] == 'crawl':
                return extract(Page('https://example.com/', 200, '<a href="https://github.com/acme">Acme</a>',
                                    {'content-type': 'text/html'}), ScanConfig(**job['config']), 0)
            return {'validation': validate(Page('https://github.com/acme', 404), 'blh')}
        async def run():
            for _ in range(5):
                await run_one(self.store, fixture)
        asyncio.run(run())
        self.assertEqual(self.store.get(sid)['state'], 'COMPLETED')
        result = self.store.results(sid)[0]
        self.assertEqual(result['status'], 'broken')
        self.assertEqual(result['evidence'][0]['anchor'], 'Acme')

    def test_api_queue_control_review_and_pagination(self):
        app.dependency_overrides[get_store] = lambda: self.store
        client = TestClient(app)
        response = client.post('/api/v2/scans', json={'domain': 'example.com', 'providers': []})
        self.assertEqual(response.status_code, 201)
        sid = response.json()['scan_id']
        self.assertEqual(client.post(f'/api/v2/scans/{sid}/pause').json()['state'], 'PAUSED')
        self.assertEqual(client.get(f'/api/v2/scans/{sid}/urls?limit=0').status_code, 422)
        self.assertEqual(client.get('/api/v2/scans/missing').status_code, 404)
        self.assertEqual(client.get('/v2').status_code, 200)


class AnalyzerTests(unittest.TestCase):
    def test_content_tools_redact_and_do_not_enqueue_post_or_expressions(self):
        import json
        from unittest.mock import patch
        from lazy_dorking.v2.intelligence import analyze_content
        async def command(args, **kwargs):
            if args[0] == 'jsluice':
                return [json.dumps({'url': '/api/read', 'method': 'GET'}),
                        json.dumps({'url': '/api/delete', 'method': 'POST'}),
                        json.dumps({'url': '/api/EXPR', 'method': 'GET'})]
            report = Path(args[args.index('--report-path') + 1])
            report.write_text(json.dumps([{'RuleID': 'test-key', 'StartLine': 3,
                                          'Secret': 'DO_NOT_STORE', 'Match': 'DO_NOT_STORE'}]))
            return []
        config = ScanConfig(domain='example.com', js_analysis=True, secret_signals=True)
        with patch('lazy_dorking.v2.intelligence.command_lines', new=command):
            out = asyncio.run(analyze_content(Page('https://example.com/app.js', 200, 'const key=1',
                                                 {'content-type': 'application/javascript'}), config, 1))
        self.assertEqual([u['url'] for u in out['urls']], ['https://example.com/api/read'])
        self.assertNotIn('DO_NOT_STORE', json.dumps(out))
        self.assertEqual(out['findings'][0]['evidence']['rule'], 'test-key')

    def test_nuclei_only_uses_repo_template_for_selected_candidate(self):
        from unittest.mock import AsyncMock, patch
        from lazy_dorking.v2.intelligence import validate_exposure
        with patch('lazy_dorking.v2.intelligence.command_lines', new=AsyncMock(return_value=[])) as tool:
            self.assertEqual(asyncio.run(validate_exposure('https://example.com/backup.zip')), [])
            tool.assert_not_called()
            asyncio.run(validate_exposure('https://example.com/.env'))
            args = tool.call_args.args[0]
            self.assertTrue(args[args.index('-t') + 1].endswith('env.yaml'))
            self.assertNotIn('-headless', args)

    def test_tool_timeout_reaps_child(self):
        import sys
        from lazy_dorking.v2.providers import command_lines
        with self.assertRaises(TimeoutError):
            asyncio.run(command_lines([sys.executable, '-c', 'import time; time.sleep(20)'], timeout=0.2))

    def test_source_redirect_is_not_fetched_outside_scope(self):
        requested = []
        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(302, headers={'location': 'https://outside.test/'})
        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
                return await fetch('https://example.com/', 'example.com', client=client, allow_private=True)
        page = asyncio.run(run())
        self.assertIn('Out-of-scope', page.error)
        self.assertEqual(len(requested), 1)

    def test_fetch_body_limit(self):
        async def run():
            async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b'x'*100))) as c:
                return await fetch('https://example.com', client=c, allow_private=True, max_bytes=10)
        page = asyncio.run(run())
        self.assertEqual(len(page.body), 10)
        self.assertTrue(page.truncated)

    def test_extraction_evidence_and_forms_are_not_crawled(self):
        config = ScanConfig(domain='example.com', browser=True)
        page = Page('https://example.com/', 200, '<div id="root"></div><script src="/app.js"></script><form action="/delete"></form><a href="https://github.com/acme">Follow</a>', {'content-type':'text/html'})
        out = extract(page, config, 0)
        self.assertTrue(out['browser'])
        self.assertNotIn('https://example.com/delete', [u['url'] for u in out['urls']])
        self.assertEqual(out['findings'][0]['evidence']['selector'], 'a[href]')

    def test_login_and_transient_errors_are_not_alive_or_broken(self):
        self.assertEqual(validate(Page('https://instagram.com/accounts/login/', 200), 'blh')['status'], 'login_required')
        self.assertEqual(validate(Page('https://github.com/acme', 503), 'blh')['status'], 'unknown')
        self.assertEqual(validate(Page('https://drive.google.com/drive/a', 200), 'bac')['status'], 'reachable')

    def test_fragments_and_share_links_rejected(self):
        config = ScanConfig(domain='example.com')
        self.assertEqual(classify('https://github.com/acme#frag', config), [])
        self.assertEqual(classify('https://instagram.com/acme?share=x', config), [])

    def test_crawlee_adapter_executes_real_framework_with_fixture_http(self):
        from lazy_dorking.v2.engines import crawlee_fetch
        async def fake(url, domain):
            return Page(url, 200, '<a href="/about">About</a>', {'content-type': 'text/html'})
        result = asyncio.run(crawlee_fetch('https://example.com/', 'example.com', fetch_fn=fake))
        self.assertEqual(result.engine, 'crawlee')
        self.assertIn('About', result.body)

    def test_browser_adapter_renders_javascript_on_local_fixture(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from unittest.mock import AsyncMock, patch
        from lazy_dorking.v2.engines import browser_fetch
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(b'<div id="root"></div><script>document.getElementById("root").innerHTML="<a href=/rendered>Rendered</a>"</script>')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch('lazy_dorking.v2.engines.public_address', new=AsyncMock()):
                page = asyncio.run(browser_fetch(f'http://127.0.0.1:{server.server_port}/', '127.0.0.1'))
            self.assertIn('href="/rendered"', page.body)
            self.assertEqual(page.engine, 'browser')
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
