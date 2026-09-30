"""Smoke-test installed recon binaries against local fixtures, never real targets."""
import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import AsyncMock, patch

from lazy_dorking.v2.engines import browser_fetch, crawlee_fetch
from lazy_dorking.v2.intelligence import analyze_content, validate_exposure
from lazy_dorking.v2.models import ScanConfig
from lazy_dorking.v2.network import Page
from lazy_dorking.v2.providers import capabilities, command_lines


class Fixture(BaseHTTPRequestHandler):
    def do_GET(self):
        contents = {
            '/': ('text/html', '<html><a href="/child">Child</a><div id="root"></div>'
                   '<script>document.getElementById("root").innerHTML="<a href=/rendered>Rendered</a>"</script></html>'),
            '/child': ('text/html', '<html>Child</html>'),
            '/.env': ('text/plain', 'DB_PASSWORD=synthetic-not-a-real-password\n'),
            '/.git/config': ('text/plain', '[core]\nrepositoryformatversion = 0\n'),
            '/openapi.json': ('application/json', '{"openapi":"3.0.0","paths":{}}'),
        }
        ctype, body = contents.get(self.path, ('text/plain', 'not found'))
        self.send_response(200 if self.path in contents else 404)
        self.send_header('Content-Type', ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


async def check(base):
    assert all(capabilities().values()), capabilities()
    for binary, flag in [('subfinder', '-version'), ('gau', '--version'), ('katana', '-version'),
                         ('httpx-toolkit', '-version'), ('nuclei', '-version'), ('gitleaks', 'version')]:
        await command_lines([binary, flag], timeout=20)
        print(f'{binary}: executable OK', flush=True)

    with patch('lazy_dorking.v2.engines.public_address', new=AsyncMock()):
        page = await browser_fetch(base, '127.0.0.1')
        assert 'href="/rendered"' in page.body, page.metadata()
    print('Crawlee browser: JavaScript rendering OK', flush=True)

    async def fixture_fetch(url, domain):
        return Page(url, 200, '<html>fixture</html>', {'content-type': 'text/html'})
    page = await crawlee_fetch('https://example.com/', 'example.com', fetch_fn=fixture_fetch)
    assert page.status == 200

    # Synthetic PAT syntax, not an issued credential. Only rule/line evidence is returned.
    body = 'fetch("/api/read"); const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";'
    out = await analyze_content(Page('https://example.com/app.js', 200, body,
                                {'content-type': 'application/javascript'}),
                                ScanConfig(domain='example.com', js_analysis=True, secret_signals=True), 0)
    assert any(row['url'].endswith('/api/read') for row in out['urls']), 'jsluice URL extraction failed'
    assert any(row['finding']['kind'] == 'secret' for row in out['findings']), 'Gitleaks detection failed'
    assert 'ghp_' not in json.dumps(out), 'Raw synthetic secret escaped redaction'
    print('jsluice and Gitleaks: extraction and redaction OK', flush=True)

    for path in ('.env', '.git/config', 'openapi.json'):
        matches = await validate_exposure(base + path)
        assert matches, f'Nuclei content template failed for {path}'
    print('Nuclei: all three selected content templates OK', flush=True)

    lines = await command_lines(['httpx-toolkit', '-u', base, '-json', '-silent', '-sc', '-title',
                                 '-timeout', '5', '-retries', '0'], timeout=30)
    assert any(json.loads(line).get('status_code') == 200 for line in lines if line.startswith('{'))
    lines = await command_lines(['katana', '-u', base, '-jsonl', '-silent', '-d', '2', '-ct', '10s',
                                 '-rl', '2', '-c', '1', '-cs', '^' + base], timeout=30)
    assert any('/child' in line for line in lines), 'Katana did not discover local child link'
    print('PD httpx and Katana: local HTTP fixture OK', flush=True)


def main():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        asyncio.run(check(f'http://127.0.0.1:{server.server_port}/'))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
