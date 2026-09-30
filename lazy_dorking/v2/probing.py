import json
import os
import re
import time

from .network import fetch, public_address
from .providers import command_lines


async def probe(url, domain, engine):
    if engine == 'pd-httpx':
        await public_address(url)
        # Use a distinct binary name to avoid colliding with Python's httpx CLI.
        binary = os.getenv('BLH_HTTPX_BIN', 'httpx-toolkit')
        lines = await command_lines([binary, '-u', url, '-json', '-silent', '-sc', '-title',
            '-location', '-cl', '-rt', '-td', '-timeout', '10', '-retries', '0'], timeout=30)
        rows = [json.loads(line) for line in lines if line.startswith('{')]
        if not rows:
            return {'status': 'unknown', 'engine': 'pd-httpx', 'reason': 'No HTTP probe result; URLs remain eligible for crawling'}
        row = rows[0]
        allowed = ('url', 'status_code', 'title', 'location', 'webserver', 'content_length', 'time', 'tech', 'a', 'aaaa', 'cname')
        return {**{k: row[k] for k in allowed if k in row}, 'engine': 'pd-httpx'}
    start = time.monotonic()
    page = await fetch(url, domain, max_bytes=200000)
    title = re.search(r'<title[^>]*>(.*?)</title>', page.body, re.I | re.S)
    return {**page.metadata(), 'title': title[1].strip()[:200] if title else '',
            'response_ms': round((time.monotonic() - start) * 1000),
            'server': page.headers.get('server', '')}
