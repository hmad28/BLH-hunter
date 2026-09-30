"""Optional bounded content tools. No credential verification or raw secret storage."""
import json
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .analyzers import classify
from .providers import command_lines
from ..shared import url_in_scope, canonical_url


async def analyze_content(page, config, depth):
    output = {"urls": [], "findings": []}
    if page.error or not 200 <= page.status < 300 or not url_in_scope(page.url, config.domain):
        return output
    ctype = page.headers.get('content-type', '').lower()
    is_js = 'javascript' in ctype or urlparse(page.url).path.lower().endswith(('.js', '.mjs'))
    textual = is_js or any(s in ctype for s in ('text/', 'json', 'xml'))
    if not (config.js_analysis and is_js or config.secret_signals and textual):
        return output
    with tempfile.TemporaryDirectory(prefix='blh-content-') as directory:
        source = Path(directory) / ('source.js' if is_js else 'source.txt')
        source.write_text(page.body, encoding='utf-8')
        if config.js_analysis and is_js:
            lines = await command_lines(['jsluice', 'urls', str(source)], timeout=20)
            for line in lines[:2000]:
                if not line.startswith('{'):
                    continue
                item = json.loads(line)
                raw = item.get('url', '')
                if not raw or 'EXPR' in raw:
                    continue
                url = urljoin(page.url, raw)
                proof = {'source_url': page.url, 'source_type': 'javascript', 'discovered_by': 'jsluice',
                         'method': item.get('method', 'GET'), 'match_type': item.get('type', '')}
                for finding in classify(url, config):
                    output['findings'].append({'finding': finding, 'evidence': proof})
                if item.get('method', 'GET').upper() == 'GET' and url_in_scope(url, config.domain):
                    output['urls'].append({'url': url, 'provider': 'jsluice', 'depth': depth + 1})
        if config.secret_signals and textual:
            report = Path(directory) / 'report.json'
            await command_lines(['gitleaks', 'dir', str(source), '--report-format', 'json',
                '--report-path', str(report), '--redact=100', '--exit-code', '0', '--no-banner'], timeout=20)
            rows = json.loads(report.read_text(encoding='utf-8')) if report.exists() else []
            for row in rows[:200]:
                # Exclude Secret, Match, source snippets and temporary file paths.
                rule = str(row.get('RuleID', 'unknown'))[:100]
                output['findings'].append({'finding': {'kind': 'secret', 'category': 'secret_signal',
                    'url': canonical_url(page.url)}, 'evidence': {'source_url': page.url,
                    'discovered_by': 'gitleaks', 'rule': rule, 'line': row.get('StartLine'),
                    'redacted': True, 'credential_verified': False}})
    return output


async def validate_exposure(url):
    path = urlparse(url).path.lower()
    template = None
    if path.endswith('/.env'):
        template = 'env.yaml'
    elif path.endswith('/.git/config'):
        template = 'git-config.yaml'
    elif path.endswith(('/swagger.json', '/openapi.json')):
        template = 'api-docs.yaml'
    if not template:
        return []
    template_path = Path(__file__).with_name('templates') / template
    lines = await command_lines(['nuclei', '-u', url, '-t', str(template_path), '-jsonl', '-silent',
        '-duc', '-ni', '-timeout', '10', '-retries', '0', '-rl', '2', '-c', '1'], timeout=30)
    return [{'template': row.get('template-id'), 'matcher': row.get('matcher-name', ''),
             'severity': row.get('info', {}).get('severity', 'info')}
            for row in (json.loads(line) for line in lines if line.startswith('{'))]
