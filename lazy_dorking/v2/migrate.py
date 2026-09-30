"""Explicit, idempotent import from a consistent read-only legacy SQLite snapshot."""
import argparse
import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy import delete, insert, select, update

from .models import ScanConfig
from .store import Store, scans, pages, jobs, findings, key, uid
from .analyzers import target_identity
from ..shared import canonical_url


def timestamp(value):
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, TypeError):
        return time.time()


def import_legacy(path, store, apply=False):
    path = Path(path).resolve(strict=True)
    source = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    snapshot = sqlite3.connect(':memory:')
    try:
        source.backup(snapshot)
    finally:
        source.close()
    snapshot.row_factory = sqlite3.Row
    summary = {'scans': 0, 'findings': 0, 'pages': 0, 'already_imported': 0, 'apply': apply}
    try:
        tables = {r[0] for r in snapshot.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        with store.tx() as con:
            for feature, prefix, selection in [('blh', '', 'platforms'), ('bac', 'bac_', 'services'), ('cred', 'cred_', 'categories')]:
                if prefix + 'scans' not in tables:
                    continue
                for scan in snapshot.execute(f'SELECT * FROM {prefix}scans'):
                    sid = 'legacy-' + key(feature + ':' + scan['id'])[:48]
                    if con.scalar(select(scans.c.id).where(scans.c.id == sid)):
                        summary['already_imported'] += 1
                        continue
                    summary['scans'] += 1
                    config = ScanConfig(**{'domain': scan['domain'], 'platforms': [], 'services': [],
                        'categories': [], 'providers': [], selection: json.loads(scan[selection])})
                    result_rows = snapshot.execute(f'SELECT * FROM {prefix}results WHERE scan_id=?', (scan['id'],)).fetchall()
                    crawl_rows = snapshot.execute(f'SELECT * FROM {prefix}crawl_pages WHERE scan_id=?', (scan['id'],)).fetchall() if prefix + 'crawl_pages' in tables else []
                    summary['findings'] += len(result_rows)
                    summary['pages'] += len(crawl_rows)
                    if not apply:
                        continue
                    con.execute(insert(scans).values(id=sid, domain=config.domain, config=config.model_dump(),
                        state='COMPLETED' if scan['status'] == 'done' else 'CANCELLED', created_at=timestamp(scan['created_at']),
                        finished_at=timestamp(scan['finished_at']), last_dispatch=0, last_host=''))
                    for row in crawl_rows:
                        url = canonical_url(row['source_url'])
                        digest = key(url)
                        if con.scalar(select(pages.c.id).where(pages.c.scan_id == sid, pages.c.key == digest)):
                            continue
                        con.execute(insert(pages).values(id=uid(), scan_id=sid, key=digest, url=url,
                            coverage=[f'{feature}:{p}' for p in row['platforms_key'].split(',') if p]
                                     if row['platforms_key'] else config.coverage(),
                            data={'engine': 'legacy', 'imported': True, 'final_url': row['final_url'],
                                  'http_code': row['http_code'], 'error': row['error_reason'],
                                  'crawl_status': row['crawl_status']}, created_at=timestamp(row['crawled_at'])))
                    for row in result_rows:
                        category = row[{'blh': 'platform', 'bac': 'service', 'cred': 'file_type'}[feature]]
                        url = target_identity(row['target_url']) if feature == 'blh' else canonical_url(row['target_url'])
                        self_key = key(feature + ':' + url)
                        existed = con.scalar(select(findings.c.id).where(findings.c.key == self_key))
                        store.add_finding(con, sid, {'kind': feature, 'category': category, 'url': url},
                            {'source_url': row['source_url'], 'anchor': row['anchor_text'], 'discovered_by': 'legacy-import'})
                        if not existed:
                            data = {'imported': True}
                            if feature == 'blh':
                                data.update(http_code=row['http_code'], final_url=row['final_url'])
                            con.execute(update(findings).where(findings.c.key == self_key).values(
                                status=row['status'] if feature == 'blh' else 'discovered', confidence='low',
                                reason='Imported legacy result; confidence has not been recalibrated', data=data))
                    # Import is a historical snapshot, never an implicit network scan.
                    con.execute(delete(jobs).where(jobs.c.scan_id == sid))
                    store.log(con, sid, f"Imported legacy {feature} scan {scan['id']} (state: {scan['status']}). "
                              "Legacy in-memory frontier cannot be resumed; create a new v2 scan to continue discovery.")
    finally:
        snapshot.close()
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sqlite_path')
    parser.add_argument('--apply', action='store_true', help='Commit import; otherwise only report counts')
    args = parser.parse_args()
    store = Store()
    store.init()
    try:
        print(json.dumps(import_legacy(args.sqlite_path, store, args.apply), indent=2))
    finally:
        store.engine.dispose()


if __name__ == '__main__':
    main()
