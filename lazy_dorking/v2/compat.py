"""Classic UI contract backed exclusively by the durable v2 store and workers."""
import csv
import io
from collections import Counter
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, ValidationError
from sqlalchemy import select, func, update

from .api import get_store
from .models import ScanConfig
from .providers import capabilities
from .store import scans, pages, findings, references, evidence
from ..db import FEATURE_STATS

router = APIRouter(tags=['Classic UI / v2 engine'])
FIELDS = {'blh': 'platforms', 'bac': 'services', 'cred': 'categories'}
STATES = {'QUEUED': 'pending', 'PAUSED': 'paused', 'COMPLETED': 'done',
          'FAILED': 'error', 'CANCELLED': 'cancelled'}


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat() if value else None


def field(feature):
    if feature not in FIELDS:
        raise HTTPException(404, 'Feature not found')
    return FIELDS[feature]


def belongs(row, feature):
    return bool(row['config'].get(field(feature))) or (
        feature == 'cred' and row['config'].get('secret_signals'))


def require(store, feature, sid):
    row = store.get(sid)
    if not row or not belongs(row, feature):
        raise HTTPException(404, 'Scan not found')
    return row


def classic_scan(row):
    return {**{k: row['config'].get(k, []) for k in FIELDS.values()},
            'id': row['id'], 'domain': row['domain'],
            'status': STATES.get(row['state'], 'running'), 'phase': row['state'],
            'created_at': iso(row['created_at']), 'finished_at': iso(row['finished_at']),
            'total_sources': row.get('pages', 0), 'total_links': row.get('result_count', 0),
            'engine': 'v2', 'logs': [{'message': e['message'], 'created_at': iso(e['created_at'])}
                                  for e in reversed(row.get('events', []))]}


def feature_scans(store, feature):
    field(feature)
    with store.engine.connect() as con:
        rows = [dict(r) for r in con.execute(select(scans).order_by(scans.c.created_at.desc())).mappings()
                if belongs(r, feature)]
        counts = dict(con.execute(select(pages.c.scan_id, func.count()).group_by(pages.c.scan_id)).all())
        kinds = ['cred', 'secret'] if feature == 'cred' else [feature]
        results = dict(con.execute(select(references.c.scan_id, func.count()).join(findings)
                       .where(findings.c.kind.in_(kinds)).group_by(references.c.scan_id)).all())
    return [classic_scan({**r, 'pages': counts.get(r['id'], 0), 'result_count': results.get(r['id'], 0)}) for r in rows]


def result_rows(store, feature, sids):
    kinds = ['cred', 'secret'] if feature == 'cred' else [feature]
    with store.engine.connect() as con:
        rows = con.execute(select(findings, references.c.scan_id).join(references)
               .where(references.c.scan_id.in_(sids), findings.c.kind.in_(kinds))
               .order_by(findings.c.created_at.desc(), findings.c.id)).mappings().all()
        proofs = {}
        for p in con.execute(select(evidence).where(evidence.c.scan_id.in_(sids))).mappings():
            proofs.setdefault((p['scan_id'], p['finding_id']), []).append(p['data'])
    output = []
    for r in rows:
        ev = proofs.get((r['scan_id'], r['id']), [])
        proof = ev[0] if ev else {}
        data = r['data'] or {}
        status = data.get('manual_status', r['status'])
        if feature == 'blh':
            # HTTP success is not evidence that an account exists.
            status = {'discovered': 'pending', 'reachable': 'unknown', 'login_required': 'unknown'}.get(status, status)
        output.append({'id': r['id'], 'scan_id': r['scan_id'], 'platform': r['category'],
            'service': r['category'], 'file_type': r['category'], 'category': r['category'],
            'type': r['category'], 'source_url': proof.get('source_url', ''), 'target_url': r['url'],
            'anchor_text': proof.get('anchor', ''), 'pattern_matched': proof.get('rule', r['category']),
            'pattern': proof.get('rule', r['category']), 'status': status, 'engine_status': r['status'],
            'http_code': data.get('http_code'), 'final_url': data.get('final_url', r['url']),
            'error_reason': r['reason'], 'confidence': r['confidence'], 'evidence': ev,
            'checked_at': iso(r['created_at']), 'extracted_at': iso(r['created_at']), 'found_at': iso(r['created_at'])})
    return output


class ClassicRequest(BaseModel):
    domain: str
    platforms: list[str] = []
    services: list[str] = []
    categories: list[str] = []
    include_dorking: bool = False
    active_bruteforce: bool = False


@router.post('/api/{feature}/scans', status_code=201)
def create(feature: str, body: ClassicRequest, store=Depends(get_store)):
    selection = field(feature)
    if not getattr(body, selection):
        raise HTTPException(400, f'Select at least one {selection}')
    if body.active_bruteforce:
        raise HTTPException(422, 'Active brute-force is not implemented; use discovered exposure analysis')
    caps = capabilities()
    providers = ['sitemap', 'gau'] if caps['gau'] else ['sitemap', 'wayback', 'commoncrawl']
    if caps['subfinder']:
        providers.append('subfinder')
    values = dict(domain=body.domain, platforms=[], services=[], categories=[], providers=providers,
        browser=caps['browser'], js_analysis=caps['jsluice'], secret_signals=feature == 'cred' and caps['gitleaks'],
        exposure_validation=feature == 'cred' and caps['nuclei'],
        include_dorking=feature == 'bac' and body.include_dorking, max_pages=2000)
    values[selection] = getattr(body, selection)
    try:
        config = ScanConfig(**values)
    except ValidationError as exc:
        raise HTTPException(422, str(exc))
    return {'scan_id': store.create(config), 'engine': 'v2'}


@router.get('/api/{feature}/scans')
def listing(feature: str, store=Depends(get_store)):
    return feature_scans(store, feature)[:30]


@router.get('/api/{feature}/scans/{sid}')
def detail(feature: str, sid: str, store=Depends(get_store)):
    row = require(store, feature, sid)
    row['result_count'] = len(result_rows(store, feature, [sid]))
    return classic_scan(row)


@router.get('/api/{feature}/scans/{sid}/results')
def results(feature: str, sid: str, status: str = '', platform: str = '', service: str = '',
            file_type: str = '', category: str = '', store=Depends(get_store)):
    require(store, feature, sid)
    selection = platform or service or file_type or category
    return [r for r in result_rows(store, feature, [sid])
            if (not status or r['status'] == status) and (not selection or r['type'] == selection)]


@router.post('/api/{feature}/scans/{sid}/{action}')
def control(feature: str, sid: str, action: str, store=Depends(get_store)):
    require(store, feature, sid)
    action = {'continue': 'resume', 'stop': 'cancel'}.get(action, action)
    if action not in {'pause', 'resume', 'cancel'}:
        raise HTTPException(404, 'Unknown action')
    state = store.control(sid, action)
    return {'status': STATES.get(state, 'running')}


@router.delete('/api/{feature}/scans/{sid}')
def remove(feature: str, sid: str, store=Depends(get_store)):
    require(store, feature, sid)
    return {'status': store.control(sid, 'delete')}


class StatusUpdate(BaseModel):
    status: str


@router.patch('/api/{feature}/results/{fid}/status')
def override(feature: str, fid: str, body: StatusUpdate, store=Depends(get_store)):
    if feature != 'blh' or body.status not in {'pending', 'broken', 'alive', 'redirect', 'blocked', 'timeout', 'unknown'}:
        raise HTTPException(400, 'Invalid manual status')
    with store.tx() as con:
        row = con.execute(select(findings).where(findings.c.id == fid, findings.c.kind == 'blh')).mappings().first()
        if not row:
            raise HTTPException(404, 'Result not found')
        con.execute(update(findings).where(findings.c.id == fid).values(
            data={**(row['data'] or {}), 'manual_status': body.status}, review='confirmed'))
    return {'id': fid, 'status': body.status}


@router.get('/api/{feature}/scans/{sid}/export')
def export(feature: str, sid: str, store=Depends(get_store)):
    require(store, feature, sid)
    fields = ['scan_id', {'blh': 'platform', 'bac': 'service', 'cred': 'file_type'}[feature],
              'source_url', 'target_url', 'anchor_text', 'status', 'http_code', 'confidence', 'error_reason']
    output = io.StringIO(); writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    for row in result_rows(store, feature, [sid]):
        writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@')) else v
                         for k, v in row.items()})
    return Response(output.getvalue(), media_type='text/csv',
                    headers={'Content-Disposition': f'attachment; filename={feature}_{sid[:8]}.csv'})


def feature_summary(store, feature):
    spec = next(s for s in FEATURE_STATS if s['id'] == feature)
    rows = feature_scans(store, feature)
    usage = {}
    for r in rows:
        for name in r[FIELDS[feature]]:
            item = usage.setdefault(name, {'name': name, 'count': 0, 'last_used_at': r['created_at']})
            item['count'] += 1
    return {**{k: spec[k] for k in ('id', 'label', 'title', 'usage_label')},
        'scan_count': len(rows), 'result_count': sum(r['total_links'] for r in rows),
        'source_count': sum(r['total_sources'] for r in rows), 'link_count': sum(r['total_links'] for r in rows),
        'status_counts': dict(Counter(r['status'] for r in rows)),
        'last_used_at': rows[0]['created_at'] if rows else '',
        'usage': sorted(usage.values(), key=lambda r: -r['count'])[:8],
        'recent': [{**r, 'used_for': r[FIELDS[feature]]} for r in rows[:8]]}


@router.get('/api/dashboard')
def dashboard(store=Depends(get_store)):
    features = [feature_summary(store, f) for f in FIELDS]
    return {'features': features, 'totals': {k: sum(f[k] for f in features)
            for k in ('scan_count', 'result_count', 'source_count', 'link_count')}}


@router.get('/api/dashboard/{feature}')
def dashboard_feature(feature: str, store=Depends(get_store)):
    rows = feature_scans(store, feature)
    domains = {}
    for r in rows:
        d = domains.setdefault(r['domain'], {'domain': r['domain'], 'scan_count': 0,
            'last_scan_at': r['created_at'], 'total_sources': 0, 'total_links': 0})
        for k in ('total_sources', 'total_links'):
            d[k] += r[k]
        d['scan_count'] += 1
    summary = feature_summary(store, feature)
    return {'feature': summary, 'domains': list(domains.values()),
            'crawled_url_count': summary['source_count'], 'target_link_count': summary['result_count']}


@router.get('/api/dashboard/{feature}/domains/{domain:path}')
def dashboard_domain(feature: str, domain: str, q: str = '', result_type: str = '', status: str = '',
                     limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                     view: str = 'targets', store=Depends(get_store)):
    detail = dashboard_feature(feature, store)
    row = next((d for d in detail['domains'] if d['domain'] == domain), None)
    if not row:
        raise HTTPException(404, 'Domain not found')
    sids = [s['id'] for s in feature_scans(store, feature) if s['domain'] == domain]
    targets = [r for r in result_rows(store, feature, sids)
               if (not result_type or r['type'] == result_type) and (not status or r['status'] == status)
               and (not q or q.lower() in ' '.join(str(r[k]) for k in ('target_url','source_url','anchor_text','type')).lower())]
    payload = {'feature_id': feature, 'domain': row, 'target_count': len(targets),
               'crawled_count': row['total_sources'], 'limit': limit, 'offset': offset, 'view': view}
    if view == 'crawled':
        with store.engine.connect() as con:
            rows = con.execute(select(pages).where(pages.c.scan_id.in_(sids))
                   .order_by(pages.c.created_at.desc(), pages.c.id).limit(limit).offset(offset)).mappings()
            payload['crawled_urls'] = [{'scan_id': p['scan_id'], 'domain': domain,
                'used_for': ','.join(p['coverage'] or []), 'source_url': p['url'],
                'final_url': p['data'].get('final_url', p['url']), 'http_code': p['data'].get('http_code'),
                'crawl_status': p['data'].get('crawl_status', 'error' if p['data'].get('error') else 'visited'),
                'error_reason': p['data'].get('error', ''), 'platform_hits': 0, 'account_hits': 0,
                'crawled_at': iso(p['created_at'])} for p in rows]
    else:
        payload['target_links'] = targets[offset:offset + limit]
    return payload
