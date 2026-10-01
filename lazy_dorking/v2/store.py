"""Short, serialized mutations; network work always happens outside transactions.

The database is the queue of record. Job tokens fence stale workers after pause,
deletion or lease recovery. Commit output and checkpoint in the same transaction.
"""
import hashlib
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import (JSON, Boolean, Column, Float, ForeignKey, Index, Integer, MetaData,
                        String, Table, Text, UniqueConstraint, create_engine, delete, event,
                        func, insert, select, text, update)

from ..shared import canonical_url, url_in_scope
from .models import ScanConfig

meta = MetaData()
scans = Table("v2_scans", meta,
    Column("id", String(64), primary_key=True), Column("domain", String(253), nullable=False),
    Column("config", JSON, nullable=False), Column("state", String(24), nullable=False),
    Column("created_at", Float, nullable=False), Column("finished_at", Float),
    Column("last_dispatch", Float, default=0), Column("last_host", String(253), default=""))
jobs = Table("v2_jobs", meta,
    Column("id", String(64), primary_key=True),
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), nullable=False),
    Column("key", String(64), nullable=False), Column("kind", String(24), nullable=False),
    Column("host", String(253), default=""), Column("payload", JSON, nullable=False),
    Column("state", String(16), default="queued", nullable=False),
    Column("attempts", Integer, default=0), Column("token", String(64)),
    Column("lease_until", Float), Column("created_at", Float, nullable=False),
    Column("error", Text, default=""), UniqueConstraint("scan_id", "key"))
Index("v2_job_queue", jobs.c.state, jobs.c.scan_id, jobs.c.created_at)
hosts = Table("v2_hosts", meta,
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), primary_key=True),
    Column("host", String(253), primary_key=True), Column("data", JSON), Column("probed_at", Float))
urls = Table("v2_urls", meta,
    Column("id", String(64), primary_key=True),
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), nullable=False),
    Column("key", String(64), nullable=False), Column("url", Text, nullable=False),
    Column("host", String(253)), Column("depth", Integer),
    Column("providers", JSON), Column("state", String(24), default="discovered"),
    UniqueConstraint("scan_id", "key"))
pages = Table("v2_pages", meta,
    Column("id", String(64), primary_key=True),
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), nullable=False),
    Column("key", String(64), nullable=False), Column("url", Text),
    Column("coverage", JSON), Column("data", JSON), Column("created_at", Float),
    UniqueConstraint("scan_id", "key"))
findings = Table("v2_findings", meta,
    Column("id", String(64), primary_key=True), Column("key", String(64), unique=True),
    Column("url", Text), Column("kind", String(24)), Column("category", String(64)),
    Column("status", String(32)), Column("confidence", String(16)),
    Column("reason", Text), Column("data", JSON), Column("review", String(32), default="unreviewed"),
    Column("created_at", Float))
references = Table("v2_scan_findings", meta,
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), primary_key=True),
    Column("finding_id", ForeignKey(findings.c.id, ondelete="CASCADE"), primary_key=True),
    Column("is_new", Boolean, nullable=False))
evidence = Table("v2_evidence", meta,
    Column("id", String(64), primary_key=True),
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), nullable=False),
    Column("finding_id", ForeignKey(findings.c.id, ondelete="CASCADE"), nullable=False),
    Column("key", String(64)), Column("data", JSON), UniqueConstraint("scan_id", "key"))
events = Table("v2_events", meta,
    Column("id", String(64), primary_key=True),
    Column("scan_id", ForeignKey(scans.c.id, ondelete="CASCADE"), nullable=False),
    Column("created_at", Float), Column("message", Text))
ACTIVE = {"QUEUED", "DISCOVERING", "PROBING", "CRAWLING", "VALIDATING"}


def uid():
    return uuid.uuid4().hex


def key(value):
    return hashlib.sha256(value.encode()).hexdigest()


def job_label(job):
    payload = job['payload']
    raw = payload.get('url')
    if raw:
        parsed = urlparse(raw)
        return f'{parsed.scheme}://{parsed.hostname}{parsed.path}'[:250]
    return payload.get('provider') or payload.get('service') or job['kind']


class Store:
    def __init__(self, url=None):
        url = url or os.getenv("BLH_DATABASE_URL") or f"sqlite:///{Path(__file__).resolve().parents[2] / 'blh_v2.db'}"
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        self.engine = create_engine(url, pool_pre_ping=True)
        if self.engine.dialect.name == "sqlite":
            @event.listens_for(self.engine, "connect")
            def configure(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("PRAGMA busy_timeout=15000")
                connection.execute("PRAGMA journal_mode=WAL")

    def init(self):
        meta.create_all(self.engine)

    @contextmanager
    def tx(self):
        with self.engine.connect() as con:
            try:
                if self.engine.dialect.name == "sqlite":
                    con.exec_driver_sql("BEGIN IMMEDIATE")
                else:
                    con.execute(text("SELECT pg_advisory_xact_lock(724819260)"))
                yield con
                con.commit()
            except BaseException:
                con.rollback()
                raise

    def log(self, con, sid, message):
        con.execute(insert(events).values(id=uid(), scan_id=sid, created_at=time.time(), message=message[:1000]))

    def enqueue(self, con, sid, kind, payload, identity, host=""):
        digest = key(kind + ":" + identity)
        if con.execute(select(jobs.c.id).where(jobs.c.scan_id == sid, jobs.c.key == digest)).first():
            return
        con.execute(insert(jobs).values(id=uid(), scan_id=sid, key=digest, kind=kind,
            payload=payload, host=host, state="queued", attempts=0, created_at=time.time()))

    def create(self, config: ScanConfig):
        sid = uid()
        with self.tx() as con:
            con.execute(insert(scans).values(id=sid, domain=config.domain, config=config.model_dump(),
                state="QUEUED", created_at=time.time(), last_dispatch=0, last_host=""))
            for provider in ["roots"] + config.providers:
                self.enqueue(con, sid, "discover", {"provider": provider}, provider)
            if config.include_dorking:
                for service in config.services:
                    self.enqueue(con, sid, 'dork', {'service': service}, service)
            self.log(con, sid, f"[QUEUED] {config.domain} | engine={config.engine} | page budget={config.max_pages} | waiting for worker")
        return sid

    def get(self, sid):
        with self.engine.connect() as con:
            row = con.execute(select(scans).where(scans.c.id == sid)).mappings().first()
            if not row:
                return None
            result = dict(row)
            result["jobs"] = dict(con.execute(select(jobs.c.state, func.count()).where(jobs.c.scan_id == sid)
                                               .group_by(jobs.c.state)).all())
            result["pages"] = con.scalar(select(func.count()).select_from(pages).where(pages.c.scan_id == sid))
            result["urls"] = con.scalar(select(func.count()).select_from(urls).where(urls.c.scan_id == sid))
            result["hosts"] = con.scalar(select(func.count()).select_from(hosts).where(hosts.c.scan_id == sid))
            result["new_findings"] = con.scalar(select(func.count()).select_from(references).where(
                references.c.scan_id == sid, references.c.is_new.is_(True)))
            result["already_seen_targets"] = con.scalar(select(func.count()).select_from(references).where(
                references.c.scan_id == sid, references.c.is_new.is_(False)))
            result["events"] = [dict(r) for r in con.execute(select(events).where(events.c.scan_id == sid)
                .order_by(events.c.created_at.desc()).limit(100)).mappings()]
            return result

    def list(self):
        with self.engine.connect() as con:
            return [dict(r) for r in con.execute(select(scans).order_by(scans.c.created_at.desc()).limit(100)).mappings()]

    def control(self, sid, action):
        with self.tx() as con:
            scan = con.execute(select(scans).where(scans.c.id == sid)).mappings().first()
            if not scan:
                raise KeyError(sid)
            if action == "delete":
                con.execute(delete(scans).where(scans.c.id == sid))
                con.execute(delete(findings).where(~findings.c.id.in_(select(references.c.finding_id))))
                return "deleted"
            state = scan["state"]
            if action == "pause" and state in ACTIVE:
                state = "PAUSED"
                con.execute(update(jobs).where(jobs.c.scan_id == sid, jobs.c.state == "running")
                    .values(state="queued", token=None, lease_until=None, attempts=jobs.c.attempts - 1))
            elif action == "resume" and state == "PAUSED":
                state = "QUEUED"
            elif action == "cancel" and (state in ACTIVE or state == "PAUSED"):
                state = "CANCELLED"
                con.execute(update(jobs).where(jobs.c.scan_id == sid, jobs.c.state.in_(["running", "queued"]))
                    .values(state="cancelled", token=None, lease_until=None))
            con.execute(update(scans).where(scans.c.id == sid).values(state=state,
                finished_at=time.time() if state == "CANCELLED" else scan["finished_at"]))
            self.log(con, sid, f"{action}: {state}; outstanding worker tokens revoked when paused/cancelled.")
            return state

    def claim(self, lease_seconds=120):
        now = time.time()
        with self.tx() as con:
            expired = con.execute(select(jobs).where(jobs.c.state == "running", jobs.c.lease_until < now)).mappings().all()
            for job in expired:
                con.execute(update(jobs).where(jobs.c.id == job["id"]).values(
                    state="queued" if job["attempts"] < 3 else "failed", token=None, lease_until=None,
                    error="Worker lease expired"))
                self.log(con, job["scan_id"], "Recovered expired worker lease; unfinished job will retry up to 3 attempts.")
            for scan in con.execute(select(scans).where(scans.c.state.in_(ACTIVE))
                                    .order_by(scans.c.last_dispatch, scans.c.created_at)).mappings().all():
                sid = scan["id"]
                pending = con.execute(select(jobs).where(jobs.c.scan_id == sid,
                    jobs.c.state.in_(["queued", "running"])).order_by(jobs.c.created_at)).mappings().all()
                if not pending:
                    failed = con.scalar(select(func.count()).select_from(jobs).where(jobs.c.scan_id == sid, jobs.c.state == "failed"))
                    con.execute(update(scans).where(scans.c.id == sid).values(
                        state="FAILED" if failed else "COMPLETED", finished_at=now))
                    new_count = con.scalar(select(func.count()).select_from(references).where(
                        references.c.scan_id == sid, references.c.is_new.is_(True)))
                    seen_count = con.scalar(select(func.count()).select_from(references).where(
                        references.c.scan_id == sid, references.c.is_new.is_(False)))
                    covered = con.scalar(select(func.count()).select_from(urls).where(
                        urls.c.scan_id == sid, urls.c.state == 'covered'))
                    outcome = 'No valid selected targets found.' if not new_count and not seen_count else (
                        'All targets already seen.' if not new_count else f'{new_count} new findings.')
                    self.log(con, sid, f"{'Finished with failed jobs' if failed else 'Completed'}: {outcome} "
                             f"already_seen_targets={seen_count}; source URLs skipped as already crawled={covered}.")
                    continue
                busy_hosts = {j["host"] for j in pending if j["state"] == "running" and j["host"]}
                candidates = [j for j in pending if j["state"] == "queued"
                              and (not j["host"] or j["host"] not in busy_hosts)]
                # A host waits only for its own probe, never the whole asset inventory.
                probing_hosts = {j['host'] for j in pending if j['kind'] == 'probe'}
                candidates = [j for j in candidates if j['kind'] != 'crawl' or j['host'] not in probing_hosts]
                visited = con.scalar(select(func.count()).select_from(pages).where(pages.c.scan_id == sid))
                in_flight = sum(j['state'] == 'running' and j['kind'] == 'crawl' for j in pending)
                if visited >= scan['config']['max_pages'] and any(j['kind'] == 'crawl' and j['state'] == 'queued' for j in pending):
                    con.execute(update(jobs).where(jobs.c.scan_id == sid, jobs.c.kind == 'crawl',
                        jobs.c.state == 'queued').values(state='skipped', error='Crawl budget reached'))
                    self.log(con, sid, 'Crawl budget reached; remaining source jobs skipped.')
                if visited + in_flight >= scan['config']['max_pages']:
                    candidates = [j for j in candidates if j['kind'] != 'crawl']
                if not candidates:
                    continue
                phase = next(k for k in ('discover', 'dork', 'validate', 'browser', 'crawl', 'probe')
                             if any(j['kind'] == k for j in candidates))
                candidates = [j for j in candidates if j['kind'] == phase]
                if phase == 'probe':
                    # Prioritize submitted root/www assets over alphabetical archive hosts.
                    roots = [j for j in candidates if j['host'] in {scan['domain'], 'www.' + scan['domain']}]
                    if roots:
                        candidates = roots
                hosts = sorted({j["host"] for j in candidates})
                host = next((h for h in hosts if h > (scan["last_host"] or "")), hosts[0])
                job = next(j for j in candidates if j["host"] == host)
                token = uid()
                con.execute(update(jobs).where(jobs.c.id == job["id"]).values(state="running", token=token,
                    lease_until=now + lease_seconds, attempts=job["attempts"] + 1))
                con.execute(update(scans).where(scans.c.id == sid).values(last_host=host, last_dispatch=now,
                    state={"discover": "DISCOVERING", "dork": "DISCOVERING", "probe": "PROBING", "crawl": "CRAWLING", "browser": "CRAWLING", "validate": "VALIDATING"}[phase]))
                self.log(con, sid, f"[{phase.upper()}] Started {job_label(job)} | attempt {job['attempts'] + 1}/3")
                return {**job, "token": token, "config": scan["config"], "attempts": job["attempts"] + 1}
        return None

    def valid(self, con, job):
        return con.execute(select(jobs.c.id).join(scans).where(jobs.c.id == job["id"],
            jobs.c.token == job["token"], jobs.c.state == "running", jobs.c.lease_until > time.time(),
            scans.c.state.in_(ACTIVE))).first() is not None

    def heartbeat(self, job):
        with self.tx() as con:
            if not self.valid(con, job):
                return False
            con.execute(update(jobs).where(jobs.c.id == job["id"]).values(lease_until=time.time() + 120))
            return True

    def fail(self, job, error):
        with self.tx() as con:
            if not self.valid(con, job):
                return
            con.execute(update(jobs).where(jobs.c.id == job["id"]).values(
                state="queued" if job["attempts"] < 3 else "failed", token=None, lease_until=None, error=error[:500]))
            outcome = 'will retry' if job['attempts'] < 3 else 'failed after 3 attempts; other jobs continue'
            self.log(con, job["scan_id"], f"[ERROR] {job['kind']} {job_label(job)} | {outcome} | {error[:300]}")

    def add_url(self, con, sid, config, url, provider, depth=0):
        try:
            if not url_in_scope(url, config.domain) or urlparse(url).username:
                return
            url = canonical_url(url)
        except ValueError:
            return
        digest = key(url)
        row = con.execute(select(urls).where(urls.c.scan_id == sid, urls.c.key == digest)).mappings().first()
        if row:
            con.execute(update(urls).where(urls.c.id == row["id"]).values(providers=sorted(set(row["providers"] + [provider]))))
            return
        count = con.scalar(select(func.count()).select_from(urls).where(urls.c.scan_id == sid))
        if count >= config.max_urls:
            return
        host = urlparse(url).hostname
        if not con.execute(select(hosts.c.host).where(hosts.c.scan_id == sid, hosts.c.host == host)).first():
            con.execute(insert(hosts).values(scan_id=sid, host=host, data={}))
            if config.prober != 'none':
                base = urlparse(url)._replace(path='/', query='', fragment='').geturl()
                self.enqueue(con, sid, 'probe', {'url': base}, host, host)
        con.execute(insert(urls).values(id=uid(), scan_id=sid, key=digest, url=url, host=host,
            depth=depth, providers=[provider], state="discovered"))
        # Coverage is computed from retained page records, never a hidden global cache.
        covered = set()
        for coverage in con.execute(select(pages.c.coverage).join(scans).where(
                scans.c.domain == config.domain, pages.c.key == digest)).scalars():
            covered.update(coverage)
        if set(config.coverage()) <= covered:
            con.execute(update(urls).where(urls.c.scan_id == sid, urls.c.key == digest).values(state="covered"))
            return
        if depth <= config.max_depth:
            self.enqueue(con, sid, "crawl", {"url": url, "depth": depth}, url, host)

    def add_finding(self, con, sid, finding, proof):
        if finding['kind'] == 'blh':
            from .analyzers import target_identity
            finding = {**finding, 'url': target_identity(finding['url'])}
        digest = key(finding["kind"] + ":" + finding["url"])
        fid = con.scalar(select(findings.c.id).where(findings.c.key == digest))
        is_new = fid is None
        if is_new:
            fid = uid()
            con.execute(insert(findings).values(id=fid, key=digest, created_at=time.time(),
                status="discovered", confidence="low", reason="Candidate discovered; not yet validated", data={},
                **finding))
        exists = con.execute(select(references).where(references.c.scan_id == sid, references.c.finding_id == fid)).first()
        if not exists:
            con.execute(insert(references).values(scan_id=sid, finding_id=fid, is_new=is_new))
        proof_key = key(fid + ":" + str(sorted(proof.items())))
        if not con.execute(select(evidence.c.id).where(evidence.c.scan_id == sid, evidence.c.key == proof_key)).first():
            con.execute(insert(evidence).values(id=uid(), scan_id=sid, finding_id=fid, key=proof_key, data=proof))
        if is_new:
            self.enqueue(con, sid, "validate", {"finding_id": fid, **finding}, fid, urlparse(finding["url"]).hostname)
        return not exists

    def complete(self, job, output):
        config = ScanConfig(**job["config"])
        sid = job["scan_id"]
        with self.tx() as con:
            if not self.valid(con, job):
                return False
            if "page" in output:
                page = output["page"]
                digest = key(job["payload"]["url"])
                previous = con.scalar(select(pages.c.id).where(pages.c.scan_id == sid, pages.c.key == digest))
                coverage = config.coverage()
                if output.get('browser'):
                    coverage = [item for item in coverage if item != 'render:browser']
                values = dict(url=job["payload"]["url"], coverage=coverage, data=page, created_at=time.time())
                if previous:
                    con.execute(update(pages).where(pages.c.id == previous).values(**values))
                else:
                    con.execute(insert(pages).values(id=uid(), scan_id=sid, key=digest, **values))
                con.execute(update(urls).where(urls.c.scan_id == sid, urls.c.key == digest).values(state="visited"))
            for item in output.get("urls", []):
                self.add_url(con, sid, config, **item)
            new_targets = 0
            for item in output.get("findings", []):
                if self.add_finding(con, sid, item["finding"], item["evidence"]):
                    new_targets += 1
                    if new_targets <= 10:
                        self.log(con, sid, f"[FOUND] {item['finding']['category']} | " +
                                 job_label({'kind': 'finding', 'payload': item['finding']}))
            if output.get("browser"):
                browser_count = con.scalar(select(func.count()).select_from(jobs).where(jobs.c.scan_id == sid, jobs.c.kind == "browser"))
                if browser_count < config.browser_budget:
                    self.enqueue(con, sid, "browser", job["payload"], job["payload"]["url"], job["host"])
            if "validation" in output:
                current = con.scalar(select(findings.c.data).where(findings.c.id == job['payload']['finding_id'])) or {}
                if 'manual_status' in current:
                    output['validation']['data'] = {**output['validation'].get('data', {}),
                                                    'manual_status': current['manual_status']}
                con.execute(update(findings).where(findings.c.id == job["payload"]["finding_id"])
                    .values(**output["validation"]))
            if "probe" in output:
                con.execute(update(hosts).where(hosts.c.scan_id == sid, hosts.c.host == job['host'])
                            .values(data=output['probe'], probed_at=time.time()))
            con.execute(update(jobs).where(jobs.c.id == job["id"]).values(state="done", token=None, lease_until=None))
            if output.get("message"):
                self.log(con, sid, f"[{job['kind'].upper()}] {output['message']}")
            if 'page' in output:
                p = output['page']
                repeated = len(output.get('findings', [])) - new_targets
                self.log(con, sid, f"[{job['kind'].upper()}] {job_label(job)} | HTTP {p.get('http_code') or '-'} | "
                         f"{len(output.get('urls', []))} extracted URLs | {new_targets} new targets | {repeated} repeated targets merged" +
                         (f" | {p['error']}" if p.get('error') else ''))
            elif 'probe' in output:
                p = output['probe']
                self.log(con, sid, f"[PROBE] {job_label(job)} | HTTP {p.get('http_code', p.get('status_code')) or '-'} | "
                         f"{p.get('error') or p.get('reason') or 'host check complete'}")
            elif 'validation' in output:
                self.log(con, sid, f"[VALIDATE] {job_label(job)} | {output['validation']['status']} | "
                         f"{output['validation'].get('reason', '')}")
            return True

    def results(self, sid, limit=100, offset=0):
        with self.engine.connect() as con:
            rows = con.execute(select(findings, references.c.is_new).join(references)
                .where(references.c.scan_id == sid).order_by(findings.c.created_at, findings.c.id)
                .limit(limit).offset(offset)).mappings().all()
            return [{**r, "evidence": [dict(e[0]) for e in con.execute(select(evidence.c.data).where(
                evidence.c.scan_id == sid, evidence.c.finding_id == r["id"]))]} for r in rows]

    def inventory(self, sid, limit=100, offset=0):
        with self.engine.connect() as con:
            return [dict(r) for r in con.execute(select(urls).where(urls.c.scan_id == sid)
                .order_by(urls.c.host, urls.c.url).limit(limit).offset(offset)).mappings()]

    def assets(self, sid, limit=100, offset=0):
        with self.engine.connect() as con:
            return [dict(r) for r in con.execute(select(hosts).where(hosts.c.scan_id == sid)
                .order_by(hosts.c.host).limit(limit).offset(offset)).mappings()]
