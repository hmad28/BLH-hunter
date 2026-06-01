import json
import sqlite3
from pathlib import Path

from .shared import canonical_url, canonical_target_url, utc_now_iso

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = str(BASE_DIR / "blh_hunter.db")

FEATURE_STATS = (
    {
        "id": "blh",
        "label": "BLH",
        "title": "Broken Link Hijacking",
        "scans_table": "scans",
        "results_table": "results",
        "crawl_table": "crawl_pages",
        "payload_column": "platforms",
        "usage_label": "Platforms",
        "result_type_column": "platform",
        "result_time_column": "checked_at",
    },
    {
        "id": "bac",
        "label": "BAC",
        "title": "Public Resource Finder",
        "scans_table": "bac_scans",
        "results_table": "bac_results",
        "crawl_table": "bac_crawl_pages",
        "payload_column": "services",
        "usage_label": "Services",
        "result_type_column": "service",
        "result_time_column": "extracted_at",
    },
    {
        "id": "cred",
        "label": "CRED",
        "title": "Credential and Config Finder",
        "scans_table": "cred_scans",
        "results_table": "cred_results",
        "crawl_table": "cred_crawl_pages",
        "payload_column": "categories",
        "usage_label": "Categories",
        "result_type_column": "file_type",
        "result_time_column": "extracted_at",
    },
)


def _load_json_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _usage_rows(rows: list[sqlite3.Row], payload_column: str) -> list[dict]:
    usage: dict[str, dict] = {}
    for row in rows:
        when = row["created_at"] or row["finished_at"] or ""
        for name in _load_json_list(row[payload_column]):
            item = usage.setdefault(name, {"name": name, "count": 0, "last_used_at": ""})
            item["count"] += 1
            if when and when > item["last_used_at"]:
                item["last_used_at"] = when
    return sorted(
        usage.values(),
        key=lambda item: (-item["count"], item["last_used_at"] or "", item["name"]),
        reverse=False,
    )


def _feature_dashboard_stats(con: sqlite3.Connection, spec: dict) -> dict:
    rows = con.execute(
        f"SELECT id, domain, {spec['payload_column']}, status, created_at, finished_at, "
        f"total_sources, total_links FROM {spec['scans_table']} "
        "ORDER BY created_at DESC"
    ).fetchall()
    status_counts = {
        row["status"]: row["count"]
        for row in con.execute(
            f"SELECT status, COUNT(*) AS count FROM {spec['scans_table']} GROUP BY status"
        ).fetchall()
    }
    scan_count = con.execute(f"SELECT COUNT(*) AS count FROM {spec['scans_table']}").fetchone()["count"]
    result_count = con.execute(f"SELECT COUNT(*) AS count FROM {spec['results_table']}").fetchone()["count"]
    source_count = con.execute(
        f"SELECT COALESCE(SUM(total_sources), 0) AS count FROM {spec['scans_table']}"
    ).fetchone()["count"]
    link_count = con.execute(
        f"SELECT COALESCE(SUM(total_links), 0) AS count FROM {spec['scans_table']}"
    ).fetchone()["count"]
    last_used = ""
    for row in rows:
        when = row["created_at"] or row["finished_at"] or ""
        if when and when > last_used:
            last_used = when
    recent = [
        {
            "id": row["id"],
            "domain": row["domain"],
            "status": row["status"],
            "used_for": _load_json_list(row[spec["payload_column"]]),
            "created_at": row["created_at"],
            "finished_at": row["finished_at"],
            "total_sources": row["total_sources"] or 0,
            "total_links": row["total_links"] or 0,
        }
        for row in rows[:8]
    ]
    return {
        "id": spec["id"],
        "label": spec["label"],
        "title": spec["title"],
        "usage_label": spec["usage_label"],
        "scan_count": scan_count,
        "result_count": result_count,
        "source_count": source_count or 0,
        "link_count": link_count or 0,
        "status_counts": status_counts,
        "last_used_at": last_used,
        "usage": _usage_rows(rows, spec["payload_column"])[:8],
        "recent": recent,
    }


def _feature_spec(feature_id: str) -> dict | None:
    return next((spec for spec in FEATURE_STATS if spec["id"] == feature_id), None)


def _dashboard_domains(con: sqlite3.Connection, spec: dict) -> list[dict]:
    rows = con.execute(
        f"SELECT domain, COUNT(*) AS scan_count, MAX(created_at) AS last_scan_at, "
        f"COALESCE(SUM(total_sources), 0) AS total_sources, "
        f"COALESCE(SUM(total_links), 0) AS total_links "
        f"FROM {spec['scans_table']} GROUP BY domain "
        "ORDER BY last_scan_at DESC, domain ASC"
    ).fetchall()
    return [
        {
            "domain": row["domain"],
            "scan_count": row["scan_count"],
            "last_scan_at": row["last_scan_at"],
            "total_sources": row["total_sources"] or 0,
            "total_links": row["total_links"] or 0,
        }
        for row in rows
    ]


def _count_table(con: sqlite3.Connection, table_name: str) -> int:
    return con.execute(f"SELECT COUNT(*) AS count FROM {table_name}").fetchone()["count"]


def _dashboard_target_links(
    con: sqlite3.Connection,
    spec: dict,
    domain: str | None = None,
    q: str = "",
    result_type: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    if spec["id"] == "blh":
        status_select = "r.status AS status"
        http_code_select = "r.http_code AS http_code"
        pattern_select = "'' AS pattern"
    elif spec["id"] == "cred":
        status_select = "'' AS status"
        http_code_select = "NULL AS http_code"
        pattern_select = "r.pattern_matched AS pattern"
    else:
        status_select = "'' AS status"
        http_code_select = "NULL AS http_code"
        pattern_select = "'' AS pattern"
    where = []
    params = []
    if domain:
        where.append("s.domain=?")
        params.append(domain)
    if q:
        like = f"%{q}%"
        where.append(
            f"(r.target_url LIKE ? OR r.source_url LIKE ? OR r.anchor_text LIKE ? "
            f"OR r.{spec['result_type_column']} LIKE ?)"
        )
        params.extend([like, like, like, like])
    if result_type:
        where.append(f"r.{spec['result_type_column']}=?")
        params.append(result_type)
    if status and spec["id"] == "blh":
        where.append("r.status=?")
        params.append(status)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    params.extend([limit, offset])
    rows = con.execute(
        f"SELECT r.scan_id, r.{spec['result_type_column']} AS result_type, r.source_url, r.target_url, "
        f"r.anchor_text, {status_select}, {http_code_select}, "
        f"{pattern_select}, r.{spec['result_time_column']} AS found_at "
        f"FROM {spec['results_table']} r JOIN {spec['scans_table']} s ON s.id=r.scan_id "
        f"{where_sql} ORDER BY r.{spec['result_time_column']} DESC, r.id DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return [
        {
            "scan_id": row["scan_id"],
            "type": row["result_type"],
            "source_url": row["source_url"],
            "target_url": row["target_url"],
            "anchor_text": row["anchor_text"],
            "status": row["status"],
            "http_code": row["http_code"],
            "pattern": row["pattern"],
            "found_at": row["found_at"],
        }
        for row in rows
    ]


def _dashboard_target_link_count(
    con: sqlite3.Connection,
    spec: dict,
    domain: str | None = None,
    q: str = "",
    result_type: str = "",
    status: str = "",
) -> int:
    where = []
    params = []
    if domain:
        where.append("s.domain=?")
        params.append(domain)
    if q:
        like = f"%{q}%"
        where.append(
            f"(r.target_url LIKE ? OR r.source_url LIKE ? OR r.anchor_text LIKE ? "
            f"OR r.{spec['result_type_column']} LIKE ?)"
        )
        params.extend([like, like, like, like])
    if result_type:
        where.append(f"r.{spec['result_type_column']}=?")
        params.append(result_type)
    if status and spec["id"] == "blh":
        where.append("r.status=?")
        params.append(status)
    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    return con.execute(
        f"SELECT COUNT(*) AS count FROM {spec['results_table']} r "
        f"JOIN {spec['scans_table']} s ON s.id=r.scan_id {where_sql}",
        params,
    ).fetchone()["count"]


def _dashboard_domain_crawled_urls(
    con: sqlite3.Connection,
    spec: dict,
    domain: str,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    where = ["s.domain=?"]
    params = [domain]
    limit = max(1, min(int(limit or 100), 500))
    offset = max(0, int(offset or 0))
    params.extend([limit, offset])
    rows = con.execute(
        f"SELECT cp.scan_id, s.domain, cp.platforms_key, cp.source_url, cp.final_url, cp.crawl_status, "
        f"cp.http_code, cp.error_reason, cp.platform_hits, cp.account_hits, cp.crawled_at "
        f"FROM {spec['crawl_table']} cp JOIN {spec['scans_table']} s ON s.id=cp.scan_id "
        f"WHERE {' AND '.join(where)} ORDER BY cp.crawled_at DESC, cp.id DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()
    return [
        {
            "scan_id": row["scan_id"],
            "domain": row["domain"],
            "used_for": row["platforms_key"],
            "source_url": row["source_url"],
            "final_url": row["final_url"],
            "crawl_status": row["crawl_status"],
            "http_code": row["http_code"],
            "error_reason": row["error_reason"],
            "platform_hits": row["platform_hits"] or 0,
            "account_hits": row["account_hits"] or 0,
            "crawled_at": row["crawled_at"],
        }
        for row in rows
    ]


def _dashboard_domain_crawled_count(con: sqlite3.Connection, spec: dict, domain: str, q: str = "") -> int:
    where = ["s.domain=?"]
    params = [domain]
    if q:
        like = f"%{q}%"
        where.append("(cp.source_url LIKE ? OR cp.final_url LIKE ? OR cp.crawl_status LIKE ?)")
        params.extend([like, like, like])
    return con.execute(
        f"SELECT COUNT(*) AS count FROM {spec['crawl_table']} cp "
        f"JOIN {spec['scans_table']} s ON s.id=cp.scan_id WHERE {' AND '.join(where)}",
        params,
    ).fetchone()["count"]


def get_dashboard_stats() -> dict:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        features = [_feature_dashboard_stats(con, spec) for spec in FEATURE_STATS]
    finally:
        con.close()
    return {
        "totals": {
            "scan_count": sum(feature["scan_count"] for feature in features),
            "result_count": sum(feature["result_count"] for feature in features),
            "source_count": sum(feature["source_count"] for feature in features),
            "link_count": sum(feature["link_count"] for feature in features),
        },
        "features": features,
    }


def get_dashboard_feature_detail(feature_id: str) -> dict | None:
    spec = _feature_spec(feature_id)
    if not spec:
        return None
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        feature = _feature_dashboard_stats(con, spec)
        domains = _dashboard_domains(con, spec)
        crawled_url_count = _count_table(con, spec["crawl_table"])
        target_link_count = _count_table(con, spec["results_table"])
    finally:
        con.close()
    return {
        "feature": feature,
        "domains": domains,
        "crawled_url_count": crawled_url_count,
        "target_link_count": target_link_count,
    }


def get_dashboard_domain_detail(
    feature_id: str,
    domain: str,
    q: str = "",
    result_type: str = "",
    status: str = "",
    limit: int = 100,
    offset: int = 0,
    view: str = "targets",
) -> dict | None:
    spec = _feature_spec(feature_id)
    if not spec:
        return None
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        domains = _dashboard_domains(con, spec)
        domain_row = next((row for row in domains if row["domain"] == domain), None)
        if not domain_row:
            return None
        payload = {
            "feature_id": feature_id,
            "domain": domain_row,
            "target_count": _dashboard_target_link_count(con, spec, domain, q, result_type, status),
            "crawled_count": _dashboard_domain_crawled_count(con, spec, domain),
            "limit": max(1, min(int(limit or 100), 500)),
            "offset": max(0, int(offset or 0)),
            "view": view,
        }
        if view == "crawled":
            payload["crawled_urls"] = _dashboard_domain_crawled_urls(con, spec, domain, limit, offset)
        else:
            payload["target_links"] = _dashboard_target_links(con, spec, domain, q, result_type, status, limit, offset)
        return {
            **payload,
        }
    finally:
        con.close()


def _ensure_crawl_pages_schema(con, table_name="crawl_pages", platforms_key_fn=None, load_platforms_fn=None):
    columns = {row[1] for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if "domain" not in columns:
        con.execute(f"ALTER TABLE {table_name} ADD COLUMN domain TEXT")
    if "platforms_key" not in columns:
        con.execute(f"ALTER TABLE {table_name} ADD COLUMN platforms_key TEXT")
    if "canonical_source_url" not in columns:
        con.execute(f"ALTER TABLE {table_name} ADD COLUMN canonical_source_url TEXT")
    rows = con.execute(
        f"SELECT id, source_url FROM {table_name} "
        "WHERE canonical_source_url IS NULL OR canonical_source_url=''"
    ).fetchall()
    if rows:
        con.executemany(
            f"UPDATE {table_name} SET canonical_source_url=? WHERE id=?",
            [(canonical_url(row[1]), row[0]) for row in rows if row[1]],
        )
    if platforms_key_fn and load_platforms_fn:
        rows = con.execute(
            f"SELECT cp.id, cp.domain, cp.platforms_key, s.domain, s.platforms "
            f"FROM {table_name} cp LEFT JOIN scans s ON s.id=cp.scan_id "
            "WHERE cp.domain IS NULL OR cp.domain='' OR cp.platforms_key IS NULL OR cp.platforms_key=''"
        ).fetchall()
        updates = []
        for crawl_id, current_domain, current_key, scan_domain, scan_platforms in rows:
            domain_value = current_domain or scan_domain
            key_value = current_key or platforms_key_fn(load_platforms_fn(scan_platforms))
            updates.append((domain_value, key_value, crawl_id))
        if updates:
            con.executemany(
                f"UPDATE {table_name} SET domain=?, platforms_key=? WHERE id=?",
                updates,
            )


def _ensure_columns(con, table_name: str, columns: dict[str, str]):
    existing = {row[1] for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    for column, definition in columns.items():
        if column not in existing:
            con.execute(f"ALTER TABLE {table_name} ADD COLUMN {column} {definition}")


def _scan_payload_column(con, table_name: str) -> str | None:
    columns = {row[1] for row in con.execute(f"PRAGMA table_info({table_name})").fetchall()}
    for candidate in ("platforms", "services", "categories"):
        if candidate in columns:
            return candidate
    return None


def init_db():
    from .blh.scanner import PLATFORM_DOMAINS, normalize_platforms_list, platforms_key, load_platforms_json

    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            platforms TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            finished_at TEXT,
            total_sources INTEGER DEFAULT 0,
            total_links INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            platform TEXT,
            source_url TEXT,
            target_url TEXT,
            anchor_text TEXT,
            status TEXT,
            http_code INTEGER,
            final_url TEXT,
            error_reason TEXT,
            status_overridden INTEGER DEFAULT 0,
            checked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            message TEXT,
            created_at TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
        CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_results_target ON results(target_url);
        CREATE INDEX IF NOT EXISTS idx_results_source ON results(source_url);
        CREATE TABLE IF NOT EXISTS crawl_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            domain TEXT,
            platforms_key TEXT,
            source_url TEXT NOT NULL,
            canonical_source_url TEXT,
            final_url TEXT,
            crawl_status TEXT NOT NULL,
            http_code INTEGER,
            error_reason TEXT,
            platform_hits INTEGER DEFAULT 0,
            account_hits INTEGER DEFAULT 0,
            crawled_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_crawl_pages_scan ON crawl_pages(scan_id);
        CREATE INDEX IF NOT EXISTS idx_crawl_pages_domain ON crawl_pages(domain);
        CREATE INDEX IF NOT EXISTS idx_crawl_pages_source ON crawl_pages(source_url);

        -- BAC tables
        CREATE TABLE IF NOT EXISTS bac_scans (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            services TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            finished_at TEXT,
            total_sources INTEGER DEFAULT 0,
            total_links INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS bac_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            service TEXT,
            source_url TEXT,
            target_url TEXT,
            anchor_text TEXT,
            extracted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS bac_scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            message TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS bac_crawl_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            domain TEXT,
            platforms_key TEXT,
            source_url TEXT NOT NULL,
            canonical_source_url TEXT,
            final_url TEXT,
            crawl_status TEXT NOT NULL,
            http_code INTEGER,
            error_reason TEXT,
            platform_hits INTEGER DEFAULT 0,
            account_hits INTEGER DEFAULT 0,
            crawled_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bac_scans_domain ON bac_scans(domain);
        CREATE INDEX IF NOT EXISTS idx_bac_results_scan ON bac_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_bac_results_target ON bac_results(target_url);
        CREATE INDEX IF NOT EXISTS idx_bac_crawl_pages_scan ON bac_crawl_pages(scan_id);
        CREATE INDEX IF NOT EXISTS idx_bac_crawl_pages_domain ON bac_crawl_pages(domain);
        CREATE INDEX IF NOT EXISTS idx_bac_crawl_pages_source ON bac_crawl_pages(source_url);

        -- Cred tables
        CREATE TABLE IF NOT EXISTS cred_scans (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            categories TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            finished_at TEXT,
            total_sources INTEGER DEFAULT 0,
            total_links INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS cred_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            file_type TEXT,
            pattern_matched TEXT,
            source_url TEXT,
            target_url TEXT,
            anchor_text TEXT,
            extracted_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cred_scan_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            message TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS cred_crawl_pages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            domain TEXT,
            platforms_key TEXT,
            source_url TEXT NOT NULL,
            canonical_source_url TEXT,
            final_url TEXT,
            crawl_status TEXT NOT NULL,
            http_code INTEGER,
            error_reason TEXT,
            platform_hits INTEGER DEFAULT 0,
            account_hits INTEGER DEFAULT 0,
            crawled_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cred_scans_domain ON cred_scans(domain);
        CREATE INDEX IF NOT EXISTS idx_cred_results_scan ON cred_results(scan_id);
        CREATE INDEX IF NOT EXISTS idx_cred_results_target ON cred_results(target_url);
        CREATE INDEX IF NOT EXISTS idx_cred_crawl_pages_scan ON cred_crawl_pages(scan_id);
        CREATE INDEX IF NOT EXISTS idx_cred_crawl_pages_domain ON cred_crawl_pages(domain);
        CREATE INDEX IF NOT EXISTS idx_cred_crawl_pages_source ON cred_crawl_pages(source_url);
    """
    )
    _ensure_crawl_pages_schema(con, "crawl_pages", platforms_key, load_platforms_json)
    _ensure_columns(con, "results", {"status_overridden": "INTEGER DEFAULT 0"})
    _ensure_columns(con, "cred_results", {"file_type": "TEXT", "pattern_matched": "TEXT"})
    cred_columns = {row[1] for row in con.execute("PRAGMA table_info(cred_results)").fetchall()}
    if "category" in cred_columns:
        con.execute("UPDATE cred_results SET file_type=COALESCE(file_type, category) WHERE file_type IS NULL")
    con.execute("CREATE INDEX IF NOT EXISTS idx_crawl_pages_canonical_source ON crawl_pages(canonical_source_url)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_crawl_pages_domain_source_platforms ON crawl_pages(domain, canonical_source_url, platforms_key)")
    con.execute(
        "UPDATE scans SET status='cancelled', finished_at=? WHERE status IN ('pending', 'running')",
        (utc_now_iso(),),
    )
    con.execute(
        "UPDATE bac_scans SET status='cancelled', finished_at=? WHERE status IN ('pending', 'running')",
        (utc_now_iso(),),
    )
    con.execute(
        "UPDATE cred_scans SET status='cancelled', finished_at=? WHERE status IN ('pending', 'running')",
        (utc_now_iso(),),
    )
    con.commit()
    con.close()


def log_scan(scan_id: str, message: str, deleted_scans: set = None, scans_table="scans", log_table="scan_log"):
    deleted_scans = deleted_scans or set()
    if scan_id in deleted_scans:
        return
    con = sqlite3.connect(DB_PATH)
    row = con.execute(f"SELECT 1 FROM {scans_table} WHERE id=?", (scan_id,)).fetchone()
    if not row:
        con.close()
        return
    con.execute(
        f"INSERT INTO {log_table} (scan_id, message, created_at) VALUES (?, ?, ?)",
        (scan_id, message, utc_now_iso()),
    )
    con.commit()
    con.close()


def update_scan_status(scan_id: str, status: str, deleted_scans: set = None,
                       scans_table="scans", total_sources=None, total_links=None):
    deleted_scans = deleted_scans or set()
    if scan_id in deleted_scans:
        return
    con = sqlite3.connect(DB_PATH)
    fields = ["status=?"]
    params = [status]
    if status in {"done", "error", "cancelled"}:
        fields.append("finished_at=?")
        params.append(utc_now_iso())
    if total_sources is not None:
        fields.append("total_sources=?")
        params.append(total_sources)
    if total_links is not None:
        fields.append("total_links=?")
        params.append(total_links)
    params.append(scan_id)
    con.execute(f"UPDATE {scans_table} SET {', '.join(fields)} WHERE id=?", params)
    con.commit()
    con.close()


def get_cached_target_statuses(results_table="results"):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        f"SELECT target_url, status, http_code, final_url, error_reason, checked_at "
        f"FROM {results_table} WHERE status IN ('alive', 'broken', 'redirect', 'blocked', 'timeout', 'unknown') "
        "ORDER BY id ASC"
    ).fetchall()
    con.close()
    cache = {}
    for row in rows:
        cache[canonical_target_url(row[0])] = {
            "status": row[1],
            "http_code": row[2],
            "final_url": row[3],
            "error_reason": row[4],
            "checked_at": row[5],
        }
    return cache


def get_seen_target_urls(results_table="results"):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(f"SELECT DISTINCT target_url FROM {results_table}").fetchall()
    con.close()
    return {canonical_target_url(row[0]) for row in rows}


def get_known_source_urls(domain: str, platforms: list[str], crawl_table="crawl_pages",
                          normalize_fn=None, platforms_key_fn=None, parse_key_fn=None):
    required_platforms = set(normalize_fn(platforms)) if normalize_fn else set(platforms)
    if not required_platforms:
        return set()
    con = sqlite3.connect(DB_PATH)
    rows = con.execute(
        f"SELECT COALESCE(NULLIF(canonical_source_url, ''), source_url), platforms_key "
        f"FROM {crawl_table} WHERE domain=?",
        (domain,),
    ).fetchall()
    con.close()
    coverage_by_source: dict[str, set[str]] = {}
    for source_url, key in rows:
        if not source_url:
            continue
        source_key = canonical_url(source_url)
        if parse_key_fn:
            coverage_by_source.setdefault(source_key, set()).update(parse_key_fn(key))
        else:
            coverage_by_source.setdefault(source_key, set()).add(key)
    return {
        source_key
        for source_key, covered_platforms in coverage_by_source.items()
        if required_platforms.issubset(covered_platforms)
    }


def _write_crawl_page(scan_id, source_url, final_url, crawl_status,
                      deleted_scans=None, crawl_table="crawl_pages",
                      scans_table="scans", http_code=None, error_reason=None,
                      platform_hits=0, account_hits=0, domain=None, platforms=None,
                      platforms_key_fn=None, load_platforms_fn=None):
    deleted_scans = deleted_scans or set()
    if scan_id in deleted_scans:
        return
    canonical_source = canonical_url(source_url)
    con = sqlite3.connect(DB_PATH)
    payload_column = _scan_payload_column(con, scans_table)
    select_clause = f"domain, {payload_column}" if payload_column else "domain, NULL"
    scan_row = con.execute(f"SELECT {select_clause} FROM {scans_table} WHERE id=?", (scan_id,)).fetchone()
    if not scan_row:
        con.close()
        return
    domain = domain or scan_row[0]
    if platforms_key_fn and load_platforms_fn:
        platform_key = platforms_key_fn(platforms if platforms is not None else load_platforms_fn(scan_row[1]))
    else:
        platform_key = ",".join(platforms) if platforms else scan_row[1]
    con.execute(
        f"""INSERT INTO {crawl_table} (scan_id, domain, platforms_key, source_url, canonical_source_url,
           final_url, crawl_status, http_code, error_reason, platform_hits, account_hits,
           crawled_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (scan_id, domain, platform_key, source_url, canonical_source, final_url, crawl_status,
         http_code, error_reason, platform_hits, account_hits, utc_now_iso()),
    )
    con.commit()
    con.close()
