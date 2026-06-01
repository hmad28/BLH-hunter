import asyncio
import json
import re
import sqlite3
from typing import Optional
from urllib.parse import urlparse

import httpx

from ..shared import (
    canonical_url, canonical_target_url, utc_now_iso,
    url_in_scope, host_matches_domain,
    domain_base_urls, fetch_sitemap_urls, fetch_wayback_source_urls,
    fetch_commoncrawl_source_urls, dedupe_urls, should_skip_url,
    discover_sources_by_crawling, MAX_FRESH_TARGETS,
)
from ..db import (
    DB_PATH, log_scan as db_log_scan,
    update_scan_status as db_update_scan_status,
    get_known_source_urls,
    _write_crawl_page as db_write_crawl_page,
)

CRED_CATEGORIES = {
    "config": {
        "label": "Config Files",
        "patterns": [
            r"\.env$", r"\.env\.local$", r"\.env\.production$", r"\.env\.development$",
            r"config\.json$", r"config\.ya?ml$", r"settings\.json$",
            r"application\.properties$", r"web\.config$",
        ],
    },
    "docker": {
        "label": "Docker",
        "patterns": [
            r"dockerfile$", r"docker-compose\.ya?ml$", r"\.dockerignore$",
        ],
    },
    "database": {
        "label": "Database Dumps",
        "patterns": [
            r"\.sql$", r"\.dump$", r"\.backup$", r"\.bak$", r"\.db$", r"\.sqlite$",
        ],
    },
    "archives": {
        "label": "Archives",
        "patterns": [
            r"\.zip$", r"\.tar\.gz$", r"\.tgz$", r"\.rar$", r"\.7z$", r"\.sql\.gz$",
        ],
    },
    "logs": {
        "label": "Logs",
        "patterns": [
            r"\.log$", r"access\.log$", r"error\.log$", r"debug\.log$",
        ],
    },
    "source_control": {
        "label": "Source Control",
        "patterns": [
            r"\.git/config$", r"\.git/HEAD$", r"\.svn/entries$", r"\.hg/",
        ],
    },
    "other": {
        "label": "Other",
        "patterns": [
            r"robots\.txt$", r"sitemap\.xml$", r"crossdomain\.xml$",
            r"phpinfo\.php$", r"server-status$", r"api-docs$",
            r"swagger\.json$", r"openapi\.json$",
        ],
    },
}


def normalize_categories_list(categories) -> list[str]:
    return sorted({c for c in (categories or []) if c in CRED_CATEGORIES})


def categories_key(categories) -> str:
    return ",".join(normalize_categories_list(categories))


def parse_categories_key(value: str) -> set[str]:
    return {c for c in (value or "").split(",") if c in CRED_CATEGORIES}


def load_categories_json(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def get_category_for_pattern(target_url: str, categories: list) -> Optional[str]:
    """Determine which category a URL belongs to based on patterns."""
    path = urlparse(target_url).path.lower()
    for cat in categories:
        cat_info = CRED_CATEGORIES.get(cat)
        if not cat_info:
            continue
        for pat in cat_info["patterns"]:
            if re.search(pat, path, re.IGNORECASE):
                return cat
    return None


def match_sensitive_url(target_url: str, domain: str, categories: list) -> Optional[dict]:
    if not url_in_scope(target_url, domain):
        return None
    path = urlparse(target_url).path.lower().lstrip("/")
    for category in categories:
        cat_info = CRED_CATEGORIES.get(category)
        if not cat_info:
            continue
        for pattern in cat_info["patterns"]:
            if re.search(pattern, path, re.IGNORECASE):
                return {
                    "file_type": category,
                    "pattern_matched": pattern,
                }
    return None


def cred_extract_targets(anchors, final_url, domain, categories, known_target_keys, fresh_keys):
    """Cred-specific target extraction: find URLs matching sensitive file patterns on the target domain."""
    seen = set()
    page_links = []
    pattern_hits = 0
    already_seen_targets = 0
    duplicate_targets = 0
    for href, anchor_text in anchors:
        match = match_sensitive_url(href, domain, categories)
        if not match:
            continue
        pattern_hits += 1
        key = canonical_target_url(href)
        if key in known_target_keys:
            already_seen_targets += 1
            continue
        if key in seen or key in fresh_keys:
            duplicate_targets += 1
            continue
        seen.add(key)
        fresh_keys.add(key)
        page_links.append({
            "target_url": href,
            "anchor_text": anchor_text,
            "file_type": match["file_type"],
            "pattern_matched": match["pattern_matched"],
            "source_url": final_url,
        })
        if len(page_links) >= MAX_FRESH_TARGETS:
            break
    return page_links, {
        "platform_hits": pattern_hits,
        "already_seen_targets": already_seen_targets,
        "duplicate_targets_in_scan": duplicate_targets,
    }


def collect_sensitive_seed_targets(seed_urls, domain, categories, known_target_keys, fresh_keys):
    page_links = []
    for seed_url in seed_urls:
        match = match_sensitive_url(seed_url, domain, categories)
        if not match:
            continue
        key = canonical_target_url(seed_url)
        if key in known_target_keys or key in fresh_keys:
            continue
        fresh_keys.add(key)
        page_links.append({
            "target_url": seed_url,
            "anchor_text": "",
            "file_type": match["file_type"],
            "pattern_matched": match["pattern_matched"],
            "source_url": "seed:passive-discovery",
        })
        if len(page_links) >= MAX_FRESH_TARGETS:
            break
    return page_links


async def run_cred_scan(scan_id: str, domain: str, categories: list,
                        active_bruteforce: bool = False,
                        cancel_event=None, pause_event=None, deleted_scans=None,
                        running_scans=None, paused_scans=None):
    deleted_scans = deleted_scans or set()
    source_count = 0
    total_links = 0
    cancelled = False
    try:
        if scan_id in deleted_scans:
            return
        db_update_scan_status(scan_id, "running", deleted_scans,
                              scans_table="cred_scans")
        db_log_scan(scan_id, f"Cred scan started - domain: {domain} | categories: {', '.join(categories)}",
                    deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")
        if active_bruteforce:
            db_log_scan(scan_id, "Active brute-force requested but MVP runs passive discovery only.",
                        deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")

        async with httpx.AsyncClient(
            headers={"User-Agent": "Lazy-Dorking/1.0 (security research)"},
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            seed_urls = domain_base_urls(domain)

            db_log_scan(scan_id, "Loading sitemap seeds...", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")
            sitemap = await fetch_sitemap_urls(client, domain)
            seed_urls.extend(sitemap)
            db_log_scan(scan_id, f"Sitemap: {len(sitemap)} seeds found", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

            for sub in ("www", "blog", "news", "media", "press", "shop", "store", "support", "help", "docs", "dev", "api", "status"):
                try:
                    sub_sitemap = await fetch_sitemap_urls(client, f"{sub}.{domain}")
                    seed_urls.extend(sub_sitemap)
                    if sub_sitemap:
                        db_log_scan(scan_id, f"Subdomain sitemap {sub}.{domain}: {len(sub_sitemap)} seeds",
                                    deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")
                except Exception:
                    pass

            db_log_scan(scan_id, "Loading Wayback URL seeds...", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")
            wb = await fetch_wayback_source_urls(client, domain)
            seed_urls.extend(wb)
            db_log_scan(scan_id, f"Wayback: {len(wb)} seeds found", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

            db_log_scan(scan_id, "Loading CommonCrawl URL seeds...", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")
            cc = await fetch_commoncrawl_source_urls(client, domain)
            seed_urls.extend(cc)
            db_log_scan(scan_id, f"CommonCrawl: {len(cc)} seeds found", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

            raw_seed_urls = dedupe_urls(seed_urls)
            seed_urls = dedupe_urls(
                [u for u in seed_urls if url_in_scope(u, domain) and not should_skip_url(u)]
            )
            root_seeds = [u for u in seed_urls if urlparse(u).path in ("", "/")]
            other_seeds = [u for u in seed_urls if urlparse(u).path not in ("", "/")]
            seed_urls = root_seeds + other_seeds
            db_log_scan(scan_id, f"Scoped seed pages: {len(seed_urls)}", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

            known_sources = get_known_source_urls(domain, categories, "cred_crawl_pages",
                                                   normalize_categories_list, categories_key, parse_categories_key)
            if known_sources:
                db_log_scan(scan_id, f"Skipping {len(known_sources)} source URL(s) already crawled.",
                            deleted_scans, scans_table="cred_scans", log_table="cred_scan_log")

            def _log_fn(sid, msg):
                db_log_scan(sid, msg, deleted_scans,
                            scans_table="cred_scans", log_table="cred_scan_log")

            def _write_fn(sid, src, final, status, **kw):
                db_write_crawl_page(sid, src, final, status, deleted_scans,
                                    crawl_table="cred_crawl_pages",
                                    scans_table="cred_scans",
                                    platforms_key_fn=categories_key,
                                    load_platforms_fn=load_categories_json,
                                    **kw)

            def _extract_fn(anchors, final_url, _platform_domains, known_target_keys, fresh_keys):
                return cred_extract_targets(anchors, final_url, domain, categories, known_target_keys, fresh_keys)

            source_list, fresh_links, crawl_stats = await discover_sources_by_crawling(
                client, domain, [domain], seed_urls, scan_id, cancel_event,
                known_sources=known_sources,
                extract_targets_fn=_extract_fn,
                log_fn=_log_fn,
                write_crawl_fn=_write_fn,
                pause_event=pause_event,
            )
            fresh_keys = {canonical_target_url(link["target_url"]) for link in fresh_links}
            seed_targets = collect_sensitive_seed_targets(
                raw_seed_urls, domain, categories, set(), fresh_keys
            )
            fresh_links.extend(seed_targets)
            if cancel_event and cancel_event.is_set():
                cancelled = True
            source_count = crawl_stats["visited"]
            db_log_scan(scan_id, f"Source pages crawled: {source_count}", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")
            db_log_scan(scan_id, f"Target links found: {len(fresh_links)}", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

            rows = []
            for lnk in fresh_links:
                if scan_id in deleted_scans:
                    cancelled = True
                    break
                if cancel_event and cancel_event.is_set():
                    cancelled = True
                    break
                rows.append((
                    scan_id, lnk["file_type"], lnk["pattern_matched"], lnk["source_url"],
                    lnk["target_url"], lnk["anchor_text"], utc_now_iso(),
                ))

            if scan_id in deleted_scans:
                return

            con = sqlite3.connect(DB_PATH)
            scan_row = con.execute("SELECT 1 FROM cred_scans WHERE id=?", (scan_id,)).fetchone()
            if scan_row:
                con.executemany(
                    """INSERT INTO cred_results (scan_id, file_type, pattern_matched, source_url, target_url, anchor_text, extracted_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                con.commit()
            con.close()
            if not scan_row:
                return

            total_links = len(rows)
            db_log_scan(scan_id, f"Done. {total_links} links saved.", deleted_scans,
                        scans_table="cred_scans", log_table="cred_scan_log")

        if cancelled:
            db_update_scan_status(scan_id, "cancelled", deleted_scans,
                                  scans_table="cred_scans",
                                  total_sources=source_count, total_links=total_links)
        else:
            db_update_scan_status(scan_id, "done", deleted_scans,
                                  scans_table="cred_scans",
                                  total_sources=source_count, total_links=total_links)
    except Exception as e:
        db_log_scan(scan_id, f"Error: {type(e).__name__}: {str(e)[:200]}", deleted_scans,
                    scans_table="cred_scans", log_table="cred_scan_log")
        db_update_scan_status(scan_id, "error", deleted_scans,
                              scans_table="cred_scans",
                              total_sources=source_count, total_links=total_links)
    finally:
        if running_scans is not None:
            running_scans.pop(scan_id, None)
        if paused_scans is not None:
            paused_scans.pop(scan_id, None)
        deleted_scans.discard(scan_id)
