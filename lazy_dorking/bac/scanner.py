import asyncio
import json
import re
import sqlite3
from html import unescape
from typing import Optional
from urllib.parse import quote_plus, urlparse

import httpx

from ..shared import (
    canonical_url, canonical_target_url, utc_now_iso,
    url_in_scope, host_matches_any,
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

BAC_SERVICES = {
    "google_drive": ["drive.google.com"],
    "google_docs": ["docs.google.com"],
    "google_sheets": ["sheets.google.com"],
    "google_slides": ["slides.google.com"],
    "google_forms": ["forms.gle"],
    "google_sites": ["sites.google.com"],
    "onedrive": ["onedrive.live.com"],
    "sharepoint": ["sharepoint.com"],
    "dropbox": ["dropbox.com"],
    "box": ["box.com"],
    "mega": ["mega.nz"],
    "mediafire": ["mediafire.com"],
    "github": ["github.com"],
    "gitlab": ["gitlab.com"],
    "bitbucket": ["bitbucket.org"],
    "notion": ["notion.so"],
    "confluence": ["confluence.com"],
    "jira": ["jira.com"],
    "trello": ["trello.com"],
    "figma": ["figma.com"],
    "miro": ["miro.com"],
    "canva": ["canva.com"],
    "prezi": ["prezi.com"],
    "pitch": ["pitch.com"],
}


def normalize_services_list(services) -> list[str]:
    return sorted({s for s in (services or []) if s in BAC_SERVICES})


def services_key(services) -> str:
    return ",".join(normalize_services_list(services))


def parse_services_key(value: str) -> set[str]:
    return {s for s in (value or "").split(",") if s in BAC_SERVICES}


def load_services_json(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def get_service_for_domain(pd: str, services: list) -> Optional[str]:
    for s in services:
        if pd in BAC_SERVICES.get(s, []):
            return s
    return pd


def is_allowed_bac_target(href: str, platform_domain: str) -> bool:
    parsed = urlparse(href)
    if platform_domain == "drive.google.com":
        path = parsed.path.lower()
        tail = f"{parsed.path}?{parsed.query}#{parsed.fragment}".lower()
        return path.startswith("/drive/") and "sharing" not in tail
    return True


def bac_extract_targets(anchors, final_url, platform_domains, known_target_keys, fresh_keys):
    """BAC-specific target extraction: collect all links to selected services."""
    seen = set()
    page_links = []
    platform_hits = 0
    already_seen_targets = 0
    duplicate_targets = 0
    for href, anchor_text in anchors:
        parsed = urlparse(href)
        pd = host_matches_any(parsed.hostname or "", platform_domains)
        if not pd:
            continue
        if not is_allowed_bac_target(href, pd):
            continue
        platform_hits += 1
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
            "platform_domain": pd,
            "source_url": final_url,
        })
        if len(page_links) >= MAX_FRESH_TARGETS:
            break
    return page_links, {
        "platform_hits": platform_hits,
        "already_seen_targets": already_seen_targets,
        "duplicate_targets_in_scan": duplicate_targets,
    }


async def fetch_bing_dork_targets(client, domain, platform_domains, known_target_keys, fresh_keys):
    """Best-effort SERP supplement. Skips silently on rate limit or markup drift."""
    dork_links = []
    warnings = []
    for service_domain in platform_domains:
        query = quote_plus(f"site:*.{domain} {service_domain}")
        url = f"https://www.bing.com/search?q={query}"
        try:
            resp = await client.get(url, timeout=12, follow_redirects=True)
        except Exception as e:
            warnings.append(f"Bing dork failed for {service_domain}: {type(e).__name__}")
            continue
        if resp.status_code in {403, 429}:
            warnings.append(f"Bing dork rate-limited for {service_domain}: HTTP {resp.status_code}")
            continue
        if resp.status_code != 200:
            warnings.append(f"Bing dork skipped for {service_domain}: HTTP {resp.status_code}")
            continue
        hrefs = re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"']", resp.text, re.IGNORECASE)
        added = 0
        for href in hrefs:
            href = unescape(href)
            parsed = urlparse(href)
            pd = host_matches_any(parsed.hostname or "", platform_domains)
            if not pd:
                continue
            if not is_allowed_bac_target(href, pd):
                continue
            key = canonical_target_url(href)
            if key in known_target_keys or key in fresh_keys:
                continue
            fresh_keys.add(key)
            dork_links.append({
                "target_url": href,
                "anchor_text": "Bing dork result",
                "platform_domain": pd,
                "source_url": f"dork:site:*.{domain} {service_domain}",
            })
            added += 1
            if added >= 10 or len(dork_links) >= MAX_FRESH_TARGETS:
                break
        await asyncio.sleep(1.0)
        if len(dork_links) >= MAX_FRESH_TARGETS:
            break
    return dork_links, warnings


async def run_bac_scan(scan_id: str, domain: str, services: list,
                       include_dorking: bool = False,
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
                              scans_table="bac_scans")
        db_log_scan(scan_id, f"BAC scan started - domain: {domain} | services: {', '.join(services)}",
                    deleted_scans, scans_table="bac_scans", log_table="bac_scan_log")

        selected_pds = []
        for s in services:
            selected_pds.extend(BAC_SERVICES.get(s, []))

        async with httpx.AsyncClient(
            headers={"User-Agent": "Lazy-Dorking/1.0 (security research)"},
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            seed_urls = domain_base_urls(domain)

            db_log_scan(scan_id, "Loading sitemap seeds...", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")
            sitemap = await fetch_sitemap_urls(client, domain)
            seed_urls.extend(sitemap)
            db_log_scan(scan_id, f"Sitemap: {len(sitemap)} seeds found", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

            for sub in ("www", "blog", "news", "media", "press", "shop", "store", "support", "help", "docs", "dev", "api", "status"):
                try:
                    sub_sitemap = await fetch_sitemap_urls(client, f"{sub}.{domain}")
                    seed_urls.extend(sub_sitemap)
                    if sub_sitemap:
                        db_log_scan(scan_id, f"Subdomain sitemap {sub}.{domain}: {len(sub_sitemap)} seeds",
                                    deleted_scans, scans_table="bac_scans", log_table="bac_scan_log")
                except Exception:
                    pass

            db_log_scan(scan_id, "Loading Wayback URL seeds...", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")
            wb = await fetch_wayback_source_urls(client, domain)
            seed_urls.extend(wb)
            db_log_scan(scan_id, f"Wayback: {len(wb)} seeds found", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

            db_log_scan(scan_id, "Loading CommonCrawl URL seeds...", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")
            cc = await fetch_commoncrawl_source_urls(client, domain)
            seed_urls.extend(cc)
            db_log_scan(scan_id, f"CommonCrawl: {len(cc)} seeds found", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

            seed_urls = dedupe_urls(
                [u for u in seed_urls if url_in_scope(u, domain) and not should_skip_url(u)]
            )
            root_seeds = [u for u in seed_urls if urlparse(u).path in ("", "/")]
            other_seeds = [u for u in seed_urls if urlparse(u).path not in ("", "/")]
            seed_urls = root_seeds + other_seeds
            db_log_scan(scan_id, f"Scoped seed pages: {len(seed_urls)}", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

            known_sources = get_known_source_urls(domain, services, "bac_crawl_pages",
                                                   normalize_services_list, services_key, parse_services_key)
            if known_sources:
                db_log_scan(scan_id, f"Skipping {len(known_sources)} source URL(s) already crawled.",
                            deleted_scans, scans_table="bac_scans", log_table="bac_scan_log")

            def _log_fn(sid, msg):
                db_log_scan(sid, msg, deleted_scans,
                            scans_table="bac_scans", log_table="bac_scan_log")

            def _write_fn(sid, src, final, status, **kw):
                db_write_crawl_page(sid, src, final, status, deleted_scans,
                                    crawl_table="bac_crawl_pages",
                                    scans_table="bac_scans",
                                    platforms_key_fn=services_key,
                                    load_platforms_fn=load_services_json,
                                    **kw)

            source_list, fresh_links, crawl_stats = await discover_sources_by_crawling(
                client, domain, selected_pds, seed_urls, scan_id, cancel_event,
                known_sources=known_sources,
                extract_targets_fn=bac_extract_targets,
                log_fn=_log_fn,
                write_crawl_fn=_write_fn,
                pause_event=pause_event,
            )
            if include_dorking and not (cancel_event and cancel_event.is_set()):
                db_log_scan(scan_id, "Running optional Bing dork supplement...", deleted_scans,
                            scans_table="bac_scans", log_table="bac_scan_log")
                fresh_keys = {canonical_target_url(link["target_url"]) for link in fresh_links}
                dork_links, dork_warnings = await fetch_bing_dork_targets(
                    client, domain, selected_pds, set(), fresh_keys
                )
                fresh_links.extend(dork_links)
                for warning in dork_warnings[:5]:
                    db_log_scan(scan_id, warning, deleted_scans,
                                scans_table="bac_scans", log_table="bac_scan_log")
                db_log_scan(scan_id, f"Dork supplement: {len(dork_links)} links found", deleted_scans,
                            scans_table="bac_scans", log_table="bac_scan_log")
            if cancel_event and cancel_event.is_set():
                cancelled = True
            source_count = crawl_stats["visited"]
            db_log_scan(scan_id, f"Source pages crawled: {source_count}", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")
            db_log_scan(scan_id, f"Target links found: {len(fresh_links)}", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

            rows = []
            for lnk in fresh_links:
                if scan_id in deleted_scans:
                    cancelled = True
                    break
                if cancel_event and cancel_event.is_set():
                    cancelled = True
                    break
                service_name = get_service_for_domain(lnk["platform_domain"], services)
                rows.append((
                    scan_id, service_name, lnk["source_url"], lnk["target_url"],
                    lnk["anchor_text"], utc_now_iso(),
                ))

            if scan_id in deleted_scans:
                return

            con = sqlite3.connect(DB_PATH)
            scan_row = con.execute("SELECT 1 FROM bac_scans WHERE id=?", (scan_id,)).fetchone()
            if scan_row:
                con.executemany(
                    """INSERT INTO bac_results (scan_id, service, source_url, target_url, anchor_text, extracted_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    rows,
                )
                con.commit()
            con.close()
            if not scan_row:
                return

            total_links = len(rows)
            db_log_scan(scan_id, f"Done. {total_links} links saved.", deleted_scans,
                        scans_table="bac_scans", log_table="bac_scan_log")

        if cancelled:
            db_update_scan_status(scan_id, "cancelled", deleted_scans,
                                  scans_table="bac_scans",
                                  total_sources=source_count, total_links=total_links)
        else:
            db_update_scan_status(scan_id, "done", deleted_scans,
                                  scans_table="bac_scans",
                                  total_sources=source_count, total_links=total_links)
    except Exception as e:
        db_log_scan(scan_id, f"Error: {type(e).__name__}: {str(e)[:200]}", deleted_scans,
                    scans_table="bac_scans", log_table="bac_scan_log")
        db_update_scan_status(scan_id, "error", deleted_scans,
                              scans_table="bac_scans",
                              total_sources=source_count, total_links=total_links)
    finally:
        if running_scans is not None:
            running_scans.pop(scan_id, None)
        if paused_scans is not None:
            paused_scans.pop(scan_id, None)
        deleted_scans.discard(scan_id)
