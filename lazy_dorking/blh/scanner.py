import asyncio
import json
import re
import sqlite3
from typing import Optional
from urllib.parse import urlparse

import httpx

from ..shared import (
    canonical_url, canonical_target_url, utc_now_iso,
    url_in_scope, host_matches_any, host_matches_domain,
    domain_base_urls, fetch_sitemap_urls, fetch_wayback_source_urls,
    fetch_commoncrawl_source_urls, dedupe_urls, should_skip_url,
    discover_sources_by_crawling, MAX_FRESH_TARGETS,
)
from ..db import (
    DB_PATH, log_scan as db_log_scan,
    update_scan_status as db_update_scan_status,
    get_cached_target_statuses,
    get_known_source_urls, _write_crawl_page as db_write_crawl_page,
)

PLATFORM_DOMAINS = {
    "twitter": ["twitter.com", "x.com"],
    "instagram": ["instagram.com"],
    "tiktok": ["tiktok.com"],
    "facebook": ["facebook.com", "fb.com"],
    "youtube": ["youtube.com"],
    "linkedin": ["linkedin.com"],
    "github": ["github.com"],
    "discord": ["discord.gg", "discord.com"],
    "bitly": ["bit.ly"],
    "flickr": ["flickr.com"],
}

SUBDOMAIN_SITEMAP_CANDIDATES = (
    "www", "blog", "news", "media", "press", "shop", "store",
    "support", "help", "docs", "dev", "api", "status",
)


def normalize_platforms_list(platforms) -> list[str]:
    return sorted({p for p in (platforms or []) if p in PLATFORM_DOMAINS})


def platforms_key(platforms) -> str:
    return ",".join(normalize_platforms_list(platforms))


def parse_platforms_key(value: str) -> set[str]:
    return {p for p in (value or "").split(",") if p in PLATFORM_DOMAINS}


def load_platforms_json(value: str) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


ACCOUNT_PATH_PATTERNS = {
    "twitter.com": re.compile(r"^/[A-Za-z0-9_]{1,50}/?$"),
    "x.com":       re.compile(r"^/[A-Za-z0-9_]{1,50}/?$"),
    "instagram.com": re.compile(r"^/[A-Za-z0-9_.]{1,50}/?$"),
    "facebook.com":  re.compile(r"^/[A-Za-z0-9_.-]{1,80}/?$"),
    "fb.com":        re.compile(r"^/[A-Za-z0-9_.-]{1,80}/?$"),
    "youtube.com":   re.compile(r"^/@[\w.-]{1,80}/?$"),
    "linkedin.com":  re.compile(r"^/in/[\w%-]{1,100}/?$"),
    "github.com":    re.compile(r"^/[A-Za-z0-9-]{1,39}/?$"),
    "tiktok.com":    re.compile(r"^/@[\w.]{1,50}/?$"),
    "discord.gg":    re.compile(r"^/[A-Za-z0-9-]{1,32}/?$"),
    "discord.com":   re.compile(r"^/invite/[A-Za-z0-9-]{1,32}/?$"),
    "bit.ly":        re.compile(r"^/[A-Za-z0-9_-]{1,128}/?$"),
    "flickr.com":    re.compile(r"^/(?:photos|people)/[A-Za-z0-9@._-]{1,100}/?$"),
}

RESERVED_PATHS: dict[str, frozenset[str]] = {
    "twitter.com": frozenset({
        "home", "login", "logout", "signup", "explore", "search", "notifications",
        "messages", "settings", "i", "intent", "share", "hashtag", "widgets",
        "oauth", "privacy", "tos",
    }),
    "x.com": frozenset({
        "home", "login", "logout", "signup", "explore", "search", "notifications",
        "messages", "settings", "i", "intent", "share", "hashtag", "widgets",
        "oauth", "privacy", "tos",
    }),
    "instagram.com": frozenset({
        "accounts", "explore", "p", "reel", "reels", "stories", "tv", "login",
        "signup", "privacy", "legal", "about", "directory", "developer", "help",
        "press",
    }),
    "facebook.com": frozenset({
        "events", "groups", "pages", "marketplace", "gaming", "watch", "login",
        "signup", "help", "privacy", "legal", "settings", "bookmarks",
        "notifications", "sharer", "dialog", "plugins", "share",
    }),
    "fb.com": frozenset({
        "events", "groups", "pages", "marketplace", "gaming", "watch", "login",
        "signup", "help", "privacy", "legal", "sharer", "dialog", "plugins",
        "share",
    }),
    "youtube.com": frozenset({
        "watch", "results", "feed", "playlist", "channel", "embed", "shorts",
        "live", "gaming", "music", "trending", "account", "signin", "logout",
        "t", "howyoutubeworks", "about", "advertise", "policies", "premium",
    }),
    "bit.ly": frozenset({"pages", "pricing", "sign-in", "sign_up", "login", "oauth"}),
    "flickr.com": frozenset({
        "about", "explore", "groups", "map", "prints", "search", "services",
        "signin", "signup", "upload",
    }),
    "github.com": frozenset({
        "login", "logout", "signup", "explore", "topics", "trending",
        "collections", "events", "marketplace", "pricing", "security",
        "features", "about", "contact", "enterprise", "settings",
        "notifications", "pulls", "issues", "codespaces", "copilot",
    }),
    "linkedin.com": frozenset({
        "feed", "login", "signup", "jobs", "learning", "messaging",
        "notifications", "search", "mynetwork", "events", "groups", "legal",
        "help", "premium", "pulse", "news", "uas",
    }),
    "tiktok.com": frozenset({
        "login", "signup", "explore", "live", "foryou", "following", "trending",
        "discover", "music", "effects", "creators", "legal", "privacy", "about",
    }),
    "discord.gg": frozenset({"login", "register", "app"}),
    "discord.com": frozenset({
        "login", "register", "app", "channels", "events", "store", "discovery",
        "nitro", "safety", "privacy",
    }),
}

PROFILE_FILE_PATH_RE = re.compile(r"\.(?:php|aspx?|jsp|html?|cfm|cgi|pl)$", re.IGNORECASE)

BLOCKED_BODY_MARKERS = (
    "captcha",
    "rate limit",
    "too many requests",
    "access denied",
    "forbidden",
    "verify you are human",
    "unusual traffic",
)
# Markers that genuinely indicate a DELETED/missing account (safe to call broken).
TWITTER_NOT_FOUND_MARKERS = (
    "this account doesn't exist",
    "this account doesn&apos;t exist",
    "hmm...this page doesn't exist",
)
# Ambiguous anti-bot / generic error pages. X serves these (HTTP 200) to
# datacenter/bot IPs even for LIVE accounts, so they must NOT be called broken -
# they mean "could not verify" (blocked), not "account is gone".
TWITTER_BLOCK_MARKERS = (
    "something went wrong, but don't fret",
    "something went wrong. try reloading",
)
# Facebook's unambiguous deleted-page text.
FACEBOOK_NOT_FOUND_MARKERS = (
    "sorry, this page isn't available",
    "the link you followed may be broken",
)
# Facebook shows these to logged-out/bot visitors for live pages too -> ambiguous.
FACEBOOK_BLOCK_MARKERS = (
    "this content isn't available right now",
    "this content isn&apos;t available right now",
    "this page isn't available right now",
    "konten ini tidak tersedia saat ini",
    "cometerrorroute",
)


def is_probably_blocked(resp):
    if resp.status_code != 200:
        return False
    body = (resp.text or "").lower()[:500]
    return any(marker in body for marker in BLOCKED_BODY_MARKERS)


def is_twitter_account_not_found(resp, host):
    if host not in ("twitter.com", "x.com", "www.twitter.com", "www.x.com"):
        return False
    if resp.status_code != 200:
        return False
    body = (resp.text or "").lower()[:2000]
    return any(marker in body for marker in TWITTER_NOT_FOUND_MARKERS)


def is_twitter_blocked(resp, host):
    if host not in ("twitter.com", "x.com", "www.twitter.com", "www.x.com"):
        return False
    if resp.status_code != 200:
        return False
    body = (resp.text or "").lower()[:2000]
    return any(marker in body for marker in TWITTER_BLOCK_MARKERS)


def is_facebook_page_not_found(resp, host):
    if host not in ("facebook.com", "www.facebook.com", "fb.com", "www.fb.com"):
        return False
    if resp.status_code != 200:
        return False
    body = (resp.text or "").lower()[:2000]
    return any(marker in body for marker in FACEBOOK_NOT_FOUND_MARKERS)


def is_facebook_blocked(resp, host):
    if host not in ("facebook.com", "www.facebook.com", "fb.com", "www.fb.com"):
        return False
    if resp.status_code != 200:
        return False
    body = (resp.text or "").lower()[:2000]
    return any(marker in body for marker in FACEBOOK_BLOCK_MARKERS)


def is_facebook_account_not_found(resp, host):
    return is_facebook_page_not_found(resp, host)


def get_platform_for_domain(pd: str, platforms: list) -> Optional[str]:
    for p in platforms:
        if pd in PLATFORM_DOMAINS.get(p, []):
            return p
    return pd


def is_non_account_url(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    path = parsed.path or "/"
    if parsed.query:
        return True
    if PROFILE_FILE_PATH_RE.search(path.rstrip("/")):
        return True
    pattern = ACCOUNT_PATH_PATTERNS.get(host)
    if pattern is None:
        return True
    if not pattern.match(path):
        return True
    slug = path.strip("/").split("/", 1)[0].lower()
    if slug in RESERVED_PATHS.get(host, frozenset()):
        return True
    return False


def blh_extract_targets(anchors, final_url, platform_domains, known_target_keys, fresh_keys):
    """BLH-specific target extraction: filter account/profile URLs."""
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
        platform_hits += 1
        non_account = is_non_account_url(href)
        if non_account:
            continue
        key = canonical_target_url(href, ACCOUNT_PATH_PATTERNS)
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


def save_pending_result(scan_id: str, link: dict, platforms: list, deleted_scans=None) -> int | None:
    deleted_scans = deleted_scans or set()
    if scan_id in deleted_scans:
        return None
    con = sqlite3.connect(DB_PATH)
    scan_row = con.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan_row:
        con.close()
        return None
    existing = con.execute(
        "SELECT id FROM results WHERE scan_id=? AND target_url=?",
        (scan_id, link["target_url"]),
    ).fetchone()
    if existing:
        con.close()
        return existing[0]
    platform_name = get_platform_for_domain(link["platform_domain"], platforms)
    cur = con.execute(
        """
        INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text,
            status, http_code, final_url, error_reason, status_overridden, checked_at)
        VALUES (?, ?, ?, ?, ?, 'pending', NULL, ?, ?, 0, ?)
        """,
        (
            scan_id,
            platform_name,
            link["source_url"],
            link["target_url"],
            link["anchor_text"],
            link["target_url"],
            "Waiting for status check",
            utc_now_iso(),
        ),
    )
    con.commit()
    result_id = cur.lastrowid
    con.close()
    return result_id


def update_saved_result(scan_id: str, link: dict, check: dict, platforms: list, deleted_scans=None) -> int | None:
    deleted_scans = deleted_scans or set()
    if scan_id in deleted_scans:
        return None
    platform_name = get_platform_for_domain(link["platform_domain"], platforms)
    con = sqlite3.connect(DB_PATH)
    cur = con.execute(
        """
        UPDATE results
        SET platform=?, source_url=?, anchor_text=?,
            status=CASE WHEN COALESCE(status_overridden, 0)=1 THEN status ELSE ? END,
            http_code=?,
            final_url=?, error_reason=?, checked_at=?
        WHERE scan_id=? AND target_url=?
        """,
        (
            platform_name,
            link["source_url"],
            link["anchor_text"],
            check["status"],
            check["http_code"],
            check["final_url"],
            check["error_reason"],
            utc_now_iso(),
            scan_id,
            link["target_url"],
        ),
    )
    if cur.rowcount == 0:
        cur = con.execute(
            """
            INSERT INTO results (scan_id, platform, source_url, target_url, anchor_text,
                status, http_code, final_url, error_reason, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                platform_name,
                link["source_url"],
                link["target_url"],
                link["anchor_text"],
                check["status"],
                check["http_code"],
                check["final_url"],
                check["error_reason"],
                utc_now_iso(),
            ),
        )
    con.commit()
    result_id = cur.lastrowid
    con.close()
    return result_id


def count_saved_results(scan_id: str) -> int:
    con = sqlite3.connect(DB_PATH)
    row = con.execute("SELECT COUNT(*) FROM results WHERE scan_id=?", (scan_id,)).fetchone()
    con.close()
    return int(row[0] or 0)


async def wait_if_paused(pause_event=None, cancel_event=None) -> bool:
    while pause_event and pause_event.is_set():
        if cancel_event and cancel_event.is_set():
            return True
        await asyncio.sleep(0.25)
    return False


async def fetch_subdomain_sitemap_batches(client, domain: str):
    async def _fetch(sub: str):
        host = f"{sub}.{domain}"
        try:
            urls = await fetch_sitemap_urls(client, host)
        except Exception:
            urls = []
        return host, urls

    tasks = [_fetch(sub) for sub in SUBDOMAIN_SITEMAP_CANDIDATES]
    for task in asyncio.as_completed(tasks):
        yield await task


async def check_link(client, url):
    if url.startswith("http://"):
        url = "https://" + url[7:]
    result = {"status": "unknown", "http_code": None, "final_url": url, "error_reason": ""}
    for attempt in range(2):
        try:
            resp = await client.get(url, timeout=12, follow_redirects=True)
            break
        except httpx.TimeoutException:
            if attempt == 1:
                result["status"] = "timeout"
                result["error_reason"] = "Timed out after retry"
                return result
            await asyncio.sleep(0.5)
        except httpx.TooManyRedirects:
            result["status"] = "redirect"
            result["error_reason"] = "Too many redirects"
            return result
        except httpx.ConnectError as e:
            # These targets are all major platforms; a connection failure is
            # almost always network/anti-bot (or IP throttling after heavy
            # crawling), NOT a deleted account. Don't call it broken.
            result["status"] = "unknown"
            result["error_reason"] = f"Connection failed (network/block, not necessarily dead): {str(e)[:50]}"
            return result
        except Exception as e:
            result["status"] = "unknown"
            result["error_reason"] = str(e)[:80]
            return result

    try:
        code = resp.status_code
        result["http_code"] = code
        result["final_url"] = str(resp.url)
        redirected = bool(resp.history) or canonical_url(url) != canonical_url(str(resp.url))
        final_host = (urlparse(str(resp.url)).hostname or "").lower()
        final_path = urlparse(str(resp.url)).path or "/"
        auth_redirect = (
            redirected
            and code == 200
            and (
                (final_host in ("instagram.com", "www.instagram.com") and final_path.startswith("/accounts/login"))
                or (final_host in ("facebook.com", "www.facebook.com") and final_path.startswith("/login"))
                or (final_host in ("twitter.com", "x.com", "www.twitter.com", "www.x.com") and final_path.startswith("/login"))
            )
        )
        twitter_not_found = is_twitter_account_not_found(resp, final_host)
        facebook_not_found = is_facebook_page_not_found(resp, final_host)
        twitter_blocked = is_twitter_blocked(resp, final_host)
        facebook_blocked = is_facebook_blocked(resp, final_host)
        if code in (404, 410) or twitter_not_found or facebook_not_found:
            result["status"] = "broken"
            if twitter_not_found:
                result["error_reason"] = "Account does not exist (Twitter/X error page)"
            elif facebook_not_found:
                result["error_reason"] = "Page does not exist (Facebook error page)"
            elif redirected:
                result["error_reason"] = "Redirected to missing page"
        elif twitter_blocked or facebook_blocked:
            # 200-OK anti-bot / generic error page: cannot verify from a bot IP.
            # Report as blocked (likely alive) rather than a false broken/alive.
            result["status"] = "blocked"
            result["error_reason"] = "Anti-bot/error page - status unverifiable (likely alive)"
        elif auth_redirect:
            result["status"] = "alive"
            result["error_reason"] = "Account exists (login redirect)"
        elif code in (401, 403, 429) or is_probably_blocked(resp):
            result["status"] = "blocked"
            result["error_reason"] = f"HTTP {code}" if code != 200 else "Bot block or captcha"
        elif code == 520:
            result["status"] = "blocked"
            result["error_reason"] = "Cloudflare 520 (origin refused)"
        elif code >= 500:
            result["status"] = "broken"
            result["error_reason"] = f"Server error {code}"
        elif redirected:
            result["status"] = "redirect"
            result["error_reason"] = f"Final HTTP {code}"
        elif 200 <= code < 300:
            result["status"] = "alive"
        else:
            result["status"] = "unknown"
            result["error_reason"] = f"HTTP {code}"
    except Exception as e:
        result["status"] = "unknown"
        result["error_reason"] = str(e)[:80]
    return result


async def run_scan(scan_id: str, domain: str, platforms: list,
                   cancel_event=None, pause_event=None, deleted_scans=None,
                   running_scans=None, paused_scans=None):
    deleted_scans = deleted_scans or set()
    source_count = 0
    link_count = 0
    total_links = 0
    cancelled = False
    try:
        if scan_id in deleted_scans:
            return
        db_update_scan_status(scan_id, "running", deleted_scans)
        db_log_scan(scan_id, f"Scan started - domain: {domain} | platforms: {', '.join(platforms)}", deleted_scans)

        selected_pds = []
        for p in platforms:
            selected_pds.extend(PLATFORM_DOMAINS.get(p, []))

        cached_targets = get_cached_target_statuses()

        async with httpx.AsyncClient(
            headers={"User-Agent": "BLH-Hunter/1.0 (security research)"},
            follow_redirects=True,
            max_redirects=5,
        ) as client:
            seed_urls = domain_base_urls(domain)

            db_log_scan(scan_id, "Loading sitemap and robots sitemap seeds...", deleted_scans)
            sitemap = await fetch_sitemap_urls(client, domain)
            seed_urls.extend(sitemap)
            db_log_scan(scan_id, f"Sitemap: {len(sitemap)} seeds found", deleted_scans)

            db_log_scan(
                scan_id,
                f"Probing {len(SUBDOMAIN_SITEMAP_CANDIDATES)} common subdomain sitemaps...",
                deleted_scans,
            )
            subdomain_sitemap_hits = 0
            subdomain_sitemap_processed = 0
            async for host, sub_sitemap in fetch_subdomain_sitemap_batches(client, domain):
                subdomain_sitemap_processed += 1
                seed_urls.extend(sub_sitemap)
                if sub_sitemap:
                    subdomain_sitemap_hits += len(sub_sitemap)
                    db_log_scan(scan_id, f"Subdomain sitemap {host}: {len(sub_sitemap)} seeds", deleted_scans)
                elif subdomain_sitemap_processed % 4 == 0:
                    db_log_scan(
                        scan_id,
                        f"Subdomain sitemap progress: {subdomain_sitemap_processed}/{len(SUBDOMAIN_SITEMAP_CANDIDATES)} checked",
                        deleted_scans,
                    )
            db_log_scan(scan_id, f"Subdomain sitemap seeds found: {subdomain_sitemap_hits}", deleted_scans)

            db_log_scan(scan_id, "Loading Wayback URL seeds...", deleted_scans)
            wb = await fetch_wayback_source_urls(client, domain)
            seed_urls.extend(wb)
            db_log_scan(scan_id, f"Wayback: {len(wb)} seeds found", deleted_scans)

            db_log_scan(scan_id, "Loading CommonCrawl URL seeds...", deleted_scans)
            cc = await fetch_commoncrawl_source_urls(client, domain)
            seed_urls.extend(cc)
            db_log_scan(scan_id, f"CommonCrawl: {len(cc)} seeds found", deleted_scans)

            seed_urls = dedupe_urls(
                [u for u in seed_urls if url_in_scope(u, domain) and not should_skip_url(u)]
            )
            root_seeds = [u for u in seed_urls if urlparse(u).path in ("", "/")]
            other_seeds = [u for u in seed_urls if urlparse(u).path not in ("", "/")]
            seed_urls = root_seeds + other_seeds
            db_log_scan(scan_id, f"Scoped seed pages: {len(seed_urls)}", deleted_scans)

            known_sources = get_known_source_urls(domain, platforms, "crawl_pages",
                                                   normalize_platforms_list, platforms_key, parse_platforms_key)
            if known_sources:
                db_log_scan(scan_id, f"Skipping {len(known_sources)} source URL(s) already crawled for selected platform(s).", deleted_scans)

            def _log_fn(sid, msg):
                db_log_scan(sid, msg, deleted_scans)

            def _write_fn(sid, src, final, status, **kw):
                db_write_crawl_page(sid, src, final, status, deleted_scans,
                                    platforms_key_fn=platforms_key, load_platforms_fn=load_platforms_json,
                                    **kw)

            def _found_fn(sid, links):
                for link in links:
                    save_pending_result(sid, link, platforms, deleted_scans)

            source_list, fresh_links, crawl_stats = await discover_sources_by_crawling(
                client, domain, selected_pds, seed_urls, scan_id, cancel_event,
                known_sources=known_sources,
                extract_targets_fn=blh_extract_targets,
                log_fn=_log_fn,
                write_crawl_fn=_write_fn,
                pause_event=pause_event,
                found_links_fn=_found_fn,
            )
            if cancel_event and cancel_event.is_set():
                cancelled = True
            source_count = crawl_stats["visited"]
            source_with_new_targets = len(source_list)
            db_log_scan(scan_id, f"Source pages crawled in this scan: {source_count}", deleted_scans)
            db_log_scan(scan_id, f"Source pages with new target links: {source_with_new_targets}", deleted_scans)
            db_log_scan(
                scan_id,
                f"Crawl hits: platform_hits={crawl_stats['platform_hits']} "
                f"account_hits={crawl_stats['account_hits']} "
                f"already_seen_targets={crawl_stats['already_seen_targets']} "
                f"duplicate_targets_in_scan={crawl_stats['duplicate_targets_in_scan']}",
                deleted_scans,
            )
            db_log_scan(scan_id, f"Target links found in this scan: {len(fresh_links)}", deleted_scans)

            newly_checked = 0

            for i, lnk in enumerate(fresh_links):
                if scan_id in deleted_scans:
                    cancelled = True
                    break
                if cancel_event and cancel_event.is_set():
                    cancelled = True
                    db_log_scan(scan_id, "Scan cancelled by user.", deleted_scans)
                    break
                if await wait_if_paused(pause_event, cancel_event):
                    cancelled = True
                    db_log_scan(scan_id, "Scan cancelled by user.", deleted_scans)
                    break
                db_log_scan(scan_id, f"Checking [{i + 1}/{len(fresh_links)}]: {lnk['target_url'][:80]}", deleted_scans)
                cache_key = canonical_target_url(lnk["target_url"], ACCOUNT_PATH_PATTERNS)
                cached = cached_targets.get(cache_key)
                if cached:
                    check = cached
                    db_log_scan(scan_id, f"Using cached check result: {cached['status']}", deleted_scans)
                else:
                    check = await check_link(client, lnk["target_url"])
                    cached_targets[cache_key] = check

                update_saved_result(scan_id, lnk, check, platforms, deleted_scans)
                newly_checked += 1
                await asyncio.sleep(0.2)

            if scan_id in deleted_scans:
                return

            con = sqlite3.connect(DB_PATH)
            scan_row = con.execute("SELECT 1 FROM scans WHERE id=?", (scan_id,)).fetchone()
            con.close()
            if not scan_row:
                return

            total_links = count_saved_results(scan_id)
            db_log_scan(scan_id, f"Done. {total_links} links saved for this scan.", deleted_scans)
            if newly_checked == 0:
                if crawl_stats["already_seen_targets"] > 0 and crawl_stats["account_hits"] > 0:
                    db_log_scan(scan_id, "No new target links saved. Valid target links found were already in DB.", deleted_scans)
                elif crawl_stats["duplicate_targets_in_scan"] > 0 and crawl_stats["account_hits"] > 0:
                    db_log_scan(scan_id, "No new target links saved. Valid target links were duplicates inside this scan.", deleted_scans)
                elif crawl_stats["platform_hits"] > 0:
                    db_log_scan(scan_id, "No valid account target links found. Platform links were share/system/non-account URLs.", deleted_scans)
                else:
                    db_log_scan(scan_id, "No platform links found for selected platforms on crawled source URLs.", deleted_scans)

        if cancelled:
            db_update_scan_status(scan_id, "cancelled", deleted_scans, total_sources=source_count, total_links=total_links)
        else:
            db_update_scan_status(scan_id, "done", deleted_scans, total_sources=source_count, total_links=total_links)
    except Exception as e:
        db_log_scan(scan_id, f"Error: {type(e).__name__}: {str(e)[:200]}", deleted_scans)
        db_update_scan_status(scan_id, "error", deleted_scans, total_sources=source_count, total_links=link_count)
    finally:
        if running_scans is not None:
            running_scans.pop(scan_id, None)
        if paused_scans is not None:
            paused_scans.pop(scan_id, None)
        deleted_scans.discard(scan_id)
