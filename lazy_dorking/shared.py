import asyncio
import json
import re
from collections import deque
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urldefrag, urljoin, urlparse

import httpx

MAX_FRESH_TARGETS = 100
MAX_CRAWLED_PAGES = 2000
MAX_LINKS_PER_SOURCE = 100
ACCESS_CHALLENGE_STATUS_CODES = {403, 429, 503}
ACCESS_CHALLENGE_LOG_LIMIT = 5

CLOUDFLARE_MARKERS = (
    "cloudflare",
    "__cf_chl",
    "cf-chl",
    "challenge-platform",
    "cf-browser-verification",
)
ACCESS_CHALLENGE_MARKERS = (
    "just a moment",
    "attention required",
    "checking your browser",
    "verify you are human",
    "enable javascript and cookies",
    "browser challenge",
    "captcha",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
SKIP_PATH_RE = re.compile(
    r"\.(?:7z|avi|css|docx?|eot|gif|gz|ico|jpe?g|js|json|map|mp4|mp3|pdf|png|rar|svg|tar|ttf|webm|webp|woff2?|xlsx?|zip)(?:$|\?)",
    re.IGNORECASE,
)


class AnchorExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = []
        self._href = None
        self._text_parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "a":
            return
        href = dict(attrs).get("href")
        if href:
            self._href = href
            self._text_parts = []

    def handle_data(self, data):
        if self._href:
            self._text_parts.append(data)

    def handle_endtag(self, tag):
        if tag.lower() != "a" or not self._href:
            return
        text = " ".join("".join(self._text_parts).split())[:120]
        self.anchors.append((self._href, text))
        self._href = None
        self._text_parts = []


def canonical_url(url: str) -> str:
    url = urldefrag(url).url.strip()
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower().strip(".")
    port = ""
    if parsed.port and not (
        (scheme == "http" and parsed.port == 80) or (scheme == "https" and parsed.port == 443)
    ):
        port = f":{parsed.port}"
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{host}{port}{path}{query}"


def canonical_target_url(url: str, account_patterns: dict = None) -> str:
    canonical = canonical_url(url)
    parsed = urlparse(canonical)
    host = (parsed.hostname or "").lower()
    if host.startswith("www.") and (not account_patterns or host[4:] in account_patterns):
        return parsed._replace(netloc=host[4:]).geturl()
    return canonical


def clean_href(page_url: str, href: str) -> Optional[str]:
    href = unescape((href or "").strip())
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urldefrag(urljoin(page_url, href)).url
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return absolute


def extract_anchors(html: str, page_url: str):
    parser = AnchorExtractor()
    try:
        parser.feed(html)
    except Exception:
        return []
    anchors = []
    for href, text in parser.anchors:
        absolute = clean_href(page_url, href)
        if absolute:
            anchors.append((absolute, text))
    return anchors


def is_probably_html(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    return not ctype or "html" in ctype or "text/plain" in ctype or "application/xhtml" in ctype


def _header_value(headers, name: str) -> str:
    if not headers:
        return ""
    try:
        return headers.get(name, "")
    except Exception:
        lowered = name.lower()
        for key, value in headers.items():
            if str(key).lower() == lowered:
                return value
    return ""


def detect_access_challenge(resp: httpx.Response) -> Optional[str]:
    status_code = getattr(resp, "status_code", None)
    body = ((getattr(resp, "text", "") or "")[:4000]).lower()
    headers = getattr(resp, "headers", {}) or {}
    server = _header_value(headers, "server").lower()
    cf_ray = _header_value(headers, "cf-ray")
    cloudflare_seen = bool(cf_ray) or "cloudflare" in server or any(marker in body for marker in CLOUDFLARE_MARKERS)
    challenge_seen = any(marker in body for marker in ACCESS_CHALLENGE_MARKERS)

    if cloudflare_seen and (status_code in ACCESS_CHALLENGE_STATUS_CODES or challenge_seen):
        return "Cloudflare challenge"
    if status_code in ACCESS_CHALLENGE_STATUS_CODES and challenge_seen:
        return "access challenge"
    return None


def should_skip_url(url: str) -> bool:
    return bool(SKIP_PATH_RE.search(urlparse(url).path))


def dedupe_urls(urls: list[str]) -> list[str]:
    seen = set()
    output = []
    for url in urls:
        if not url:
            continue
        key = canonical_url(url)
        if key not in seen:
            seen.add(key)
            output.append(url)
    return output


def normalize_domain(raw: str) -> str:
    value = raw.strip().lower()
    if not value:
        raise ValueError("Domain required")
    if "://" in value:
        parsed = urlparse(value)
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Enter root domain only, no path/query")
        host = parsed.hostname or ""
    else:
        if any(part in value for part in ["/", "?", "#", "@"]):
            raise ValueError("Enter root domain only, no path/query")
        host = value
    host = host.removeprefix("*.").strip(".")
    if not DOMAIN_RE.match(host):
        raise ValueError("Invalid domain")
    return host


def host_matches_domain(host: str, domain: str) -> bool:
    host = (host or "").lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith(f".{domain}")


def url_in_scope(url: str, domain: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and host_matches_domain(parsed.hostname or "", domain)


def host_matches_any(host: str, domains: list[str]) -> Optional[str]:
    for domain in domains:
        if host_matches_domain(host, domain):
            return domain
    return None


def domain_base_urls(domain: str) -> list[str]:
    bases = [f"https://{domain}", f"http://{domain}"]
    if not domain.startswith("www."):
        bases.extend([f"https://www.{domain}", f"http://www.{domain}"])
    return bases


async def fetch_wayback_source_urls(client, domain, limit=300):
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&matchType=domain&output=json"
        f"&fl=original&filter=statuscode:200&collapse=urlkey&limit={limit}"
    )
    try:
        resp = await client.get(url, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [row[0] for row in data[1:] if row and url_in_scope(row[0], domain)]
    except Exception:
        return []


async def fetch_commoncrawl_indexes(client):
    try:
        resp = await client.get("https://index.commoncrawl.org/collinfo.json", timeout=15)
        if resp.status_code != 200:
            return []
        data = resp.json()
        return [item.get("cdx-api") for item in data[:2] if item.get("cdx-api")]
    except Exception:
        return []


async def fetch_commoncrawl_source_urls(client, domain, limit=300):
    urls = []
    indexes = await fetch_commoncrawl_indexes(client)
    for index_url in indexes:
        query = f"{index_url}?url=*.{domain}/*&output=json&fl=url&filter=status:200&collapse=urlkey&limit={limit}"
        try:
            resp = await client.get(query, timeout=30)
            if resp.status_code != 200:
                continue
            for line in resp.text.strip().splitlines():
                try:
                    obj = json.loads(line)
                    src = obj.get("url", "")
                    if url_in_scope(src, domain):
                        urls.append(src)
                except Exception:
                    continue
        except Exception:
            continue
    return dedupe_urls(urls)


async def fetch_sitemap_urls(client, domain, limit=300):
    sitemap_urls = set()
    page_urls = []
    for base in domain_base_urls(domain):
        sitemap_urls.add(urljoin(base, "/sitemap.xml"))
        try:
            robots = await client.get(urljoin(base, "/robots.txt"), timeout=10, follow_redirects=True)
            if robots.status_code == 200:
                for line in robots.text.splitlines():
                    if line.lower().startswith("sitemap:"):
                        sitemap_urls.add(line.split(":", 1)[1].strip())
        except Exception:
            continue

    queue = deque(list(sitemap_urls))
    seen_sitemaps = set()
    while queue and len(page_urls) < limit:
        sitemap_url = queue.popleft()
        if sitemap_url in seen_sitemaps or not url_in_scope(sitemap_url, domain):
            continue
        seen_sitemaps.add(sitemap_url)
        try:
            resp = await client.get(sitemap_url, timeout=20, follow_redirects=True)
            if resp.status_code != 200:
                continue
            locs = re.findall(r"<loc>\s*([^<]+)\s*</loc>", resp.text, re.IGNORECASE)
            for loc in locs:
                loc = unescape(loc.strip())
                if loc.endswith(".xml") and len(seen_sitemaps) < 20:
                    queue.append(loc)
                elif url_in_scope(loc, domain) and not should_skip_url(loc):
                    page_urls.append(loc)
                    if len(page_urls) >= limit:
                        break
        except Exception:
            continue
    return dedupe_urls(page_urls)


def build_host_frontier(seed_urls, domain, known_sources=None):
    known_sources = set(known_sources or set())
    host_queues: dict[str, deque] = {}
    host_order: list[str] = []
    seen_queue_urls: set[str] = set()
    skipped_sources = 0
    for url in dedupe_urls(seed_urls):
        if not url_in_scope(url, domain) or should_skip_url(url):
            continue
        ckey = canonical_url(url)
        if ckey in known_sources:
            skipped_sources += 1
            continue
        if ckey in seen_queue_urls:
            skipped_sources += 1
            continue
        seen_queue_urls.add(ckey)
        host = (urlparse(url).hostname or "").lower()
        if host not in host_queues:
            host_queues[host] = deque()
            host_order.append(host)
        host_queues[host].append((url, 0))
    return host_queues, host_order, seen_queue_urls, skipped_sources


def format_host_summary(host_queues, host_order, limit=8):
    host_parts = [f"{host}={len(host_queues[host])}" for host in host_order[:limit]]
    if len(host_order) > limit:
        host_parts.append(f"...+{len(host_order) - limit} hosts")
    return ", ".join(host_parts) if host_parts else "none"


async def discover_sources_by_crawling(
    client, domain, platform_domains, seed_urls, scan_id,
    cancel_event=None, known_targets: set = None, known_sources: set = None,
    extract_targets_fn=None, is_target_fn=None,
    log_fn=None, write_crawl_fn=None,
    target_canonical_fn=None,
    pause_event=None,
    found_links_fn=None,
):
    """Crawl + extract in one pass with host-balanced round-robin frontier.
    
    extract_targets_fn(anchors, final_url) -> list[dict] with keys: target_url, anchor_text, platform_domain, source_url
    is_target_fn(url) -> bool
    log_fn(scan_id, message)
    write_crawl_fn(scan_id, source_url, final_url, crawl_status, **kwargs)
    target_canonical_fn(url) -> str
    """
    known_sources = set(known_sources or set())
    host_queues, host_order, seen_queue_urls, skipped_sources = build_host_frontier(
        seed_urls, domain, known_sources
    )
    if log_fn:
        log_fn(scan_id, f"Seed hosts: {format_host_summary(host_queues, host_order)}")

    visited = set()
    known_target_keys = set(known_targets) if known_targets else set()
    fresh_keys = set()
    sources = []
    source_keys = set()
    fresh_links = []
    already_seen_targets = 0
    duplicate_targets = 0
    crawled_hosts: set[str] = set()
    last_log = 0
    rr_idx = 0
    total_platform_hits = 0
    total_account_hits = 0
    access_challenge_notices = 0

    while True:
        if len(fresh_links) >= MAX_FRESH_TARGETS:
            break
        if len(visited) >= MAX_CRAWLED_PAGES:
            break
        if cancel_event and cancel_event.is_set():
            if log_fn:
                log_fn(scan_id, "Scan cancelled by user.")
            break
        while pause_event and pause_event.is_set():
            if cancel_event and cancel_event.is_set():
                if log_fn:
                    log_fn(scan_id, "Scan cancelled by user.")
                break
            await asyncio.sleep(0.25)
        if cancel_event and cancel_event.is_set():
            break

        tried = 0
        page_url = None
        depth = 0
        while tried < len(host_order):
            h = host_order[rr_idx % len(host_order)]
            rr_idx += 1
            tried += 1
            if host_queues.get(h):
                page_url, depth = host_queues[h].popleft()
                if not host_queues[h]:
                    del host_queues[h]
                    host_order.remove(h)
                    rr_idx = 0
                break

        if page_url is None:
            break

        page_key = canonical_url(page_url)
        if page_key in visited or page_key in known_sources:
            skipped_sources += 1
            continue
        visited.add(page_key)

        if log_fn and len(visited) - last_log >= 25:
            last_log = len(visited)
            log_fn(scan_id,
                f"Crawling... visited={len(visited)} skipped_sources={skipped_sources} "
                f"skipped_targets={already_seen_targets + duplicate_targets} "
                f"already_seen_targets={already_seen_targets} duplicate_targets_in_scan={duplicate_targets} "
                f"new_targets={len(fresh_links)} "
                f"platform_hits={total_platform_hits} account_hits={total_account_hits} "
                f"hosts={len(crawled_hosts)}")

        try:
            resp = await client.get(page_url, timeout=15, follow_redirects=True)
            final_url = str(resp.url)
            final_host = (urlparse(final_url).hostname or "").lower()
            crawled_hosts.add(final_host)
            access_challenge = detect_access_challenge(resp)

            if resp.status_code != 200 or not url_in_scope(final_url, domain) or not is_probably_html(resp):
                if access_challenge:
                    reason = access_challenge
                elif resp.status_code != 200:
                    reason = "non-200"
                elif not url_in_scope(final_url, domain):
                    reason = "out-of-scope redirect"
                else:
                    reason = "non-html"
                if write_crawl_fn:
                    write_crawl_fn(scan_id, page_url, final_url, "skipped",
                                   http_code=resp.status_code,
                                   error_reason=reason, domain=domain)
                if access_challenge and log_fn and access_challenge_notices < ACCESS_CHALLENGE_LOG_LIMIT:
                    access_challenge_notices += 1
                    log_fn(
                        scan_id,
                        f"[blocked] {page_url[:70]}: HTTP {resp.status_code} {access_challenge}; "
                        "page content not scanned. Results may miss links visible in browser.",
                    )
                    if access_challenge_notices == ACCESS_CHALLENGE_LOG_LIMIT:
                        log_fn(scan_id, "[blocked] Further blocked-source notices suppressed.")
                continue

            source_key = canonical_url(final_url)
            anchors = extract_anchors(resp.text, final_url)

            # Discover internal links -> add to host queues
            for href, _ in anchors:
                parsed = urlparse(href)
                if depth < 3 and url_in_scope(href, domain) and not should_skip_url(href):
                    href_key = canonical_url(href)
                    if href_key in known_sources or href_key in visited or href_key in seen_queue_urls:
                        skipped_sources += 1
                        continue
                    seen_queue_urls.add(href_key)
                    h = (parsed.hostname or "").lower()
                    if h not in host_queues:
                        host_queues[h] = deque()
                        host_order.append(h)
                    host_queues[h].append((href, depth + 1))

            # Extract target links using feature-specific function
            if extract_targets_fn:
                extracted = extract_targets_fn(anchors, final_url, platform_domains, known_target_keys, fresh_keys)
                if isinstance(extracted, tuple):
                    page_links, extract_stats = extracted
                else:
                    page_links, extract_stats = extracted, {}
            else:
                page_links, extract_stats = [], {}

            platform_hits = int(extract_stats.get("platform_hits", 0))
            account_hits = len(page_links)
            already_seen_targets += int(extract_stats.get("already_seen_targets", 0))
            duplicate_targets += int(extract_stats.get("duplicate_targets_in_scan", 0))
            total_platform_hits += platform_hits
            total_account_hits += account_hits

            if write_crawl_fn:
                write_crawl_fn(scan_id, page_url, final_url, "success",
                               platform_hits=platform_hits, account_hits=account_hits,
                               domain=domain)

            if page_links:
                if source_key not in source_keys:
                    source_keys.add(source_key)
                    sources.append(final_url)
                fresh_links.extend(page_links)
                if found_links_fn:
                    result = found_links_fn(scan_id, page_links)
                    if hasattr(result, "__await__"):
                        await result
                if log_fn:
                    log_fn(scan_id, f"[found] {final_url[:70]}: {len(page_links)} new target(s)")
                if len(fresh_links) >= MAX_FRESH_TARGETS:
                    break

            if platform_hits > 0 and account_hits == 0 and len(sources) <= 10 and log_fn:
                log_fn(scan_id, f"[filter] {final_url[:70]}: {platform_hits} platform links, all filtered.")
            elif platform_hits == 0 and len(visited) <= 5 and log_fn:
                log_fn(scan_id, f"[debug] {final_url[:70]}: no platform links ({len(anchors)} anchors)")
        except Exception as e:
            if write_crawl_fn:
                write_crawl_fn(scan_id, page_url, page_url, "error",
                               error_reason=str(e)[:80], domain=domain)
            continue
        await asyncio.sleep(0.15)

    if log_fn:
        log_fn(
            scan_id,
            f"Crawl summary: visited={len(visited)} skipped_sources={skipped_sources} "
            f"skipped_targets={already_seen_targets + duplicate_targets} "
            f"already_seen_targets={already_seen_targets} duplicate_targets_in_scan={duplicate_targets} "
            f"new_targets={len(fresh_links)} platform_hits={total_platform_hits} "
            f"account_hits={total_account_hits} hosts={len(crawled_hosts)}",
        )
    stats = {
        "visited": len(visited),
        "skipped_sources": skipped_sources,
        "skipped_targets": already_seen_targets + duplicate_targets,
        "already_seen_targets": already_seen_targets,
        "duplicate_targets_in_scan": duplicate_targets,
        "platform_hits": total_platform_hits,
        "account_hits": total_account_hits,
        "hosts": len(crawled_hosts),
    }
    return sources, fresh_links, stats
