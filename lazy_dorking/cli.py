#!/usr/bin/env python3
"""
BLH-Hunter — Lightweight terminal scanner (no web UI, no database).

Reuses the exact crawl + link-check engine that the FastAPI app uses
(`shared.discover_sources_by_crawling` + `blh.scanner.check_link`), but runs
entirely in-memory and prints results straight to the terminal.

Output format (one line per social/profile link found):

    [200] <source_page_url> [PLATFORM] <social_url> [STATUS]

Where the first bracket is the source page (always a live 200 in-scope HTML
page) and the last bracket is the checked status of the social link:
an HTTP code like [200] when alive, otherwise a label like
[BROKEN] / [REDIRECT] / [BLOCKED] / [TIMEOUT] / [UNKNOWN].

Examples:
    python -m lazy_dorking.cli nasa.gov
    python -m lazy_dorking.cli nasa.gov -p youtube,twitter,instagram
    python -m lazy_dorking.cli example.com --max 30
    python -m lazy_dorking.cli example.com --deep   # max coverage, slower
    python -m lazy_dorking.cli example.com --json out.json --csv out.csv -q

Only dependency: httpx (already in requirements.txt). No DB file is created
or read.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from urllib.parse import urlparse

import httpx

from . import shared
from .shared import (
    MAX_FRESH_TARGETS,
    canonical_target_url,
    canonical_url,
    dedupe_urls,
    discover_sources_by_crawling,
    domain_base_urls,
    fetch_commoncrawl_source_urls,
    fetch_sitemap_urls,
    fetch_wayback_source_urls,
    normalize_domain,
    should_skip_url,
    url_in_scope,
    utc_now_iso,
)
from .blh.scanner import (
    ACCOUNT_PATH_PATTERNS,
    PLATFORM_DOMAINS,
    blh_extract_targets,
    check_link,
    fetch_subdomain_sitemap_batches,
    get_platform_for_domain,
    normalize_platforms_list,
)

USER_AGENT = "BLH-Hunter-CLI/1.0 (security research)"

# ---------------------------------------------------------------- colors ----

class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


_USE_COLOR = True


def _c(text: str, color: str) -> str:
    return f"{color}{text}{C.RESET}" if _USE_COLOR else text


# status label -> color
_STATUS_COLOR = {
    "alive": C.GREEN,
    "broken": C.RED,
    "redirect": C.YELLOW,
    "blocked": C.YELLOW,
    "timeout": C.YELLOW,
    "unknown": C.GRAY,
    "pending": C.GRAY,
}


def status_bracket(check: dict) -> str:
    """Render the trailing [STATUS] bracket for a checked link."""
    status = (check.get("status") or "unknown").lower()
    code = check.get("http_code")
    if status == "alive" and code:
        label = f"[{code}]"
    else:
        label = f"[{status.upper()}]"
    return _c(label, _STATUS_COLOR.get(status, C.GRAY))


# ----------------------------------------------------------------- logging --


class Logger:
    def __init__(self, verbose: bool, quiet: bool):
        self.verbose = verbose
        self.quiet = quiet

    def info(self, msg: str):
        if not self.quiet:
            print(_c(msg, C.CYAN), file=sys.stderr)

    def step(self, msg: str):
        if not self.quiet:
            print(_c(f"[*] {msg}", C.BLUE), file=sys.stderr)

    def debug(self, msg: str):
        if self.verbose and not self.quiet:
            print(_c(f"    {msg}", C.GRAY), file=sys.stderr)

    def warn(self, msg: str):
        if not self.quiet:
            print(_c(f"[!] {msg}", C.YELLOW), file=sys.stderr)


# ---------------------------------------------------------------- seeding ---


async def collect_seeds(client, domain: str, log: Logger, passive: bool) -> list[str]:
    """Gather seed source URLs (sitemap/robots, optionally wayback + CC + subs)."""
    seed_urls = domain_base_urls(domain)

    log.step("Loading sitemap / robots seeds...")
    sitemap = await fetch_sitemap_urls(client, domain)
    seed_urls.extend(sitemap)
    log.debug(f"sitemap: {len(sitemap)} seeds")

    if passive:
        log.step("Probing common subdomain sitemaps...")
        sub_hits = 0
        async for host, sub_sitemap in fetch_subdomain_sitemap_batches(client, domain):
            if sub_sitemap:
                sub_hits += len(sub_sitemap)
                seed_urls.extend(sub_sitemap)
                log.debug(f"subdomain sitemap {host}: {len(sub_sitemap)} seeds")
        log.debug(f"subdomain sitemap seeds: {sub_hits}")

        log.step("Loading Wayback Machine seeds...")
        wb = await fetch_wayback_source_urls(client, domain)
        seed_urls.extend(wb)
        log.debug(f"wayback: {len(wb)} seeds")

        log.step("Loading CommonCrawl seeds...")
        cc = await fetch_commoncrawl_source_urls(client, domain)
        seed_urls.extend(cc)
        log.debug(f"commoncrawl: {len(cc)} seeds")
    else:
        log.debug("passive sources skipped (--fast)")

    seed_urls = dedupe_urls(
        [u for u in seed_urls if url_in_scope(u, domain) and not should_skip_url(u)]
    )
    # root pages first (richest footer/social links), then the rest
    root_seeds = [u for u in seed_urls if urlparse(u).path in ("", "/")]
    other_seeds = [u for u in seed_urls if urlparse(u).path not in ("", "/")]
    ordered = root_seeds + other_seeds
    log.info(f"Scoped seed pages: {len(ordered)}")
    return ordered


# --------------------------------------------------------------- checking ---


async def check_all(client, links: list[dict], concurrency: int, log: Logger) -> dict:
    """Check every unique target URL concurrently; return {cache_key: check}."""
    unique: dict[str, str] = {}
    for lnk in links:
        key = canonical_target_url(lnk["target_url"], ACCOUNT_PATH_PATTERNS)
        unique.setdefault(key, lnk["target_url"])

    results: dict[str, dict] = {}
    sem = asyncio.Semaphore(max(1, concurrency))
    done = 0
    total = len(unique)

    async def _one(key: str, url: str):
        nonlocal done
        async with sem:
            check = await check_link(client, url)
        results[key] = check
        done += 1
        if not log.quiet:
            print(
                _c(f"\r[*] Checked {done}/{total} links", C.BLUE),
                end="",
                file=sys.stderr,
                flush=True,
            )

    log.step(f"Checking {total} unique link(s) (concurrency={concurrency})...")
    await asyncio.gather(*(_one(k, u) for k, u in unique.items()))
    if not log.quiet and total:
        print("", file=sys.stderr)
    return results


# ------------------------------------------------------------------ state ---


def load_state(path: str, domain: str, log: Logger) -> dict:
    """Load a prior scan state file. Returns {sources:set, results:list}."""
    empty = {"sources": set(), "results": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return empty
    except (OSError, json.JSONDecodeError) as e:
        log.warn(f"Could not read state file {path}: {e}. Starting fresh.")
        return empty
    if data.get("domain") and data["domain"] != domain:
        log.warn(
            f"State file is for '{data['domain']}', not '{domain}'. Starting fresh."
        )
        return empty
    sources = {canonical_url(u) for u in data.get("sources", []) if u}
    results = [r for r in data.get("results", []) if isinstance(r, dict)]
    log.info(
        f"Loaded state: {len(sources)} crawled source(s), {len(results)} known result(s)."
    )
    return {"sources": sources, "results": results}


def save_state(path: str, domain: str, sources: set, results: list, log: Logger):
    payload = {
        "domain": domain,
        "updated_at": utc_now_iso(),
        "sources": sorted(sources),
        "results": results,
    }
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        log.info(
            f"State saved: {len(sources)} crawled source(s), {len(results)} result(s) "
            f"-> {path}"
        )
    except OSError as e:
        log.warn(f"Could not write state file {path}: {e}")


def merge_results(prior: list[dict], fresh: list[dict]) -> list[dict]:
    """Merge prior + fresh result rows, deduped by canonical target URL.
    Fresh rows win (newer status check)."""
    by_key: dict[str, dict] = {}
    for r in prior:
        key = canonical_target_url(r["target_url"], ACCOUNT_PATH_PATTERNS)
        by_key[key] = r
    for r in fresh:
        key = canonical_target_url(r["target_url"], ACCOUNT_PATH_PATTERNS)
        by_key[key] = r
    return list(by_key.values())


# ------------------------------------------------------------------- scan ---


async def run_cli_scan(args) -> list[dict]:
    domain = normalize_domain(args.domain)
    platforms = normalize_platforms_list(args.platforms)
    if not platforms:
        platforms = sorted(PLATFORM_DOMAINS.keys())

    log = Logger(args.verbose, args.quiet)
    log.info(f"Target: {domain}")
    log.info(f"Platforms: {', '.join(platforms)}")

    selected_pds: list[str] = []
    for p in platforms:
        selected_pds.extend(PLATFORM_DOMAINS.get(p, []))

    timeout = httpx.Timeout(20.0, connect=10.0)
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        follow_redirects=True,
        max_redirects=5,
        timeout=timeout,
    ) as client:
        # Load prior state (crawled sources + known results) if requested, so a
        # repeat run skips already-crawled source pages and already-found links.
        state = {"sources": set(), "results": []}
        if args.state:
            state = load_state(args.state, domain, log)
        known_sources = set(state["sources"])
        prior_results = state["results"]
        known_targets = {
            canonical_target_url(r["target_url"], ACCOUNT_PATH_PATTERNS)
            for r in prior_results
            if r.get("target_url")
        }

        seed_urls = await collect_seeds(client, domain, log, passive=args.deep)

        # Record every page actually crawled this run, so state persists them and
        # the next run can skip them (this is what makes repeat scans fast).
        crawled_sources: set[str] = set()

        def _write_fn(_sid, src, _final, _status, **_kw):
            if src:
                crawled_sources.add(canonical_url(src))

        # Crawl log callback. In verbose mode show everything; otherwise surface
        # only the lines that signal liveness/progress ("Crawling... visited=N",
        # "[found] ...", "[blocked] ...") so a big domain never looks frozen.
        def _log_fn(_sid, msg):
            if args.verbose:
                log.debug(msg)
            elif msg.startswith(("Crawling...", "[found]", "[blocked]")):
                log.info(msg)

        # Honor a custom target cap so the crawl actually STOPS early (lighter
        # run), instead of always crawling up to the default 100. The engine
        # reads shared.MAX_FRESH_TARGETS as a module global; this is a single
        # short-lived CLI process, so overriding it here is safe.
        if args.max and args.max > 0:
            shared.MAX_FRESH_TARGETS = args.max

        # Wall-clock budget: large domains (many slow/dead subdomains, each hit
        # with a 15s crawl timeout sequentially) can otherwise run for hours.
        # A watchdog sets the engine's cancel_event when the budget expires, and
        # the crawl returns whatever it has found so far.
        cancel_event = asyncio.Event()
        watchdog = None
        if args.timeout and args.timeout > 0:
            async def _watchdog():
                try:
                    await asyncio.sleep(args.timeout)
                    cancel_event.set()
                    log.warn(
                        f"Time budget {args.timeout}s reached - stopping crawl "
                        "and reporting partial results. Use --timeout 0 to disable, "
                        "or --fast / --max to narrow the scan."
                    )
                except asyncio.CancelledError:
                    pass
            watchdog = asyncio.create_task(_watchdog())

        budget_note = f" (budget {args.timeout}s)" if args.timeout and args.timeout > 0 else ""
        log.step(
            f"Crawling in-scope pages (root domain + subdomains){budget_note}... "
            "progress lines follow below."
        )
        try:
            sources, fresh_links, stats = await discover_sources_by_crawling(
                client,
                domain,
                selected_pds,
                seed_urls,
                scan_id="cli",
                cancel_event=cancel_event,
                known_targets=known_targets or None,
                known_sources=known_sources or None,
                extract_targets_fn=blh_extract_targets,
                log_fn=_log_fn,
                write_crawl_fn=_write_fn,
                pause_event=None,
                found_links_fn=None,
            )
        finally:
            if watchdog is not None:
                watchdog.cancel()

        log.info(
            f"Crawl done: visited={stats['visited']} hosts={stats['hosts']} "
            f"platform_hits={stats['platform_hits']} account_hits={stats['account_hits']} "
            f"targets={len(fresh_links)}"
        )

        if args.max and args.max > 0:
            fresh_links = fresh_links[: args.max]

        if fresh_links:
            checks = await check_all(client, fresh_links, args.concurrency, log)
        else:
            checks = {}
            if known_sources:
                log.warn(
                    "No NEW social/profile links found (already-crawled sources skipped)."
                )
            else:
                log.warn("No social/profile links found for the selected platforms.")

    # Build rows for links found in THIS run.
    new_rows: list[dict] = []
    for lnk in fresh_links:
        key = canonical_target_url(lnk["target_url"], ACCOUNT_PATH_PATTERNS)
        check = checks.get(key, {"status": "unknown", "http_code": None})
        platform = get_platform_for_domain(lnk["platform_domain"], platforms)
        new_rows.append(
            {
                "source_url": lnk["source_url"],
                "platform": platform,
                "target_url": lnk["target_url"],
                "anchor_text": lnk.get("anchor_text", ""),
                "status": check.get("status", "unknown"),
                "http_code": check.get("http_code"),
                "final_url": check.get("final_url", lnk["target_url"]),
                "error_reason": check.get("error_reason", ""),
            }
        )

    new_keys = {
        canonical_target_url(r["target_url"], ACCOUNT_PATH_PATTERNS) for r in new_rows
    }

    # Merge with prior results and persist state (when --state is used).
    if not args.state:
        return new_rows, new_keys
    merged = merge_results(prior_results, new_rows)
    all_sources = known_sources | crawled_sources
    save_state(args.state, domain, all_sources, merged, log)
    log.info(f"New links this run: {len(new_rows)} | total known: {len(merged)}")
    return merged, new_keys


# ----------------------------------------------------------------- output ---


def print_rows(rows: list[dict], only_broken: bool, new_only: bool = False, new_keys: set = None):
    new_keys = new_keys or set()
    for r in rows:
        if only_broken and r["status"] == "alive":
            continue
        if new_only:
            key = canonical_target_url(r["target_url"], ACCOUNT_PATH_PATTERNS)
            if key not in new_keys:
                continue
        check = {"status": r["status"], "http_code": r["http_code"]}
        src = _c("[200]", C.GREEN) + " " + _c(r["source_url"], C.DIM)
        plat = _c(f"[{r['platform'].upper()}]", C.BOLD + C.CYAN)
        line = f"{src} {plat} {r['target_url']} {status_bracket(check)}"
        print(line)


def print_summary(rows: list[dict], elapsed: float):
    by_status: dict[str, int] = {}
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    parts = []
    order = ["alive", "broken", "redirect", "blocked", "timeout", "unknown"]
    for s in order:
        if by_status.get(s):
            parts.append(f"{s}={by_status[s]}")
    summary = (
        f"\nFound {len(rows)} link(s) in {elapsed:.1f}s"
        + (f"  ({', '.join(parts)})" if parts else "")
    )
    print(_c(summary, C.BOLD), file=sys.stderr)


def write_json(path: str, rows: list[dict]):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)


def write_csv(path: str, rows: list[dict]):
    fields = [
        "source_url", "platform", "target_url", "anchor_text",
        "status", "http_code", "final_url", "error_reason",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)


# ------------------------------------------------------------------- main ---


def build_parser() -> argparse.ArgumentParser:
    platforms_help = ", ".join(sorted(PLATFORM_DOMAINS.keys()))
    p = argparse.ArgumentParser(
        prog="python -m lazy_dorking.cli",
        description="Lightweight terminal scanner for broken social/profile links "
                    "(BLH) - no web UI, no database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python -m lazy_dorking.cli nasa.gov\n"
            "  python -m lazy_dorking.cli nasa.gov -p youtube,twitter\n"
            "  python -m lazy_dorking.cli example.com --max 30 --broken-only\n"
            "  python -m lazy_dorking.cli example.com --deep   # max coverage, slower\n"
            "  python -m lazy_dorking.cli example.com --json out.json --csv out.csv -q\n"
        ),
    )
    p.add_argument("domain", help="root domain to scan, e.g. nasa.gov")
    p.add_argument(
        "-p", "--platforms", default="",
        help=f"comma-separated platforms (default: all). choices: {platforms_help}",
    )
    p.add_argument(
        "--deep", action="store_true",
        help="include slow passive seed sources (wayback, commoncrawl, subdomain "
             "sitemaps) for maximum coverage; off by default",
    )
    p.add_argument(
        "--fast", action="store_true",
        help=argparse.SUPPRESS,  # deprecated no-op: fast is now the default
    )
    p.add_argument(
        "--max", type=int, default=0,
        help=f"max target links to collect (default: {MAX_FRESH_TARGETS})",
    )
    p.add_argument(
        "-c", "--concurrency", type=int, default=10,
        help="concurrent link status checks (default: 10)",
    )
    p.add_argument(
        "--timeout", type=int, default=300, metavar="SECONDS",
        help="overall crawl time budget in seconds; stops with partial results "
             "(default: 300, use 0 to disable)",
    )
    p.add_argument(
        "--broken-only", action="store_true",
        help="only print links that are not alive",
    )
    p.add_argument(
        "--state", metavar="FILE",
        help="persist crawled sources + results to a JSON state file; a repeat "
             "run skips already-crawled pages and accumulates results (incremental)",
    )
    p.add_argument(
        "--new-only", action="store_true",
        help="print only links newly found in this run (useful with --state)",
    )
    p.add_argument("--json", metavar="FILE", help="write full results to a JSON file")
    p.add_argument("--csv", metavar="FILE", help="write full results to a CSV file")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("-v", "--verbose", action="store_true", help="show crawl/debug logs")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress logs")
    return p


def _parse_platforms(raw: str) -> list[str]:
    return [x.strip().lower() for x in raw.split(",") if x.strip()]


def main(argv=None):
    global _USE_COLOR
    args = build_parser().parse_args(argv)

    # color: off if asked or not a tty
    if args.no_color or not sys.stdout.isatty():
        _USE_COLOR = False

    # validate platforms early with a friendly message
    requested = _parse_platforms(args.platforms)
    unknown = [x for x in requested if x not in PLATFORM_DOMAINS]
    if unknown:
        print(
            f"[!] Unknown platform(s): {', '.join(unknown)}. "
            f"Valid: {', '.join(sorted(PLATFORM_DOMAINS.keys()))}",
            file=sys.stderr,
        )
        return 2
    args.platforms = requested

    start = time.time()
    try:
        rows, new_keys = asyncio.run(run_cli_scan(args))
    except ValueError as e:  # bad domain
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130

    print_rows(rows, args.broken_only, args.new_only, new_keys)
    if not args.quiet:
        print_summary(rows, time.time() - start)

    if args.json:
        write_json(args.json, rows)
        if not args.quiet:
            print(_c(f"[+] JSON written to {args.json}", C.GREEN), file=sys.stderr)
    if args.csv:
        write_csv(args.csv, rows)
        if not args.quiet:
            print(_c(f"[+] CSV written to {args.csv}", C.GREEN), file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
