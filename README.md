# BLH Hunter

The new **v2 recon workspace** is available at `/v2`, with durable workers,
checkpoint recovery, Crawlee adapters and an optional PostgreSQL/Celery deployment.
See [v2 setup, migration and current limitations](docs/V2.md). Legacy endpoints
and the original SQLite database remain available during migration.

BLH Hunter is a local FastAPI + SQLite reconnaissance workspace for finding broken social/profile links, exposed third-party collaboration links, and sensitive configuration-style URLs across a target domain and its subdomains.

The app is built for authorized security review. Use it only on assets you own or have explicit permission to test.

## Overview

BLH Hunter runs as a local web app with three scanner modules:

- **BLH Finder**: discovers social/profile links on in-scope pages and checks whether those accounts look alive, broken, redirected, blocked, timed out, or unknown.
- **BAC Finder**: discovers publicly linked third-party resources such as Google Drive, GitHub, SharePoint, Dropbox, Notion, Trello, Figma, and other collaboration links.
- **Credential/Config Finder**: discovers in-scope URLs that look like exposed config files, source-control paths, database dumps, archives, logs, API docs, or similar sensitive paths.

No paid API key is required. Data is stored locally in SQLite at `blh_hunter.db`.

## Features

- Local FastAPI backend with single-page HTML UI.
- SQLite persistence for scan history, results, logs, and crawled pages.
- Passive seed discovery from root URLs, `robots.txt`, sitemaps, Wayback Machine CDX, and Common Crawl index data.
- Round-robin crawling across discovered hosts so one host does not consume the full crawl budget.
- Per-module scan history, filtering, stop/delete actions, and CSV export.
- Dashboard summaries across BLH, BAC, and Credential/Config results.
- Lazy-loaded dashboard domain detail pages with pagination for target links and crawled URLs.
- Legacy BLH API compatibility through root `main.py` and `/api/scans` routes.

## Tech Stack

- Python 3
- FastAPI
- Uvicorn
- SQLite
- httpx
- Pydantic
- aiosqlite
- python-dotenv

## Repository Layout

```text
main.py                    Compatibility entrypoint for the FastAPI app
index.html                 Browser UI
requirements.txt           Python dependencies
test_main.py               Unit and API tests
rules.md                   Scanner behavior contract
lazy_dorking/
  main.py                  FastAPI app, routers, static UI serving
  db.py                    SQLite schema, migrations, dashboard queries, shared DB helpers
  models.py                Request models
  shared.py                Domain validation, seed discovery, shared crawler helpers
  blh/
    api.py                 BLH endpoints and scan lifecycle
    scanner.py             BLH extraction and account checking
  bac/
    api.py                 BAC endpoints and scan lifecycle
    scanner.py             BAC service extraction and dork fallback
  cred/
    api.py                 Credential/Config endpoints and scan lifecycle
    scanner.py             Sensitive URL matching
  img/
    *.webp                 UI logo assets
```

## Prerequisites

- Python 3.11+ recommended.
- Network access for crawling target pages and public discovery sources.
- Authorization to test target domains.

## Installation

```bash
pip install -r requirements.txt
```

For isolated development, create and activate a virtual environment first:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Running Locally

Start the app:

```bash
uvicorn main:app --reload --port 8000
```

Open:

```text
http://localhost:8000
```

You can also run the compatibility entrypoint directly:

```bash
python main.py
```

The app creates `blh_hunter.db` automatically when it starts.

## Terminal Scanner (CLI)

For a lightweight run with **no web UI and no database**, use the terminal
scanner. It reuses the same crawl + link-check engine as the web app but keeps
everything in memory and prints results straight to stdout. The only dependency
is `httpx` (already in `requirements.txt`) — FastAPI, SQLite, and SQLAlchemy are
not needed.

```bash
# scan all platforms on a domain
python scan.py nasa.gov

# only specific platforms
python scan.py nasa.gov -p youtube,twitter,instagram

# cap the crawl at 30 target links
python scan.py example.com --max 30

# deep mode: also pull slow passive seeds (Wayback, CommonCrawl, subdomain
# sitemaps) for maximum coverage
python scan.py example.com --deep

# show only broken/non-alive links, export to JSON + CSV, quiet logs
python scan.py example.com --broken-only --json out.json --csv out.csv -q
```

By default the scanner seeds only from the live sitemap/robots and crawls the
root domain + subdomains — fast, and where almost all social/profile links
actually live (headers/footers). `--deep` adds Wayback + CommonCrawl +
subdomain-sitemap seeds for completeness, but those archive URLs are often slow
or dead, so a deep run on a large domain is much slower.

Equivalent module form: `python -m lazy_dorking.cli nasa.gov`.

Each result line is printed as:

```text
[200] <source_page_url> [PLATFORM] <social_url> [STATUS]
```

The first bracket is the source page (a live, in-scope 200 HTML page); the last
is the checked status of the social/profile link — an HTTP code like `[200]`
when alive, otherwise a label like `[BROKEN]`, `[REDIRECT]`, `[BLOCKED]`,
`[TIMEOUT]`, or `[UNKNOWN]`. Progress logs go to stderr, so piping stdout to a
file keeps only the result lines.

Key flags (`python scan.py --help` for the full list):

| Flag | Purpose |
| --- | --- |
| `-p, --platforms` | Comma-separated platforms (default: all) |
| `--deep` | Also pull slow passive seed sources for maximum coverage |
| `--max N` | Stop the crawl after N target links |
| `--timeout N` | Overall crawl time budget in seconds; stops with partial results (default: 300, `0` disables) |
| `--state FILE` | Persist crawled sources + results to a JSON file; repeat runs skip already-crawled pages (incremental) |
| `-c, --concurrency N` | Concurrent status checks (default: 10) |
| `--broken-only` | Print only links that are not alive |
| `--json FILE` / `--csv FILE` | Export full results |
| `-v` / `-q` | Verbose crawl logs / quiet |

### Large domains

Big targets (e.g. `nasa.gov`) have thousands of pages and many slow/dead
subdomains. The defaults already keep a run light:

- The default run **skips** the passive seed sources, so you are not waiting on
  slow/dead Wayback + CommonCrawl archive URLs. Only add `--deep` when you
  specifically want that extra coverage and can afford the wait. Note the
  seeding phase (including `--deep` sources) runs *before* the crawl and is
  **not** covered by `--timeout`.
- **`--timeout`** (default 300s) and **`--max`** bound the crawl itself, so it
  stops with partial results instead of grinding through up to 2000 pages.

Recommended first pass on a large domain:

```bash
python scan.py nasa.gov -p instagram,twitter --max 40 --timeout 120
```

Without `-v`, the crawl prints `[found] ...` and periodic `Crawling... visited=N`
lines to stderr so it never looks frozen.

### Incremental scans (`--state`)

The CLI is stateless by default: each run starts fresh and re-crawls everything,
so running the same command twice does the same work and returns the same links.
That is intentional (no database), but on a big domain it means every run pays
the full crawl cost.

Pass `--state FILE` to make runs **incremental**. The file (plain JSON) records
every source page crawled and every result found. On the next run with the same
file, already-crawled pages are skipped and new findings are merged in, so repeat
scans are near-instant and accumulate results over time:

```bash
# first run: full crawl, writes state
python scan.py nasa.gov -p instagram,twitter --state nasa.json

# later runs: skip already-crawled pages, only crawl/collect what's new
python scan.py nasa.gov -p instagram,twitter --state nasa.json
```

Add `--new-only` to print just the links discovered in the current run (instead
of the full accumulated set), which makes per-run progress obvious:

```bash
python scan.py nasa.gov -p instagram,twitter --state nasa.json --new-only
```

Use a separate state file per domain. Delete the file to force a fresh full scan.

**Note on very large domains:** a single run is bounded by `--timeout`/`--max`,
and a domain like `nasa.gov` has far more pages than one budget can crawl. With
`--state`, each run crawls a *fresh batch* of not-yet-seen pages and accumulates
new links, so coverage grows run over run — but an individual run still uses its
full time budget. It is incremental, not instant, on huge sites. For a quick
sample instead, use a small `--max`.

## Usage

1. Open the web UI.
2. Choose **BLH**, **BAC**, or **CRED** from the activity bar.
3. Enter a root domain.
4. Select platforms, services, or credential categories.
5. Start the scan and watch scan logs/results.
6. Use filters and CSV export for review.
7. Use **Dashboard** to inspect totals, recent scans, domains, target links, and crawled URLs.

A root-domain scan includes subdomains under that root. For example, scanning `example.com` keeps source crawling in scope for hosts ending in `.example.com`. External platform URLs may be checked as targets, but they are not crawled as source pages.

## Scanner Modules

### BLH Finder

Input: root domain plus selected platforms.

Supported platform families include:

| Platform | Domains |
|---|---|
| X / Twitter | `twitter.com`, `x.com` |
| Instagram | `instagram.com` |
| TikTok | `tiktok.com` |
| Facebook | `facebook.com`, `fb.com` |
| YouTube | `youtube.com`, `youtu.be` |
| LinkedIn | `linkedin.com` |
| GitHub | `github.com` |
| Discord | `discord.gg`, `discord.com` |
| Bitly | `bit.ly` |
| Flickr | `flickr.com` |

BLH stores source evidence and checks new target account URLs with HTTP requests. Known status labels are `pending`, `broken`, `alive`, `redirect`, `timeout`, `blocked`, and `unknown`.

### BAC Finder

Input: root domain plus selected services.

BAC discovers third-party resource links for Google Workspace, Microsoft sharing links, cloud storage links, development platforms, and collaboration tools. BAC stores discovered URLs for manual verification; it does not prove resource accessibility.

Google Drive target collection is scoped to `drive.google.com/drive/...` URLs and skips Drive links whose path, query, or fragment contains `sharing`.

### Credential/Config Finder

Input: root domain plus selected categories.

| Category | Examples |
|---|---|
| Config | `.env`, `config.json`, `settings.json`, `application.properties`, `web.config` |
| Docker | `Dockerfile`, `docker-compose.yml`, `.dockerignore` |
| Database Dumps | `.sql`, `.dump`, `.backup`, `.bak`, `.db`, `.sqlite` |
| Archives | `.zip`, `.tar.gz`, `.tgz`, `.rar`, `.7z`, `.sql.gz` |
| Logs | `.log`, `access.log`, `error.log`, `debug.log` |
| Source Control | `.git/config`, `.git/HEAD`, `.svn/entries`, `.hg/` |
| Other | `robots.txt`, `sitemap.xml`, `phpinfo.php`, `swagger.json`, `openapi.json` |

The current implementation is passive-first. If active brute-force is selected, the scan logs that MVP passive discovery is used.

## Database

`blh_hunter.db` contains independent tables per feature:

| Feature | Tables |
|---|---|
| BLH | `scans`, `results`, `scan_log`, `crawl_pages` |
| BAC | `bac_scans`, `bac_results`, `bac_scan_log`, `bac_crawl_pages` |
| Cred | `cred_scans`, `cred_results`, `cred_scan_log`, `cred_crawl_pages` |

BLH table names remain unchanged for backward compatibility.

## API

Feature-specific endpoints:

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/blh/scans` | Create BLH scan |
| `POST` | `/api/bac/scans` | Create BAC scan |
| `POST` | `/api/cred/scans` | Create Credential/Config scan |
| `GET` | `/api/{feature}/scans` | List recent scans |
| `GET` | `/api/{feature}/scans/{id}` | Scan detail and logs |
| `GET` | `/api/{feature}/scans/{id}/results` | Scan results |
| `GET` | `/api/{feature}/scans/{id}/export` | CSV export |
| `POST` | `/api/{feature}/scans/{id}/stop` | Cancel running scan |
| `DELETE` | `/api/{feature}/scans/{id}` | Delete scan and related data |

Legacy BLH endpoints under `/api/scans` are still available.

Dashboard endpoints:

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/dashboard` | Overall totals and feature summaries |
| `GET` | `/api/dashboard/{feature}` | Lightweight feature detail with stats, domain list, target-link count, and crawled-URL count |
| `GET` | `/api/dashboard/{feature}/domains/{domain}?view=targets` | Paginated target links for one main domain |
| `GET` | `/api/dashboard/{feature}/domains/{domain}?view=crawled` | Paginated crawled URLs for one main domain |

Supported query params for domain detail:

| Param | Applies to | Description |
|---|---|---|
| `view` | domain detail | `targets` or `crawled` |
| `limit` | domain detail | Page size, capped at 500; UI uses 100 |
| `offset` | domain detail | Row offset for pagination |
| `q` | `view=targets` | Text filter across target/source/anchor/type |
| `result_type` | `view=targets` | Platform, service, or file type |
| `status` | BLH `view=targets` | `pending`, `broken`, `alive`, `redirect`, `blocked`, `timeout`, or `unknown` |

Example BLH request:

```bash
curl -X POST http://localhost:8000/api/blh/scans \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"example.com\",\"platforms\":[\"twitter\",\"github\"]}"
```

Example BAC request:

```bash
curl -X POST http://localhost:8000/api/bac/scans \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"example.com\",\"services\":[\"google_drive\",\"github\"],\"include_dorking\":false}"
```

Example Credential/Config request:

```bash
curl -X POST http://localhost:8000/api/cred/scans \
  -H "Content-Type: application/json" \
  -d "{\"domain\":\"example.com\",\"categories\":[\"config\",\"source_control\"]}"
```

## Testing

```bash
python -m unittest test_main.py -v
```

The test suite covers BLH compatibility, database migration behavior, crawl-page writes, BAC extraction, Credential/Config URL matching, dashboard summaries, lazy domain detail loading, scan deletion, pause/continue behavior, manual BLH status updates, blocked-source logging, and logo asset serving.

## Safety Notes

- `rules.md` is the scanner behavior contract and should win over README/UI/test expectations if there is a conflict.
- Source crawling must stay within the requested root domain and subdomains.
- External social/collaboration links may be recorded or checked as target links, but should not be crawled as source pages.
- Deleting a scan removes its scan rows, results, logs, and crawl history from the local database.
- Use only on authorized targets.
