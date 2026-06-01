# Lazy Dorking Expansion Plan

Expand BLH Hunter into a multi-feature security recon tool named "Lazy Dorking" by adding BAC Finder and Exposed Credential/Config Finder modules, while keeping rules.md untouched and preserving all existing BLH behavior.

## Phase 1: Foundation Refactor

### 1.1 Project Rebrand
- Rename UI title from "BLH Hunter" to "Lazy Dorking" in `index.html` title bar and status bar.
- Keep DB file name `blh_hunter.db` to avoid breaking existing data (or migrate if trivial).
- Update README branding to reflect multi-feature scope.

### 1.2 Modularize Backend
- Split `main.py` into a package structure:
  ```
  lazy_dorking/
  ├── __init__.py
  ├── main.py              # FastAPI app, lifespan, shared middleware
  ├── db.py                # init_db(), helpers, shared connection logic
  ├── models.py            # Pydantic request models
  ├── shared.py            # utc_now_iso(), DOMAIN_RE, SKIP_PATH_RE, AnchorExtractor, canonical_url()
  ├── blh/
  │   ├── __init__.py
  │   ├── scanner.py       # BLH-specific crawl + check logic (moved from main.py)
  │   └── api.py           # BLH API endpoints (/api/blh/scans, etc.)
  ├── bac/
  │   ├── __init__.py
  │   ├── scanner.py       # BAC crawl + extract logic
  │   └── api.py           # BAC API endpoints (/api/bac/scans, etc.)
  └── cred/
      ├── __init__.py
      ├── scanner.py       # Cred crawl + extract logic
      └── api.py           # Cred API endpoints (/api/cred/scans, etc.)
  ```
- **Rationale**: Each feature has independent scan lifecycle, results table, and API surface. Shared code lives in `db.py`, `shared.py`, and `models.py`.

### 1.3 Database Schema Extension
- Keep existing tables (`scans`, `results`, `scan_log`, `crawl_pages`) under BLH namespace or rename prefix.
- Add new tables:
  - `bac_scans`, `bac_results`, `bac_scan_log`, `bac_crawl_pages`
  - `cred_scans`, `cred_results`, `cred_scan_log`, `cred_crawl_pages`
- Alternatively, generalize with a `feature` column on shared tables. **Decision**: separate tables per feature for isolation and simpler queries.
- `_running_scans` and `_deleted_scans` in-memory state must become per-feature (e.g., `_running_blh`, `_running_bac`, `_running_cred`).

### 1.4 Shared Crawl Infrastructure
- `discover_sources_by_crawling` and host-balanced frontier logic are generic. Extract to `shared.py` so BAC and Cred can reuse the same frontier, dedup, and crawl-page tracking.
- Parameterize: pass `extract_targets_fn` and `is_target_fn` so each module defines its own link-filtering rules while sharing the crawl engine.

## Phase 2: BAC Finder

### 2.1 Scope & Behavior
- **Goal**: Discover publicly linked cloud resources (Drive, Docs, Sheets, GitHub, GitLab, etc.) on the target domain/subdomains.
- **Approach**: Same as BLH — seed discovery (sitemap/robots/Wayback/CommonCrawl) → host-balanced crawling → extract matching links.
- **No accessibility check**: BAC Finder only collects URLs. User verifies manually.

### 2.2 Target Services (user-selectable chips)
- **Google Workspace**: `drive.google.com`, `docs.google.com`, `sheets.google.com`, `slides.google.com`, `forms.gle`, `sites.google.com`
- **Microsoft**: `onedrive.live.com`, `sharepoint.com`
- **Cloud Storage**: `dropbox.com`, `box.com`, `mega.nz`, `mediafire.com`
- **Dev Platforms**: `github.com`, `gitlab.com`, `bitbucket.org`
- **Collab**: `notion.so`, `confluence.*`, `jira.*`, `trello.com`, `figma.com`, `miro.com`, `canva.com`
- **Presentation**: `prezi.com`, `pitch.com`

### 2.3 Link Extraction Rules
- Extract `<a href>` pointing to any selected service domain.
- Validate with `ACCOUNT_PATH_PATTERNS`-equivalent regexes per service where applicable (e.g., GitHub repo path, Google Drive folder ID pattern).
- No reserved-path filtering needed for BAC (all links to these services are interesting).

### 2.4 Results Schema
- `bac_results`: `scan_id`, `service`, `source_url`, `target_url`, `anchor_text`, `extracted_at`

### 2.5 Alternative Discovery: Google Dorking
- If user opts in, supplement crawling with SERP scraping for queries like:
  - `site:*.target.com drive.google.com`
  - `site:*.target.com github.com`
  - `site:*.target.com notion.so`
- **Constraint**: No paid APIs (no Google Custom Search). Use lightweight HTTP requests to Google/Bing with parsing fallback. Handle rate-limit gracefully (log warning, skip).
- **Dork results are de-duplicated against crawl results** before storage.

## Phase 3: Exposed Credential/Config Finder

### 3.1 Scope & Behavior
- **Goal**: Discover URLs on the target domain/subdomains that match sensitive file patterns or paths.
- **Approach**: Same crawling engine, but target URLs are **on the target domain itself** (not external platforms).
- **No content check**: Only URL discovery. User verifies manually.

### 3.2 Pattern Categories (hardcoded list, extensible via config file)
- **Config Files**: `.env`, `.env.local`, `.env.production`, `.env.development`, `config.json`, `config.yaml`, `config.yml`, `settings.json`, `application.properties`, `web.config`
- **Docker**: `dockerfile`, `docker-compose.yml`, `docker-compose.yaml`, `.dockerignore`
- **Database Dumps**: `*.sql`, `*.dump`, `*.backup`, `*.bak`, `*.db`, `*.sqlite`
- **Archives**: `*.zip`, `*.tar.gz`, `*.tgz`, `*.rar`, `*.7z`, `*.sql.gz`
- **Logs**: `*.log`, `access.log`, `error.log`, `debug.log`
- **Source Control**: `.git/config`, `.git/HEAD`, `.svn/entries`, `.hg/`
- **Other**: `robots.txt`, `sitemap.xml`, `crossdomain.xml`, `phpinfo.php`, `server-status`, `api-docs`, `swagger.json`, `openapi.json`

### 3.3 Discovery Modes
- **Passive** (default): During normal crawl, any encountered URL matching patterns above is captured.
- **Active** (optional): After crawl, brute-force common paths against discovered subdomains (e.g., `https://sub.target.com/.env`, `https://sub.target.com/config.json`). Use lightweight `HEAD` requests with rate limiting. **This is a stretch goal; default to passive only.**

### 3.4 Results Schema
- `cred_results`: `scan_id`, `file_type`, `pattern_matched`, `source_url`, `target_url`, `extracted_at`

## Phase 4: UI Integration

### 4.1 Activity Bar
- Replace current 3-icon bar with feature switcher:
  - 🔗 **BLH** (link icon)
  - 📁 **BAC** (folder icon)
  - 🔑 **Cred** (key icon)
  - ▶️ **Run** (play icon — focuses the active feature's form)
  - ⚙️ **Settings** (gear icon)
- Clicking an icon updates `sidebar-content` with that feature's form and history tree.

### 4.2 Sidebar Per Feature
- Each feature gets its own form template:
  - **BLH**: Domain input + platform chips (existing)
  - **BAC**: Domain input + service chips (Drive, Docs, GitHub, GitLab, etc.) + optional "Include Google Dorking" checkbox
  - **Cred**: Domain input + pattern category checkboxes (Config, Docker, DB Dumps, Archives, Logs, Source Control, Other) + optional "Active brute-force" checkbox (stretch)
- Scan history tree per feature shows only that feature's scans.

### 4.3 Main Area
- Shared results table per feature.
- Columns adapt:
  - BLH: Platform | Target URL | Status | HTTP Code | Source
  - BAC: Service | Target URL | Source | Anchor Text
  - Cred: File Type | Pattern | Target URL | Source
- Filter and export CSV per feature.

### 4.4 Terminal Panel
- Shared terminal panel. Logs prefixed with feature tag: `[BLH]`, `[BAC]`, `[CRED]`.
- Stop button works on the currently active feature's running scan.

## Data Model Summary

| Table | Purpose |
|---|---|
| `scans` / `results` / `scan_log` / `crawl_pages` | Keep as-is for BLH backward-compat, or prefix with `blh_` |
| `bac_scans` / `bac_results` / `bac_scan_log` / `bac_crawl_pages` | BAC lifecycle |
| `cred_scans` / `cred_results` / `cred_scan_log` / `cred_crawl_pages` | Cred lifecycle |

All follow same schema shape as existing tables for consistency.

## API Surface

| Endpoint | Feature | Action |
|---|---|---|
| `POST /api/blh/scans` | BLH | Create scan |
| `POST /api/bac/scans` | BAC | Create scan |
| `POST /api/cred/scans` | Cred | Create scan |
| `POST /api/{feature}/scans/{id}/stop` | All | Cancel scan |
| `DELETE /api/{feature}/scans/{id}` | All | Delete scan |
| `GET /api/{feature}/scans` | All | List scans |
| `GET /api/{feature}/scans/{id}` | All | Scan detail + logs |
| `GET /api/{feature}/scans/{id}/results` | All | Filtered results |
| `GET /api/{feature}/scans/{id}/export` | All | CSV export |

## Testing Strategy
- Unit tests per module (`test_blh.py`, `test_bac.py`, `test_cred.py`) using mocked `httpx` responses.
- Shared crawl engine tests in `test_shared.py`.
- UI: manual verification of activity bar switching and per-feature form rendering.

## Notes & Constraints
- **rules.md must remain unchanged**.
- No paid APIs for dorking. SERP scraping is optional and must fail gracefully.
- Active brute-force for Cred is stretch; passive discovery is MVP.
- Keep VS Code aesthetic. Do not introduce new CSS frameworks.
- Preserve all existing BLH tests and behavior.
