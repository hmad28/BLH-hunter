from urllib.parse import urlparse

import lazy_dorking.db as db
from lazy_dorking.main import app
from lazy_dorking.shared import canonical_target_url, canonical_url
from lazy_dorking.blh import api as blh_api
from lazy_dorking.blh import scanner as blh_scanner
from lazy_dorking.bac import api as bac_api
from lazy_dorking.bac import scanner as bac_scanner
from lazy_dorking.cred import api as cred_api
from lazy_dorking.cred import scanner as cred_scanner

DB_PATH = db.DB_PATH
_running_scans = blh_api._running_scans
_paused_scans = blh_api._paused_scans
_deleted_scans = blh_api._deleted_scans

is_non_account_url = blh_scanner.is_non_account_url
is_facebook_account_not_found = blh_scanner.is_facebook_account_not_found


def _sync_db_path():
    db.DB_PATH = DB_PATH
    blh_api.DB_PATH = DB_PATH
    blh_scanner.DB_PATH = DB_PATH
    bac_api.DB_PATH = DB_PATH
    bac_scanner.DB_PATH = DB_PATH
    cred_api.DB_PATH = DB_PATH
    cred_scanner.DB_PATH = DB_PATH


def init_db():
    _sync_db_path()
    return db.init_db()


def update_scan_status(*args, **kwargs):
    _sync_db_path()
    return db.update_scan_status(*args, **kwargs)


def log_scan(*args, **kwargs):
    _sync_db_path()
    return db.log_scan(*args, **kwargs)


def _write_crawl_page(*args, **kwargs):
    _sync_db_path()
    return db._write_crawl_page(
        *args,
        platforms_key_fn=kwargs.pop("platforms_key_fn", blh_scanner.platforms_key),
        load_platforms_fn=kwargs.pop("load_platforms_fn", blh_scanner.load_platforms_json),
        **kwargs,
    )


def get_known_source_urls(domain, platforms, *args, **kwargs):
    _sync_db_path()
    return db.get_known_source_urls(
        domain,
        platforms,
        *(args or ("crawl_pages",)),
        normalize_fn=kwargs.pop("normalize_fn", blh_scanner.normalize_platforms_list),
        platforms_key_fn=kwargs.pop("platforms_key_fn", blh_scanner.platforms_key),
        parse_key_fn=kwargs.pop("parse_key_fn", blh_scanner.parse_platforms_key),
        **kwargs,
    )


def get_seen_target_urls(*args, **kwargs):
    _sync_db_path()
    return db.get_seen_target_urls(*args, **kwargs)


async def stop_scan(scan_id: str):
    _sync_db_path()
    return await blh_api.stop_scan(scan_id)


async def delete_scan(scan_id: str):
    _sync_db_path()
    return await blh_api.delete_scan(scan_id)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
