import argparse
import asyncio
import contextlib
import logging

from .analyzers import classify, extract, validate
from .engines import browser_fetch, crawlee_fetch
from .models import ScanConfig
from .network import fetch
from .providers import discover
from .store import Store
from ..shared import url_in_scope
from .intelligence import analyze_content, validate_exposure
from .probing import probe

log = logging.getLogger(__name__)


async def execute(job, store):
    config = ScanConfig(**job["config"])
    payload = job["payload"]
    if job["kind"] == "discover":
        provider = payload["provider"]
        seeds = await discover(provider, config.domain)
        output = {"urls": [], "findings": [], "message": f"{provider}: {len(seeds)} candidate URLs discovered"}
        for url in seeds[:config.max_urls]:
            if not url_in_scope(url, config.domain):
                continue
            output["urls"].append({"url": url, "provider": provider})
            for finding in classify(url, config):
                output["findings"].append({"finding": finding, "evidence": {
                    "source_url": "provider:" + provider, "source_type": "discovery", "discovered_by": provider}})
        return output
    await asyncio.sleep(config.per_host_delay)
    if job['kind'] == 'probe':
        return {'probe': await probe(payload['url'], config.domain, config.prober)}
    if job["kind"] in {"crawl", "browser"}:
        if job["kind"] == "browser":
            page = await browser_fetch(payload["url"], config.domain)
        else:
            engine = crawlee_fetch if config.engine == "crawlee" else fetch
            page = await engine(payload["url"], config.domain)
        output = extract(page, config, payload["depth"])
        intelligence = await analyze_content(page, config, payload["depth"])
        output['urls'].extend(intelligence['urls'])
        output['findings'].extend(intelligence['findings'])
        return output
    if job["kind"] == "validate":
        if payload['kind'] == 'secret':
            return {'validation': {'status': 'secret_signal', 'confidence': 'low',
                'reason': 'Pattern match only; values redacted and credentials not verified',
                'data': {'credential_verified': False}}}
        domain = config.domain if payload["kind"] == "cred" else None
        page = await fetch(payload["url"], domain)
        result = validate(page, payload['kind'])
        if payload['kind'] == 'cred' and config.exposure_validation and not page.error and 200 <= page.status < 300:
            matches = await validate_exposure(payload['url'])
            result['data']['template_matches'] = matches
            if matches:
                result.update(status='content_matched', confidence='high',
                              reason='Selected content template matched; impact requires manual review')
        return {'validation': result}
    raise ValueError("Unknown job kind")


async def run_one(store, execute_fn=execute):
    job = store.claim()
    if not job:
        return False
    task = asyncio.create_task(execute_fn(job, store))
    try:
        async with asyncio.timeout(100):
            while not task.done():
                await asyncio.wait({task}, timeout=2)
                if not store.heartbeat(job):
                    task.cancel()
                    return True
            store.complete(job, await task)
    except asyncio.CancelledError:
        store.fail(job, "Worker shutting down; job released for retry")
        raise
    except Exception as exc:
        store.fail(job, f"{type(exc).__name__}: {str(exc)[:300]}")
        log.warning("Job %s failed: %s", job["id"], type(exc).__name__)
    finally:
        if not task.done():
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task
    return True


async def serve(store, once=False):
    while True:
        worked = await run_one(store)
        if once:
            return
        if not worked:
            await asyncio.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="BLH v2 durable worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    store = Store()
    store.init()
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(serve(store, args.once))
    except KeyboardInterrupt:
        pass
    finally:
        store.engine.dispose()


if __name__ == "__main__":
    main()
