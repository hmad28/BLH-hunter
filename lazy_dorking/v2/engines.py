"""Crawlee adapters consume leased pages; BLH owns the durable frontier."""
import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta

from .network import Page, fetch, public_address
from ..shared import url_in_scope


async def crawlee_fetch(url, domain, *, fetch_fn=fetch):
    from crawlee import ConcurrencySettings
    from crawlee.crawlers import HttpCrawler
    from crawlee.http_clients import HttpClient, HttpCrawlingResult
    from crawlee.storage_clients import MemoryStorageClient

    captured = []

    class Response:
        def __init__(self, page):
            self.page = page
            self.status_code = page.status or 599
            self.headers = page.headers
            self.http_version = "HTTP/1.1"

        async def read(self):
            return self.page.body.encode()

        async def read_stream(self):
            yield await self.read()

    class ScopedClient(HttpClient):
        def __init__(self):
            super().__init__(persist_cookies_per_session=False)

        async def crawl(self, request, **kwargs):
            page = await fetch_fn(request.url, domain)
            page.engine = "crawlee"
            captured.append(page)
            request.loaded_url = page.url
            return HttpCrawlingResult(http_response=Response(page))

        async def send_request(self, url, **kwargs):
            return Response(await fetch_fn(url, domain))

        @asynccontextmanager
        async def stream(self, url, **kwargs):
            yield await self.send_request(url, **kwargs)

        async def cleanup(self):
            pass

    crawler = HttpCrawler(http_client=ScopedClient(), storage_client=MemoryStorageClient(),
        max_requests_per_crawl=1, max_request_retries=0, use_session_pool=False,
        concurrency_settings=ConcurrencySettings(min_concurrency=1, max_concurrency=1, desired_concurrency=1),
        ignore_http_error_status_codes=range(400, 600), configure_logging=False,
        request_handler_timeout=timedelta(seconds=30))

    @crawler.router.default_handler
    async def handle(context):
        # Never enqueue links here: only the persistent BLH frontier may do that.
        pass

    await crawler.run([url])
    if not captured:
        raise RuntimeError("Crawlee completed without a response")
    return captured[-1]


async def browser_fetch(url, domain):
    from crawlee import ConcurrencySettings
    from crawlee.crawlers import PlaywrightCrawler
    from crawlee.storage_clients import MemoryStorageClient

    await public_address(url)
    captured = []
    crawler = PlaywrightCrawler(storage_client=MemoryStorageClient(), headless=True,
        browser_type="chromium", max_requests_per_crawl=1, max_request_retries=0,
        browser_new_context_options={"service_workers": "block", "accept_downloads": False},
        use_session_pool=False, configure_logging=False,
        concurrency_settings=ConcurrencySettings(min_concurrency=1, max_concurrency=1, desired_concurrency=1),
        navigation_timeout=timedelta(seconds=20), request_handler_timeout=timedelta(seconds=30),
        ignore_http_error_status_codes=range(400, 600))

    @crawler.pre_navigation_hook
    async def scope_guard(context):
        async def route_request(route):
            request = route.request
            # Render in-scope resources only; external links are extracted, never navigated.
            if (request.method != "GET" or not url_in_scope(request.url, domain)
                    or request.resource_type in {'image', 'media', 'font'}):
                await route.abort()
                return
            try:
                await public_address(request.url)
            except (ValueError, OSError):
                await route.abort()
                return
            await route.continue_()
        await context.page.context.route("**/*", route_request)

    @crawler.router.default_handler
    async def handle(context):
        await asyncio.sleep(1)
        if not url_in_scope(context.page.url, domain):
            captured.append(Page(context.page.url, error="Out-of-scope browser navigation excluded", engine="browser"))
            return
        body = await context.page.content()
        response = context.response
        captured.append(Page(context.page.url, response.status if response else 0, body[:1_000_000],
            {"content-type": "text/html"}, truncated=len(body) > 1_000_000, engine="browser"))

    await crawler.run([url])
    if not captured:
        raise RuntimeError("Browser produced no page; check Chromium installation and worker logs")
    return captured[-1]
