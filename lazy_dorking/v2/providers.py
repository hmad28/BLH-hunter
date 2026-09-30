import asyncio
import json
import os
import re
import shutil
from html import unescape
from urllib.parse import urljoin

import httpx

from ..shared import (domain_base_urls, fetch_wayback_source_urls,
                      fetch_commoncrawl_source_urls, url_in_scope)
from .network import fetch


def capabilities():
    import importlib.util
    return {"crawlee": importlib.util.find_spec("crawlee") is not None,
            "browser": importlib.util.find_spec("playwright") is not None,
            **{name: shutil.which(name) is not None for name in ("subfinder", "gau", "katana", "jsluice", "gitleaks", "nuclei")},
            "pd-httpx": shutil.which(os.getenv('BLH_HTTPX_BIN', 'httpx-toolkit')) is not None}


async def command_lines(args, timeout=75, max_bytes=8_000_000):
    """No shell interpolation; cap output; kill/reap on timeout or cancellation."""
    executable = shutil.which(args[0])
    if not executable:
        raise RuntimeError(f"{args[0]} is not installed on this worker")
    proc = await asyncio.create_subprocess_exec(executable, *args[1:],
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        start_new_session=os.name != "nt")

    async def bounded(stream):
        output = bytearray()
        while chunk := await stream.read(65536):
            output.extend(chunk)
            if len(output) > max_bytes:
                raise RuntimeError("Tool output limit exceeded")
        return output.decode(errors="replace")

    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await asyncio.gather(bounded(proc.stdout), bounded(proc.stderr))
            await proc.wait()
            if proc.returncode:
                # Tool stderr can contain fetched source code or credential values.
                raise RuntimeError(f"{args[0]} exited {proc.returncode}")
            return stdout.splitlines()
    finally:
        if proc.returncode is None:
            if os.name != "nt":
                import signal
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
            await proc.wait()


async def sitemap_urls(domain):
    seeds, queue, seen = [], [], set()
    for base in domain_base_urls(domain):
        queue.append(urljoin(base, "/sitemap.xml"))
        robots = await fetch(urljoin(base, "/robots.txt"), domain, max_bytes=200000)
        if robots.status == 200:
            queue.extend(line.split(":", 1)[1].strip() for line in robots.body.splitlines()
                         if line.lower().startswith("sitemap:"))
    while queue and len(seen) < 20 and len(seeds) < 2000:
        url = queue.pop(0)
        if url in seen or not url_in_scope(url, domain):
            continue
        seen.add(url)
        page = await fetch(url, domain)
        if page.status != 200:
            continue
        is_index = "<sitemapindex" in page.body.lower()
        for loc in re.findall(r"<loc>\s*([^<]+)\s*</loc>", page.body, re.I):
            loc = unescape(loc.strip())
            if url_in_scope(loc, domain):
                (queue if is_index else seeds).append(loc)
    return seeds[:2000]


async def discover(provider, domain):
    if provider == "roots":
        return domain_base_urls(domain)
    if provider == "sitemap":
        return await sitemap_urls(domain)
    if provider in {"wayback", "commoncrawl"}:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False) as client:
            fn = fetch_wayback_source_urls if provider == "wayback" else fetch_commoncrawl_source_urls
            return await fn(client, domain, limit=1000)
    if provider == "subfinder":
        lines = await command_lines(["subfinder", "-d", domain, "-json", "-silent", "-max-time", "1"])
        return [f"https://{json.loads(line)['host']}/" for line in lines if line.startswith("{")]
    if provider == "gau":
        return await command_lines(["gau", "--subs", "--threads", "2", "--timeout", "20", domain])
    if provider == "katana":
        # Explicit opt-in; bounded independent discovery, no automatic form submission.
        lines = await command_lines(["katana", "-u", f"https://{domain}", "-jsonl", "-silent",
            "-d", "2", "-ct", "45s", "-rl", "2", "-c", "2", "-jc",
            "-cs", rf"^https?://([a-zA-Z0-9-]+\.)*{re.escape(domain)}(?::\d+)?(?:/|$)"])
        return [json.loads(line).get("request", {}).get("endpoint", "") for line in lines if line.startswith("{")]
    raise ValueError(f"Unsupported provider: {provider}")
