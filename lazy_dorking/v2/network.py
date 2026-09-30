"""Bounded HTTP fetches with explicit redirect policy for source/target separation."""
import asyncio
import hashlib
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from ..shared import url_in_scope


@dataclass
class Page:
    url: str
    status: int = 0
    body: str = ""
    headers: dict = field(default_factory=dict)
    error: str = ""
    truncated: bool = False
    engine: str = "native"

    def metadata(self):
        return {"final_url": self.url, "http_code": self.status, "error": self.error,
                "content_type": self.headers.get("content-type", ""), "engine": self.engine,
                "truncated": self.truncated, "body_sha256": hashlib.sha256(self.body.encode()).hexdigest()}


async def public_address(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Unsupported URL")
    addresses = await asyncio.get_running_loop().getaddrinfo(parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise ValueError("Non-public destination excluded")


async def fetch(url, domain=None, *, client=None, allow_private=False, max_bytes=1_000_000):
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False,
        headers={"User-Agent": "BLH-Hunter/2.0 (authorized exposure review)"})
    current = url
    try:
        for _ in range(6):
            if domain and not url_in_scope(current, domain):
                return Page(current, error="Out-of-scope redirect excluded")
            if not allow_private:
                await public_address(current)
            async with client.stream("GET", current, follow_redirects=False) as response:
                if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("location"):
                    current = urljoin(current, response.headers["location"])
                    continue
                chunks = bytearray()
                truncated = False
                async for chunk in response.aiter_bytes():
                    if len(chunks) + len(chunk) > max_bytes:
                        chunks.extend(chunk[:max_bytes - len(chunks)])
                        truncated = True
                        break
                    chunks.extend(chunk)
                return Page(current, response.status_code, bytes(chunks).decode("utf-8", errors="replace"),
                            dict(response.headers), truncated=truncated)
        return Page(current, error="Redirect limit exceeded")
    except (httpx.HTTPError, ValueError, OSError) as exc:
        return Page(current, error=f"{type(exc).__name__}: {str(exc)[:160]}")
    finally:
        if own_client:
            await client.aclose()
