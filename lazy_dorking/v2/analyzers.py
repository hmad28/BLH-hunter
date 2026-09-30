import re
from html.parser import HTMLParser
from types import SimpleNamespace
from urllib.parse import urljoin, urlparse

from ..shared import canonical_target_url, canonical_url, host_matches_any, url_in_scope, detect_access_challenge
from ..blh.scanner import (PLATFORM_DOMAINS, is_non_account_url, is_twitter_account_not_found,
                           is_facebook_page_not_found)
from ..bac.scanner import BAC_SERVICES, is_allowed_bac_target
from ..cred.scanner import match_sensitive_url


class Extractor(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = []
        self.anchor = None
        self.line = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        attr = {"a": "href", "script": "src", "iframe": "src", "form": "action", "link": "href"}.get(tag)
        value = attrs.get(attr, "") if attr else ""
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\"]+)", attrs.get("content", ""), re.I)
            value = match[1] if match else ""
            attr = "content"
        if value:
            url = urljoin(self.base, value)
            if urlparse(url).scheme in {"http", "https"}:
                item = {"url": url, "source_url": self.base, "source_type": tag,
                        "selector": f"{tag}[{attr}]", "line": self.getpos()[0], "anchor": ""}
                self.links.append(item)
                if tag == "a":
                    self.anchor = item

    def handle_data(self, data):
        if self.anchor is not None:
            self.anchor["anchor"] = (self.anchor["anchor"] + data.strip())[:200]

    def handle_endtag(self, tag):
        if tag == "a":
            self.anchor = None


def target_identity(url):
    url = canonical_target_url(url)
    parsed = urlparse(url)
    if parsed.hostname == "twitter.com":
        url = parsed._replace(netloc="x.com").geturl()
    return url


def classify(url, config):
    result = []
    try:
        parsed = urlparse(url)
        if parsed.username or parsed.password:
            return result
        if not parsed.fragment and not is_non_account_url(url):
            for platform in config.platforms:
                if host_matches_any(parsed.hostname, PLATFORM_DOMAINS[platform]):
                    result.append({"kind": "blh", "category": platform, "url": target_identity(url)})
                    break
        for service in config.services:
            domain = host_matches_any(parsed.hostname, BAC_SERVICES[service])
            if domain and is_allowed_bac_target(url, domain):
                result.append({"kind": "bac", "category": service, "url": canonical_target_url(url)})
                break
        match = match_sensitive_url(url, config.domain, config.categories)
        if match:
            result.append({"kind": "cred", "category": match["file_type"], "url": canonical_url(url)})
    except (ValueError, TypeError):
        return []
    return result


def extract(page, config, depth):
    output = {"page": page.metadata(), "urls": [], "findings": []}
    if page.error or not url_in_scope(page.url, config.domain):
        return output
    parser = Extractor(page.url)
    ctype = page.headers.get("content-type", "").lower()
    if "html" in ctype or (not ctype and "<" in page.body[:200]):
        parser.feed(page.body)
    for link in parser.links[:1000]:
        for finding in classify(link["url"], config):
            output["findings"].append({"finding": finding, "evidence": {
                **{k: v for k, v in link.items() if k != "url"}, "discovered_by": page.engine}})
        # Forms are evidence only: never submit or crawl their action automatically.
        if link["source_type"] != "form" and url_in_scope(link["url"], config.domain):
            output["urls"].append({"url": link["url"], "provider": page.engine, "depth": depth + 1})
    meaningful_links = sum(link["source_type"] == "a" for link in parser.links)
    shell = any(marker in page.body.lower() for marker in ('id="root"', 'id="app"', "__next", "app-root"))
    output["browser"] = bool(config.browser and page.engine != "browser" and
                             200 <= page.status < 300 and meaningful_links < 3 and shell)
    return output


def validate(page, kind):
    data = page.metadata()
    status, confidence, reason = "unknown", "low", "Response does not establish resource state"
    body = page.body.lower()
    parsed = urlparse(page.url)
    response = SimpleNamespace(status_code=page.status, text=page.body, headers=page.headers)
    if page.error:
        reason = page.error
        status = "timeout" if "timeout" in reason.lower() else "unknown"
    elif page.status in (401, 403):
        status, confidence, reason = "blocked", "high", f"HTTP {page.status}; access not established"
    elif page.status == 429 or detect_access_challenge(response):
        status, confidence, reason = "blocked", "high", "Rate limit or browser challenge"
    elif any(p in parsed.path.lower() for p in ("/login", "/signin", "/accounts/login")) or parsed.hostname == "accounts.google.com":
        status, confidence, reason = "login_required", "high", "Redirected to an authentication page; existence is unproven"
    elif page.status in (404, 410):
        status, confidence, reason = "broken" if kind == "blh" else "missing", "high", f"HTTP {page.status}"
    elif kind == "blh" and (is_twitter_account_not_found(response, parsed.hostname or "") or
                            is_facebook_page_not_found(response, parsed.hostname or "")):
        status, confidence, reason = "broken", "high", "Platform-specific not-found response (soft 404)"
    elif page.status >= 500:
        status, confidence, reason = "unknown", "low", f"Transient server error {page.status}; does not prove a broken profile"
    elif kind == "bac" and any(marker in body for marker in ("you need access", "request access", "access denied", "permission denied")):
        status, confidence, reason = "permission_denied", "medium", "Permission gate detected in response"
    elif 200 <= page.status < 300:
        status, confidence, reason = "reachable", "medium", "HTTP success; resource/account semantics require review"
        if kind == "cred":
            status, confidence, reason = "accessible_candidate", "medium", "Candidate path responds; content sensitivity requires review"
    # Raw bodies and credential values are never persisted in validation evidence.
    return {"status": status, "confidence": confidence, "reason": reason, "data": data}
