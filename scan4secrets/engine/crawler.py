"""DAST crawler: concurrent, scope-aware, supports auth headers/cookies/proxy.

v2.1 — JS + CSS aware:
- Inline <script> blocks scanned for URL string literals
- CSS files parsed for url(...) references
- .css.map files parsed (like .js.map)
- HTML <meta> content URLs followed
- Binary content-types skipped (image/, video/, audio/, font/, application/octet-stream)
- Response headers deduplicated globally by (header_name, sha256(value)) — no per-page repeats
"""

from __future__ import annotations
import hashlib
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

from .rules import Rule, KeywordIndex
from .findings import Finding
from .scanner import scan_text
from .sourcemap import extract_from_sourcemap

log = logging.getLogger("scan4secrets.crawler")

DEFAULT_UA = "scan4secrets/2.0 (+https://github.com/m14r41/scan4secrets)"

JS_URL_REGEX = re.compile(r'''["'`](/[A-Za-z0-9_\-./]{2,}?)["'`]''')
CSS_URL_REGEX = re.compile(r'''url\(\s*["']?([^)"']+)["']?\s*\)''', re.IGNORECASE)
CSS_IMPORT_REGEX = re.compile(r'''@import\s+(?:url\()?\s*["']([^"')]+)["']''', re.IGNORECASE)

BINARY_CONTENT_TYPES = (
    "image/", "video/", "audio/", "font/",
    "application/octet-stream", "application/pdf",
    "application/zip", "application/x-tar", "application/gzip",
    "application/x-rar", "application/x-7z-compressed",
    "application/wasm",
)

# Suffixes that we will refuse to queue (purely binary by convention)
SKIP_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".svg",
    ".mp4", ".mp3", ".webm", ".ogg", ".wav", ".flac", ".mov", ".avi",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".dmg", ".iso",
    ".wasm",
)


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def etld_plus_one(host: str) -> str:
    if _HAS_TLDEXTRACT:
        e = tldextract.extract(host)
        return f"{e.domain}.{e.suffix}" if e.suffix else host
    return ".".join(host.rsplit(".", 2)[-2:])


def build_session(
    *,
    user_agent: str = DEFAULT_UA,
    headers: Optional[Dict[str, str]] = None,
    cookie: Optional[str] = None,
    proxy: Optional[str] = None,
    verify_tls: bool = True,
    timeout: int = 10,
    pool_size: int = 64,
) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = user_agent
    if headers:
        s.headers.update(headers)
    if cookie:
        s.headers["Cookie"] = cookie
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.verify = verify_tls
    s.request_timeout = timeout  # type: ignore[attr-defined]
    adapter = requests.adapters.HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _get(session: requests.Session, url: str, timeout: int) -> Optional[requests.Response]:
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        log.debug("fetch failed %s: %s", url, e)
        return None


def _content_type(resp: requests.Response) -> str:
    ct = resp.headers.get("Content-Type", "").lower()
    return ct.split(";", 1)[0].strip()


def _is_binary_response(resp: requests.Response) -> bool:
    ct = _content_type(resp)
    return any(ct.startswith(p) for p in BINARY_CONTENT_TYPES)


def _looks_binary_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(SKIP_SUFFIXES)


def _extract_links_html(html: str, base_url: str) -> Set[str]:
    """Pull URLs out of an HTML page: anchors, scripts, links, images, iframes,
    forms, meta refresh, plus inline <script> string literals."""
    out: Set[str] = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return out

    for tag in soup.find_all(["a", "script", "link", "img", "iframe", "form", "source", "video", "audio"]):
        for attr in ("href", "src", "action", "data-src", "data-href"):
            v = tag.get(attr)
            if not v:
                continue
            full, _ = urldefrag(urljoin(base_url, v))
            if full.startswith(("http://", "https://")):
                out.add(full)

    # <meta http-equiv="refresh" content="0;url=/somewhere">
    for tag in soup.find_all("meta"):
        ctype = (tag.get("http-equiv") or "").lower()
        content = tag.get("content") or ""
        if ctype == "refresh" and "url=" in content.lower():
            target = content.split("=", 1)[1].split(";")[0].strip().strip("'\"")
            full, _ = urldefrag(urljoin(base_url, target))
            if full.startswith(("http://", "https://")):
                out.add(full)

    # inline <script> blocks — extract URL string literals
    for tag in soup.find_all("script"):
        if tag.get("src"):
            continue  # external scripts followed via src attribute already
        body = tag.string or ""
        for m in JS_URL_REGEX.finditer(body):
            path = m.group(1)
            if path.startswith("//"):
                continue
            full, _ = urldefrag(urljoin(base_url, path))
            if full.startswith(("http://", "https://")):
                out.add(full)

    # inline <style> blocks — extract url() references
    for tag in soup.find_all("style"):
        body = tag.string or ""
        for m in CSS_URL_REGEX.finditer(body):
            ref = m.group(1).strip()
            if ref.startswith(("data:", "//")):
                continue
            full, _ = urldefrag(urljoin(base_url, ref))
            if full.startswith(("http://", "https://")):
                out.add(full)
    return out


def _extract_endpoints_from_js(js: str, base_url: str) -> Set[str]:
    out: Set[str] = set()
    for m in JS_URL_REGEX.finditer(js):
        path = m.group(1)
        if path.startswith("//"):
            continue
        out.add(urljoin(base_url, path))
    # ALSO follow //# sourceMappingURL=foo.js.map references
    for m in re.finditer(r'sourceMappingURL\s*=\s*([^\s*]+)', js):
        ref = m.group(1).strip()
        full, _ = urldefrag(urljoin(base_url, ref))
        if full.startswith(("http://", "https://")):
            out.add(full)
    return out


def _extract_urls_from_css(css: str, base_url: str) -> Set[str]:
    """Pull url(...) and @import targets from a CSS file, plus sourceMappingURL."""
    out: Set[str] = set()
    for regex in (CSS_URL_REGEX, CSS_IMPORT_REGEX):
        for m in regex.finditer(css):
            ref = m.group(1).strip()
            if ref.startswith(("data:", "//")):
                continue
            full, _ = urldefrag(urljoin(base_url, ref))
            if full.startswith(("http://", "https://")):
                out.add(full)
    # /*# sourceMappingURL=foo.css.map */
    for m in re.finditer(r'sourceMappingURL\s*=\s*([^\s*]+)', css):
        ref = m.group(1).strip()
        full, _ = urldefrag(urljoin(base_url, ref))
        if full.startswith(("http://", "https://")):
            out.add(full)
    return out


def _scope_ok(url: str, scope_etld: str, scope_strict_host: Optional[str]) -> bool:
    host = urlparse(url).netloc.split(":")[0]
    if scope_strict_host:
        return host == scope_strict_host
    return etld_plus_one(host) == scope_etld


def _header_dedup_key(name: str, value: str) -> Tuple[str, str]:
    return (name.lower(), hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest())


def crawl_and_scan(
    start_url: str,
    rules: List[Rule],
    *,
    session: Optional[requests.Session] = None,
    max_urls: int = 500,
    max_depth: int = 3,
    threads: int = 16,
    timeout: int = 10,
    strict_host: bool = False,
    extra_seeds: Optional[Iterable[str]] = None,
    parse_sourcemaps: bool = True,
    extract_js_endpoints: bool = True,
    progress_cb=None,
) -> List[Finding]:
    session = session or build_session()
    start_url = normalize_url(start_url)
    host = urlparse(start_url).netloc.split(":")[0]
    scope_etld = etld_plus_one(host)
    scope_host = host if strict_host else None

    index = KeywordIndex(rules)
    visited: Set[str] = set()
    queue: List[tuple] = [(start_url, 0)]
    for s in extra_seeds or []:
        queue.append((s, 0))
    findings: List[Finding] = []
    seen_header_values: Set[Tuple[str, str]] = set()
    header_lock = threading.Lock()

    while queue and len(visited) < max_urls:
        batch = []
        next_queue: List[tuple] = []
        for url, depth in queue:
            if url in visited or depth > max_depth:
                continue
            if not _scope_ok(url, scope_etld, scope_host):
                continue
            if _looks_binary_url(url):
                continue
            visited.add(url)
            batch.append((url, depth))
            if len(visited) >= max_urls:
                break
        if not batch:
            queue = next_queue
            continue

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(_get, session, u, timeout): (u, d) for u, d in batch}
            for fut in as_completed(futs):
                url, depth = futs[fut]
                if progress_cb:
                    progress_cb(url)
                resp = fut.result()
                if resp is None:
                    continue
                if _is_binary_response(resp):
                    continue
                text = resp.text or ""
                if not text:
                    continue

                ct = _content_type(resp)

                findings.extend(scan_text(text, url, rules, index, source_kind="dast"))

                # response-header scan — DEDUPLICATED across the whole crawl
                for hname, hval in resp.headers.items():
                    key = _header_dedup_key(hname, hval)
                    with header_lock:
                        if key in seen_header_values:
                            continue
                        seen_header_values.add(key)
                    findings.extend(
                        scan_text(f"{hname}: {hval}", f"{url}#header:{hname}", rules, index, source_kind="dast")
                    )

                # source map embedded sources
                if parse_sourcemaps and (url.endswith(".js.map") or url.endswith(".css.map")):
                    for srcname, src in extract_from_sourcemap(text):
                        findings.extend(
                            scan_text(src, f"{url}#source:{srcname}", rules, index, source_kind="dast")
                        )

                # link extraction depends on content type
                child_links: Set[str] = set()
                if "html" in ct or text.lstrip().startswith(("<!", "<html", "<HTML", "<?xml")):
                    child_links |= _extract_links_html(text, url)
                if "css" in ct or url.lower().endswith((".css",)):
                    child_links |= _extract_urls_from_css(text, url)
                if extract_js_endpoints and (
                    "javascript" in ct or "json" in ct or url.lower().endswith((".js", ".mjs"))
                ):
                    child_links |= _extract_endpoints_from_js(text, url)

                if depth + 1 <= max_depth:
                    for link in child_links:
                        if link not in visited and not _looks_binary_url(link):
                            next_queue.append((link, depth + 1))
        queue = next_queue

    return findings
