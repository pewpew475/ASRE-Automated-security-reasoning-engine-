import asyncio
import json
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from api.routes.websocket import publish_scan_event
from config import settings

try:
    from playwright.async_api import Browser, BrowserContext, Page, async_playwright

    PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover
    Browser = object  # type: ignore[assignment]
    BrowserContext = object  # type: ignore[assignment]
    Page = object  # type: ignore[assignment]
    async_playwright = None  # type: ignore[assignment]
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class EndpointData:
    url: str
    method: str
    params: List[Dict]
    body_params: List[Dict]
    headers: Dict[str, str]
    auth_required: bool = False
    content_type: Optional[str] = None
    status_code: Optional[int] = None
    source: str = "httpx"


@dataclass
class CrawlConfig:
    max_depth: int = 5
    max_pages: int = 100
    excluded_paths: List[str] = field(default_factory=list)
    follow_redirects: bool = True
    scan_rate_limit: int = 10
    respect_robots: bool = True
    user_agent: str = (
        "ASRE-Scanner/1.0 (Authorized Security Audit; "
        "+https://github.com/your-org/asre)"
    )


class Crawler:
    def __init__(
        self,
        target_url: str,
        config: Optional[dict],
        credentials: Optional[dict],
        scan_id: str,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.credentials = credentials or {}
        self.scan_id = scan_id

        self.config = CrawlConfig(**config) if config else CrawlConfig()
        self.visited_urls: Set[str] = set()
        self.discovered: List[EndpointData] = []
        self.base_domain: str = urlparse(self.target_url).netloc.lower()
        self.robots_disallowed: Set[str] = set()
        self.session_cookies: Dict[str, str] = {}
        self.allow_subdomains = bool((config or {}).get("subdomain_scope", False))

        self.logger = logging.getLogger(__name__)

    async def crawl(self) -> List[EndpointData]:
        parsed = urlparse(self.target_url)
        self.base_domain = parsed.netloc.lower()

        if self.config.respect_robots:
            await self._fetch_robots_txt()

        if self.credentials:
            await self._authenticate_with_playwright()

        await self._bfs_crawl(start_url=self.target_url)

        deduped: List[EndpointData] = []
        seen: Set[Tuple[str, str]] = set()
        for endpoint in self.discovered:
            key = (endpoint.url.rstrip("/"), endpoint.method.upper())
            if key in seen:
                continue
            seen.add(key)
            deduped.append(endpoint)

        self.discovered = deduped

        await publish_scan_event(
            self.scan_id,
            "scan.progress",
            {
                "endpoints_found": len(self.discovered),
                "vulns_found": 0,
                "chains_found": 0,
            },
        )

        self.logger.info("Crawl complete: %s endpoints discovered", len(self.discovered))
        return self.discovered

    async def _fetch_robots_txt(self) -> None:
        parsed = urlparse(self.target_url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}/"
        robots_url = urljoin(base_origin, "robots.txt")
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                verify=False,
                headers={"User-Agent": self.config.user_agent},
            ) as client:
                response = await client.get(robots_url)

            if response.status_code >= 400:
                self.logger.warning(
                    "robots.txt unavailable at %s (status=%s)",
                    robots_url,
                    response.status_code,
                )
                return

            in_wildcard_section = False
            for raw_line in response.text.splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                lower_line = line.lower()
                if lower_line.startswith("user-agent:"):
                    agent = line.split(":", 1)[1].strip()
                    in_wildcard_section = agent == "*"
                    continue

                if in_wildcard_section and lower_line.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        self.robots_disallowed.add(path)
        except Exception as exc:
            self.logger.warning("Failed to fetch robots.txt: %s", exc)

    async def _authenticate_with_playwright(self) -> None:
        cookie_header = self.credentials.get("cookie")
        if cookie_header:
            parts = [part.strip() for part in cookie_header.split(";") if part.strip()]
            for part in parts:
                if "=" not in part:
                    continue
                key, value = part.split("=", 1)
                self.session_cookies[key.strip()] = value.strip()
            return

        if not PLAYWRIGHT_AVAILABLE or async_playwright is None:
            self.logger.warning("Playwright not installed, continuing unauthenticated crawl")
            return

        login_url = self.credentials.get("login_url")
        username = self.credentials.get("username")
        password = self.credentials.get("password")
        if not login_url or not username or not password:
            self.logger.warning("Incomplete credentials supplied, continuing unauthenticated")
            return

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=self.config.user_agent,
                    ignore_https_errors=True,
                )
                page = await context.new_page()

                original_login_url = login_url
                await page.goto(login_url, wait_until="domcontentloaded")

                username_selectors = [
                    "input[type='email']",
                    "input[type='text']",
                    "input[name*='user' i]",
                    "input[name*='email' i]",
                ]
                password_selectors = [
                    "input[type='password']",
                    "input[name*='pass' i]",
                ]
                submit_selectors = [
                    "button[type='submit']",
                    "input[type='submit']",
                    "button:has-text('Login')",
                    "button:has-text('Sign in')",
                ]

                username_selector = await self._first_selector(page, username_selectors)
                password_selector = await self._first_selector(page, password_selectors)
                submit_selector = await self._first_selector(page, submit_selectors)

                if not username_selector or not password_selector or not submit_selector:
                    self.logger.warning("Login form fields not detected, continuing unauthenticated")
                    await browser.close()
                    return

                await page.fill(username_selector, str(username))
                await page.fill(password_selector, str(password))
                await page.click(submit_selector)

                try:
                    await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    self.logger.debug("Login navigation did not reach networkidle before timeout")

                login_failed_markers = ["invalid password", "login failed", "incorrect password"]
                body_text = (await page.content()).lower()
                login_failed = any(marker in body_text for marker in login_failed_markers)
                current_url = page.url

                if login_failed or current_url.rstrip("/") == original_login_url.rstrip("/"):
                    self.logger.warning("Login appears unsuccessful, continuing unauthenticated")
                    await browser.close()
                    return

                cookies = await context.cookies()
                extracted: Dict[str, str] = {}
                for cookie in cookies:
                    name = cookie.get("name")
                    value = cookie.get("value")
                    if name is None or value is None:
                        continue
                    extracted[name] = value
                self.session_cookies = extracted

                await browser.close()

                self.logger.info(
                    "Authentication successful - %s cookies captured",
                    len(self.session_cookies),
                )
        except Exception as exc:
            self.logger.warning("Playwright authentication failed: %s", exc)

    async def _bfs_crawl(self, start_url: str) -> None:
        queue: deque[Tuple[str, int]] = deque([(start_url, 0)])
        semaphore = asyncio.Semaphore(self.config.scan_rate_limit)

        static_asset_pattern = re.compile(
            r"\.(css|js|png|jpg|gif|ico|woff2?|ttf|svg|pdf)$", re.IGNORECASE
        )

        while queue and len(self.visited_urls) < self.config.max_pages:
            url, depth = queue.popleft()
            normalized_url = self._normalize_url(url)

            if normalized_url in self.visited_urls:
                continue
            if depth > self.config.max_depth:
                continue
            if not self._is_same_domain(normalized_url):
                continue
            if self._is_robots_disallowed(normalized_url):
                continue
            if self._is_excluded_path(normalized_url):
                continue
            if static_asset_pattern.search(urlparse(normalized_url).path):
                continue

            self.visited_urls.add(normalized_url)

            async with semaphore:
                endpoint_data, new_urls = await self._fetch_and_parse(normalized_url, depth)

            if endpoint_data:
                self.discovered.append(endpoint_data)
                await publish_scan_event(
                    self.scan_id,
                    "crawl.endpoint",
                    {
                        "url": endpoint_data.url,
                        "method": endpoint_data.method,
                        "depth": depth,
                    },
                )

            for new_url in new_urls:
                normalized_new = self._normalize_url(new_url)
                if normalized_new not in self.visited_urls:
                    queue.append((normalized_new, depth + 1))

            await self._rate_limit_delay()

    async def _fetch_and_parse(
        self,
        url: str,
        depth: int,
    ) -> Tuple[Optional[EndpointData], List[str]]:
        headers = {
            "User-Agent": self.config.user_agent,
        }
        cookie_header = self._format_cookies()
        if cookie_header:
            headers["Cookie"] = cookie_header

        try:
            async with httpx.AsyncClient(
                follow_redirects=self.config.follow_redirects,
                timeout=settings.REQUEST_TIMEOUT_SECONDS,
                verify=False,
                headers=headers,
            ) as client:
                response = await client.get(url)

            endpoint = EndpointData(
                url=str(response.url),
                method="GET",
                params=self._extract_query_params(url),
                body_params=[],
                headers=self._extract_security_headers(dict(response.headers)),
                auth_required=self._detect_auth_required(response),
                content_type=response.headers.get("content-type"),
                status_code=response.status_code,
                source="httpx",
            )

            content_type = (response.headers.get("content-type") or "").lower()
            new_urls: List[str] = []

            if "text/html" in content_type:
                soup = BeautifulSoup(response.text, "lxml")
                new_urls = self._extract_links(soup, str(response.url))
                form_endpoints = self._extract_forms(soup, str(response.url))
                self.discovered.extend(form_endpoints)

                # Check if this is a JavaScript framework site
                if self._should_use_playwright(response.text):
                    # Extract API endpoints from JS code first
                    js_endpoints = self._extract_api_endpoints_from_js(response.text, str(response.url))
                    for js_endpoint in js_endpoints:
                        endpoint_url = urljoin(str(response.url), js_endpoint) if js_endpoint.startswith('/') else js_endpoint
                        normalized = self._normalize_url(endpoint_url)
                        api_endpoint = EndpointData(
                            url=normalized,
                            method="GET",
                            params=self._extract_query_params(normalized),
                            body_params=[],
                            headers={},
                            source="javascript",
                        )
                        self.discovered.append(api_endpoint)
                        new_urls.append(normalized)

                    # Use Playwright to render and capture real network requests
                    playwright_endpoints = await self._use_playwright_for_page(str(response.url))
                    for intercepted in playwright_endpoints:
                        # Only add GET requests as crawlable URLs
                        if intercepted.method == "GET" and intercepted.url:
                            new_urls.append(intercepted.url)
                    self.discovered.extend(playwright_endpoints)
                    
                    # Also try common SPA routes
                    spa_routes = self._generate_spa_routes(str(response.url))
                    new_urls.extend(spa_routes)
            elif "application/json" in content_type:
                api_endpoint = EndpointData(
                    url=url,
                    method="GET",
                    params=[],
                    body_params=[],
                    headers={},
                    status_code=response.status_code,
                    source="httpx",
                )
                self.discovered.append(api_endpoint)

            return endpoint, new_urls
        except Exception as exc:
            self.logger.warning("Failed to crawl %s at depth %s: %s", url, depth, exc)
            return None, []

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        candidates: Set[str] = set()

        for a_tag in soup.find_all("a", href=True):
            candidates.add(a_tag["href"])

        for link_tag in soup.find_all("link", href=True):
            href = link_tag["href"]
            if href.lower().endswith(".css"):
                continue
            candidates.add(href)

        for tag in soup.find_all(attrs={"data-href": True}):
            candidates.add(tag.get("data-href", ""))

        for tag in soup.find_all(attrs={"data-url": True}):
            candidates.add(tag.get("data-url", ""))

        normalized: Set[str] = set()
        for href in candidates:
            if not href:
                continue
            if href.startswith("mailto:") or href.startswith("tel:"):
                continue

            absolute = urljoin(base_url, href)
            absolute = absolute.split("#", 1)[0]
            absolute = self._normalize_url(absolute)

            if not self._is_same_domain(absolute):
                continue
            if absolute in self.visited_urls:
                continue
            normalized.add(absolute)

        return list(normalized)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[EndpointData]:
        endpoints: List[EndpointData] = []

        for form in soup.find_all("form"):
            action = form.get("action", base_url) or base_url
            action_url = self._normalize_url(urljoin(base_url, action))
            method = str(form.get("method", "GET")).upper()

            inputs = form.find_all(["input", "textarea", "select"])
            body_params = []
            for inp in inputs:
                name = inp.get("name", "")
                if not name:
                    continue
                body_params.append(
                    {
                        "name": name,
                        "type": inp.get("type", "text"),
                        "required": inp.has_attr("required"),
                    }
                )

            endpoints.append(
                EndpointData(
                    url=action_url,
                    method=method,
                    params=[],
                    body_params=body_params,
                    headers={},
                    source="httpx",
                )
            )

        return endpoints

    def _extract_query_params(self, url: str) -> List[Dict]:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        extracted: List[Dict] = []

        for key, values in query.items():
            value = values[0] if values else ""
            extracted.append({"name": key, "value": value, "type": "query"})

        return extracted

    def _extract_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        target_headers = {
            "content-security-policy": "Content-Security-Policy",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "strict-transport-security": "Strict-Transport-Security",
            "x-xss-protection": "X-XSS-Protection",
            "access-control-allow-origin": "Access-Control-Allow-Origin",
            "access-control-allow-methods": "Access-Control-Allow-Methods",
            "set-cookie": "Set-Cookie",
            "server": "Server",
            "x-powered-by": "X-Powered-By",
        }

        extracted: Dict[str, str] = {}
        lowered = {k.lower(): v for k, v in headers.items()}
        for key_lower, canonical_key in target_headers.items():
            if key_lower in lowered:
                extracted[canonical_key] = lowered[key_lower]
        return extracted

    def _detect_auth_required(self, response: httpx.Response) -> bool:
        if response.status_code in {401, 403}:
            return True

        response_url = str(response.url).lower()
        if any(token in response_url for token in ["/login", "/signin", "/auth"]):
            return True

        if response.headers.get("www-authenticate") is not None:
            return True

        return False

    def _is_same_domain(self, url: str) -> bool:
        netloc = urlparse(url).netloc.lower()
        if netloc == self.base_domain:
            return True

        if self.allow_subdomains and netloc.endswith(f".{self.base_domain}"):
            return True

        return False

    def _is_robots_disallowed(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        return any(path.startswith(rule) for rule in self.robots_disallowed)

    def _is_excluded_path(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        return any(fnmatch(path, pattern) for pattern in self.config.excluded_paths)

    def _format_cookies(self) -> str:
        if not self.session_cookies:
            return ""
        return "; ".join(
            f"{key}={value}" for key, value in self.session_cookies.items() if key
        )

    async def _use_playwright_for_page(self, url: str) -> List[EndpointData]:
        if not PLAYWRIGHT_AVAILABLE or async_playwright is None:
            self.logger.warning("Playwright not installed, skipping JS-rendered crawl")
            return []

        collected: List[EndpointData] = []

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent=self.config.user_agent,
                    ignore_https_errors=True,
                )

                if self.session_cookies:
                    cookie_payload = []
                    for name, value in self.session_cookies.items():
                        cookie_payload.append(
                            {
                                "name": name,
                                "value": value,
                                "domain": self.base_domain.split(":")[0],
                                "path": "/",
                            }
                        )
                    await context.add_cookies(cookie_payload)

                page = await context.new_page()

                async def on_request(request) -> None:
                    req_url = self._normalize_url(request.url)
                    if not self._is_same_domain(req_url):
                        return
                    query = urlparse(req_url).query
                    params = []
                    if query:
                        parsed = parse_qs(query, keep_blank_values=True)
                        params = [
                            {
                                "name": key,
                                "value": (values[0] if values else ""),
                                "type": "query",
                            }
                            for key, values in parsed.items()
                        ]

                    collected.append(
                        EndpointData(
                            url=req_url,
                            method=request.method.upper(),
                            params=params,
                            body_params=[],
                            headers={},
                            source="intercepted",
                        )
                    )

                page.on("request", on_request)
                
                # Increased timeout for slow-loading React apps
                # Try with networkidle first, fall back to load_state
                try:
                    await page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception:
                    self.logger.debug("networkidle timeout for %s, trying domcontentloaded", url)
                    try:
                        await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    except Exception:
                        self.logger.debug("domcontentloaded timeout for %s", url)

                # Allow additional time for lazy-loaded content
                await asyncio.sleep(2)

                html = await page.content()
                
                # Extract more endpoints from the rendered JS
                js_endpoints = self._extract_api_endpoints_from_js(html, url)
                for js_endpoint in js_endpoints:
                    endpoint_url = urljoin(url, js_endpoint) if js_endpoint.startswith('/') else js_endpoint
                    normalized = self._normalize_url(endpoint_url)
                    collected.append(
                        EndpointData(
                            url=normalized,
                            method="GET",
                            params=self._extract_query_params(normalized),
                            body_params=[],
                            headers={},
                            source="javascript_rendered",
                        )
                    )
                
                soup = BeautifulSoup(html, "lxml")
                links = self._extract_links(soup, url)
                forms = self._extract_forms(soup, url)

                for link in links:
                    collected.append(
                        EndpointData(
                            url=link,
                            method="GET",
                            params=self._extract_query_params(link),
                            body_params=[],
                            headers={},
                            source="playwright",
                        )
                    )

                collected.extend(forms)
                await browser.close()
                
                self.logger.info(
                    "Playwright crawl for %s found %d endpoints (intercepted + extracted)",
                    url,
                    len(collected)
                )
        except Exception as exc:
            self.logger.warning("Playwright page crawl failed for %s: %s", url, exc)

        return collected

    async def _rate_limit_delay(self) -> None:
        safe_rate = max(self.config.scan_rate_limit, 1)
        await asyncio.sleep(1.0 / safe_rate)

    async def _first_selector(self, page, selectors: List[str]) -> Optional[str]:
        for selector in selectors:
            try:
                if await page.locator(selector).count() > 0:
                    return selector
            except Exception:
                continue
        return None

    def _should_use_playwright(self, body: str) -> bool:
        signatures = [
            "__NEXT_DATA__",
            "window.__reactFiber",
            "ng-app",
            "v-app",
            "window.__NUXT__",
            "__svelte",
            "__remixContext",
            "window.Ember",
        ]

        if any(signature in body for signature in signatures):
            return True

        try:
            if "application/json" in body[:100].lower():
                json.loads(body)
                return False
        except Exception:
            pass

        return False

    def _extract_api_endpoints_from_js(self, html: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from JavaScript strings and patterns."""
        endpoints: Set[str] = set()
        
        # Common API endpoint patterns in JS
        patterns = [
            r'["\']/api/[a-zA-Z0-9_\-/]*["\']',  # /api/users, /api/v1/products
            r'["\']/rest/[a-zA-Z0-9_\-/]*["\']',  # /rest/...
            r'["\']/v\d+/[a-zA-Z0-9_\-/]*["\']',  # /v1/users, /v2/data
            r'["\']/graphql["\']',                  # /graphql
            r'["\']/ajax/[a-zA-Z0-9_\-/]*["\']',   # /ajax/...
            r'["\']/endpoint/[a-zA-Z0-9_\-/]*["\']', # /endpoint/...
            r'["\']/services/[a-zA-Z0-9_\-/]*["\']', # /services/...
            r'["\']https?://[^"\']+?/api/[a-zA-Z0-9_\-/]*["\']',  # full URLs
            r'[\s(]fetch\(["\']([^"\']+?)["\'][\s,\)]',  # fetch() calls
            r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+?)["\']',  # axios calls
            r'\.get\(["\']([^"\']+?)["\']',  # jQuery .get() calls
            r'\.post\(["\']([^"\']+?)["\']',  # jQuery .post() calls
            r'url:\s*["\']([^"\']+?)["\']',   # url: property in AJAX
            r'endpoint:\s*["\']([^"\']+?)["\']', # endpoint: property
        ]

        try:
            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    # Handle regex groups - take the captured group if exists, else take whole match
                    url = match[0] if isinstance(match, tuple) and match else match
                    if isinstance(url, str):
                        url = url.strip('\'"')
                        
                        # Skip obvious false positives
                        if any(skip in url.lower() for skip in ['.css', '.js', '.png', '.jpg', '.svg', '.woff', 'cdn', 'google', 'facebook']):
                            continue
                            
                        # Resolve relative URLs
                        if url.startswith('/'):
                            endpoints.add(url)
                        elif url.startswith('http'):
                            parsed = urlparse(url)
                            if self._is_same_domain(url):
                                endpoints.add(parsed.path + ('?' + parsed.query if parsed.query else ''))
        except Exception as exc:
            self.logger.debug("Error extracting API endpoints from JS: %s", exc)

        return list(endpoints)

    def _generate_spa_routes(self, base_url: str) -> List[str]:
        """Generate common SPA routes to test."""
        routes: Set[str] = set()
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common SPA route patterns
        common_routes = [
            "/dashboard", "/admin", "/settings", "/profile", "/user",
            "/products", "/items", "/list", "/data", "/users", "/accounts",
            "/home", "/main", "/explore", "/search", "/about", "/contact",
            "/login", "/signup", "/register", "/account", "/api", "/api/v1",
            "/api/v2", "/graphql", "/users/:id", "/products/:id", "/items/:id",
        ]
        
        for route in common_routes:
            if ':' not in route:  # Skip parameterized routes for now
                routes.add(urljoin(base, route))
        
        return list(routes)

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/")

        query = parsed.query
        if query:
            query_items = parse_qs(query, keep_blank_values=True)
            query = urlencode(query_items, doseq=True)

        return parsed._replace(fragment="", path=path, query=query).geturl()
