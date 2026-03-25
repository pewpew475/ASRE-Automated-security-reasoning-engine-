import asyncio
import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from api.routes.websocket import publish_scan_event
from config import settings
from scanner.rule_engine import FindingData
from utils.audit_logger import log_audit_entry


class SourceCodeExtractor:
    """Extracts source code, JavaScript, and sensitive files from web applications."""

    def __init__(self, scan_id: str, target_url: str, cookies: Optional[Dict[str, str]] = None):
        self.scan_id = scan_id
        self.target_url = target_url.rstrip("/")
        self.cookies = cookies or {}
        self.logger = logging.getLogger(__name__)
        self.base_domain = urlparse(target_url).netloc
        self.extracted_files: Set[str] = set()
        self.sensitive_data_found: List[FindingData] = []

    async def run(self) -> List[FindingData]:
        """Extract all discoverable source code and sensitive files."""
        findings: List[FindingData] = []

        # Extract common source files
        await self._extract_common_files()

        # Extract JavaScript files and deobfuscate
        await self._extract_javascript_files()

        # Search for sensitive information
        await self._search_sensitive_data()

        # Try to extract API keys and secrets
        await self._extract_secrets_from_responses()

        # Check for backup/config files
        await self._find_backup_files()

        # Extract source maps
        await self._extract_source_maps()

        findings.extend(self.sensitive_data_found)
        return findings

    async def _extract_common_files(self) -> None:
        """Extract JavaScript bundles and common files."""
        common_paths = [
            "/index.html",
            "/main.js",
            "/app.js",
            "/bundle.js",
            "/build/main.js",
            "/static/js/main.js",
            "/static/js/app.js",
            "/assets/main.js",
            "/js/main.js",
            "/dist/index.js",
            "/dist/bundle.js",
            "/_next/static/chunks/main.js",  # Next.js
            "/_nuxt/",  # Nuxt
            "/public/",
            "/.next/",
        ]

        for path in common_paths:
            await self._fetch_and_extract_file(path)

    async def _extract_javascript_files(self) -> None:
        """Extract and deobfuscate JavaScript files."""
        js_patterns = [
            r'src=["\'](.*?\.js["\'])',
            r'<script\s+src=["\'](.*?)["\']',
            r'import.*?from\s+["\'](.*?)["\']',
            r'require\(["\']([^"\']+\.js)["\']',
            r'["\'](/.*?\.js)["\']',
        ]

        # Fetch the main page
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, cookies=self.cookies) as client:
                resp = await client.get(self.target_url)
                html = resp.text
        except Exception:
            return

        # Extract script tags
        for pattern in js_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                js_url = match.replace('"', "").replace("'", "")
                if "//" not in js_url and not js_url.startswith("http"):
                    js_url = urljoin(self.target_url, js_url)
                
                if js_url.endswith(".js") or "chunk" in js_url:
                    await self._fetch_and_extract_file(js_url)

    async def _fetch_and_extract_file(self, path: str) -> None:
        """Fetch a file and extract secrets."""
        url = path if path.startswith("http") else urljoin(self.target_url, path)
        
        try:
            async with httpx.AsyncClient(timeout=10, verify=False, cookies=self.cookies) as client:
                resp = await client.get(url, follow_redirects=True)
                
                if resp.status_code == 200:
                    content = resp.text
                    self.extracted_files.add(url)

                    # Extract API endpoints
                    self._extract_api_endpoints(content)

                    # Extract secrets
                    self._extract_secrets(url, content)

                    # Log the discovery
                    await log_audit_entry(
                        scan_id=self.scan_id,
                        module="source_code_extractor",
                        request_method="GET",
                        request_url=url,
                        response_code=resp.status_code,
                        notes=f"Extracted {len(content)} bytes from {url}",
                    )
        except Exception as exc:
            self.logger.debug("Failed to extract %s: %s", path, exc)

    def _extract_api_endpoints(self, content: str) -> None:
        """Extract API endpoints from JavaScript."""
        patterns = [
            r'["\'](/api/[a-zA-Z0-9_\-/]*)["\']',
            r'["\'](/rest/[a-zA-Z0-9_\-/]*)["\']',
            r'["\'](https?://[^"\']+/api/[a-zA-Z0-9_\-/]*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for endpoint in matches:
                self.logger.info("Discovered endpoint from code: %s", endpoint)

    def _extract_secrets(self, url: str, content: str) -> None:
        """Extract API keys, tokens, and other secrets."""
        secret_patterns = {
            "api_key": r'["\'](api[_-]?key|apikey)["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_.]+)["\']',
            "jwt_token": r'["\'](token|jwt|Bearer)["\']?\s*[:=]\s*["\'](eyJ[a-zA-Z0-9\-_.]+)["\']',
            "aws_key": r'(AKIA[0-9A-Z]{16})',
            "private_key": r'-----BEGIN (RSA|DSA|EC)? ?PRIVATE KEY-----',
            "password": r'["\'](password|passwd)["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            "database_url": r'(mongodb|postgres|mysql)://[a-zA-Z0-9\-_.@:/?]+',
            "slack_webhook": r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "stripe_key": r'(sk|pk)_live_[a-zA-Z0-9]{24}',
        }

        for secret_type, pattern in secret_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # For complex patterns, extract the actual secret
                if isinstance(match, tuple):
                    secret_value = match[-1] if match[-1] else match[0]
                else:
                    secret_value = match

                finding = FindingData(
                    title=f"Exposed {secret_type} found in source code",
                    description=f"Found {secret_type} in {url}: {secret_value[:20]}...",
                    severity="critical",
                    cvss_score=9.0,
                    vulnerability_class=f"information_disclosure_{secret_type}",
                    affected_url=url,
                    attack_vector="network",
                    remediation="Remove sensitive data from client-side code. Use environment variables.",
                    cwes=[200],  # Information Exposure
                )
                self.sensitive_data_found.append(finding)
                self.logger.warning("CRITICAL: Found exposed %s in %s", secret_type, url)

    async def _search_sensitive_data(self) -> None:
        """Search for sensitive files and directories."""
        sensitive_paths = [
            "/.git/config",
            "/.git/HEAD",
            "/.env",
            "/.env.local",
            "/.env.development",
            "/.env.production",
            "/config.php",
            "/config.js",
            "/settings.json",
            "/.htaccess",
            "/web.config",
            "/package.json",
            "/.github/workflows",
            "/Dockerfile",
            "/.dockerignore",
            "/docker-compose.yml",
            "/.aws/credentials",
            "/.ssh/id_rsa",
            "/admin",
            "/admin.php",
            "/administrator",
            "/.well-known/",
            "/README.md",
            "/CHANGELOG.md",
        ]

        for path in sensitive_paths:
            url = urljoin(self.target_url, path)
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, cookies=self.cookies) as client:
                    resp = await client.get(url, follow_redirects=False)
                    
                    if resp.status_code == 200:
                        finding = FindingData(
                            title=f"Sensitive file accessible: {path}",
                            description=f"The sensitive file {path} is publicly accessible",
                            severity="high" if ".env" in path or ".git" in path else "medium",
                            cvss_score=7.5,
                            vulnerability_class="information_disclosure",
                            affected_url=url,
                            attack_vector="network",
                            remediation=f"Remove or restrict access to {path}",
                            cwes=[200],
                        )
                        self.sensitive_data_found.append(finding)
                        self.logger.warning("Found sensitive file: %s", path)
            except Exception:
                pass

    async def _extract_secrets_from_responses(self) -> None:
        """Check API responses for leaked secrets."""
        test_endpoints = [
            "/api/config",
            "/api/settings",
            "/api/user",
            "/api/profile",
            "/.well-known/configuration",
            "/config.json",
        ]

        for endpoint in test_endpoints:
            url = urljoin(self.target_url, endpoint)
            try:
                async with httpx.AsyncClient(timeout=5, verify=False, cookies=self.cookies) as client:
                    resp = await client.get(url)
                    
                    if resp.status_code == 200:
                        self._extract_secrets(url, resp.text)
            except Exception:
                pass

    async def _find_backup_files(self) -> None:
        """Search for backup and temporary files."""
        backup_patterns = [
            "*.bak",
            "*.backup",
            "*.old",
            "*.tmp",
            "*.swp",
            "*.swo",
            "*~",
            ".DS_Store",
        ]

        extensions = ["php", "js", "py", "java", "rb", "go", "sql"]
        for ext in extensions:
            for pattern in ["index", "config", "admin", "user", "auth", "api"]:
                paths = [
                    f"/{pattern}.{ext}.bak",
                    f"/{pattern}.{ext}.old",
                    f"/{pattern}.{ext}~",
                ]
                for path in paths:
                    url = urljoin(self.target_url, path)
                    try:
                        async with httpx.AsyncClient(timeout=5, verify=False, cookies=self.cookies) as client:
                            resp = await client.get(url, follow_redirects=False)
                            if resp.status_code == 200:
                                finding = FindingData(
                                    title=f"Backup file found: {path}",
                                    description=f"Backup file {path} is accessible and may contain source code",
                                    severity="high",
                                    cvss_score=7.5,
                                    vulnerability_class="information_disclosure_backup",
                                    affected_url=url,
                                    attack_vector="network",
                                    remediation="Remove backup files or restrict access",
                                    cwes=[200],
                                )
                                self.sensitive_data_found.append(finding)
                    except Exception:
                        pass

    async def _extract_source_maps(self) -> None:
        """Extract and analyze source maps for debugging info."""
        patterns = [
            r'sourceMappingURL=([^\s"\']+\.map)',
            r'SourceMap:\s*([^\s"\']+\.map)',
        ]

        try:
            async with httpx.AsyncClient(timeout=10, verify=False, cookies=self.cookies) as client:
                resp = await client.get(self.target_url)
                content = resp.text

                for pattern in patterns:
                    matches = re.findall(pattern, content)
                    for map_file in matches:
                        map_url = urljoin(self.target_url, map_file)
                        try:
                            map_resp = await client.get(map_url)
                            if map_resp.status_code == 200:
                                finding = FindingData(
                                    title="Source map file exposed",
                                    description=f"Source map {map_file} is publicly accessible, allowing source code reconstruction",
                                    severity="high",
                                    cvss_score=7.5,
                                    vulnerability_class="information_disclosure_sourcemap",
                                    affected_url=map_url,
                                    attack_vector="network",
                                    remediation="Remove .map files from production or restrict access",
                                    cwes=[200],
                                )
                                self.sensitive_data_found.append(finding)
                        except Exception:
                            pass
        except Exception:
            pass
