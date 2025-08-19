
from __future__ import annotations
import asyncio, httpx, re
from typing import Set, List
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .models import Finding
from .checks.base import CheckContext
from .checks.security_headers import SecurityHeadersCheck
from .checks.cors import CORSCheck
from .checks.cookie_flags import CookieFlagsCheck
from .checks.dirlisting import DirectoryListingCheck
from .checks.xss_reflect import ReflectedXSSCheck
from .checks.open_redirect import OpenRedirectCheck
from .checks.csrf import CSRFHeuristicCheck
from .checks.oauth import OAuthRedirectURICheck, OAuthImplicitFlowHeuristic
from .checks.oauth_pkce import OAuthPKCEHeuristicCheck
from .checks.saml import SAMLRelayStateOpenRedirect, SAMLRequestExposureHeuristic
from .checks.takeover import SubdomainTakeoverCheck
from .checks.csp_weak import CSPWeakCheck
from .checks.mixed_content import MixedContentCheck
from .checks.jsonp import JSONPCallbackCheck
from .checks.oidc_discovery import OIDCDiscoveryCheck

from .checks.saml_oauth import SAMLRequestParamCheck, OAuthPKCECheck
from .checks.takeover import SubdomainTakeoverCheck

DEFAULT_CHECKS = [
    SecurityHeadersCheck(),
    CORSCheck(),
    CookieFlagsCheck(),
    DirectoryListingCheck(),
    ReflectedXSSCheck(),
    OpenRedirectCheck(),
    CSRFHeuristicCheck(),
    OAuthRedirectURICheck(),
    OAuthImplicitFlowHeuristic(),
    OAuthPKCEHeuristicCheck(),
    SAMLRelayStateOpenRedirect(),
    SAMLRequestExposureHeuristic(),
    SubdomainTakeoverCheck(),
    CSPWeakCheck(),
    MixedContentCheck(),
    JSONPCallbackCheck(),
    OIDCDiscoveryCheck(),
    SAMLRequestParamCheck(),
    OAuthPKCECheck(),
    SubdomainTakeoverCheck(),
    CSPWeakCheck(),
    MixedContentCheck(),
    JSONPCallbackCheck(),
    OIDCDiscoveryCheck(),
]

class Crawler:
    def __init__(self, scope, concurrency: int = 8, timeout: float = 10.0, per_host_qps: float = 2.0, max_pages_per_host: int = 150, time_budget_sec: int = 600):
        self.scope = scope
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.visited: Set[str] = set()
        self.client = httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers={"User-Agent":"RavenX/1.0"})
        self.per_host_qps = per_host_qps
        self.max_pages_per_host = max_pages_per_host
        self.time_budget_sec = time_budget_sec
        self._host_count = {}
        self._host_last = {}
        import time as _t
        self._start = _t.time()
        self.checks = list(DEFAULT_CHECKS)
        self.memo = {}
        for s in scope.seeds:
            self.queue.put_nowait(s)

    async def close(self):
        await self.client.aclose()

    async def enqueue(self, url: str):
        if url not in self.visited and self.scope.in_scope(url):
            self.visited.add(url)
            await self.queue.put(url)

    async def worker(self, idx: int, findings: List[Finding]):
        import time as _t
        while True:
            try:
                url = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                return
            try:
                # respect time budget
                if _t.time() - self._start > self.time_budget_sec:
                    return
                host = __import__('urllib.parse').urlparse(url).netloc
                # per-host cap
                cnt = self._host_count.get(host,0)
                if cnt >= self.max_pages_per_host:
                    self.queue.task_done(); continue
                # qps throttle
                last = self._host_last.get(host,0.0)
                delay = max(0.0, (1.0/self.per_host_qps) - (_t.time()-last))
                if delay>0: await asyncio.sleep(delay)
                r = await self.client.get(url)
                self._host_last[host] = _t.time()
                self._host_count[host] = cnt + 1
                body = r.text
                ctx = CheckContext(self.client, self.memo)
                for chk in self.checks:
                    outs = await chk.run(url, r, body, ctx)
                    if outs:
                        findings.extend(outs)
                # simple link finder
                if "text/html" in (r.headers.get("content-type","")):
                    s = BeautifulSoup(body, "html.parser")
                    for a in s.find_all("a", href=True):
                        nxt = urljoin(url, a["href"])
                        if self.scope.in_scope(nxt) and nxt not in self.visited:
                            self.visited.add(nxt)
                            await self.queue.put(nxt)
            except Exception:
                pass
            finally:
                self.queue.task_done()

    async def crawl(self) -> List[Finding]:
        findings: List[Finding] = []
        workers = [asyncio.create_task(self.worker(i, findings)) for i in range(10)]
        await self.queue.join()
        for w in workers:
            w.cancel()
        return findings
