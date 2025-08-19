
from __future__ import annotations
from typing import List, Set
from urllib.parse import urlparse
from .base import BaseCheck, CheckContext

PROVIDER_HINTS = [
    "github.io", "github.map.fastly.net", "amazonaws.com", "s3-website", "cloudfront.net",
    "herokudns.com", "herokuapp.com", "fastly.net", "pages.dev", "vercel.app", "azurewebsites.net",
    "zendesk.com", "wpengine.com", "readme.io", "surge.sh", "bitbucket.io", "gitbooks.io"
]

BODY_SIGNATURES = [
    ("github", "There isn't a GitHub Pages site here"),
    ("s3", "NoSuchBucket"),
    ("heroku", "No such app"),
    ("fastly", "Fastly error: unknown domain"),
    ("vercel", "This deployment does not exist"),
]

class SubdomainTakeoverCheck(BaseCheck):
    name = "subdomain_takeover_possible"
    severity = "high"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        # Run once per host
        host = urlparse(url).netloc.lower()
        memo_key = "_takeover_checked"
        seen: Set[str] = ctx.memo.setdefault(memo_key, set())
        if host in seen:
            return []
        seen.add(host)

        hints = []
        cname_target = ""
        # DNS CNAME lookup (best-effort)
        try:
            import dns.resolver  # type: ignore
            ans = dns.resolver.resolve(host, "CNAME")
            for r in ans:
                cname_target = str(r.target).strip(".").lower()
                for h in PROVIDER_HINTS:
                    if h in cname_target:
                        hints.append(h)
        except Exception:
            pass

        # If we saw a provider hint OR the body contains a known message, flag
        body_text = (body or "")[:2000]
        hit_msg = None
        for key, sig in BODY_SIGNATURES:
            if sig.lower() in body_text.lower():
                hit_msg = sig
                break

        if hints or hit_msg:
            ev = f"hints={hints} cname={cname_target} bodySig={hit_msg}"
            return [await self._new(self.severity, self.name, url, ev)]
        return []
