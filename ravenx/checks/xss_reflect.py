
from __future__ import annotations
from typing import List
import httpx, html
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from .base import BaseCheck, CheckContext

class ReflectedXSSCheck(BaseCheck):
    name = "reflected_xss_probe"
    severity = "medium"

    async def run(self, url, resp, body, ctx: CheckContext):
        if resp.request.method != "GET":
            return []
        p = resp.request.url
        q = dict(parse_qsl(p.query))
        outs = []
        token = "rxss12345"
        for k in list(q.keys())[:10]:
            testq = q.copy()
            testq[k] = token
            test = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(testq, doseq=True), ""))
            try:
                r = await ctx.client.get(test, timeout=10.0)
                if token in (r.text or ""):
                    outs.append(await self._new(self.severity, "reflected_xss_param_probe", str(test), f"Reflected token in param '{k}'"))
            except Exception:
                continue
        return outs
