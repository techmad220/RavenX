
from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from .base import BaseCheck, CheckContext

class JSONPCallbackCheck(BaseCheck):
    name = "jsonp_reflection"
    severity = "medium"

    async def run(self, url, resp, body, ctx: CheckContext) -> List:
        if resp.request.method != "GET":
            return []
        p = resp.request.url
        q = dict(parse_qsl(p.query))
        outs = []
        for key in ("callback","cb","jsonp"):
            if key in q:
                testq = q.copy()
                testq[key] = "rxjsonp123"
                test = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(testq, doseq=True), ""))
                try:
                    r = await ctx.client.get(test, timeout=8.0)
                    txt = (r.text or "")[:200]
                    if txt.strip().startswith("rxjsonp123("):
                        outs.append(await self._new(self.severity, self.name, str(test), "JSONP function wrapper observed"))
                except Exception:
                    continue
        return outs
