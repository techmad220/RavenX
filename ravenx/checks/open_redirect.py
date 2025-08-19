
from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import httpx
from .base import BaseCheck

EXTERNAL = "https://example.org/"

class OpenRedirectCheck(BaseCheck):
    name = "open_redirect_param"
    severity = "medium"

    async def run(self, url, resp, body, ctx):
        p = resp.request.url
        q = dict(parse_qsl(p.query))
        cands = [k for k in q if k.lower() in {"redirect","redir","url","next","return","continue"}]
        outs = []
        for k in cands:
            newq = q.copy(); newq[k] = EXTERNAL
            test = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(newq, doseq=True), ""))
            try:
                r = await ctx.client.get(test, follow_redirects=False)
                loc = r.headers.get("location","")
                if r.status_code in (301,302,303,307,308) and loc.startswith(EXTERNAL):
                    outs.append(await self._new(self.severity, self.name, str(test), f"Unvalidated redirect via '{k}' -> {loc}"))
            except Exception:
                continue
        return outs
