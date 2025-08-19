
from __future__ import annotations
from typing import List
from .base import BaseCheck

class CSPWeakCheck(BaseCheck):
    name = "csp_weak_policy"
    severity = "low"

    BAD_TOKENS = ["'unsafe-inline'", "'unsafe-eval'"]

    async def run(self, url, resp, body, ctx) -> List:
        h = {k.lower(): v for k,v in resp.headers.items()}
        csp = h.get("content-security-policy")
        if not csp:
            return []
        bad = [t for t in self.BAD_TOKENS if t in csp.lower()]
        if bad:
            ev = f"CSP allows {', '.join(bad)}"
            return [await self._new("low", self.name, url, ev)]
        return []
