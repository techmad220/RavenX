
from __future__ import annotations
from typing import List
import httpx
from .base import BaseCheck, CheckContext

class SecurityHeadersCheck(BaseCheck):
    name = "security_headers_missing"
    severity = "low"
    REQUIRED = ["content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"]

    async def run(self, url: str, resp: httpx.Response, body: str, ctx: CheckContext) -> List:
        missing = [h for h in self.REQUIRED if h not in (resp.headers or {} and {k.lower():v for k,v in resp.headers.items()})]
        if missing:
            ev = f"Missing headers: {', '.join(missing)}"
            return [await self._new(self.severity, self.name, url, ev)]
        return []
