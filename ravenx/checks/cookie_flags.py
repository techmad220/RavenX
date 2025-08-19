
from __future__ import annotations
from typing import List
from .base import BaseCheck, CheckContext

class CookieFlagsCheck(BaseCheck):
    name = "cookie_flags_missing"
    severity = "low"

    async def run(self, url, resp, body, ctx):
        hs = {k.lower(): v for k, v in resp.headers.items()}
        set_cookie = hs.get("set-cookie","")
        if set_cookie and ("secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower()):
            return [await self._new(self.severity, self.name, url, set_cookie[:300])]
        return []
