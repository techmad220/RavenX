
from __future__ import annotations
from typing import List
from .base import BaseCheck, CheckContext
from ..validators import cors_preflight

class CORSCheck(BaseCheck):
    name = "cors_misconfiguration"
    severity = "medium"

    async def run(self, url, resp, body, ctx: CheckContext):
        hs = {k.lower(): v for k, v in resp.headers.items()}
        aco = hs.get("access-control-allow-origin","")
        acc = hs.get("access-control-allow-credentials","")
        if aco.strip() == "*" and acc.strip().lower() == "true":
            pf = await cors_preflight(ctx.client, url)
            ev = f"ACA-Origin:* with ACA-Credentials:true; preflight={pf}"
            return [await self._new(self.severity, self.name, url, ev)]
        return []
