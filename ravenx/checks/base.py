
from __future__ import annotations
from typing import List
from ..models import Finding, fingerprint_of, host_of, now_ms

class CheckContext:
    def __init__(self, client, memo: dict | None = None):
        self.client = client
        self.memo = memo or {}

class BaseCheck:
    name = "base"
    severity = "low"
    async def run(self, url, resp, body, ctx) -> List[Finding]:
        return []

    async def _new(self, sev, typ, url, evidence):
        return Finding(
            severity=sev,
            type=typ,
            url=url,
            evidence=evidence,
            fingerprint=fingerprint_of(sev, typ, host_of(url), url, evidence),
            method=getattr(getattr(self,'_req',None), 'method', None) if hasattr(self,'_req') else None,
            validated_ms=now_ms(),
        )
