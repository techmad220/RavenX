
from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qsl
from .base import BaseCheck, CheckContext

class SAMLRelayStateOpenRedirect(BaseCheck):
    name = "saml_relaystate_external_redirect"
    severity = "high"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        qs = dict(parse_qsl(p.query))
        if "SAMLRequest" not in qs and "SAMLRequest".lower() not in {k.lower() for k in qs.keys()}:
            return []
        relay = qs.get("RelayState") or qs.get("relaystate")
        if not relay:
            return []
        try:
            target = urlparse(relay)
        except Exception:
            return []
        host = target.netloc.lower()
        src_host = urlparse(str(p)).netloc.lower()
        if host and (host not in src_host and not src_host.endswith(host) and not host.endswith(src_host)):
            ev = f"RelayState points off-site: {relay} (source host: {src_host})"
            return [await self._new(self.severity, self.name, str(p), ev)]
        return []

class SAMLRequestExposureHeuristic(BaseCheck):
    name = "saml_request_get_exposure"
    severity = "low"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        qs = dict(parse_qsl(p.query))
        if any(k.lower() == "samlrequest" for k in qs.keys()):
            return [await self._new(self.severity, self.name, str(p), "SAMLRequest observed via GET (HTTP-Redirect binding).")]
        return []
