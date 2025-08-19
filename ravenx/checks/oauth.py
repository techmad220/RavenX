
from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qsl, urlunparse
from .base import BaseCheck, CheckContext

class OAuthRedirectURICheck(BaseCheck):
    name = "oauth_redirect_uri_external"
    severity = "high"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        path = p.path.lower()
        if not any(k in path for k in ["/oauth", "/authorize", "/login/oauth", "/connect/authorize"]):
            return []
        qs = dict(parse_qsl(p.query))
        ru = qs.get("redirect_uri") or qs.get("redirect_url") or qs.get("continue") or qs.get("next")
        if not ru:
            return []
        try:
            target = urlparse(ru)
        except Exception:
            return []
        host = target.netloc.lower()
        src_host = urlparse(str(p)).netloc.lower()
        # if redirect_uri host is not the same eTLD+1 or not a subdomain of src_host, flag it
        if host and (host not in src_host and not src_host.endswith(host) and not host.endswith(src_host)):
            ev = f"redirect_uri points to external host: {ru} (source host: {src_host})"
            return [await self._new(self.severity, self.name, str(p), ev)]
        return []

class OAuthImplicitFlowHeuristic(BaseCheck):
    name = "oauth_implicit_flow_enabled"
    severity = "low"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        path = p.path.lower()
        if not any(k in path for k in ["/oauth", "/authorize", "/connect/authorize"]):
            return []
        qs = dict(parse_qsl(p.query))
        rt = (qs.get("response_type") or "").lower()
        if "token" in rt and "code" not in rt:
            ev = f"response_type={rt} (implicit flow) observed on {p}"
            return [await self._new(self.severity, self.name, str(p), ev)]
        return []
