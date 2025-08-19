
from __future__ import annotations
from typing import List
from urllib.parse import urlparse, parse_qsl
from .base import BaseCheck, CheckContext

class SAMLRequestParamCheck(BaseCheck):
    name = "saml_request_param_exposed"
    severity = "medium"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        qs = dict(parse_qsl(resp.request.url.query))
        saml_req = qs.get("SAMLRequest") or qs.get("SAMLResponse")
        if saml_req:
            ev = f"SAML parameter detected on {resp.request.url}"
            return [await self._new(self.severity, self.name, str(resp.request.url), ev)]
        return []

class OAuthPKCECheck(BaseCheck):
    name = "oauth_pkce_missing"
    severity = "medium"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        path = p.path.lower()
        if not any(k in path for k in ["/oauth", "/authorize", "/connect/authorize"]):
            return []
        qs = dict(parse_qsl(p.query))
        rt = (qs.get("response_type") or "").lower()
        if "code" in rt:
            if not qs.get("code_challenge"):
                ev = f"Authorization code flow without PKCE (no code_challenge) on {p}"
                return [await self._new(self.severity, self.name, str(p), ev)]
        return []
