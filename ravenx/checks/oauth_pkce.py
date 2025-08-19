
from __future__ import annotations
from typing import List
from urllib.parse import parse_qsl
from .base import BaseCheck, CheckContext

class OAuthPKCEHeuristicCheck(BaseCheck):
    name = "oauth_pkce_missing"
    severity = "medium"

    async def run(self, url: str, resp, body, ctx: CheckContext) -> List:
        p = resp.request.url
        path = p.path.lower()
        if not any(k in path for k in ["/oauth", "/authorize", "/connect/authorize", "/login/oauth/authorize"]):
            return []
        qs = dict(parse_qsl(p.query))
        rt = (qs.get("response_type") or "").lower()
        # If using authorization code flow ('code'), PKCE should include code_challenge
        if "code" in rt and not qs.get("code_challenge"):
            ev = f"Authorization request without PKCE code_challenge observed: {p}"
            return [await self._new(self.severity, self.name, str(p), ev)]
        # If code_challenge present but method not S256, note it (but keep medium)
        if qs.get("code_challenge") and (qs.get("code_challenge_method","").upper() != "S256"):
            ev = f"PKCE code_challenge_method is not S256: {qs.get('code_challenge_method')} @ {p}"
            return [await self._new(self.severity, self.name, str(p), ev)]
        return []
