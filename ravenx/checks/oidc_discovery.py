
from __future__ import annotations
from typing import List
import json
from .base import BaseCheck, CheckContext

class OIDCDiscoveryCheck(BaseCheck):
    name = "oidc_discovery_issues"
    severity = "low"

    async def run(self, url, resp, body, ctx: CheckContext) -> List:
        # Trigger only on discovery endpoint
        path = resp.request.url.path.lower()
        if not path.endswith("/.well-known/openid-configuration"):
            return []
        try:
            data = json.loads(body)
        except Exception:
            return []
        outs = []
        methods = data.get("code_challenge_methods_supported", [])
        if "S256" not in [m.upper() for m in methods] and "s256" not in methods:
            outs.append(await self._new("medium", "oidc_pkce_s256_missing", url, "OpenID discovery lacks S256 in code_challenge_methods_supported"))
        resp_types = data.get("response_types_supported", [])
        if any(rt == "token" or rt == "id_token" for rt in resp_types):
            outs.append(await self._new("low", "oidc_implicit_enabled", url, f"Implicit/hybrid response_types advertised: {resp_types}"))
        return outs
