
from __future__ import annotations
import httpx

async def cors_preflight(client: httpx.AsyncClient, url: str, origin: str = "https://example.org") -> dict:
    headers = {
        "Origin": origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    }
    try:
        r = await client.options(url, headers=headers, timeout=15.0)
    except Exception:
        return {"ok": False, "error": "network"}
    return {"ok": True, "status": r.status_code, "headers": {k.lower(): v for k, v in r.headers.items()}}
