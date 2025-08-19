
from __future__ import annotations
import os, httpx

def send_slack_highlights(webhook_url: str, triaged: list[dict]) -> int:
    if not webhook_url:
        return 0
    highs = []
    for t in triaged:
        f = t.get("finding") if isinstance(t, dict) else t
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "low")).lower()
        if sev in ("high","critical"):
            typ = f.get("type") if isinstance(f, dict) else getattr(f, "type", "unknown")
            url = f.get("url") if isinstance(f, dict) else getattr(f, "url", "")
            highs.append(f"*{sev.upper()}* {typ} — {url}")
    if not highs:
        return 0
    text = "RavenX: high-priority findings\n" + "\n".join(highs[:20])
    with httpx.Client(timeout=10.0) as c:
        r = c.post(webhook_url, json={"text": text})
        return 1 if r.status_code in (200,204) else 0
