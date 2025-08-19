
from __future__ import annotations
import httpx, os
from ..retry import backoff_retry
from typing import List
from ..models import Finding, SEVERITY_ORDER

def export_github(findings: List[Finding], repo: str, token: str, min_severity: str = "medium") -> int:
    sev_min = SEVERITY_ORDER.get(min_severity, 2)
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{repo}/issues"
    created = 0
    with httpx.Client(timeout=20.0) as client:
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 0) < sev_min: continue
            title = f"[{f.severity.upper()}] {f.type} @ {f.url} ({f.fingerprint[:8]})"
            body = f"""Automated RavenX report

- URL: {f.url}
- Type: {f.type}
- Severity: {f.severity}
- Fingerprint: {f.fingerprint}

Evidence:
```
{f.evidence}
```"""
            r = backoff_retry(lambda: client.post(api, headers=headers, json={"title": title, "body": body}))
            if r.status_code in (200,201): created += 1
    return created
