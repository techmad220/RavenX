
from __future__ import annotations
import httpx
from ..retry import backoff_retry
from typing import List
from ..models import Finding, SEVERITY_ORDER

def export_jira(findings: List[Finding], base_url: str, project_key: str, email: str, api_token: str, min_severity: str = "medium") -> int:
    headers = {"Content-Type":"application/json"}
    auth = (email, api_token)
    create_url = base_url.rstrip("/") + "/rest/api/3/issue"
    sev_min = SEVERITY_ORDER.get(min_severity, 2)
    created = 0
    with httpx.Client(timeout=20.0) as client:
        for f in findings:
            if SEVERITY_ORDER.get(f.severity, 0) < sev_min: continue
            payload = {
                "fields": {
                    "project": {"key": project_key},
                    "summary": f"[{f.severity.upper()}] {f.type} @ {f.url}",
                    "issuetype": {"name": "Bug"},
                    "description": {
                        "type":"doc","version":1,
                        "content":[{"type":"paragraph","content":[{"type":"text","text": (f.evidence or '')[:10000]}]}]
                    }
                }
            }
            r = backoff_retry(lambda: client.post(create_url, headers=headers, json=payload, auth=auth))
            if r.status_code in (200,201): created += 1
    return created
