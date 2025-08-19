
from __future__ import annotations
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
from ..models import Finding, SEVERITY_ORDER
from ..h1 import H1Client
from .h1_weakmap import guess_cwe

SEV_MAP = {"low":"low", "medium":"medium", "high":"high", "critical":"critical"}

def _guess_scope_id(scopes: List[Dict[str,Any]], url: str) -> Optional[int]:
    p = urlparse(url); host = p.netloc.lower()
    for s in scopes:
        a = s.get("attributes") or {}
        if not a.get("eligible_for_submission", True): continue
        atype = (a.get("asset_type") or "").lower()
        ident = (a.get("asset_identifier") or "").lower()
        if atype in ("url","website","other","wildcard"):
            if host.endswith(ident.replace("*.","")) or ident in host or ident == host:
                try: return int(s.get("id"))
                except Exception: continue
    return None

def _guess_weakness_id(weaknesses: List[Dict[str,Any]], check_type: str) -> Optional[int]:
    cwe = guess_cwe(check_type)
    if not cwe: return None
    for w in weaknesses:
        a = w.get("attributes") or {}
        if cwe.lower() in (a.get("cwe_id","") or "").lower() or cwe.lower() in (a.get("name","") or "").lower():
            try: return int(w.get("id"))
            except Exception: continue
    return None

def compose_report_md(f: Finding) -> str:
    return f"""# {f.type} @ {f.url}

## Summary
{f.evidence or 'Potential issue found by RavenX.'}

## Steps to Reproduce
1. Request: `{f.method or 'GET'} {f.url}`
2. Observe the response/effect described below.

## Evidence
```
{(f.evidence or '').strip()}
```

## Impact
{f.impact or 'Impact consistent with issue type.'}

## Remediation (general)
Consider standard remediation for this weakness.
"""

def submit_findings(h1: H1Client, program_handle: str, findings: List[Finding], scopes: List[Dict[str,Any]], weaknesses: List[Dict[str,Any]] | None = None, attachments_dir: str | None = None, min_sev: str = "medium", dry_run: bool = True) -> List[Dict[str,Any]]:
    sev_rank = {"none":0,"low":1,"medium":2,"high":3,"critical":4}
    cutoff = sev_rank.get(min_sev, 2)
    results = []
    for f in findings:
        s = f.severity or "low"
        if sev_rank.get(s, 1) < cutoff: continue
        title = f"[{s.upper()}] {f.type} at {f.url}"
        vul_info = compose_report_md(f)
        impact = f.impact or "Impact consistent with issue type."
        scope_id = _guess_scope_id(scopes, f.url)
        weakness_id = _guess_weakness_id(weaknesses or [], f.type) if weaknesses is not None else None
        severity_rating = SEV_MAP.get(s, "none")
        if dry_run:
            results.append({"dry_run": True, "title": title, "structured_scope_id": scope_id, "weakness_id": weakness_id, "severity_rating": severity_rating})
        else:
            resp = h1.create_report(program_handle, title, vul_info, impact, severity_rating, weakness_id=weakness_id, structured_scope_id=scope_id)
            if attachments_dir:
                import os
                shot = os.path.join(attachments_dir, f.fingerprint + ".png")
                if os.path.exists(shot):
                    try:
                        rid = str((resp.get("data") or {}).get("id") or "")
                        if rid: h1.upload_report_attachment(rid, shot)
                    except Exception: pass
            results.append({"dry_run": False, "response": resp})
    return results
