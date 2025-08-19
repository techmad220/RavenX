
from __future__ import annotations
import httpx, os, time
from .retry import backoff_retry
from typing import Any, Dict, List, Optional

H1_BASE = os.getenv("H1_BASE", "https://api.hackerone.com/v1")

class H1Client:
    def __init__(self, username: str, token: str, timeout: float = 20.0):
        self.username = username; self.token = token; self.timeout = timeout
        self._auth = (username, token)

    def _c(self):
        return httpx.Client(base_url=H1_BASE, timeout=self.timeout, auth=self._auth, headers={"Accept":"application/json"})

    def get_program(self, handle: str) -> Dict[str, Any]:
        with self._c() as c:
            def _do():
                r = c.get(f"/hackers/programs/{handle}"); r.raise_for_status(); return r.json()
            return backoff_retry(_do)

    def get_structured_scopes(self, handle: str, page: int = 1, size: int = 100) -> List[Dict[str, Any]]:
        res = []; with self._c() as c:
            while True:
                r = backoff_retry(lambda: c.get(f"/hackers/programs/{handle}/structured_scopes", params={"page[number]":page,"page[size]":size})); r.raise_for_status(); data = r.json()
                res.extend(data.get("data", []))
                if not (data.get("links") or {}).get("next"): break
                page += 1
        return res

    def list_weaknesses(self, handle: str, page: int = 1, size: int = 100) -> List[Dict[str, Any]]:
        with self._c() as c:
            try:
                r = backoff_retry(lambda: c.get(f"/hackers/programs/{handle}/weaknesses", params={"page[number]":page,"page[size]":size})); r.raise_for_status(); return r.json().get("data", [])
            except Exception:
                return []

    def create_report(self, team_handle: str, title: str, vul_info: str, impact: str, severity_rating: str = "none", weakness_id: Optional[int] = None, structured_scope_id: Optional[int] = None) -> Dict[str, Any]:
        body = {"data":{"type":"report","attributes":{"team_handle": team_handle,"title": title,"vulnerability_information": vul_info,"impact": impact,"severity_rating": severity_rating}}}
        if weakness_id is not None: body["data"]["attributes"]["weakness_id"] = weakness_id
        if structured_scope_id is not None: body["data"]["attributes"]["structured_scope_id"] = structured_scope_id
        with self._c() as c:
            r = backoff_retry(lambda: c.post("/hackers/reports", json=body, headers={"Content-Type":"application/json"})); r.raise_for_status(); return r.json()

    def upload_report_attachment(self, report_id: str, file_path: str) -> dict | None:
        eps = [f"/hackers/reports/{report_id}/attachments", f"/hackers/reports/{report_id}/activities/attachments"]
        for ep in eps:
            try:
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
                    with self._c() as c:
                        r = c.post(ep, files=files)
                        if r.status_code in (200,201): return r.json()
            except Exception:
                continue
        return None

def policy_disallows_scanners(policy_text: str) -> bool:
    if not policy_text: return False
    t = policy_text.lower()
    for k in ["no automated scanning","automated scanning is not permitted","do not use automated scanners","no automated scanners"]:
        if k in t: return True
    return False
