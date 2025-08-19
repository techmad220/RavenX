
from __future__ import annotations
from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck

class CSRFHeuristicCheck(BaseCheck):
    name = "csrf_missing_token"
    severity = "low"

    async def run(self, url, resp, body, ctx):
        if "text/html" not in (resp.headers.get("content-type","")):
            return []
        s = BeautifulSoup(body, "html.parser")
        outs = []
        for form in s.find_all("form"):
            method = (form.get("method") or "GET").strip().upper()
            if method != "POST": continue
            fields = {(inp.get("name") or "").lower() for inp in form.find_all("input")}
            if not any(n for n in fields if n in {"csrf","_csrf","csrf_token","authenticity_token","xsrf","_token"}):
                outs.append(await self._new(self.severity, self.name, url, "POST form without obvious CSRF token field (heuristic)."))
        return outs
