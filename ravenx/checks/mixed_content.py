
from __future__ import annotations
from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck

class MixedContentCheck(BaseCheck):
    name = "mixed_content"
    severity = "low"

    async def run(self, url, resp, body, ctx) -> List:
        if not url.lower().startswith("https://"):
            return []
        ct = resp.headers.get("content-type","")
        if "text/html" not in ct:
            return []
        s = BeautifulSoup(body, "html.parser")
        issues = 0
        for tag, attr in [("img","src"),("script","src"),("link","href") ]:
            for el in s.find_all(tag):
                v = el.get(attr,"")
                if v.startswith("http://"):
                    issues += 1
        if issues:
            return [await self._new(self.severity, self.name, url, f"{issues} http:// resources on https page")]
        return []
