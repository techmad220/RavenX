
from __future__ import annotations
from typing import List
from bs4 import BeautifulSoup
from .base import BaseCheck

class DirectoryListingCheck(BaseCheck):
    name = "dir_listing"
    severity = "low"

    async def run(self, url, resp, body, ctx):
        if "text/html" not in (resp.headers.get("content-type","")):
            return []
        s = BeautifulSoup(body, "html.parser")
        if s.find(string=lambda t: isinstance(t, str) and "Index of /" in t):
            return [await self._new(self.severity, self.name, url, "Page appears to show directory listing.")]
        return []
