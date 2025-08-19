
from __future__ import annotations
from typing import Set, Tuple, Callable
from urllib.parse import urljoin
from bs4 import BeautifulSoup

async def render_and_links(playwright, url: str, scope_in_scope: Callable[[str], bool], wait_ms: int = 4000) -> Tuple[str, Set[str]]:
    browser = await playwright.chromium.launch()
    ctx = await browser.new_context()
    page = await ctx.new_page()
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=wait_ms)
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            nxt = urljoin(url, a["href"])
            if scope_in_scope(nxt):
                links.add(nxt)
        return html, links
    finally:
        await ctx.close()
        await browser.close()
