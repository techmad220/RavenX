
from __future__ import annotations
import os
from pathlib import Path

async def screenshot(url: str, out_dir: str, file_stub: str):
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except Exception:
        return None
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = os.path.join(out_dir, f"{file_stub}.png")
    async with async_playwright() as pw:
        b = await pw.chromium.launch()
        c = await b.new_context(viewport={"width":1280,"height":960})
        p = await c.new_page()
        try:
            await p.goto(url, wait_until="domcontentloaded", timeout=10000)
            await p.screenshot(path=path, full_page=True)
        finally:
            await c.close(); await b.close()
    return path if os.path.exists(path) else None
